import * as vscode from 'vscode';

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const REVIEW_STATE_KEY   = 'taintflow.reviewState';
const OPEN_VSX_URL       = 'https://open-vsx.org/extension/F1ZZ4N/taintflow-sast';

const SCANS_THRESHOLD_A  = 5;   // Condition A: ≥ 5 scans (any duration)
const SCANS_THRESHOLD_B  = 2;   // Condition B: ≥ 2 scans + 7 days
const DAYS_THRESHOLD_B   = 7;   // Condition B: used for ≥ 7 days

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

interface ReviewState {
    scanCount:     number;
    firstUseDate:  number;   // Unix timestamp (ms)
    reviewAsked:   boolean;
    dontAskAgain:  boolean;
}

// ─────────────────────────────────────────────────────────────
// ReviewManager
// ─────────────────────────────────────────────────────────────

export class ReviewManager {

    private readonly context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    // ── State helpers ─────────────────────────────────────────

    private getState(): ReviewState {
        return this.context.globalState.get<ReviewState>(REVIEW_STATE_KEY, {
            scanCount:    0,
            firstUseDate: Date.now(),
            reviewAsked:  false,
            dontAskAgain: false,
        });
    }

    private async setState(state: ReviewState): Promise<void> {
        await this.context.globalState.update(REVIEW_STATE_KEY, state);
    }

    // ── Public API ────────────────────────────────────────────

    /**
     * Called after every successful scan completion.
     * Increments the scan counter and evaluates eligibility.
     */
    public async recordScanAndCheck(): Promise<void> {
        const state = this.getState();

        // Persist first-use timestamp only once
        if (state.scanCount === 0) {
            state.firstUseDate = Date.now();
        }

        state.scanCount += 1;
        await this.setState(state);

        await this.checkReviewEligibility();
    }

    /**
     * Evaluates whether the review prompt should be shown.
     * Called automatically by recordScanAndCheck() and can
     * also be called manually via the command palette command.
     */
    public async checkReviewEligibility(): Promise<void> {
        // Guard: user opted out or already responded
        const state = this.getState();
        if (state.reviewAsked || state.dontAskAgain) {
            return;
        }

        // Guard: setting disabled
        const config = vscode.workspace.getConfiguration('taintflow');
        if (!config.get<boolean>('enableReviewPrompt', true)) {
            return;
        }

        // Condition A: ≥ 5 successful scans
        const conditionA = state.scanCount >= SCANS_THRESHOLD_A;

        // Condition B: ≥ 2 scans AND used for ≥ 7 days
        const daysSinceFirst = (Date.now() - state.firstUseDate) / (1000 * 60 * 60 * 24);
        const conditionB     = state.scanCount >= SCANS_THRESHOLD_B
                            && daysSinceFirst   >= DAYS_THRESHOLD_B;

        if (conditionA || conditionB) {
            await this.showReviewPrompt();
        }
    }

    /**
     * Directly opens the Open VSX review page.
     * Bound to the taintflow.rateExtension command.
     */
    public async openReviewPage(): Promise<void> {
        await vscode.env.openExternal(vscode.Uri.parse(OPEN_VSX_URL));
    }

    // ── Internal ──────────────────────────────────────────────

    private async showReviewPrompt(): Promise<void> {
        const LEAVE_REVIEW    = '⭐ Leave Review';
        const LATER           = 'Later';
        const DONT_ASK_AGAIN  = "Don't Ask Again";

        const selection = await vscode.window.showInformationMessage(
            'Enjoying TaintFlow+? Your feedback helps improve the project and helps other developers discover it.',
            LEAVE_REVIEW,
            LATER,
            DONT_ASK_AGAIN
        );

        const state = this.getState();

        if (selection === LEAVE_REVIEW) {
            state.reviewAsked = true;
            await this.setState(state);
            await this.openReviewPage();

        } else if (selection === DONT_ASK_AGAIN) {
            state.dontAskAgain = true;
            await this.setState(state);

        }
        // LATER or dismissed: no state change — will be asked again
    }
}
