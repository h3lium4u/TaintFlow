"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReviewManager = void 0;
const vscode = __importStar(require("vscode"));
// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────
const REVIEW_STATE_KEY = 'taintflow.reviewState';
const OPEN_VSX_URL = 'https://open-vsx.org/extension/F1ZZ4N/taintflow-sast';
const SCANS_THRESHOLD_A = 5; // Condition A: ≥ 5 scans (any duration)
const SCANS_THRESHOLD_B = 2; // Condition B: ≥ 2 scans + 7 days
const DAYS_THRESHOLD_B = 7; // Condition B: used for ≥ 7 days
// ─────────────────────────────────────────────────────────────
// ReviewManager
// ─────────────────────────────────────────────────────────────
class ReviewManager {
    constructor(context) {
        this.context = context;
    }
    // ── State helpers ─────────────────────────────────────────
    getState() {
        return this.context.globalState.get(REVIEW_STATE_KEY, {
            scanCount: 0,
            firstUseDate: Date.now(),
            reviewAsked: false,
            dontAskAgain: false,
        });
    }
    async setState(state) {
        await this.context.globalState.update(REVIEW_STATE_KEY, state);
    }
    // ── Public API ────────────────────────────────────────────
    /**
     * Called after every successful scan completion.
     * Increments the scan counter and evaluates eligibility.
     */
    async recordScanAndCheck() {
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
    async checkReviewEligibility() {
        // Guard: user opted out or already responded
        const state = this.getState();
        if (state.reviewAsked || state.dontAskAgain) {
            return;
        }
        // Guard: setting disabled
        const config = vscode.workspace.getConfiguration('taintflow');
        if (!config.get('enableReviewPrompt', true)) {
            return;
        }
        // Condition A: ≥ 5 successful scans
        const conditionA = state.scanCount >= SCANS_THRESHOLD_A;
        // Condition B: ≥ 2 scans AND used for ≥ 7 days
        const daysSinceFirst = (Date.now() - state.firstUseDate) / (1000 * 60 * 60 * 24);
        const conditionB = state.scanCount >= SCANS_THRESHOLD_B
            && daysSinceFirst >= DAYS_THRESHOLD_B;
        if (conditionA || conditionB) {
            await this.showReviewPrompt();
        }
    }
    /**
     * Directly opens the Open VSX review page.
     * Bound to the taintflow.rateExtension command.
     */
    async openReviewPage() {
        await vscode.env.openExternal(vscode.Uri.parse(OPEN_VSX_URL));
    }
    // ── Internal ──────────────────────────────────────────────
    async showReviewPrompt() {
        const LEAVE_REVIEW = '⭐ Leave Review';
        const LATER = 'Later';
        const DONT_ASK_AGAIN = "Don't Ask Again";
        const selection = await vscode.window.showInformationMessage('Enjoying TaintFlow+? Your feedback helps improve the project and helps other developers discover it.', LEAVE_REVIEW, LATER, DONT_ASK_AGAIN);
        const state = this.getState();
        if (selection === LEAVE_REVIEW) {
            state.reviewAsked = true;
            await this.setState(state);
            await this.openReviewPage();
        }
        else if (selection === DONT_ASK_AGAIN) {
            state.dontAskAgain = true;
            await this.setState(state);
        }
        // LATER or dismissed: no state change — will be asked again
    }
}
exports.ReviewManager = ReviewManager;
