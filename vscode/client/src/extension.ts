import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { ReviewManager } from './reviewManager';

// ─────────────────────────────────────────────────────────────
// Diagnostic collection (persists across scans)
// ─────────────────────────────────────────────────────────────
let diagnosticCollection: vscode.DiagnosticCollection;

// Severity mapping from TaintFlow → VS Code
const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
    CRITICAL: vscode.DiagnosticSeverity.Error,
    HIGH:     vscode.DiagnosticSeverity.Error,
    MEDIUM:   vscode.DiagnosticSeverity.Warning,
    LOW:      vscode.DiagnosticSeverity.Information,
};

interface TaintFlowFinding {
    cwe:            string;
    severity:       string;
    confidence:     number;
    file:           string;
    line:           number;
    description:    string;
    recommendation: string;
}

// ─────────────────────────────────────────────────────────────
// Extension activation
// ─────────────────────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext): void {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('taintflow');
    context.subscriptions.push(diagnosticCollection);

    // Review manager — tracks usage organically, no telemetry
    const reviewManager = new ReviewManager(context);

    // Command: Scan current file
    context.subscriptions.push(
        vscode.commands.registerCommand('taintflow.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('TaintFlow: No active file to scan.');
                return;
            }
            await scanTargetPath(editor.document.uri.fsPath, context, reviewManager);
        })
    );

    // Command: Scan workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('taintflow.scanWorkspace', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders || folders.length === 0) {
                vscode.window.showWarningMessage('TaintFlow: No workspace folder open.');
                return;
            }
            for (const folder of folders) {
                await scanTargetPath(folder.uri.fsPath, context, reviewManager);
            }
        })
    );

    // Command: Clear all diagnostics
    context.subscriptions.push(
        vscode.commands.registerCommand('taintflow.clearDiagnostics', () => {
            diagnosticCollection.clear();
            vscode.window.showInformationMessage('TaintFlow: All findings cleared.');
        })
    );

    // Command: Rate extension — opens Open VSX review page directly
    context.subscriptions.push(
        vscode.commands.registerCommand('taintflow.rateExtension', async () => {
            await reviewManager.openReviewPage();
        })
    );

    // Auto-scan on save (if enabled)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            const config = vscode.workspace.getConfiguration('taintflow');
            if (config.get<boolean>('autoScanOnSave', false)) {
                if (doc.languageId === 'python' || doc.languageId === 'java') {
                    await scanTargetPath(doc.uri.fsPath, context, reviewManager);
                }
            }
        })
    );

    console.log('TaintFlow Security Scanner activated.');
}

export function deactivate(): void {
    diagnosticCollection?.clear();
}

// ─────────────────────────────────────────────────────────────
// Core scan logic
// ─────────────────────────────────────────────────────────────
async function scanTargetPath(
    targetPath: string,
    context: vscode.ExtensionContext,
    reviewManager: ReviewManager
): Promise<void> {
    const config       = vscode.workspace.getConfiguration('taintflow');
    const pythonPath   = config.get<string>('pythonPath', 'python');
    const scriptPath   = resolveScriptPath(config, context);

    if (!scriptPath) {
        vscode.window.showErrorMessage(
            'TaintFlow: Could not locate taintflow.py. Set taintflow.taintflowScriptPath in settings.'
        );
        return;
    }

    return vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `TaintFlow: Scanning ${path.basename(targetPath)}…`,
            cancellable: false,
        },
        async () => {
            const findings = await runScan(pythonPath, scriptPath, targetPath);
            applyDiagnostics(findings, targetPath);

            const cfg = vscode.workspace.getConfiguration('taintflow');
            if (cfg.get<boolean>('showInformationMessages', true)) {
                if (findings.length === 0) {
                    vscode.window.showInformationMessage(
                        `TaintFlow: ✅ No vulnerabilities found in ${path.basename(targetPath)}.`
                    );
                } else {
                    vscode.window.showWarningMessage(
                        `TaintFlow: ⚠️ Found ${findings.length} issue(s) in ${path.basename(targetPath)}. See Problems panel.`
                    );
                }
            }

            // Record scan and conditionally show review prompt
            await reviewManager.recordScanAndCheck();
        }
    );
}

function resolveScriptPath(
    config: vscode.WorkspaceConfiguration,
    context: vscode.ExtensionContext
): string | null {
    // 1. Explicit user setting
    const explicit = config.get<string>('taintflowScriptPath', '').trim();
    if (explicit && fs.existsSync(explicit)) {
        return explicit;
    }

    // 2. Extension bundle sibling
    const bundled = path.join(context.extensionPath, '..', 'taintflow.py');
    if (fs.existsSync(bundled)) {
        return bundled;
    }

    // 3. Workspace root
    const folders = vscode.workspace.workspaceFolders;
    if (folders) {
        for (const folder of folders) {
            const candidate = path.join(folder.uri.fsPath, 'taintflow.py');
            if (fs.existsSync(candidate)) {
                return candidate;
            }
        }
    }

    return null;
}

async function runScan(
    pythonPath: string,
    scriptPath: string,
    targetPath: string
): Promise<TaintFlowFinding[]> {
    return new Promise((resolve) => {
        const cmd  = `"${pythonPath}" "${scriptPath}" scan "${targetPath}" --json`;
        const cwd  = path.dirname(scriptPath);

        cp.exec(cmd, { cwd, maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
            if (err && !stdout) {
                console.error('TaintFlow scan error:', stderr);
                resolve([]);
                return;
            }

            try {
                const parsed = JSON.parse(stdout.trim());
                // Handle both array and error-object responses
                if (Array.isArray(parsed)) {
                    resolve(parsed as TaintFlowFinding[]);
                } else if (parsed.error) {
                    console.error('TaintFlow scan error:', parsed.error);
                    resolve([]);
                } else {
                    resolve([]);
                }
            } catch {
                console.error('TaintFlow: Failed to parse output:', stdout.slice(0, 500));
                resolve([]);
            }
        });
    });
}

function applyDiagnostics(
    findings: TaintFlowFinding[],
    targetPath: string
): void {
    // Group findings by file URI
    const byFile = new Map<string, vscode.Diagnostic[]>();

    for (const finding of findings) {
        // The file field from taintflow.py is just the basename — resolve it
        let resolvedFile: string;
        if (path.isAbsolute(finding.file)) {
            resolvedFile = finding.file;
        } else if (fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory()) {
            resolvedFile = path.join(targetPath, finding.file);
        } else {
            resolvedFile = targetPath;
        }

        const uri      = vscode.Uri.file(resolvedFile);
        const uriStr   = uri.toString();

        if (!byFile.has(uriStr)) {
            byFile.set(uriStr, []);
        }

        const lineNo = Math.max(0, (finding.line ?? 1) - 1); // convert 1-indexed → 0-indexed
        const range  = new vscode.Range(lineNo, 0, lineNo, Number.MAX_SAFE_INTEGER);

        const severity = SEVERITY_MAP[finding.severity?.toUpperCase()] ??
            vscode.DiagnosticSeverity.Warning;

        const diag = new vscode.Diagnostic(
            range,
            `[${finding.cwe}] ${finding.description} (Confidence: ${Math.round(finding.confidence * 100)}%)`,
            severity
        );
        diag.source = 'TaintFlow';
        diag.code   = {
            value: finding.cwe,
            target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`)
        };
        // Attach remediation as related information
        diag.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(
                new vscode.Location(uri, range),
                `Remediation: ${finding.recommendation}`
            )
        ];

        byFile.get(uriStr)!.push(diag);
    }

    // Clear previous results for scanned scope and apply new ones
    diagnosticCollection.clear();
    for (const [uriStr, diags] of byFile.entries()) {
        diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
    }
}
