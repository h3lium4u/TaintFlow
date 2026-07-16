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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const reviewManager_1 = require("./reviewManager");
// ─────────────────────────────────────────────────────────────
// Diagnostic collection (persists across scans)
// ─────────────────────────────────────────────────────────────
let diagnosticCollection;
// Severity mapping from TaintFlow → VS Code
const SEVERITY_MAP = {
    CRITICAL: vscode.DiagnosticSeverity.Error,
    HIGH: vscode.DiagnosticSeverity.Error,
    MEDIUM: vscode.DiagnosticSeverity.Warning,
    LOW: vscode.DiagnosticSeverity.Information,
};
// ─────────────────────────────────────────────────────────────
// Extension activation
// ─────────────────────────────────────────────────────────────
function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('taintflow');
    context.subscriptions.push(diagnosticCollection);
    // Review manager — tracks usage organically, no telemetry
    const reviewManager = new reviewManager_1.ReviewManager(context);
    // Command: Scan current file
    context.subscriptions.push(vscode.commands.registerCommand('taintflow.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('TaintFlow: No active file to scan.');
            return;
        }
        await scanTargetPath(editor.document.uri.fsPath, context, reviewManager);
    }));
    // Command: Scan workspace
    context.subscriptions.push(vscode.commands.registerCommand('taintflow.scanWorkspace', async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
            vscode.window.showWarningMessage('TaintFlow: No workspace folder open.');
            return;
        }
        for (const folder of folders) {
            await scanTargetPath(folder.uri.fsPath, context, reviewManager);
        }
    }));
    // Command: Clear all diagnostics
    context.subscriptions.push(vscode.commands.registerCommand('taintflow.clearDiagnostics', () => {
        diagnosticCollection.clear();
        vscode.window.showInformationMessage('TaintFlow: All findings cleared.');
    }));
    // Command: Rate extension — opens Open VSX review page directly
    context.subscriptions.push(vscode.commands.registerCommand('taintflow.rateExtension', async () => {
        await reviewManager.openReviewPage();
    }));
    // Auto-scan on save (if enabled)
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (doc) => {
        const config = vscode.workspace.getConfiguration('taintflow');
        if (config.get('autoScanOnSave', false)) {
            if (doc.languageId === 'python' || doc.languageId === 'java') {
                await scanTargetPath(doc.uri.fsPath, context, reviewManager);
            }
        }
    }));
    console.log('TaintFlow Security Scanner activated.');
}
function deactivate() {
    diagnosticCollection?.clear();
}
// ─────────────────────────────────────────────────────────────
// Core scan logic
// ─────────────────────────────────────────────────────────────
async function scanTargetPath(targetPath, context, reviewManager) {
    const config = vscode.workspace.getConfiguration('taintflow');
    const pythonPath = config.get('pythonPath', 'python');
    const scriptPath = resolveScriptPath(config, context);
    if (!scriptPath) {
        vscode.window.showErrorMessage('TaintFlow: Could not locate taintflow.py. Set taintflow.taintflowScriptPath in settings.');
        return;
    }
    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `TaintFlow: Scanning ${path.basename(targetPath)}…`,
        cancellable: false,
    }, async () => {
        const findings = await runScan(pythonPath, scriptPath, targetPath);
        applyDiagnostics(findings, targetPath);
        const cfg = vscode.workspace.getConfiguration('taintflow');
        if (cfg.get('showInformationMessages', true)) {
            if (findings.length === 0) {
                vscode.window.showInformationMessage(`TaintFlow: ✅ No vulnerabilities found in ${path.basename(targetPath)}.`);
            }
            else {
                vscode.window.showWarningMessage(`TaintFlow: ⚠️ Found ${findings.length} issue(s) in ${path.basename(targetPath)}. See Problems panel.`);
            }
        }
        // Record scan and conditionally show review prompt
        await reviewManager.recordScanAndCheck();
    });
}
function resolveScriptPath(config, context) {
    // 1. Explicit user setting
    const explicit = config.get('taintflowScriptPath', '').trim();
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
async function runScan(pythonPath, scriptPath, targetPath) {
    return new Promise((resolve) => {
        const cmd = `"${pythonPath}" "${scriptPath}" scan "${targetPath}" --json`;
        const cwd = path.dirname(scriptPath);
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
                    resolve(parsed);
                }
                else if (parsed.error) {
                    console.error('TaintFlow scan error:', parsed.error);
                    resolve([]);
                }
                else {
                    resolve([]);
                }
            }
            catch {
                console.error('TaintFlow: Failed to parse output:', stdout.slice(0, 500));
                resolve([]);
            }
        });
    });
}
function applyDiagnostics(findings, targetPath) {
    // Group findings by file URI
    const byFile = new Map();
    for (const finding of findings) {
        // The file field from taintflow.py is just the basename — resolve it
        let resolvedFile;
        if (path.isAbsolute(finding.file)) {
            resolvedFile = finding.file;
        }
        else if (fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory()) {
            resolvedFile = path.join(targetPath, finding.file);
        }
        else {
            resolvedFile = targetPath;
        }
        const uri = vscode.Uri.file(resolvedFile);
        const uriStr = uri.toString();
        if (!byFile.has(uriStr)) {
            byFile.set(uriStr, []);
        }
        const lineNo = Math.max(0, (finding.line ?? 1) - 1); // convert 1-indexed → 0-indexed
        const range = new vscode.Range(lineNo, 0, lineNo, Number.MAX_SAFE_INTEGER);
        const severity = SEVERITY_MAP[finding.severity?.toUpperCase()] ??
            vscode.DiagnosticSeverity.Warning;
        const diag = new vscode.Diagnostic(range, `[${finding.cwe}] ${finding.description} (Confidence: ${Math.round(finding.confidence * 100)}%)`, severity);
        diag.source = 'TaintFlow';
        diag.code = {
            value: finding.cwe,
            target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`)
        };
        // Attach remediation as related information
        diag.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(new vscode.Location(uri, range), `Remediation: ${finding.recommendation}`)
        ];
        byFile.get(uriStr).push(diag);
    }
    // Clear previous results for scanned scope and apply new ones
    diagnosticCollection.clear();
    for (const [uriStr, diags] of byFile.entries()) {
        diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
    }
}
