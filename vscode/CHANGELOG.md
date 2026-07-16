# Changelog

## 1.1.3

- **3-Stage Calm Review Request System:** Non-intrusive review prompts that never interrupt scan results.
  - Stage 1: Calm welcome message 30 seconds after first install.
  - Stage 2: Warm follow-up 5 minutes after next VS Code startup (if Stage 1 was deferred).
  - Stage 3: Heartfelt message after 7 days of use (if Stage 2 was deferred).
- **New Command:** `TaintFlow+: Rate Extension` — opens Open VSX review page at any time from the Command Palette.
- **New Setting:** `taintflow.enableReviewPrompt` — set to `false` to permanently silence all review prompts.
- All review state stored locally in VS Code globalState. Zero telemetry. Zero external tracking.

## 1.1.2

- Updated VS Code Marketplace README sub-logo description text.

## 1.1.1

- Updated Visual Studio Marketplace short description for TaintFlow SAST.
- Transitioned Marketplace README hero banner to raw branch-based URL referencing `hero-v2.png`.

## 1.1.0

- **Enterprise Readiness Release** of TaintFlow SAST.
- **Zero-Configuration Deployment:** Bundled native platform-specific Rust executables for Windows, Linux, and macOS.
- **Ignore File Support:** Added support for `.taintflowignore` files to bypass scanning of third-party vendors and output folders.
- **Incremental Caching:** Bypasses scanning unmodified files using local SHA-256 content hashing to achieve <1ms check speeds.
- **Rich HTML Reporting:** Automatically generates interactive `report.html` in the workspace root with diagrams and trace navigation.
- **SARIF Exporter:** Implemented command to export project findings to standardized SARIF 2.1 compliance JSON reports.
- **Workspace Dashboard:** Added a centralized webview panel displaying scanned counts, cache hit ratios, and severity charts.
- **Advanced WebView Explanations:** View full CWE breakdowns, attack scenarios, mitigation snippets, and links to official documentation.
- **Live Inline UX:** Highlights vulnerable statement flows, renders virtual text annotations next to code, and registers CodeLens quick fixes.

## 1.0.3

- Initial public Marketplace release of **TaintFlow SAST**.
- Rebranded static security analysis engine supporting Python and Java.
- Integrated offline interprocedural control flow analysis.
- Exposes Command Palette commands for scanning files/workspaces.
- Outputs detailed taint trace reports to the VS Code Problems panel.
