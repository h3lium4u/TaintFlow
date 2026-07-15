<p align="center">
  <img src="assets/logo/logo.png" width="150" alt="TaintFlow Logo"/>
</p>

<h1 align="center">TaintFlow SAST</h1>

<p align="center">
  <strong>Offline Context-Sensitive Static Application Security Testing (SAST) Engine for VS Code</strong>
</p>

<p align="center">
  <a href="https://github.com/h3lium4u/TaintFlow"><img src="https://img.shields.io/github/v/release/h3lium4u/TaintFlow?color=blue&logo=github" alt="Release"/></a>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey" alt="Platforms"/>
</p>

---

![TaintFlow Banner](https://raw.githubusercontent.com/h3lium4u/TaintFlow/release/v1.0.0/assets/readme/hero-v2.png)

## Overview

**TaintFlow SAST** is a highly optimized, offline static application security testing (SAST) extension designed to identify high-risk data-flow vulnerabilities (injection flaws, path traversals, and unsafe deserialization) in real-time as you write code.

By combining a lightning-fast Rust-compiled taint propagation engine with advanced interprocedural analysis, TaintFlow SAST delivers the precision of enterprise-grade security tools directly into the editor—with **zero configuration** and **100% offline privacy**.

---

## Key Features

- **⚡ Zero Configuration:** Work immediately after installation. No compiler setups, external Python/Rust runtimes, or execution scripts required.
- **🔍 Real-Time Live Diagnostics:** Automatically scans files in the background on open, edit, and switch. Results appear instantly in the Problems panel.
- **🎨 Rich Inline UX:** Highlights vulnerable statement flows, displays severity-colored virtual text decorations, and shows CodeLenses for High/Critical issues.
- **🛡 TaintFlow Explorer:** A dedicated sidebar tree view showing active vulnerabilities grouped by severity, with click-to-jump step-by-step trace navigation from source to sink.
- **⚡ Performance-Optimized:** Asynchronous analysis debounced to 600ms. Stale scan processes are automatically cancelled on typing to keep the UI perfectly fluid.
- **🔒 100% Local & Private:** Code never leaves your machine. The analysis runs completely locally inside sandboxed executables.

---

## Supported Languages

- **Java** (`.java`)
- **Python** (`.py`)

---

## Detection Capabilities (CWEs)

TaintFlow SAST detects high-precision control-flow and data-flow violations including:

| CWE | Vulnerability Title | Severity | Description |
| :--- | :--- | :--- | :--- |
| **CWE-22** | Path Traversal / File Disclosure | **High** | Unsanitized input controls file system paths. |
| **CWE-78** | OS Command Injection | **Critical** | Untrusted data executes raw shell commands. |
| **CWE-79** | Reflected / Stored Cross-Site Scripting (XSS) | **High** | Injection of raw HTML/scripts into web responses. |
| **CWE-89** | SQL Injection | **Critical** | Manipulation of raw database queries. |
| **CWE-113** | HTTP Response Splitting / CR-LF Injection | **Medium** | Injection of carriage return/line feed into headers. |
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm | **Medium** | Use of MD5, SHA-1, or RC4 in security contexts. |
| **CWE-502** | Deserialization of Untrusted Data | **Critical** | Unsafe deserialization of objects leading to RCE. |
| **CWE-798** | Use of Hardcoded Credentials | **High** | Hardcoded API keys, passwords, and tokens. |
| **CWE-918** | Server-Side Request Forgery (SSRF) | **High** | Untrusted input forms outbound HTTP connections. |

---

## Architecture

```
                       ┌───────────────────────────────────────┐
                       │           VS Code Extension           │
                       │          (Typescript Client)          │
                       └──────────────────┬────────────────────┘
                                          │  1. Triggers Scan (Debounced)
                                          ▼
                       ┌───────────────────────────────────────┐
                       │          OS Temp Directory            │
                       │       (Temporary Live Code)           │
                       └──────────────────┬────────────────────┘
                                          │  2. Calls Bunled Binary
                                          ▼
                       ┌───────────────────────────────────────┐
                       │           TaintFlow Engine            │
                       │           (Rust CLI Binary)           │
                       └──────────────────┬────────────────────┘
                                          │  3. Formats Output (JSON)
                                          ▼
                       ┌───────────────────────────────────────┐
                       │            Problems Panel             │
                       │        & TaintFlow Tree View          │
                       └───────────────────────────────────────┘
```

---

## Quick Start

1. **Install:** Install TaintFlow SAST from the VS Code Marketplace.
2. **Open:** Open any Java or Python project.
3. **Type:** Begin writing or paste vulnerable code (e.g. standard SQL injection or command injection patterns).
4. **Inspect:** Inline decorations appear next to findings. Click **View Taint Trace** in the CodeLens or click items in the **TaintFlow Explorer** sidebar to see step-by-step data flows.

---

## Example Scan Output

Here is how findings are structured in JSON when run via the bundled CLI:

```json
{
  "scan_version": "1.0.0",
  "scanned_files": 1,
  "total_findings": 1,
  "findings": [
    {
      "cwe": "CWE-89",
      "title": "SQL Injection Vulnerability",
      "description": "Unsanitized parameter flows into query execution.",
      "file_path": "d:\\project\\src\\Main.java",
      "line_number": 42,
      "severity": "CRITICAL",
      "code_flow_path": [
        {
          "file_path": "d:\\project\\src\\Main.java",
          "line_number": 12,
          "message": "Source: Taint input entrypoint"
        },
        {
          "file_path": "d:\\project\\src\\Main.java",
          "line_number": 42,
          "message": "Sink: Tainted value reaches sql query execution"
        }
      ]
    }
  ]
}
```

---

## Privacy & Performance

- **Privacy:** TaintFlow SAST does not track you, does not collect telemetry, and does not upload your source code. Analysis is performed 100% locally.
- **Performance:** Scans execute asynchronously inside separate lightweight processes. If you continue typing, current scan operations are aborted immediately to ensure that typing latency is never affected.

---

## Roadmap

- [ ] Support for C# (`.cs`) and JavaScript/TypeScript (`.js`/`.ts`).
- [ ] Visual data flow graphing in webview.
- [ ] Custom validation rule sets via YAML.

---

## License

This extension is licensed under the [MIT License](LICENSE.txt).
