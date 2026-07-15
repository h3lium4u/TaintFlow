<div align="center">

# 🛡️ TaintFlow

![TaintFlow Banner](assets/readme/hero.png)

### Context-Sensitive Static Application Security Testing (SAST) Engine

**Version: v1.0.0**

[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1.svg?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/Engine-Rust-f97316.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/ML-Python-3b82f6.svg?style=for-the-badge&logo=python)](https://python.org)
[![LightGBM](https://img.shields.io/badge/Model-LightGBM-10b981.svg?style=for-the-badge)](https://lightgbm.readthedocs.io/)
[![ONNX](https://img.shields.io/badge/Deployment-ONNX-eab308.svg?style=for-the-badge)](https://onnx.ai)

---

**ROC-AUC 0.84** on Python holdout · **92.5% recall** on real-world CVE fixes · **0 data leakage** verified

</div>



---

## 📖 Overview

TaintFlow is a production-grade security scanner that combines:

- **Rust taint analysis engine** — tree-sitter parsing, CFG construction, interprocedural taint propagation
- **Security-semantic delta features** — 12 directional features measuring how patches change the attack surface
- **LightGBM classifier** — trained on 9,130 before/after patch pairs, validated on external CVE holdouts
- **ONNX export** — runtime-agnostic model deployment

TaintFlow detects **7 CWE categories** in Python and Java source code:

| CWE | Vulnerability Type |
| :-- | :-- |
| CWE-89  | SQL Injection |
| CWE-78  | OS Command Injection |
| CWE-22  | Path Traversal |
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-502 | Unsafe Deserialization |
| CWE-798 | Hardcoded Credentials |
| CWE-327 | Weak Cryptographic Algorithm |

---

## 🏗️ Architecture

```
Source Code (.py / .java)
         │
         ▼
┌──────────────────────────┐
│     Rust Engine          │
│  ┌────────────────────┐  │
│  │ tree-sitter Parser │  │
│  └────────┬───────────┘  │
│           ▼              │
│  ┌────────────────────┐  │
│  │   Normalizer IR    │  │   ← Language-agnostic AST
│  └────────┬───────────┘  │
│           ▼              │
│  ┌────────────────────┐  │
│  │   Symbol Table     │  │   ← Type inference & scope
│  └────────┬───────────┘  │
│           ▼              │
│  ┌────────────────────┐  │
│  │    CFG Builder     │  │   ← Control flow graph
│  └────────┬───────────┘  │
│           ▼              │
│  ┌────────────────────┐  │
│  │   Taint Engine     │  │   ← Source → Sink propagation
│  └────────┬───────────┘  │
│           ▼              │
│  ┌────────────────────┐  │
│  │   Rule Engine      │  │   ← CWE pattern matching
│  └────────┬───────────┘  │
│           ▼              │
│  ┌────────────────────┐  │
│  │ Feature Extractor  │  │   ← 50-dim absolute vector
│  └────────────────────┘  │
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│   Delta Encoder (Python) │   ← (after - before) + 12 RC2 security deltas
└──────────┬───────────────┘
           │
           ▼
┌──────────────────────────┐
│  LightGBM / ONNX Model   │   ← model_rc2.pkl / model_rc2.onnx
└──────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete technical breakdown.

---

## ⚡ Installation

### Prerequisites
- Python 3.9+
- Rust toolchain (`cargo`, `rustc`)

### 1. Clone and build the Rust engine
```bash
git clone https://github.com/h3lium4u/TaintFlow.git
cd TaintFlow/rust-engine
cargo build --release -p taintflow-cli
```

### 2. Install Python dependencies
```bash
pip install lightgbm scikit-learn onnxruntime numpy pandas
```

### 3. Verify installation
```bash
echo "x = input(); eval(x)" | rust-engine/target/release/taintflow-cli.exe --extract
```

---

## 🔍 Usage

### Scan a single file
```bash
py taintflow.py scan app.py
py taintflow.py scan Main.java
```

### Scan a directory
```bash
py taintflow.py scan src/
```

### JSON output
```bash
py taintflow.py scan app.py --json
```

### Generate HTML report
```bash
py taintflow.py scan src/ --html security-report.html
```

---

## 📋 CLI Examples

**Python — SQL Injection detected:**
```
TaintFlow Scan Report - Found 2 issues:

================================================================================
[1] HIGH - CWE-89 (Confidence: 0.92)
File: app.py:12
Description: Unsanitized tainted variable 'query' flows to sink method 'cursor.execute' at parameter index 0.
Recommendation: Use parameterized queries, prepared statements, or ORM frameworks instead of raw SQL concatenation.
--------------------------------------------------------------------------------
[2] CRITICAL - CWE-798 (Confidence: 0.88)
File: app.py:17
Description: Potential hard-coded secret/password found in assignment to variable 'api_token'.
Recommendation: Remove hardcoded credentials. Load secrets securely from environment variables or vault services.
--------------------------------------------------------------------------------
```

**Java — SQL Injection + Credentials detected:**
```
TaintFlow Scan Report - Found 2 issues:

================================================================================
[1] HIGH - CWE-89 (Confidence: 0.92)
File: Main.java:14
Description: Unsanitized tainted variable 'query' flows to sink method 'stmt.execute' at parameter index 0.
Recommendation: Use parameterized queries, prepared statements, or ORM frameworks instead of raw SQL concatenation.
--------------------------------------------------------------------------------
[2] CRITICAL - CWE-798 (Confidence: 0.88)
File: Main.java:19
Description: Potential hard-coded secret/password found in assignment to variable 'adminToken'.
Recommendation: Remove hardcoded credentials. Load secrets securely from environment variables or vault services.
--------------------------------------------------------------------------------
```

**JSON output:**
```json
[
  {
    "cwe": "CWE-89",
    "severity": "HIGH",
    "confidence": 0.92,
    "file": "app.py",
    "line": 12,
    "description": "Unsanitized tainted variable 'query' flows to sink method 'cursor.execute'...",
    "recommendation": "Use parameterized queries..."
  }
]
```

---

## 🧩 VS Code Extension

The TaintFlow VS Code extension integrates the scanner directly into the editor.

**Features:**
- 🔴 Red underlines for HIGH / CRITICAL findings
- 🟡 Yellow underlines for MEDIUM findings
- 🔗 Clickable CWE codes linking to MITRE definitions
- 📋 Remediation guidance in the Problems panel
- ⚡ Optional auto-scan on file save

**Commands:**
| Command | Description |
| :--- | :--- |
| `TaintFlow: Scan Current File` | Scan the open editor |
| `TaintFlow: Scan Workspace` | Scan all .py / .java files |
| `TaintFlow: Clear All Findings` | Remove all diagnostics |

See [vscode/](vscode/) for the extension source.

---

## 📊 Benchmarks

### Internal Cross-Validation (5-Fold GroupKFold)

| Model | MCC | ROC-AUC |
| :--- | :--- | :--- |
| **TaintFlow (LightGBM)** | **0.6020** | **0.8878** |
| XGBoost | 0.5810 | 0.8741 |
| Random Forest | 0.5291 | 0.8403 |

### External Holdout Validation (Unseen CVEs)

| Subset | MCC | ROC-AUC | Recall |
| :--- | :--- | :--- | :--- |
| Python | **0.6122** | **0.8362** | 94.7% |
| Combined | 0.3500 | 0.7281 | **92.5%** |

> **92.5% recall** means TaintFlow catches 9 out of 10 real-world vulnerability fixes.

### Dataset Evolution

| Version | Key Improvement | MCC |
| :--- | :--- | :--- |
| V5 | Rust extraction pipeline | -0.12 |
| V6 | Delta encoding | +0.65 |
| V7 / RC2 | Security-semantic delta features | **+0.65 CV / +0.61 Python** |

---

## 🧠 Model Performance

- **Training Data**: 9,130 before/after patch pairs
- **Dataset**: CVEFixes + OSV + GHSA (Python + Java)
- **Validation**: 5-fold GroupKFold (no pair leakage, verified)
- **Model**: LightGBM, Optuna-optimized (100 trials)
- **Export**: ONNX for runtime-agnostic deployment
- **Leakage Audit**: PASSED — no pair, metadata, or label leakage

---

## 🗺️ Future Roadmap

| Priority | Feature |
| :--- | :--- |
| 🔴 High | C / C++ language support via tree-sitter-c |
| 🔴 High | GitHub Actions / GitLab CI integration |
| 🟡 Medium | Interprocedural analysis (cross-function taint) |
| 🟡 Medium | JavaScript / TypeScript support |
| 🟢 Low | Web dashboard for scan results |
| 🟢 Low | SARIF output format (GitHub Advanced Security compatible) |

---

## 📁 Project Structure

```
taintflow/
├── rust-engine/              # Rust engine (cargo workspace)
│   ├── crates/parser/        # tree-sitter CST → AstNode
│   ├── crates/normalizer/    # AstNode → NormalizedNode IR
│   ├── crates/symbols/       # Symbol table & type inference
│   ├── crates/cfg/           # Control flow graph builder
│   ├── crates/taint/         # Taint propagation engine
│   ├── crates/rules/         # CWE rule engine
│   ├── crates/features/      # Feature extraction
│   └── crates/cli/           # taintflow-cli binary
├── vscode/                   # VS Code extension
│   └── client/src/           # extension.ts
├── scripts/                  # Dataset generation & training scripts
├── RELEASE_RC2/              # Frozen RC2 release artifacts
├── taintflow.py              # CLI scanner entry point
├── model_rc2.pkl             # Trained LightGBM model
├── model_rc2.onnx            # ONNX export
├── ARCHITECTURE.md           # Technical architecture
├── PERFORMANCE_REPORT.md     # All benchmark results
└── README.md                 # This file
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with 🦀 Rust · 🐍 Python · 🌲 tree-sitter · 📊 LightGBM

</div>
