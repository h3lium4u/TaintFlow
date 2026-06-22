# Project Status Master

This document summarizes the current status of the TaintFlow project as of **June 11, 2026**.

## 1. Executive Summary
- **Current Dataset Version**: V9 (CWE-113 Java-expanded Normalized Delta Dataset).
- **Core Pipeline Migration**: Completed. Features are generated natively via tree-sitter.
- **Model Training Status**: Completed training of CatBoost Classifier on V9 (RC4) using normalized security deltas (Set C).
- **ONNX Export**: Completed and validated for V9 (RC4) delta features (`model_rc2.onnx`).
- **Major Milestone Achieved**: Successfully audited and eliminated structural shortcut learning (file size, CFG node count, method count). Replaced absolute counts with normalized change densities (Set C). Achieved a robust, shortcut-free **Java MCC of 0.9002** and **Combined MCC of 0.6171** on external holdout.

---

## 2. Key Metrics & Comparison

| Parameter | Dataset V7 (RC2 Deltas) | Dataset V8 (RC3 Java Expanded) | Dataset V9 (RC4 Normalized Deltas) |
| :--- | :--- | :--- | :--- |
| **Total Rows** | 9,130 | 9,670 | **9,670** |
| **Active Features** | 48 | 48 | **12 (Normalized Security Deltas)** |
| **Parser Success Rate** | 99.98% | 99.98% | **99.98%** |
| **Matthews Correlation (MCC)** | `0.6020` (CV) / `0.3500` (Ext) | `0.6191` (CV) / `0.7919` (Ext) | **`0.6288` (CV) / `0.6171` (Ext)** |
| **ROC-AUC** | `0.8878` (CV) / `0.7281` (Ext) | `0.8961` (CV) / `0.9554` (Ext) | **`0.8710` (CV) / `0.8888` (Ext)** |
| **Java Holdout MCC** | `0.0000` | `1.0000` (shortcut-inflated) | **`0.9002` (trustworthy)** |
| **Java Holdout ROC-AUC** | `0.5000` | `1.0000` (shortcut-inflated) | **`0.9945` (trustworthy)** |

---

## 3. Next Steps & Action Items
1. **Production Deployment**: Integrate `model_rc2.onnx` (RC4) into the TaintFlow scanning agent.
2. **Real-time Feature Extraction**: Use `target/release/taintflow-cli.exe` (with normalized delta calculation) to generate features on pull requests and apply the model for patch validation.

