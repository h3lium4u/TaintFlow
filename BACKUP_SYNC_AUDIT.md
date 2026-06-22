# TaintFlow V2 Incremental Sync Audit Report

This audit verifies the completion, integrity, and build status of the incremental synchronization from `D:\V2 approach` (Source) to `D:\V2 Backup` (Destination).

---

## 1. Sync Summary

*   **Total Size Transferred**: 1,609,291 bytes (1.53 MB)
*   **Final Backup Size**: 53,718,907 bytes (51.23 MB)
*   **Files Copied (New)**: 21 files
*   **Files Overwritten (Modified)**: 1 file
*   **Files Skipped**: 491 files
*   **Dependencies Automatically Included**: 0 files (no new dependencies were referenced in modified Rust code)

---

## 2. Integrity & Verification Checklist

After the synchronization, a series of manual and automated verification runs were executed inside the destination directory `D:\V2 Backup` to confirm system integrity:

| Requirement | Command / Check | Status | Description |
| :--- | :--- | :---: | :--- |
| **Rust Workspace Build?** | `cargo check --workspace` | **PASS** | Evaluated workspace compilation. No errors found. |
| **Validation Harness Compile?** | `cargo check --bin v2-validation` | **PASS** | Validated compile status of validation binary. |
| **Validation Harness Run?** | `cargo run --release --bin v2-validation` (Juliet-only test) | **PASS** | Juliet test dataset ran successfully, scoring 91 TPs and 21 FPs (MCC: 0.6682). |
| **Models Resolve?** | `py taintflow.py scan test_samples\sample_vuln.py` | **PASS** | Scanner loaded `model_v11.pkl` and `model_rc4.pkl` successfully and flagged the sample as `VULNERABLE` (CWE-89 and CWE-798). |
| **VS Code Extension Build?** | `npm install; npm run compile` | **PASS** | Compiled TS codebase without typescript or dependency resolution errors. |

---

## 3. Recommended Workspace Assessment

### Is `D:\V2 Backup` now the recommended development workspace?
**YES**

### Rationale:
1.  **Parity of Critical Code & Assets**: `D:\V2 Backup` now contains all active engine code (including the latest improvements in `interproc.rs`), the VS Code extension, and all recent release assets/metadata (RC102, RC103, RC103A).
2.  **No Performance Regression**: The core engines build, compile, and execute identical results to the primary source directory.
3.  **Removal of Technical Bloat**: Over **490 unnecessary files** (e.g., massive legacy training feature matrices `training_features_v*.csv`, obsolete model checkouts like `model_rc35`, `model_rc32`, etc., and debug caches/logs) were excluded. The resulting workspace size is just **51.23 MB** compared to gigabytes of duplicate datasets in the source, making it highly compact and efficient for active development.

---

## 4. Unmigrated Source Assets

### Are there any remaining files in `D:\V2 approach` that should still be migrated?
**NO**

All skipped files have been audited and fall under explicitly banned or unnecessary directories:
*   `archive/`: Outdated scripts and code dumps.
*   `target/`: Large build outputs (automatically re-generated on first build).
*   `node_modules/`: Re-created on-demand via `npm install`.
*   `__pycache__/` & `.git/` & `.gemini/`: Runtime or version control caches.
*   **Obsolete Models**: Older checkpoints (`model_rc2`, `model_rc3`, `model_rc29`, `model_rc32`, `model_rc35`) which have been superseded by `model_rc4` and `model_v11`.
*   **Massive CSVs / Datasets**: Training datasets like `training_features_rc4.csv` and `training_labels_v6_delta.csv` which are not active or required for continued engine development and release packaging.

---
*Audit completed on: 2026-06-21 06:50:00*
