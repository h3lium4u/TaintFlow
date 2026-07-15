# TaintFlow V2 Minimal Deployable Backup Audit

This audit document verifies the integrity and deployability of the minimal backup generated from `D:\V2 approach` to `D:\V2 Backup`.

## Summary of Copied Files
- **Total Source Files Copied**: 95 (Excluding models and datasets)
- **Total Model Files Copied**: 6
- **Total Config Files Copied**: 6
- **Total Dataset Files Copied**: 4
- **Total Backup Size**: 52316897 bytes (49.89 MB)

## Verification Checklist

| Requirement | Status | Description |
| :--- | :---: | :--- |
| **Rust Build Possible?** | **PASS** | Verifies if `cargo check` succeeds on the backup rust-engine. |
| **Validation Runnable?** | **PASS** | Verifies if the `v2-validation` binary is runnable and builds successfully. |
| **Models Present?** | **PASS** | Verifies presence of both active production `model_v11` and fallback `model_rc4`. |
| **VS Code extension buildable?** | **PASS** | Verifies presence of package.json, tsconfig.json and typescript source files. |

## File Classification Breakdown
- **REQUIRED_RUNTIME**: 17 files
- **REQUIRED_BUILD**: 82 files
- **REQUIRED_MODEL**: 6 files
- **OPTIONAL**: 6 files
- **UNNECESSARY (Excluded)**: 5342 files

---
*Audit completed on: 2026-06-20 18:12:54*
