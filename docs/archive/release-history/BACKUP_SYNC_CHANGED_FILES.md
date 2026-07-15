# TaintFlow V2 Sync Changed Files Report

This report outlines the individual files copied, overwritten, or skipped during the synchronization from `D:\V2 approach` to `D:\V2 Backup`.

---

## 1. Files Copied (New)

The following 21 files were identified as new important development or release engineering assets and were copied to `D:\V2 Backup`:

1.  `CONSOLIDATED_REPORTS.md`
2.  `CONSOLIDATED_SOURCES_AND_REPORTS.md`
3.  `RC102B_CONTEXT_FEASIBILITY.md`
4.  `RC102B_FP_DISTRIBUTION.md`
5.  `RC102B_SINK_GATING.md`
6.  `RC102_FP_CASEBOOK.md`
7.  `RC103A_AUDIT.md`
8.  `RC103A_DELTA.md`
9.  `RC103A_FP_DISTRIBUTION.md`
10. `RC103A_HOTFIX_REPORT.md`
11. `RC103A_RC104_ROADMAP.md`
12. `RC103A_RELEASE_VERDICT.md`
13. `RC103A_VALIDATION.md`
14. `RC103_CHANGED_CASES.md`
15. `RC103_FINAL_VALIDATION_SUMMARY.md`
16. `RC103_LOST_TPS.md`
17. `RC103_MCC_IMPACT.md`
18. `RC103_REGRESSION_AUDIT.md`
19. `RC103_ROLLBACK_RECOMMENDATION.md`
20. `RC103_VALIDATION.md`
21. `TAINTFLOW_CONSOLIDATED_RELEASE_REPORT.md`

---

## 2. Files Overwritten (Modified & Newer)

The following 1 file was identified as modified in the source and was updated in the backup directory:

*   `rust-engine/crates/taint/src/interproc.rs`

---

## 3. Dependencies Automatically Included

*   **None**: No modified Rust files (`interproc.rs`) referenced new configurations, datasets, models, or rules that were not already included.

---

## 4. Key Files Skipped (Not Copied)

A total of 491 files were skipped to prevent workspace pollution and bloat. Key categories of skipped files include:

### A. Excluded Directories
*   `archive/` (all archives, legacy scripts, experiments)
*   `target/` (build caches)
*   `node_modules/` (dependency folders)
*   `__pycache__/` (python cache)
*   `scratch/` (temporary developer run logs)

### B. Legacy Models & Checkpoints
*   `model_rc2.*`
*   `model_rc3.*`
*   `model_rc23.*`
*   `model_rc29.*`
*   `model_rc32.*`
*   `model_rc35.*`

### C. Obsolete/Superseded Reports
*   `RC76_*`
*   `RC86_*`
*   `RC90_*`

### D. Large Training & Evaluation Assets
*   `training_features_v*.csv` (massive feature matrices)
*   `training_labels_v*.csv`
*   `external_features_v*.csv`
*   `external_labels_v*.csv`
*   `KAGGLE_VALIDATION_PACKAGE.zip` (large package archives)
*   `WORKSPACE_CLEANUP_BACKUP.zip`

---
*Report generated on: 2026-06-21 06:50:00*
