# RC108 GitHub Validation Report

This report presents the validation analysis of the **RC108** candidate build against historical release candidates (**RC104C** and **RC105**) on the **130-sample GitHub Holdout Subset**. It evaluates the effectiveness of the Tier B Python Import Resolver, logs regressions, and provides the final engineering verdict and next steps.

---

## 1. Executive Summary

- **Verdict:** **REVERT**
- **Core Recovery Status:** **Failed**. None of the 8 expected Python import recovery repositories were successfully resolved as True Positives (TPs).
- **Regressions:** **High**. Introduced **4 TP regressions** (including `ethyca/fides` and `toumorokoshi/transmute-core`) and **1 new False Positive (FP)** in `saltstack/salt`.
- **Metrics Summary:**
  - **MCC:** Degraded from **0.1238** (RC104C) to **0.0794** (RC108).
  - **Recall:** Degraded from **50.77%** (RC104C) to **41.54%** (RC108).
  - **F1 Score:** Degraded from **53.66%** (RC104C) to **47.37%** (RC108).

---

## 2. Comparative Metrics Matrix (130-Sample Subset)

The table below presents the validation metrics on the 130-sample subset (excluding pgadmin/datachain/ray heavy runs) across the active candidate builds:

| Build | TP | FP | TN | FN | Precision | Recall | F1 Score | MCC | Status / Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **RC104C** (Stable Baseline) | **33** | 25 | 40 | **32** | 56.90% | **50.77%** | **53.66%** | **0.1238** | traceback hardening (Stable) |
| **RC105** | 28 | **20** | **45** | 37 | **58.33%** | 43.08% | 49.56% | **0.1275** | Initial import resolver (Broken) |
| **RC108** (Active Candidate) | 27 | 22 | 43 | 38 | 55.10% | 41.54% | 47.37% | **0.0794** | Current run (Critical Regression) |

> [!WARNING]
> While RC105 slightly improved MCC due to FP reduction (+5 TNs), it came at a severe recall cost (-5 TPs). RC108 degrades both precision (-2 TNs) and recall (-6 TPs compared to RC104C), dropping MCC to an unacceptable **0.0794**.

---

## 3. Verification of Expected Python Import Recoveries

We audited the 8 target repositories from `RC105_EXPECTED_RECOVERIES.md` to check if their import-blocked FNs were resolved:

| Repository | Expected Recovery | Actual Status in RC108 | Forensic Result |
| :--- | :---: | :---: | :--- |
| `snowflakedb/snowflake-connector-python` | CWE-502 | **FN** | Remaining Blocked (No Recovery) |
| `PaddlePaddle/Paddle` | CWE-78 | **FN** | Remaining Blocked (No Recovery) |
| `sybrenstuvel/python-rsa` | CWE-327 | **FN** | Remaining Blocked (No Recovery) |
| `OctoPrint/OctoPrint` | CWE-78 | **FN** | Remaining Blocked (No Recovery) |
| `geopython/pygeoapi` | CWE-918 / CWE-22 | **FN** | Remaining Blocked (No Recovery) |
| `gitpython-developers/GitPython` | CWE-22 | **FN** | Remaining Blocked (No Recovery) |
| `B-Step62/mlflow` | CWE-22 | **FN** | Remaining Blocked (No Recovery) |
| `ethyca/fides` | CWE-22 / CWE-918 | **FN (Regressed)** | **Critical Regression** (Was TP in RC104C) |

---

## 4. Forensic Classification Analysis

### 4.1 Recovered TPs
- **Count:** **0** (No Python import FNs were successfully recovered as TPs).

### 4.2 Remaining Import-Blocked FNs
- **Count:** **38** (Increased from 32 in RC104C).
- **Target Repos Blocked:** All expected recoveries remain FNs.
- **TP Regressions (4 cases):**
  1. `ethyca/fides` (CWE-22, Commit: `f526d9ff`): Regressed from **TP** in RC104C to **FN** in RC108.
  2. `ethyca/fides` (CWE-918, Commit: `cd344d01`): Regressed from **TP** in RC104C to **FN** in RC108.
  3. `toumorokoshi/transmute-core` (CWE-502, Commit: `29bf82eb`): Regressed from **TP** in RC104C/RC105 to **FN** in RC108.
  4. `HumanSignal/label-studio-sdk` (CWE-22, Commit: `4a9715c6`): Regressed from **TP** in RC104C/RC105 to **FN** in RC108.

### 4.3 New FPs
- **Count:** **1**
- **Details:** `saltstack/salt` (CWE-22, Commit: `4b30218e`) became an **FP** in RC108 (was TN in RC104C & RC105).

### 4.4 Recovered FPs (turned TN)
- **Count:** **4**
- **Details:**
  1. `HumanSignal/label-studio-sdk` (CWE-22, Commit: `4a9715c6`): FP turned **TN** (but resulted in a TP regression on the vulnerable sample).
  2. `geopython/pygeoapi` (CWE-22, Commit: `bf25b869`): FP turned **TN** (Clean recovery).
  3. `pgadmin-org/pgadmin4` (CWE-502, Commit: `30a89033`): FP turned **TN** (Clean recovery).
  4. `pgadmin-org/pgadmin4` (CWE-89, Commit: `f4761f55`): FP turned **TN** (Clean recovery).

---

## 5. Root Cause Analysis of Resolver Failures

Our audit of [global.rs](file:///d:/V2%20Backup/rust-engine/crates/symbols/src/global.rs#L164-L174) and [v2_validation.rs](file:///d:/V2%20Backup/rust-engine/crates/cli/src/v2_validation.rs#L61-L63) identified two structural defects that cause the import resolver to fail:

### Defect 1: Hardcoded `test.py` Target Naming
In the validation harness, the target file is loaded as `test.py` (line 62 of `v2_validation.rs`).
- **Impact:** Since `test.py` resides at the top-level directory root, its module name is `test`.
- **Failure Mechanism:** Any relative import using dot-notation (e.g. `from .storage_client import ...` in `snowflake-connector-python`) attempts to resolve relative to `test.py`'s package. Since `test` is a top-level module with no parent package, Python relative traversals fail immediately. The engine cannot bind the target to its sibling modules.

### Defect 2: Missing `__init__.py` files in `program.source_files`
The package root discovery algorithm in `global.rs` attempts to traverse up folders checking `program.source_files` for `__init__.py`:
```rust
if program.source_files.contains_key(&init_py) || program.source_files.contains_key(&init_pyc)
```
- **Impact:** The validation harness only loads the target file and direct sibling helper files from `external_holdout.jsonl`. It **never** loads `__init__.py` files into `program.source_files`.
- **Failure Mechanism:** The lookup `contains_key` always returns `false`. The engine fails to identify package roots, causing FQNs to include unwanted directories (e.g. `web.pgadmin.utils.driver` instead of `pgadmin.utils.driver`), which mismatch imports and fail resolution.

---

## 6. Engineering Verdict

> [!CAUTION]
> **Verdict: REVERT**
> We recommend rolling back the active candidate to the stable **RC104C** baseline.
>
> **Rationale:**
> 1. **No Target Gains:** The Tier B Python Import Resolver failed to resolve any of the targeted Python import-blocked FNs due to integration bugs.
> 2. **Severe Regressions:** It introduced 4 TP regressions (turning TPs into FNs) and 1 new FP, degrading MCC from **0.1238** to **0.0794**.
> 3. **Architectural Gaps:** The generic package discovery was implemented against `program.source_files` rather than physical disk paths or harness-loaded package boundaries, rendering it completely broken for validation harness runs.

---

## 7. Next Highest-ROI Tasks (Post-RC108)

To recover progress and achieve release readiness, we rank the highest-ROI tasks after reverting to RC104C:

1. **Harness Integration Fix for Python Import Resolver (MCC ROI: +0.4381 Combined)**
   - *Action:* Modify `v2_validation.rs` to pass the correct repository-derived path to `load_file` (e.g., `snowflake/connector/ocsp_snowflake.py` instead of `test.py`) and pre-populate `program.source_files` with virtual `__init__.py` stubs for folders containing scanned Python files. This will fix Defect 1 & 2 generically, resolving the 33 Python FNs.
2. **Java/Vul4J Helper Seeding Gating (Combined ROI: +0.0050 Combined | Vul4J ROI: +0.8452)**
   - *Action:* Exclude zero-caller private or helper methods (methods starting with `_`) from entry-point seeding in `crates/taint/src/interproc.rs` for Java to eliminate the +9 FPs on the Vul4J dataset.
3. **OWASP XSS `isValidHref` Sanitizer Context Gating (Combined ROI: +0.0213 Combined)**
   - *Action:* Restrict `isValidHref` context-insensitive global sanitization to return-path-only guards to resolve 42 persistent XSS FPs on the OWASP benchmark.
