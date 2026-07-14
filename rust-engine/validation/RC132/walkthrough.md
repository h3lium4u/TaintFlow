# Phase 35 — Sentinel Classification Fix & Verification Report

The Sentinel Classification Fix is fully integrated. Validation has been executed, confirming regression recovery and baseline metric improvements.

---

## 1. Files Modified & Exact Code Changes

### [crates/v2-refiner-domain/src/lib.rs](file:///d:/V2%20Backup/rust-engine/crates/v2-refiner-domain/src/lib.rs)
We narrowed the sentinel check to strictly target `"unknown_call"` rather than matching generic `"unknown"` substrings:
```diff
     if target_is_any {
         let is_constant = curr.starts_with('"') || curr.parse::<f64>().is_ok() || curr == "true" || curr == "false" || curr == "None" || curr == "null";
-        let is_sentinel = curr.starts_with("unknown") || curr.contains("unknown");
+        let is_sentinel = curr == "unknown_call" || curr.starts_with("unknown_call");
         if is_constant || is_sentinel {
             return;
         }
```
We also added 8 dedicated unit tests verifying sentinel behavior, mixed path propagation, nested lookups, external API returns, and regression traces.

---

## 2. Test Results

* **Refiner Unit Tests**: All 73 tests passed successfully.
* **Compilation**: Binary compiled successfully.

---

## 3. Metrics Delta (OWASP & Java/Python Benchmarks)

| Metric | RC129J (Certified Baseline) | RC131 (Regressed) | **RC132 (This Run - Fixed)** | Delta vs Baseline |
| --- | --- | --- | --- | --- |
| **True Positives (TP)** | 1580 | 1579 | **1582** | **+2 (Improvement)** |
| **False Positives (FP)** | 141 | 141 | **141** | 0 (Unchanged) |
| **False Negatives (FN)** | 7 | 8 | **5** | **-2 (Improvement)** |
| **MCC** | 0.9098 | 0.9085 | **0.9106** | **+0.0008 (Improvement)** |

---

## 4. Regression Verification

### BenchmarkTest00030 & BenchmarkTest00031
* **Previous (RC131)**: Evaluated as `Infeasible` (FN) due to `"unknown_collection_val"` being pruned as a sentinel.
* **New (RC132)**: Evaluated as `Feasible` (TP).
* **Explanation**: The path solver correctly propagates `"unknown_collection_val"`, preserving the taint path.

### BenchmarkTest00475
* **Previous (RC131)**: Evaluated as `Infeasible` (FN) (triggering the dead branch check because the live path was pruned).
* **New (RC132)**: Evaluated as `Feasible` (TP).
* **Explanation**: Propagating `"unknown_collection_val"` keeps the live branch path active, preventing the dead branch check from pruning the flow.

---

## 5. Global Safety Audit

All pre-existing refinement domains have been audited and verified as **unchanged**:
* **ArrayList / HashMap**: Unchanged (verified by unit/pipeline tests).
* **Environment API / String Semantics**: Unchanged.
* **Path Feasibility / Python Collections**: Unchanged.
* **String Utility / Framework Wrappers**: Unchanged.

---

## 6. Next Recommended Implementation (Highest ROI)

### Root Cause: Collection Receiver SSA Aliasing
* **The Bug**: When collections (e.g. `ArrayList` or `HashMap`) are mutated, the SSA builder assigns them new versions (`valuesList_2`, `valuesList_3`, `valuesList_5`). Because `collection_states` tracks states per variable version name, the sequence of operations (`add`, `remove`, `get`) is split across separate states, leaving the final version empty and causing False Positives.
* **Exact File**: `crates/v2-refiner-domain/src/lib.rs`
* **Exact Function**: `MockPathSolver::evaluate_flow` (specifically where collection states are updated).
* **Estimated FP Reduction**: **14 FPs** (resolving the entire `arraylist_remove_get` cluster).
* **Implementation Plan**: Map collection states to the *base* collection variable (before SSA renaming) or propagate state updates across SSA assignments (`receiver_new = receiver_old`).
* **Implementation Risk**: Low (purely maps collection state updates to base names).
