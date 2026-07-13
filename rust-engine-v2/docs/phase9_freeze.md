# Phase 9 Design Freeze - Points-To Domain Foundation

**Prepared by**: Principal Compiler Architect  
**Status**: APPROVED DESIGN FREEZE  
**Workspace**: `rust-engine-v2`  
**Date**: June 28, 2026

---

## 1. Frozen Crate Registry

The following crate has been added to the frozen API registry of TaintFlow V2:

-   **`v2-pointsto`** ([crates/v2-pointsto](file:///d:/V2%20Backup/rust-engine-v2/crates/v2-pointsto))

No modifications to its public structures, enums, traits, or functions are permitted in subsequent development phases.

---

## 2. Frozen Types & Signatures

The following public APIs are locked:

-   `v2_pointsto::AllocationContext`
-   `v2_pointsto::AllocationSite`
-   `v2_pointsto::HeapObject`
-   `v2_pointsto::PointsToSet`
-   `v2_pointsto::HeapLocation`
-   `v2_pointsto::AliasClassId`
-   `v2_pointsto::PointsToHooks`

---

## 3. Downstream Compatibility Certification

We certify that:
1.  **Alias Analysis Compatibility**: The heap location and points-to set models are sufficient to support pointer alias analysis without modifications.
2.  **Taint Analysis Compatibility**: Access paths map cleanly to the points-to set representations, allowing field-sensitive and object-sensitive taint tracking.
3.  **Solver Integration**: The generic IFDS solver can instantiate dataflow reachability over these types.

---

## 4. Verification Logs

-   Workspace compiles: **PASS** (`cargo check` green)
-   Workspace tests: **PASS** (`cargo test` green)
-   Warnings: **0 warnings**
-   Errors: **0 errors**
