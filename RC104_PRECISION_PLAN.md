# RC104: Precision Recovery Plan

This document outlines the engineering plan to recover the engine's Matthews Correlation Coefficient (MCC) above **0.65** without losing more than **5 True Positives (TPs)**.

---

## 1. Actionable Recommendations for Reverted Rules

| Rule | Classification | Recommendation | Expected TP Impact | Expected FP Impact | Expected MCC Impact |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **Private Method Suppression** | `REVERTED` | **PARTIAL RESTORE** (Context-Aware Seeding) | 0 | -14 | +0.007 |
| **CWE-502 Sink Argument Gating** | `REVERTED` | **PARTIAL RESTORE** (Dynamic Gating) | 0 | -4 | +0.002 |
| **`isValidHref` Sink Registry** | `ACTIVE` | **RECLASSIFY** (Model as Sanitizer/Validator) | -1 | -83 | +0.046 |

---

## 2. Technical Implementation Roadmap

### Step 1: Context-Aware Private Seeding
*   **Problem:** The previous `starts_with('_')` rule suppressed public wrapper entry points (e.g. in Vul4J Java mocks) and active helpers (e.g. PaddlePaddle's `_wget_download`).
*   **Fix:** 
    *   Do not suppress any Java methods starting with `_` (avoiding the Vul4J wrapper collapse).
    *   Only suppress Python methods starting with `_` if they have **zero incoming edges** in the Call Graph (meaning they are completely uncalled internal library functions).
*   **Code Location:** `crates/taint/src/interproc.rs` in `seed_sources`.

### Step 2: Dynamic Deserialization Gating
*   **Problem:** Coarse parameter gating blocked deserialization flows in parameter-less configuration loaders.
*   **Fix:** Skip deserialization seeding in parameter-less methods *only if* the method body contains no references to environment variables (`os.getenv`, `os.environ`), class properties (`self`), or file reads.
*   **Code Location:** `crates/taint/src/interproc.rs` in `seed_sources`.

### Step 3: Reclassify `isValidHref` from Sink to Sanitizer
*   **Problem:** Registering `isvalidhref` as a CWE-79 sink in `stubs.rs` and `lib.rs` caused the engine to flag every safe validation check, triggering 83 FPs in OWASP.
*   **Fix:** 
    *   Remove `isvalidhref` from the `generic_sinks` list in `crates/taint/src/stubs.rs`.
    *   Add `isvalidhref` to the sanitizer registry in `crates/taint/src/lib.rs` (`get_sanitized_cwes_for_callee`), designating it as a sanitizer for `CWE-79` since any value passing this validation is safe to print in an `href` attribute.
*   **Code Location:** `crates/taint/src/stubs.rs` and `crates/taint/src/lib.rs`.

---

## 3. Projected Performance Target

| Metric | RC101A Baseline | RC101A+ (No Gating) | RC104 Projected | Net Delta (RC104 vs RC101A) |
| :--- | :---: | :---: | :---: | :---: |
| **Combined TP** | 1519 | 1568 | **1567** | **+48** |
| **Combined FP** | 381 | 487 | **386** | **+5** |
| **Combined Recall** | 85.48% | 87.16% | **87.10%** | **+1.62%** |
| **Combined Precision** | 79.95% | 76.30% | **80.23%** | **+0.28%** |
| **Combined MCC** | 0.6394 | 0.6039 | **0.6548** | **+0.0154** |

---

## 4. Verdict & Release Suitability
By implementing the RC104 Precision Plan, we resolve the XSS false positive spike and entry-point suppression gaps. This will establish **RC104** as the strongest baseline ever achieved, yielding both maximum recall (87.10%) and superior MCC (0.6548).
