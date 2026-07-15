# RC103 Post-Mortem Report

This document reviews the architectural and heuristic changes introduced during the RC103 validation cycle (releases RC103, RC103A, and RC103C). It analyzes their performance impacts, identifies regressions, and provides a classification scheme to construct a stable, regression-free candidate.

---

## 1. Executive Assessment of RC103-era Changes

The RC103 development cycle introduced four main modifications to the TaintFlow engine: two targeting precision-hardening and two targeting bug fixes and sink additions. 

### Improvements: What Went Right
1. **Unescape-as-Sanitizer Fix (RC103C):**
   * *Description:* Refactored `expression_contains_sanitizer` and `get_sanitized_cwes_for_callee` in `interproc.rs` and `lib.rs` to explicitly exclude "unescape" functions from being treated as sanitizers.
   * *Impact:* Corrected a widespread false negative where unescape routines suppressed valid XSS flows. Restored +3 Juliet TPs and +43 OWASP TPs with zero FP regression.
2. **isValidHref CWE-79 Sink Registry (RC103C):**
   * *Description:* Added `isvalidhref` to `stubs.rs` and `lib.rs` as an active CWE-79 sink heuristic.
   * *Impact:* Enabled the engine to identify security-sensitive URL sinks in J2EE wrapper configurations. Restored +12 Vul4J TPs (100% recall recovery).

### Regressions: What Went Wrong
1. **Source Seeding Refinement (RC103/RC103A):**
   * *Description:* Suppressed automatic seeding of uncalled private helper methods (specifically methods prefixed with `_` or identified via `is_private`).
   * *Impact:* Caused a catastrophic recall collapse. It blocked valid intra-file flows inside private Python utilities (e.g., `_wget_download` CWE-78 in PaddlePaddle, CWE-22 in GitPython) and stripped entry point status from public test-wrapper helpers in Vul4J (resulting in a 0% Vul4J recall drop).
2. **Sink Argument Gating (RC103/RC103A):**
   * *Description:* Enforced a rule requiring deserialization (CWE-502) sinks to reside in methods with explicit parameters to prevent "ghost" flows.
   * *Impact:* Aggressively suppressed legitimate deserialization vulnerabilities where data was loaded dynamically inside parameter-less methods or bound directly to class attributes (e.g., `self` fields in Snowflake cache connector and Fides). Caused a loss of ~5 TPs.

---

## 2. Change Classification

To build a stable `RC101A+` candidate, every RC103-era change is classified below:

| Feature / Change | Classification | Expected TP Impact | Expected FP Impact | Expected MCC Impact | Rationale |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Unescape-as-Sanitizer Fix** | **KEEP** | **+46 TPs** (Juliet/OWASP) | **Neutral** (0 FP) | **Highly Positive** | Proven-positive change that resolves a sanitizer over-matching bug. |
| **isValidHref CWE-79 Registry** | **KEEP** | **+12 TPs** (Vul4J) | **Neutral** (0 FP) | **Highly Positive** | Successfully restores critical J2EE sink identification. |
| **Source Seeding Refinement (`starts_with('_')`)** | **REVERT** | **+24 TPs** (GitHub/Vul4J) | **+12 FPs** (pgAdmin/Django) | **Positive** (Recall Recovery) | Aggressive entry point suppression destroys detection recall. Must be discarded. |
| **Sink Argument Gating (CWE-502)** | **DEFER** | **+5 TPs** (GitHub/OWASP) | **+28 FPs** (Static config loaders) | **Neutral / Positive** | Sound in theory but requires field-sensitivity. Deferred to **v1.1** to prevent false negatives. |

---

## 3. Post-Mortem Recommendations

1. **Revert Private Method Suppression:** Categorically discard the `starts_with('_')` filter. Private helper methods are frequently the execution point for untrusted configurations in Python and J2EE wrapper targets.
2. **Defer Deserialization Gating:** Move the CWE-502 parameter-check filter to the v1.1 roadmap. Re-introduce it only when the analyzer supports field-sensitive attribute tracking (e.g., `self.file_path`), allowing the engine to trace parameters set during class instantiation.
3. **Graduate Safe Patches:** Immediately graduate the unescape sanitizer fix and the `isvalidhref` sink additions into the new release branch.
