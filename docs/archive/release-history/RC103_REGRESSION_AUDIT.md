# RC103 Regression Audit

## 1. Context & Baseline Comparison
RC103 introduced two major precision-hardening mechanisms to the TaintFlow engine:
1. **Source Seeding Refinement**: Suppressed the automatic seeding of uncalled private helper methods (methods starting with `_`).
2. **Sink Argument Gating**: Prevented deserialization (CWE-502) sinks from being force-seeded if the enclosing method lacks explicit parameters or IR sources.

**Comparison vs. RC101A Baseline:**
*   **Total TP Drop**: 29 TPs lost.
*   **GitHub Recall**: Dropped by 21.14% (Net loss of 2 TPs, but massive spike in FNs).
*   **Vul4J Recall**: Dropped to 0% (Loss of all 12 TPs).

## 2. Root Cause Analysis

### A. Source Seeding Refinement Failure
The refinement logic (`method.name.starts_with('_')`) aggressively over-corrected in the Python GitHub Holdout dataset. 
*   **Impact**: It severed entry points for critical helper functions, notably in the PaddlePaddle repository where `_wget_download` (CWE-78) and internal file loaders (CWE-22) were legitimately responsible for handling tainted configurations. 
*   **Classification**: `SOURCE_SEEDING_REFINEMENT`

### B. Vul4J Entrypoint Collapse
Vul4J relies heavily on tiny wrapper classes (e.g., `PathResolver.resolve`, `Render.welcome`) that are instantiated and called by external Java test files. The test-file skip logic combined with the new refinement conditions inadvertently stripped these public wrapper methods of their entry-point status, completely blinding the engine to Vul4J sources.
*   **Impact**: 12 TPs lost (CWE-79, CWE-22, CWE-502, CWE-918).
*   **Classification**: `ENTRYPOINT_DISCOVERY` (Triggered by Source Seeding Refinement edge-cases).

### C. Sink Argument Gating Failure
The gating rule for CWE-502 effectively stopped "ghost" flows, but it also blocked legitimate deserialization vulnerabilities located inside static configuration loaders or parameter-less initialization methods (e.g., `__init__` loading a hardcoded file path from an env var).
*   **Impact**: Loss of CWE-502 TPs in GitHub (Snowflake/Fides) and OWASP.
*   **Classification**: `SINK_ARGUMENT_GATING`

## 3. TP Loss Quantification
*   **Lost due to Source Seeding Refinement (including Vul4J cascade)**: ~24 TPs (PaddlePaddle CWE-78, GitPython CWE-22, Vul4J suite).
*   **Lost due to Sink Argument Gating**: ~5 TPs (CWE-502 Deserialization wrappers in GitHub/OWASP).
