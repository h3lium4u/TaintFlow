# RC103A False Positive Distribution

## Overview
Following the successful suppression of 52 structural false positives in the RC103 hardening sprint, the combined False Positive count has dropped from 245 to 193. This document re-ranks the remaining FP categories to identify the next highest ROI targets.

## Re-Ranked FP Categories (Estimated Remaining: 193)

### 1. SANITIZER_MISSING_STUB (Est. 120 FPs)
*   **Description**: Flows where user input is properly sanitized by a custom or third-party validation function, but the TaintFlow engine lacks the corresponding sanitizer stub, causing it to trace the flow to the sink.
*   **Primary Driver**: The OWASP benchmark contains numerous custom sanitizer classes (`ESAPI.encoder()`, custom regex validators) that are not yet modeled in the `sanitizer_matrix.yaml`.
*   **ROI**: **Very High**. Adding a small number of high-frequency sanitizer stubs will drastically reduce the OWASP FP count (currently 159).

### 2. PATH_TRAVERSAL_NORMALIZATION_GAP (Est. 40 FPs)
*   **Description**: CWE-22 (Path Traversal) flows where user input is passed to a file operation, but the path is strictly normalized and validated (e.g., using `os.path.abspath` and checking common prefixes) prior to the sink.
*   **Primary Driver**: OWASP and GitHub samples utilizing secure file-serving patterns that TaintFlow's static control-flow cannot logically evaluate.
*   **ROI**: **Medium**. Requires deeper data-flow constant folding or dedicated stubs for standard library path normalization patterns.

### 3. MOCK_HELPER_FLOW_LEAKAGE (Est. 20 FPs)
*   **Description**: Edge cases where the IR engine over-taints return values from generic helper functions because it conservatively assumes any tainted argument infects the return value.
*   **Primary Driver**: Juliet and OWASP complex wrapper methods.
*   **ROI**: **Low**. Fixing this requires computationally expensive deep alias analysis.

### 4. HEURISTIC_CWE_MISCLASSIFICATION (Est. 13 FPs)
*   **Description**: Flows that are technically vulnerable, but map to an overlapping CWE (e.g., flagging CWE-89 SQLi when the benchmark expects CWE-564 Hibernate Injection), counting as an FP in strict evaluations.
*   **Primary Driver**: All benchmarks.
*   **ROI**: **Medium**. Can be mitigated by mapping related CWEs in the validation harness.

## 5. Determination & ROI
*   **New Largest FP Bucket**: `SANITIZER_MISSING_STUB`.
*   **New Highest ROI Precision Opportunity**: Expanding the `sanitizer_matrix.yaml` to include top OWASP sanitizers (e.g., ESAPI).

## 6. Estimated Remaining Achievable FP Reduction
*   **Estimate**: **~100 - 120 FPs**.
*   By targeting the top missing sanitizers, the OWASP FP count can realistically be halved before v1.0.0-beta, pushing Combined Precision above 90%.
