# RC104 Implementation Roadmap

## 1. Context and Strategic Pivot
The RC103 hardening sprint successfully achieved a GitHub Precision of 75.00% and a Combined Precision of 88.30%. Having securely met the beta readiness precision targets, the TaintFlow engine must now pivot to addressing **Recall**, specifically targeting the final blocker preventing full commercial viability: **Python Inter-file Import Resolution**.

## 2. RC104 Primary Objective
**Solve `MULTI_FILE_IMPORT` False Negatives.**
Currently, 74 False Negatives remain in the GitHub holdout dataset. A prior forensic audit revealed that approximately 80% (59 instances) of these FNs are caused by a structural limitation in the Interprocedural Control Flow Graph (ICFG): the inability to correctly track taint flow across local Python module boundaries (`import X from Y`). 

## 3. Implementation Phasing

### Phase 1: Python Import Graph Modeling
*   **Objective**: Enhance the `GlobalSymbolTable` (GST) and `CallGraph` builder to reliably parse and map Python `import` and `from ... import ...` statements.
*   **Action Items**:
    1. Update the IR lowering mechanism to track `InstructionKind::Import` and map local file paths.
    2. Expand the `GlobalSymbolTable` to resolve cross-file method invocations (e.g., mapping `routes.handle_request()` to `routes.py::handle_request`).
    3. Ensure the Call Graph inserts interprocedural edges between files, rather than treating external calls as unmodeled library calls.

### Phase 2: Inter-file ICFG Connection
*   **Objective**: Ensure the `InterproceduralCFG` correctly fuses the intraprocedural CFGs of connected files.
*   **Action Items**:
    1. Connect `Call` nodes in File A to `MethodEntry` nodes in File B.
    2. Ensure Taint Facts correctly propagate arguments across these new cross-file edges via the `apply_transfer_function` logic.

### Phase 3: Secondary Precision Hardening (`SANITIZER_MISSING_STUB`)
*   **Objective**: Concurrently expand the `sanitizer_matrix.yaml` to include the highest frequency OWASP validation classes (e.g., ESAPI encoders, Hibernate validators).
*   **Action Items**:
    1. Identify top 10 missing sanitizers in the OWASP benchmark.
    2. Implement domain-specific sanitization stubs.
    3. Target a reduction of ~100 FPs on OWASP.

## 4. Success Criteria for RC104
1.  **GitHub Recall Improvement**: Increase GitHub Recall from 22.11% to >50%.
2.  **FN Reduction**: Resolve at least 35 of the 59 `MULTI_FILE_IMPORT` False Negatives.
3.  **OWASP FP Reduction**: Reduce OWASP False Positives below 100 via targeted sanitizer stubs.
4.  **No Performance Regression**: Maintain scan times under 500ms per average repository.
