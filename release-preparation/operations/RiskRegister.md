# Risk Register

This document monitors operational risks associated with TaintFlow.

---

## Risks

### Risk 1: False Positive Degradation
- **Description**: Adding too many conservative flow paths to improve recall increases False Positives.
- **Severity**: Medium.
- **Mitigation**: Maintain strict baseline validation tests (Juliet, Vul4J, OWASP) on every pull request.

### Risk 2: Out of Memory (OOM) on Large Codebases
- **Description**: Evaluating extremely large projects (e.g. 10,000+ files) can exceed memory limits.
- **Severity**: Low.
- **Mitigation**: Implement node limits per CFG block to guarantee solver termination.
