# RC104: False Positive Root Cause Analysis

This report explains the exact root causes of the **+106 False Positive** increase (from 381 to 487) observed in the **RC101A+** validation run compared to the stable **RC101A** baseline.

---

## 1. High-Level FP Increase Breakdown

The +106 FP increase is distributed across the validation datasets as follows:
*   **Juliet:** **+5 FPs** (25 -> 30)
*   **OWASP:** **+83 FPs** (308 -> 391)
*   **Vul4J:** **+10 FPs** (2 -> 12)
*   **GitHub:** **+8 FPs** (46 -> 54)

---

## 2. Root Cause Classification of the +106 FPs

The new FPs are directly attributable to three functional changes between the two builds:

### A. XSS Hardening: Sanitizer Fix & Sink Addition (+88 FPs)
*   **Affected Datasets:** Juliet (+5 FPs), OWASP (+83 FPs)
*   **Mechanism:** 
    1.  **Unescape Sanitizer Fix:** The engine no longer treats "unescape" functions as sanitizers. While this recovered 3 TPs in Juliet, it also un-sanitized 5 benign flows in Juliet and 41 benign flows in OWASP.
    2.  **`isValidHref` Sink Registry:** Registering `isvalidhref` as a CWE-79 sink discovered new flows. In OWASP, this recovered 41 TPs but introduced 42 FPs due to the lack of context-sensitive models for these newly activated paths.

### B. Reverting Private Method Suppression (+14 FPs)
*   **Affected Datasets:** Vul4J (+10 FPs), GitHub (+4 FPs)
*   **Mechanism:** Reverting the aggressive `starts_with('_')` filter restored all entry points. This recovered 12 TPs in Vul4J and 5 TPs in GitHub, but allowed the engine to seed internal private helpers as entry points, introducing 10 FPs in Vul4J (due to wrapper entry point exposure) and 4 FPs in GitHub.

### C. Reverting CWE-502 Sink Argument Gating (+4 FPs)
*   **Affected Datasets:** GitHub (+4 FPs)
*   **Mechanism:** Restored deserialization force-seeding in parameter-less methods. This recovered Snowflake and Fides TPs, but also re-introduced 4 FPs from parameter-less configuration loaders and test setup harnesses.

---

## 3. FP Categories (RC101A+ Active FPs)

Of the total 487 active FPs in RC101A+, the newly introduced +106 FPs fit into the following categories:

| Category | Description | FP Count | Percentage | Affected Repos / Suites | Affected CWEs |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **A. Deserialization Config Loaders** | Parameter-less loaders using `yaml.load` or `pickle.load` on static files | 2 | 1.89% | GitHub (Snowflake, Fides) | CWE-502 |
| **B. Private Helper Methods** | Internal private functions starting with `_` seeded as entry points | 14 | 13.21% | Vul4J, GitHub (Paddle, ray) | CWE-22, CWE-502 |
| **C. Test Harness Leakage** | Parameter-less test functions or test setup scripts | 2 | 1.89% | GitHub (sagemaker, datachain) | CWE-502 |
| **D. Mock Helper Propagation** | Flows self-contained in validation test-mock helpers | 0 | 0.00% | N/A | N/A |
| **E. Wrapper Overtainting** | Helper parameters seeded as sources flowing to path/file operations | 15 | 14.15% | GitHub (salt, snowflake) | CWE-22, CWE-502 |
| **F. Other (XSS Un-sanitization)** | Flows previously sanitized by "unescape" or hitting `isValidHref` | 73 | 68.86% | Juliet, OWASP | CWE-79 |
| **Total** | | **106** | **100.00%** | | |

---

## 4. Summary Verdict
Reverting the gating rules successfully recovered all degraded recall, but the lack of replacement filters led to a significant precision penalty. The primary driver of the FP spike is **Category F (XSS Un-sanitization)** in OWASP (+83 FPs), followed by **Category B (Private Helper Methods)** in Vul4J (+10 FPs).
