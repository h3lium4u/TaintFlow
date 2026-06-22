# RC104: Gating Logic ROI Analysis

This report calculates the Return on Investment (ROI) in terms of True Positives (TP) preserved vs. False Positives (FP) eliminated if we implement refined, context-aware versions of the gating rules rather than binary on/off switches.

---

## 1. Refinement Strategies

To recover precision without introducing recall regressions, we must transition from coarse gating filters to context-aware rules:

### Rule 1: Context-Aware Private Seeding (Replaces Private Method Suppression)
*   **Coarse Rule (RC103):** Suppress all methods starting with `_`.
    *   *Result:* Lost 24 TPs (Vul4J entrypoint collapse, PaddlePaddle helper deletion).
*   **Refined Rule (RC104):** Only suppress private Python methods (starting with `_`) if they have **zero callers** in the call graph, and explicitly protect public Java methods inside wrapper/utility classes from test-skipping filters.
    *   *Target ROI:* Eliminate **14 FPs** (10 in Vul4J, 4 in GitHub) while losing **0 TPs**.

### Rule 2: Dynamic Deserialization Seating (Replaces CWE-502 Sink Argument Gating)
*   **Coarse Rule (RC103):** Suppress deserialization seeding in all parameter-less methods.
    *   *Result:* Lost 5 TPs (Snowflake/Fides configuration loaders).
*   **Refined Rule (RC104):** Skip deserialization seeding in parameter-less methods *only if* the method does not access environment variables (`os.getenv`, `os.environ`), read class attributes (`self`), or load files.
    *   *Target ROI:* Eliminate **4 FPs** (test configurations) while losing **0 TPs**.

---

## 2. ROI Metric Projection Table

The table below projects the validation metrics if we implement these refined rules:

| Gating Rule Status | Combined TPs | Combined FPs | Combined Recall | Combined Precision | Combined MCC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **RC101A Baseline** | 1519 | 381 | 85.48% | 79.95% | 0.6394 |
| **RC101A+ (No Gating)** | 1568 | 487 | 87.16% | 76.30% | 0.6039 |
| **RC104 (Refined Gating)** | **1568** | **469** | **87.16%** | **76.99%** | **0.6133** |
| *Net Delta vs RC101A+* | *0* | *-18* | *0.00%* | *+0.69%* | *+0.0094* |

---

## 3. Verdict & Next Steps
Restoring the gating logic with context-sensitive conditions yields a **net positive ROI** (eliminates 18 FPs without losing a single TP). However, because XSS un-sanitization accounts for **+88 FPs** (in Juliet and OWASP), refining the two entry-point gating rules alone is insufficient to recover Combined MCC above 0.65. We must also address the XSS sanitizer modeling gap.
