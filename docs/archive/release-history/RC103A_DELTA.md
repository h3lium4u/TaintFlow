# RC103A Delta Analysis

## Metrics Comparison (RC101A vs RC103 vs RC103A)

| Metric | RC101A (Baseline) | RC103 (Failed) | RC103A (Hotfix) |
|---|---|---|---|
| **Combined TP** | 1519 | ~1490 | 1489 |
| **Combined FP** | 381 | ~381 | 368 |
| **Combined FN** | 258 | ~310 | 310 |
| **Combined Precision** | 79.95% | 80.19% | 80.18% |
| **Combined Recall** | 85.48% | 82.77% | 82.77% |
| **Combined MCC** | 0.6394 | ~0.6207 | 0.6207 |

### GitHub Specifics
| Metric | RC101A | RC103 | RC103A |
|---|---|---|---|
| **GitHub TP** | 60 | 58 | 57 |
| **GitHub FP** | 46 | ~40 | 40 |
| **GitHub FN** | 13 | 37 | 38 |
| **GitHub Precision** | 56.60% | ~59.18% | 58.76% |
| **GitHub Recall** | 82.19% | ~61.05% | 60.00% |
| **GitHub MCC** | 0.2150 | ~0.1800 | 0.1790 |

### Vul4J Specifics
| Metric | RC101A | RC103 | RC103A |
|---|---|---|---|
| **Vul4J TP** | 12 | 0 | 0 |
| **Vul4J FN** | 0 | 12 | 12 |

## Verification Questions
**A. Vul4J recall restored?** NO. It remains at 0%.
**B. GitHub recall restored?** NO. It dropped slightly further to 57 TPs.
**C. TP recovery count?** 0 TPs were recovered by the hotfix.
**D. FP reduction retained?** Yes. We retained an overall FP drop from 381 to 368.
**E. Combined MCC improvement?** NO. Combined MCC is 0.6207, which is a regression from the 0.6394 baseline.

## Diagnostic Answers
*   **Did RC103A recover the lost TPs?** No. The `is_private` logic was *not* the sole cause of the entrypoint discovery failure, or another change introduced during the RC103 sprint is actively suppressing these flows.
*   **How many of the RC103 FP reductions survived?** We retained 13 FP reductions (381 -> 368).
*   **Is RC103A strictly better than RC101A?** No. Recall and MCC are significantly degraded.
*   **Is RC103A strictly better than RC103?** No. The metrics are virtually identical (and slightly worse on GitHub TP). The hotfix failed to address the root cause of the regression.
