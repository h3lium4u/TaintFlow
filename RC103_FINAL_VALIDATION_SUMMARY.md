# RC103 Final Validation Summary

## 1. Metrics by Dataset

### Juliet Holdout
* **TP:** 91
* **FP:** 21
* **TN:** 84
* **FN:** 14
* **Recall:** 86.67%
* **Precision:** 81.25%
* **MCC:** 0.6682

### OWASP Benchmark
* **TP:** 1341
* **FP:** 307
* **TN:** 1255
* **FN:** 246
* **Recall:** 84.50%
* **Precision:** 81.37%
* **MCC:** 0.6491

### GitHub Holdout
* **TP:** 58
* **FP:** 40
* **TN:** 55
* **FN:** 37
* **Recall:** 61.05%
* **Precision:** 59.18%
* **MCC:** 0.1896

### Vul4J Holdout
* **TP:** 0
* **FP:** 0
* **TN:** 12
* **FN:** 12
* **Recall:** 0.00%
* **Precision:** 0.00%
* **MCC:** 0.0000

### Combined
* **TP:** 1490
* **FP:** 368
* **TN:** 1406
* **FN:** 309
* **Recall:** 82.82%
* **Precision:** 80.19%
* **F1:** 81.49%
* **MCC:** 0.6213

---

## 2. Comparison to RC101A Baseline

### GitHub Holdout Deltas
| Metric | RC101A Baseline | RC103 Final | Delta |
| :--- | :---: | :---: | :---: |
| **TP** | 60 | 58 | **-2** |
| **FP** | 46 | 40 | **-6** |
| **TN** | 27 | 55 | **+28** |
| **FN** | 13 | 37 | **+24** |
| **Recall** | 82.19% | 61.05% | **-21.14%** |
| **Precision** | 56.60% | 59.18% | **+2.58%** |
| **MCC** | 0.2150 | 0.1896 | **-0.0254** |

### Combined Dataset Deltas
| Metric | RC101A Baseline | RC103 Final | Delta |
| :--- | :---: | :---: | :---: |
| **TP** | 1519 | 1490 | **-29** |
| **FP** | 381 | 368 | **-13** |
| **TN** | 1371 | 1406 | **+35** |
| **FN** | 258 | 309 | **+51** |
| **Recall** | 85.48% | 82.82% | **-2.66%** |
| **Precision** | 79.95% | 80.19% | **+0.24%** |
| **MCC** | 0.6394 | 0.6213 | **-0.0181** |

---

## 3. Executive Assessment

**Should RC103 become the new official baseline?**
**No, pending investigation.** While there are notable precision gains and FP reductions, the severe regressions in True Positives (specifically the complete loss of TPs in Vul4J and the 21.14% recall drop in GitHub) prevent this from being a strictly superior baseline. The underlying causes of the FN spikes must be addressed first.

**Any regressions?**
**Yes, severe regressions exist:**
1. **Vul4J Collapse:** Vul4J TPs dropped to 0 (0.00% Recall and Precision).
2. **GitHub Recall:** FN count surged by 24, dropping recall by 21.14% and decreasing the MCC (-0.0254).
3. **Combined TP Loss:** Overall TP count dropped by 29 flows.

**Biggest metric improvement?**
**GitHub True Negatives (+28).** The precision hardening and gating mechanisms successfully identified and correctly suppressed a massive cohort of safe GitHub flows, driving the GitHub Precision up to 59.18% (+2.58%).

**Release readiness score (0-10):**
**6/10**. 
*The Good:* Combined precision has crossed the 80% threshold (80.19%), and noise (FPs) is consistently decreasing.
*The Bad:* The sudden regression in Vul4J (0 TPs) and the loss of recall in the GitHub holdout indicate that the recent gating mechanisms were slightly too aggressive, severing legitimate taint flows. These recall blockers must be fixed before beta release.
