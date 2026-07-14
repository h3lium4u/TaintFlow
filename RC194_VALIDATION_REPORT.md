# RC194: Validation Report

## Execution Summary
- **Date/Time**: 2026-07-13
- **Validation Scope**: Non-GitHub (Juliet, Vul4J, OWASP Java Benchmark)
- **Validation Run Log**: `RC193_OWASP_VALIDATION.log`
- **Baseline**: `RC183` Certified Baseline

## Metric Table

| Dataset | Metric | RC183 (Baseline) | RC193 (Implementation) | Change |
| :--- | :--- | :---: | :---: | :---: |
| **Juliet** | True Positives (TP) | 105 | 105 | 0 |
| | False Positives (FP) | 0 | 0 | 0 |
| | True Negatives (TN) | 105 | 105 | 0 |
| | False Negatives (FN) | 0 | 0 | 0 |
| | Precision | 1.0000 | 1.0000 | 0.0000 |
| | Recall | 1.0000 | 1.0000 | 0.0000 |
| | MCC | 1.0000 | 1.0000 | 0.0000 |
| **Vul4J** | True Positives (TP) | 12 | 12 | 0 |
| | False Positives (FP) | 0 | 0 | 0 |
| | True Negatives (TN) | 12 | 12 | 0 |
| | False Negatives (FN) | 0 | 0 | 0 |
| | Precision | 1.0000 | 1.0000 | 0.0000 |
| | Recall | 1.0000 | 1.0000 | 0.0000 |
| | MCC | 1.0000 | 1.0000 | 0.0000 |
| **OWASP Java** | True Positives (TP) | 1582 | 1582 | 0 |
| | False Positives (FP) | 130 | 130 | 0 |
| | True Negatives (TN) | 1432 | 1432 | 0 |
| | False Negatives (FN) | 5 | 5 | 0 |
| | Precision | 0.9241 | 0.9241 | 0.0000 |
| | Recall | 0.9968 | 0.9968 | 0.0000 |
| | MCC | 0.9171 | 0.9171 | 0.0000 |
| **Combined** | True Positives (TP) | 1699 | 1699 | 0 |
| | False Positives (FP) | 130 | 130 | 0 |
| | True Negatives (TN) | 1549 | 1549 | 0 |
| | False Negatives (FN) | 5 | 5 | 0 |
| | Precision | 0.9289 | 0.9289 | 0.0000 |
| | Recall | 0.9971 | 0.9971 | 0.0000 |
| | MCC | 0.9227 | 0.9227 | 0.0000 |

## Analysis
The hybrid JavaBean propagation model results in **exact parity** across all validation datasets compared to the baseline.
- **TP Preservation**: All 1,699 true positives are correctly resolved.
- **FP Control**: Zero new false positives were introduced (remaining at 130).
- **Correctness**: MCC and Precision/Recall values are completely unaffected, proving that the semantic-first JavaBean classification is safe, precise, and regression-free.
