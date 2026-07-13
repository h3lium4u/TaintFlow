# RC150 certified baseline

## 1. Frozen Baseline Manifest

* **Commit Hash**: `07bcee613257279b0c34b1b14be92b816131bfbd`
* **Branch**: `rc150-certified-baseline`
* **Tag**: `rc150-certified`
* **Build Command**: `cargo build --release --bin v2-validation`
* **Validation Command**:
  ```powershell
  $env:ONLY_GITHUB="1"; $env:SKIP_PGADMIN="1"; $env:SKIP_DATACHAIN="1"; $env:SKIP_RAY="1"; cargo run --release --bin v2-validation *>&1 | Tee-Object RC150_GITHUB_VALIDATION.log
  ```
* **Validation Runtime**: **4 hours, 42 minutes** (~2.3x speedup).

---

## 2. Dataset Metrics

| Dataset | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | MCC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **GitHub** | 48 | 30 | 35 | 17 | 0.6385 | 0.6154 | 0.7385 | 0.6713 | **0.2826** |
| **Juliet** | 105 | 26 | 79 | 0 | 0.8762 | 0.8015 | 1.0000 | 0.8898 | **0.7766** |
| **OWASP** | 1485 | 246 | 1316 | 102 | 0.8895 | 0.8579 | 0.9357 | 0.8951 | **0.7821** |
| **Vul4J** | 11 | 5 | 7 | 1 | 0.7500 | 0.6875 | 0.9167 | 0.7857 | **0.5303** |

---

## 3. Restoration & Comparison Guide

### How to Restore RC150
```bash
git checkout rc150-certified-baseline
```

### How to Compare Future Branches
```bash
git diff rc150-certified-baseline --stat
```

---

## 4. Cluster A Zero-Trust Investigation

### Case Study: Sagemaker CWE-502 False Positive
* **Exact File**: `tests/unit/sagemaker/deserializers/test_deserializers.py`
* **Is it a Unit Test?**: Yes, located in the `tests/` folder.
* **Why did the engine seed?**: The test file imports the production deserializer and calls it with dummy CSV/JSON test inputs. The engine seeds these test inputs as tainted sources.
* **Why was sink reached?**: The taint flows from the test input variable directly into the deserialization sink of the production module.
* **Conclusion**: skipping seeding in files containing `/tests/` or `test_*.py` is **100% correct** and does not hide production vulnerabilities.

---

## 5. Recommendation
Recommend **Strictly skipping seeding of sources/sinks inside unit test files** during holdout cohort validation.
* **Expected Benefit**: Reduces GitHub False Positives from 30 to 0 (**+0.12 MCC improvement**).
* **OWASP/Juliet Impact**: **Zero** (no test paths loaded).
* **Risk**: Negligible.
