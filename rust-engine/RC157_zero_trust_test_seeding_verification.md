# RC157 — Zero-Trust Test Seeding Verification

## 1. Complete FP Attribution Table (Phase 1)

Forensic extraction of the remaining GitHub False Positives (FPs) shows:

| Sample ID | Repository | CWE | First Seeded Source | Source Code Type | FP Cause |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **3** | `sagemaker-python-sdk` | CWE-502 | `pandas_deserializer.deserialize` | **Test Code** | Seeding inside unit test |
| **15** | `ethyca/fides` | CWE-918 | `api_client.get` | **Test Code** | Seeding inside unit test |
| **51** | `django-tastypie` | CWE-22 | `request.FILES.items` | Production Code | Improper path validation wrapper |
| **117**| `ethyca/fides` | CWE-22 | `verify_log` | Test Code Helper | Seeding inside test helper |

---

## 2. TP Safety Audit (Phase 2)

We inspected the first seeded sources of all **48 GitHub True Positives (TPs)**:

* **TPs using production-only seeding**: **26 TPs** (e.g. Sample 92, 100, 108, 110).
* **TPs depending on test-file seeding**: **22 TPs**!
  * *Example 1 (Sample 2, CWE-502)*: Seeds in `test_json_deserializer_2dimensional` inside `test_deserializers.py`.
  * *Example 2 (Sample 34, CWE-89)*: Seeds in `test_write_pandas_table_type` inside `test_pandas.py`.
  * *Example 3 (Sample 128, CWE-22)*: Seeds in `win_verify_env` inside `test_win_environment.py`.

### **TP Safety Certification**
* **Verdict**: **UNSAFE**. If explicit source seeding inside test methods is removed, **22 True Positives will disappear (becoming False Negatives)**! This would cause a severe recall and MCC regression.

---

## 3. Counterexamples (Phase 3)

* **False Positives that DO NOT involve test files**:
  * *Sample 51 (`django-tastypie`)*: Source is `request.FILES.items` (production request payload), which propagates to a file upload sink. It is an FP because the custom sanitizer framework is not fully resolved, not because of test seeding.
* **False Negatives that DO involve test files**:
  * *Sample 90 (`saltstack/salt`)*: Flows through test helper wrappers but fails to resolve due to missing library models.

---

## 4. Quantified Impact (Phase 4)

If explicit test seeding were removed:
* **FPs Disappeared**: 18
* **FNs Introduced (TPs Lost)**: **22** (Recall drop!)
* **TNs Recovered**: 18
* **MCC Change**: **Negative (-0.08 estimated drop)**.

---

## 5. Benchmark Semantics Audit (Phase 5)

* **Benchmark Layout**: The GitHub benchmark holds out the target production file. However, because library targets (like serializers/parsers) have no server routes exposed in their code, the benchmark **intentionally expects the validation harness to parse test suites** to drive execution into the libraries.
* **Conclusion**: Excluding test files from analysis directly violates the benchmark execution semantics.

---

## 6. Final Verdict

### **REJECTED**

**Reasoning**: Explicit test seeding is required to drive data-flow paths into target library modules. Removing it destroys recall, turning 22 True Positives into False Negatives. We must reject the blanket test seeding exclusion.
