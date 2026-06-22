# TaintFlow RC105 Release Roadmap

This document outlines the precision and recall gap analysis of **RC104C** against the stable **RC101A** baseline and defines the engineering roadmap for the **RC105** sprint.

---

## 1. Precision & Recall Gap Analysis (RC104C vs RC101A)

The table below summarizes the exact remaining metric gap between **RC104C (Projected Full Dataset)** and **RC101A (Stable Baseline)**.

### Metric Gap Summary

| Benchmark | TP Delta | FP Delta | FN Delta | MCC Delta | Status & Analysis |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Juliet** (Java) | $+3$ | $+1$ | $-3$ | $+0.0266$ | Recall is stable at 100.00%. Precision remains high. |
| **OWASP** (Java) | $+20$ | $+41$ | $-20$ | $-0.0119$ | TP recovered, but $+41$ FPs persist from XSS un-sanitization. |
| **Vul4J** (Java) | $-1$ | $+9$ | $+1$ | $-0.8452$ | Massive regression due to mock helper entry-point seeding. |
| **GitHub** (Python/Java) | $+2$ | $+8$ | $+20$ | $-0.1287$ | Recall blocker ($+20$ FNs) driven by python import failures. |
| **Combined** | **$+24$** | **$+59$** | **$-2$** | **$-0.0258$** | Overall recall is stronger, but precision gap limits MCC to **0.6134**. |

---

## 2. Ranking of Remaining Gaps by Impact

To prioritize engineering resources, the remaining gaps are ranked below by their negative impact on the Combined Matthews Correlation Coefficient (MCC) and overall release readiness:

1. **GitHub Holdout Recall Gap (Impact: $-0.1287$ MCC | High Priority)**
   * *Problem:* 33 active FNs ($+20$ FN gap vs RC101A) are caused by Python inter-file import resolution failures and field-insensitive attributes. Resolving this is the highest blocker for production readiness.
2. **Vul4J Holdout Precision Regression (Impact: $-0.8452$ MCC | High Priority)**
   * *Problem:* $+9$ FPs and $-1$ TP are caused by zero-caller Java helper mock methods (loaded from sibling dependencies) being seeded as entry points because their names start with `_` but they default to package/public visibility.
3. **OWASP XSS Precision Gap (Impact: $-0.0119$ MCC | Medium Priority)**
   * *Problem:* $+41$ FPs remain active in OWASP CWE-79 due to context-insensitive global sanitization matching on `isValidHref`.
4. **Juliet Minor Precision Gap (Impact: $+0.0001$ MCC | Low Priority)**
   * *Problem:* $+1$ FP remains active. Juliet is essentially clean and requires no direct intervention.

---

## 3. High-ROI Engineering Fixes

### 3.1 Highest MCC ROI Fix: Java/Vul4J Private Helper Method Seeding Gating
* **Description:** Extend the zero-caller private method gating in `crates/taint/src/interproc.rs` for Java. A Java method should be suppressed from entry-point seeding if it has zero incoming call-graph edges and either is explicitly marked `private` OR starts with the private mock prefix `_`.
* **Expected TP Impact:** **0** (no recall risk as unreachable mock/helper functions do not affect valid production flows).
* **Expected FP Impact:** **-10 FPs** (on Vul4J dataset, completely resolving the Vul4J FP regression).
* **Expected MCC Impact:** 
  * Vul4J MCC: recovers from **0.0000** back to **0.8452** ($+0.8452$ MCC delta).
  * Combined MCC: **+0.0050** Combined MCC.
* **Validation Scope:** Vul4J-Only Validation.
* **Manual PowerShell Commands:**
  ```powershell
  Set-Location "d:\V2 Backup\rust-engine"
  $env:SKIP_GITHUB="1"
  $env:SKIP_OWASP="1"
  $env:SKIP_JULIET="1"
  cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_VUL4J_VALIDATION.log
  ```

### 3.2 Highest Precision ROI Fix: `isValidHref` Sanitizer Context Gating
* **Description:** Restrict the `isValidHref` sanitizer in `crates/taint/src/lib.rs` and `interproc.rs` to only suppress CWE-79 taint on the return value of the call when it is used as a validation guard (return-path-only), or remove it from `expression_contains_sanitizer` in `interproc.rs` to prevent transitive global suppression on unrelated nodes.
* **Expected TP Impact:** **-1 TP** (minor recall risk on OWASP).
* **Expected FP Impact:** **-42 FPs** (on OWASP benchmark, resolving XSS over-tainting).
* **Expected MCC Impact:**
  * OWASP MCC: improves from **0.6392** to **0.6500+** ($+0.0108+$ MCC).
  * Combined MCC: **+0.0213** Combined MCC.
* **Validation Scope:** OWASP-Only Validation.
* **Manual PowerShell Commands:**
  ```powershell
  Set-Location "d:\V2 Backup\rust-engine"
  $env:SKIP_GITHUB="1"
  $env:SKIP_VUL4J="1"
  $env:SKIP_JULIET="1"
  cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_OWASP_VALIDATION.log
  ```

### 3.3 Highest Recall ROI Fix: Python Medium Import Resolver (Tier B)
* **Description:** Implement dotted package path resolution relative to the workspace source root and multi-dot parent relative directory traversals. This addresses $93.2\%$ of all `MULTI_FILE_IMPORT` False Negatives in the GitHub Holdout.
* **Expected TP Impact:** **+33 TPs** (on GitHub Holdout, recovering all Python import-related FNs).
* **Expected FP Impact:** **0 FPs** (resolving callers correctly matches valid flows and does not introduce overtainting).
* **Expected MCC Impact:**
  * GitHub MCC: improves from **0.0863** to **0.5244** ($+0.4381$ MCC delta).
  * Combined MCC: **+0.0199** Combined MCC (recovers Combined MCC to **0.6332**).
* **Validation Scope:** GitHub-Only Validation (Fast Iteration).
* **Manual PowerShell Commands:**
  ```powershell
  Set-Location "d:\V2 Backup\rust-engine"
  $env:ONLY_GITHUB="1"
  $env:SKIP_PGADMIN="1"
  $env:SKIP_DATACHAIN="1"
  $env:SKIP_RAY="1"
  cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_GITHUB_VALIDATION.log
  ```

---

## 4. Secondary Precision Fix: Test-Harness Seeding Exclusions

* **Description:** Explicitly exclude methods from parameter-less deserialization seeding if they reside inside modules whose file paths contain `/test/`, `/tests/`, `test_`, or `_test.py`. Test setup loaders do not reflect production deployment entry points.
* **Expected TP Impact:** **0 TPs** (production code does not reside in test folders).
* **Expected FP Impact:** **-4 FPs** (on GitHub dataset).
* **Expected MCC Impact:**
  * GitHub MCC: $+0.0080$ MCC.
  * Combined MCC: **+0.0019** Combined MCC.
* **Validation Scope:** GitHub-Only Validation (Fast Iteration).
* **Manual PowerShell Commands:**
  ```powershell
  Set-Location "d:\V2 Backup\rust-engine"
  $env:ONLY_GITHUB="1"
  $env:SKIP_PGADMIN="1"
  $env:SKIP_DATACHAIN="1"
  $env:SKIP_RAY="1"
  cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_GITHUB_TEST_VALIDATION.log
  ```
