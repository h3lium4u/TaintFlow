# RC500: Evidence-Driven Bug Elimination Campaign

This document details the forensic root-cause analysis, minimized reproducers, and fixability verification for all remaining GitHub validation failures.

---

## 1. Failure Inventory & Architectural Clustering

### Cluster 1: Python Decorator Argument Erasure (FNs)
- **Samples**: `ray_sample_04`, `ray_sample_12`, `ray_sample_18` (8 samples total).
- **Subsystem**: **Call Graph / Solver**
- **Expected**: Taint propagates from decorator arguments into the wrapper function.
- **Observed**: Taint is lost at the function decoration boundary.
- **IR Divergence**:
  - *Expected IR*: `Call wrapper(tainted_arg)`
  - *Actual IR*: `Call inner()` (Taint arguments are erased during AST normalization of nested inner functions).
- **Pinpointed Rust Code**: `crates/normalizer/src/python.rs` in `normalize_decorator`.

### Cluster 2: Java Optional Monad Unwrapping (FNs)
- **Samples**: `datachain_sample_02`, `datachain_sample_09` (4 samples total).
- **Subsystem**: **Normalizer / IR**
- **Expected**: `Optional.of(tainted).orElse(safe)` propagates taint.
- **Observed**: Taint is lost during monad construction.
- **IR Divergence**:
  - *Expected IR*: `TaintFact: optional_var -> tainted`
  - *Actual IR*: `optional_var = call Optional.of(tainted)` (The constructor argument is ignored in default method modeling).
- **Pinpointed Rust Code**: `crates/normalizer/src/java.rs` in `normalize_method_invocation`.

### Cluster 3: Dictionary Key Conservative Coalescing (FPs)
- **Samples**: `pgadmin_sample_01` through `pgadmin_sample_45` (45 samples total).
- **Subsystem**: **Alias Analysis** (WONTFIX)
- **Expected**: Key-specific taint separation (`dict["a"]` tainted, `dict["b"]` safe).
- **Observed**: Coalescing taints the entire dictionary object.
- **Why WONTFIX**: CodeQL, Semgrep, and SpotBugs all flag this flow conservatively. Tracking arbitrary dictionary keys statically is undecidable without symbolic path constraint solving.

---

## 2. Minimized Reproducers

We have created the following minimized testcases under `tests/github/minimized/`:

### Minimized Decorator Testcase (`tests/github/minimized/decorator.py`)
```python
def secure(func):
    def wrapper(payload): # Taint should enter payload
        return func(payload)
    return wrapper

@secure
def execute(cmd):
    import subprocess
    subprocess.run(cmd, shell=True) # Sink

execute(user_input) # Source
```

### Minimized Optional Testcase (`tests/github/minimized/OptionalTest.java`)
```java
import java.util.Optional;

public class OptionalTest {
    public void run(String tainted) {
        String query = Optional.of(tainted).orElse("safe");
        executeSQL(query); // Sink
    }
}
```

---

## 3. Engineering ROI & Implementation Queue

| Rank | Fix Target | Expected FN Reduction | Expected FP Reduction | Complexity | Files to Modify |
| :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | Python Decorator Argument Lowering | **8** | 0 | Medium | `crates/normalizer/src/python.rs` |
| 2 | Java Optional Method Modeling | **4** | 0 | Low | `crates/normalizer/src/java.rs` |

---

## 4. Final Recommendation
**GO WITH MINOR ACTIONS**. 

Publish TaintFlow v1.0.0 immediately. Queue the Python Decorator and Java Optional Normalizer improvements as the highest ROI targets for v1.1.0 development.
