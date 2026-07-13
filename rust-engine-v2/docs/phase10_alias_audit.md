# Phase 10.1 Audit - Flow-Sensitive Alias Analysis

**Prepared by**: Principal Static Analysis Researcher  
**Status**: APPROVED AUDIT  
**Workspace**: `rust-engine-v2`  
**Date**: June 28, 2026

---

## 1. Correctness

-   **Strong Updates**: Handled correctly. Allocations and assignments overwrite variables' points-to sets.
-   **Weak Updates**: Handled correctly. Writes to base fields `x.f = y` perform weak updates (unioning) over all potential base targets, preserving soundness.
-   **MayAlias & MustAlias**: Mapped correctly to points-to set intersections.
-   **Interprocedural Mappings**: Parameter passing (Actual-to-Formal) and return value mappings (Formal-to-Actual) are correctly routed across ICFG call and return edges.
-   **CFG Diamonds**: Diamond merges are correctly joined using a centralized, deterministic, idempotent lattice join.

---

## 2. Soundness & Precision Limits

-   **Soundness (False Negatives)**: The analysis is sound under the standard pointer-analysis assumptions (field-sensitive, context-insensitive heap tracking). There are no false negatives.
-   **Precision (False Positives)**:
    -   *Context Insensitivity*: Since call states are joined at callee entry points and returned states are joined at return sites without context stack tags, merging states across polymorphic call boundaries can introduce spurious aliases.
    -   *Example*:
        ```python
        def identity(x):
            return x

        a = identity(obj1)
        b = identity(obj2)
        ```
        Under context-insensitive propagation, `identity`'s parameter merges both `obj1` and `obj2`, causing both `a` and `b` to point to `{obj1, obj2}`. This is a standard precision loss (false positive) that will be optimized in V3 using our context sensitivity hooks.

---

## 3. Complexity & Scaling

Let:
-   \( |N^*| \) be the number of program points (ICFG nodes).
-   \( |AP| \) be the number of access paths under analysis.
-   \( |H| \) be the number of heap allocations.

| Operation | Complexity |
| :--- | :--- |
| **Assign** | \( O(\log |AP| + |H|) \) |
| **HeapLoad** | \( O(|H| \times (\log |AP| + |H|)) \) |
| **HeapStore** | \( O(|H| \times (\log |AP| + |H|)) \) |
| **Join** | \( O(|AP| \times |H| \log |H|) \) |

### Scalability Estimations:
-   **10K LOC**: Instantly analyzed, negligible memory.
-   **100K LOC**: Scale is linear in program size due to the sparsity of pointer variables.
-   **1M LOC**: The dominant bottleneck is the number of local variables and heap allocation nodes. Reusing `Arc<BTreeSet>` structures is vital to keep memory usage minimal.

---

## 4. Memory Analysis

-   **Arc Reuse**: Points-to sets (`PointsToSet`) are wrapped in `Arc` internally, preventing deep clones of sets.
-   **HashMap Growth**: Mappings grow linearly with the number of variables.
-   **Future Optimizations**: Could replace standard `HashMap` inside `AliasState` with an immutable map (e.g. `im::HashMap` or similar) to share structure between program points and prevent map copy allocations.

---

## 5. Parallel & Integration Readiness

-   **v2-scheduler**: Fully compatible. The `AliasEngine` is thread-safe and stateless. It does not read or write global mutable states, allowing multiple methods to be analyzed in parallel.
-   **Integration**: Seamless. Plugs into frozen `v2-accesspath`, `v2-pointsto`, and `v2-icfg` APIs without modification.

---

## 6. Final Verdict

**FINAL VERDICT**: **A) Freeze Phase 10.**

The implementation is correct, sound, fully tested, and ready to serve as the pointer alias infrastructure for Phase 11 Taint analysis.
