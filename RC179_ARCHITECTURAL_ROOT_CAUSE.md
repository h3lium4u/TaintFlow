# RC179 — Architectural Root Cause Certification

## 1. Trace for BenchmarkTest02454 (`SeparateClassRequest`)

In `BenchmarkTest02454.java`, the code executes:
```java
java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
statement.addBatch(sql);
int[] counts = statement.executeBatch();
```

### Targeted Audit Findings
- **Is `addBatch` registered as a stub?**
  **NO**. In `crates/taint/src/stubs.rs`, the `LibraryStub` for `java.sql.Statement` registers `execute`, `executeQuery`, and `executeUpdate` as sinks, but completely omits `addBatch`.
- **Is it modeled as a propagator?**
  **NO**. Because it is not in the stub registry and does not match any fallback rules (e.g. `generic_sources` or `generic_sanitizers` or `generic_sinks`).
- **Does taint reach `Statement` after `addBatch`?**
  **NO**. The transfer function in `interproc.rs` (lines 3834–3927) only propagates taint for resolved stubs. Since `addBatch` is unresolved, fallback propagation (lines 3929–4000) checks if the instruction is unresolved. However, because it has `dest: None` and is a member call, fallback propagation tries to taint the receiver or destination. But since `addBatch` is not modeled as a propagator, the solver does not generate a new taint fact for `statement`.
- **Is `executeBatch` analyzed correctly?**
  **YES**. `executeBatch` is correctly registered in `generic_sinks` (line 183 of `stubs.rs`), meaning it behaves as a valid sink. However, since the receiver `statement` is untainted, and `executeBatch()` takes no arguments, the sink is never triggered.
- **First Architectural Divergence**: The lack of a propagator model for `addBatch(...)` on `java.sql.Statement`.

---

## 2. Trace for BenchmarkTest02647 (`Base64`)

In `BenchmarkTest02647.java`, the nested expression is:
```java
bar = new String(
        org.apache.commons.codec.binary.Base64.decodeBase64(
                org.apache.commons.codec.binary.Base64.encodeBase64(
                        param.getBytes())));
```

### Targeted Audit Findings
- **Exact Lowered IR**:
  The AST node for the RHS contains nested calls. The IR lowerer (`collect_statements` in `crates/ir/src/lib.rs`) extracts all nested call expressions and emits them sequentially. Because these are nested expressions and not direct assignments, they are lowered with `dest: None`:
  1. `Call { dest: None, callee: "param.getBytes", args: [] }`
  2. `Call { dest: None, callee: "org.apache.commons.codec.binary.Base64.encodeBase64", args: ["param.getBytes()"] }`
  3. `Call { dest: None, callee: "org.apache.commons.codec.binary.Base64.decodeBase64", args: ["org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())"] }`
  4. `Call { dest: Some("bar"), callee: "new String", args: [...] }`
- **Whether nested call returns are discarded**:
  **YES**. The intermediate values returned by `getBytes()`, `encodeBase64()`, and `decodeBase64()` are discarded because the IR does not bind them to any named destination variable.
- **Whether the solver can propagate taint without a destination**:
  **NO**. In `interproc.rs`, the solver's transfer functions propagate taint to the destination variable (`dest`) or the receiver variable (`receiver`). When `dest` is `None` and the call is static (no receiver variable), the propagation logic executes but cannot output any new `TaintFact`.
- **First Architectural Divergence**: The IR generator lowering nested call expressions as `Call` instructions with `dest: None` rather than introducing synthetic temporary variables (`_tmp_1`, `_tmp_2`, etc.) to track intermediate results.

---

## 3. Counterfactual Analysis

### Target 1: BenchmarkTest02454
- **A. Only adding a stub**: **YES**. Registering `addBatch` as a propagator on `java.sql.Statement` (propagating taint from argument `0` to receiver `this`) will successfully taint the `statement` object, allowing the subsequent `executeBatch()` sink call to correctly flag the vulnerability.

### Target 2: BenchmarkTest02647
- **B. Only changing IR lowering**: **YES**. If the IR lowering phase is modified to flatten nested expressions into three-address code with synthetic temporary variables (e.g. `_tmp = encodeBase64(...)`), the existing stubs and propagation rules will correctly carry the taint through to `bar`. Modifying the stubs alone cannot fix this because the IR lack of destinations is a structural blocker.

---

## 4. Generalization & Production Impact

| Metric | Statement.addBatch | Nested-Call IR Lowering |
| :--- | :--- | :--- |
| **Production Frequency** | **Low**. Most modern enterprise applications use JPA/Hibernate or parameterized queries rather than raw JDBC batching. | **High**. Nested call expressions (e.g., `sanitize(encode(val))`) are extremely common in standard production code. |
| **Regression Risk** | **Low**. Narrowly scoped to the `Statement` class. | **Medium**. Generating temporary variables changes the instruction set size and variable mapping, which must be carefully integrated. |
| **Implementation Complexity** | **Very Low** (1 line in `stubs.rs`). | **Medium** (requires rewriting the nested call parser/lowering logic in `ir`). |
| **Expected ROI** | **Low** (restores specific JDBC batching cases). | **High** (globally repairs taint flow through all nested sanitization/utility calls). |

---

## FINAL VERDICT

**C. Both are independent architectural defects.**
