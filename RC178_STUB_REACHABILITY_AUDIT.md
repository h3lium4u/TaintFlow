# RC178 — Stub Reachability & Dispatch Audit

## Executive Summary

We performed a reachability and propagation audit for two classes of stubs previously hypothesized to be "missing":
1. `SeparateClassRequest.getTheParameter(...)`
2. `org.apache.commons.codec.binary.Base64.encodeBase64(...)` / `decodeBase64(...)`

Our findings show that **both stubs already exist** in `crates/taint/src/stubs.rs` and the stub lookup queries **do succeed** during static analysis. However, taint propagation fails afterward due to downstream architectural issues (unsupported JDBC sink methods and lack of temporary destinations for nested call expressions in lowered IR).

---

## 1. Trace for BenchmarkTest02454 (`SeparateClassRequest`)

In `BenchmarkTest02454.java`, the relevant code snippet is:
```java
org.owasp.benchmark.helpers.SeparateClassRequest scr =
        new org.owasp.benchmark.helpers.SeparateClassRequest(request);
String param = scr.getTheParameter("BenchmarkTest02454");
```

### Complete Execution & Stub Lookup Trace

1. **Parsed AST Call**: 
   - Constructor: Node type `object_creation_expression` (mapped to `NodeKind::CallExpression`), raw value `new org.owasp.benchmark.helpers.SeparateClassRequest(request)`.
   - Method: Node type `method_invocation` (mapped to `NodeKind::CallExpression`), raw value `scr.getTheParameter("BenchmarkTest02454")`.
2. **Lowered IR Instruction**:
   - Constructor: `Call { dest: Some("scr"), callee: "new org.owasp.benchmark.helpers.SeparateClassRequest", args: ["request"] }`
   - Method: `Call { dest: Some("param"), callee: "scr.getTheParameter", args: ["\"BenchmarkTest02454\""] }`
3. **Resolved Callee**:
   - Constructor: Class FQN `org.owasp.benchmark.helpers.SeparateClassRequest`, method name `<init>`.
   - Method: `resolve_callee_info_internal` resolves the receiver `"scr"` type via local variable declaration to `org.owasp.benchmark.helpers.SeparateClassRequest`.
4. **class_fqn**: `"org.owasp.benchmark.helpers.SeparateClassRequest"`
5. **method_name**: `"getTheParameter"`
6. **StubRegistry::lookup() Input**: `class_or_module = "org.owasp.benchmark.helpers.SeparateClassRequest"`, `method = "getTheParameter"`.
7. **Lookup Normalization**:
   - `class_clean` is `"org.owasp.benchmark.helpers.SeparateClassRequest"`.
   - Normalization matches `class_lower.ends_with(".separateclassrequest")` and returns `"org.owasp.benchmark.helpers.SeparateClassRequest"`.
8. **Registry Match Result**: `SUCCESS`.
9. **Stub Selected**: `MethodStub { name: "getTheParameter", kind: StubKind::Source, propagates_from: None }`.
10. **Transfer Function Execution**:
    - Under `find_initial_sources`, the engine recognizes `getTheParameter` as a `Source` stub.
    - Since it is a benchmark helper, it calls `determine_helper_propagation_decision(Some(&class_fqn), callee, dest_var)`.
    - Since `"param"` is not a container read, `shadow_decision` defaults to `true`.
    - The engine successfully seeds taint on the variable `"param"`.
11. **First Point Where Taint is Lost**:
    - Taint successfully propagates through `doSomething(request, param)` to the local variable `bar` and then to the query string `sql`.
    - However, the code executes:
      ```java
      java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
      statement.addBatch(sql);
      int[] counts = statement.executeBatch();
      ```
    - The type of `statement` is resolved as `"java.sql.Statement"`.
    - The call `statement.addBatch(sql)` has callee `statement.addBatch` and argument `sql`.
    - The lookup for `"java.sql.Statement"` method `"addBatch"` **fails** because `addBatch` is not in the stub registry for `"java.sql.Statement"` (only `execute`, `executeQuery`, and `executeUpdate` are defined). It is also not in `generic_sinks`.
    - Because `addBatch` is not recognized as a propagator/sink, the taint from `sql` is **never** propagated to the `statement` object.
    - When `statement.executeBatch()` is subsequently called, `statement` is untainted, and since `executeBatch()` takes no arguments, no taint flow is recorded.

---

## 2. Trace for BenchmarkTest02647 (`Base64`)

In `BenchmarkTest02647.java`, the relevant code snippet is:
```java
bar = new String(
        org.apache.commons.codec.binary.Base64.decodeBase64(
                org.apache.commons.codec.binary.Base64.encodeBase64(
                        param.getBytes())));
```

### Complete Execution & Stub Lookup Trace

1. **Parsed AST Call**: 
   Nested call expressions are parsed in post-order:
   - `param.getBytes()` (NodeKind::CallExpression)
   - `org.apache.commons.codec.binary.Base64.encodeBase64(...)` (NodeKind::CallExpression)
   - `org.apache.commons.codec.binary.Base64.decodeBase64(...)` (NodeKind::CallExpression)
   - `new String(...)` (NodeKind::CallExpression)
2. **Lowered IR Instruction**:
   Because these calls are nested on the RHS of the assignment and their intermediate return values are not stored in variables, they are lowered to:
   - `Call { dest: None, callee: "param.getBytes", args: [] }`
   - `Call { dest: None, callee: "org.apache.commons.codec.binary.Base64.encodeBase64", args: ["param.getBytes()"] }`
   - `Call { dest: None, callee: "org.apache.commons.codec.binary.Base64.decodeBase64", args: ["org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())"] }`
   - `Call { dest: Some("bar"), callee: "new String", args: [...] }`
3. **Resolved Callee**:
   - `resolve_callee_info_internal` falls back to `Some(("org.apache.commons.codec.binary.Base64", "encodeBase64"))` and `Some(("org.apache.commons.codec.binary.Base64", "decodeBase64"))` because there are no imports or local variables for `org`.
4. **class_fqn**: `"org.apache.commons.codec.binary.Base64"`
5. **method_name**: `"encodeBase64"` / `"decodeBase64"`
6. **StubRegistry::lookup() Input**: `class_or_module = "org.apache.commons.codec.binary.Base64"`, `method = "encodeBase64"` / `"decodeBase64"`.
7. **Lookup Normalization**:
   - Falls back directly to class_clean since it matches the exact FQN.
8. **Registry Match Result**: `SUCCESS`.
9. **Stub Selected**:
   - For `encodeBase64`: `MethodStub { name: "encodeBase64", kind: StubKind::Propagator, propagates_from: Some(vec![0]) }`.
   - For `decodeBase64`: `MethodStub { name: "decodeBase64", kind: StubKind::Propagator, propagates_from: Some(vec![0]) }`.
10. **Transfer Function Execution**:
    - The engine processes the call to `encodeBase64` and recognizes it as a propagator.
    - Since `is_propagating` is `true`, it attempts to taint `dest` (if present) and `receiver` (if present).
11. **First Point Where Taint is Lost**:
    - Because the nested call was lowered with `dest: None` (it has no named temporary variable destination) and has no receiver instance (it is a static class call), the transfer function has **no destination variable** to assign the taint fact to.
    - Consequently, the return value of `encodeBase64` is never marked as tainted, preventing taint from propagating to `decodeBase64` and eventually to the variable `bar`.

---

## VERIFY RC175

- **"Missing getTheParameter stub"**
  - **REJECTED**: The stub is already registered in `stubs.rs` (under `"org.owasp.benchmark.helpers.SeparateClassRequest"` and `"SeparateClassRequest"`).
- **"Missing Apache Base64 stub"**
  - **REJECTED**: The stub is already registered in `stubs.rs` (under `"org.apache.commons.codec.binary.Base64"`).

---

## Architectural Divergence and Recommendations

### 1. First Actual Architectural Divergence
- **For `SeparateClassRequest`**: The failure to register the intermediate state modifying method `addBatch(...)` on `java.sql.Statement` as a propagator or sink, causing the `statement` object to remain untainted.
- **For `Base64`**: The IR lowerer discarding assignment destinations (`dest: None`) for nested call expressions, meaning return values of intermediate static functions cannot hold taint.

### 2. Corrected Engineering Recommendation
1. **Extend the JDBC `Statement` Stubs**: Add `addBatch` as a propagator (propagating taint from argument 0 to the receiver instance `this`).
2. **Flatten Nested Call Expressions / Temporary Variables**: Update the IR lowering phase (`lower_statements` / `collect_statements` in `crates/ir/src/lib.rs`) to assign a synthetic temporary variable (`_tmp_val_X`) as the `dest` of nested call expressions so that their return values can carry taint through the transfer function.

---

## FINAL VERDICT

**B. Existing stubs are reached but propagation fails afterward.**
