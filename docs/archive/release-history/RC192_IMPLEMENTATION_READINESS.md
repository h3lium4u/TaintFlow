# RC192 — JavaBean Implementation Readiness Report

## 1. IR Representation Compatibility

We verified that the proposed JavaBean propagation rules can be implemented using the current IR representation:

- **IR Representation**: Variable assignments and returns in `crates/ir/src/lib.rs` are stored as `String` values.
- **Symbol Table Fields**: Field definitions of all types are stored in the global symbol table `TypeInfo.fields`.
- **Exact Field Matching**:
  - For `return this.username;`:
    - We check if the body has exactly one `Return` instruction.
    - We extract the return expression `val` string.
    - We verify if `val` matches `username` or `this.username`, where `username` is a valid field name retrieved from the class's `TypeInfo` and superclasses.
  - For `this.username = username;`:
    - We check if the body has exactly one `Assign` instruction.
    - We verify if `src` matches parameter 0, and `dest` matches a class field name (or is prefixed with `this.`).
- **Inherited Fields**: Class field collection recursively traverses the class's superclasses via `superclass` pointers in `TypeInfo` to collect all inherited fields.
- **Conclusion**: Exact field-name matching using the symbol table is safe, precise, and completely independent of any string heuristics.

---

## 2. False Positive Audit

We audited potential counterexamples:
- **`return this.getConnection();` / `return foo.bar();`**:
  - The IR lowers these calls as `InstructionKind::Call`. Because the method body contains a `Call` instead of a `Return` or `Assign`, they are immediately disqualified from semantic classification.
- **`return other.username;`**:
  - The return expression `"other.username"` has a dot prefix of `"other."` which is not `"this."`, and the class does not have a field named `"other.username"`. Thus, it is rejected.
- **`this.connection = DriverManager.getConnection(...);`**:
  - Disqualified because the assignment source expression contains a nested `Call` instruction.

---

## 3. Inheritance Audit

- **Inherited Fields**: Recursively gathered from the parent classes.
- **Shadowed Fields**: Child class fields are gathered first. Duplicate names are stored in a `HashSet`, so matching either the shadowed or shadowing field remains valid.
- **Overridden Getters/Setters**: Overridden method definitions have unique `MethodId`s and are classified independently.

---

## 4. Lombok Audit

- **Lombok Fallback**: Generated Lombok classes do not have source code in the workspace; hence `method.body.is_empty()` is `true`. The classifier falls back to naming heuristics (`get*`, `is*`, `set*`, `with*`) plus package blocklists.
- **Application Preference**: Any method with an IR body will bypass naming fallback and be analyzed semantically, prioritizing correct logic detection over naming heuristics.

---

## 5. Performance Audit

- **Cache Hit Ratio**: Estimated $> 95\%$ due to repeated call site traversal in interprocedural analysis.
- **Complexity**: $O(1)$ per method classification (analyzed only once, and body size is limited to 1 statement).
- **Allocations**: Negligible (uses local string matching and a single `HashSet` per uncached method).

---

## 6. Implementation Checklist

- [ ] Create `JavaBeanKind` enum in `crates/taint/src/interproc.rs`.
- [ ] Implement `JavaBeanClassifier` struct and its semantic checks.
- [ ] Add `RefCell<HashMap<MethodId, JavaBeanKind>>` cache to `InterproceduralTaintEngine`.
- [ ] Add DTO getter/setter propagation checks in `InstructionKind::Call` transfer function.
- [ ] Verify compilation: `cargo build --release` and `cargo test`.
- [ ] Execute validation script and collect metrics reports.

---

## FINAL DECISION

**A. The implementation is fully specified and can now be coded safely.**
