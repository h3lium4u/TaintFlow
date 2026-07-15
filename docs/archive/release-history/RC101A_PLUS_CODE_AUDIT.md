# RC101A+ Code Construction Audit

This audit evaluates the codebase's current state to ensure it matches the requirements for the **RC101A+** candidate. 

---

## 1. Feature / Heuristic Classification

The table below lists all RC103-era modifications and their audit status (whether they should be kept, reverted, or deferred) in the active engine code:

| Feature / Logic | Intent | Current Code Status | Audit Classification |
| :--- | :---: | :---: | :---: |
| **Unescape Sanitizer Fix** | Exclude "unescape" functions from acting as sanitizers | **Enabled** (present in `interproc.rs` and `lib.rs`) | **KEEP** (Approved) |
| **isValidHref CWE-79 Sink Registry** | Register `isvalidhref` as a CWE-79 sink | **Enabled** (present in `stubs.rs` and `lib.rs`) | **KEEP** (Approved) |
| **Private Method Suppression** | Skip entry-point seeding for `starts_with('_')` methods | **Absent** (reverted successfully) | **REVERT** (Approved) |
| **Subprocess shell=True Gating** | Suppress command injection sinks when `shell=False` | **Absent** (reverted successfully) | **REVERT** (Approved) |
| **CWE-502 Sink Argument Gating** | Skip deserialization seeding for parameter-less methods | **Enabled** (present in `interproc.rs:L733-744`) | **DEFER** (Leftover Blocker) |

---

## 2. Compilation and Test Results

The engine's local compilation and unit/integration test suites have been verified:
*   **`cargo check` status:** **PASS**. Compiles cleanly (with a minor compiler warning regarding an escaped newline in `crates/rules/src/lib.rs`).
*   **`cargo test` status:** **PASS**. All 34 tests across assignment, alias, container, loop/try, sanitizer, and interprocedural modules executed and passed successfully.
*   **Expected Validation Behavior:**
    *   *If run as-is:* Vul4J recall would recover to 100%, and Juliet/OWASP recall would recover. However, the presence of the leftover CWE-502 Sink Argument Gating logic in `interproc.rs` will continue to block ~5 TPs (Fides, Snowflake) where deserialization is performed inside parameter-less static initializers.
    *   *If fully cleaned:* Reverting the leftover gating logic will completely restore the RC101A baseline recall (100% on GitHub), while the XSS fixes will provide a net improvement (+46 combined TPs).

---

## 3. Leftover Logic Details (Blocker)

The following block is still present in `crates/taint/src/interproc.rs` (lines 733–744) inside `seed_sources`:
```rust
                // Sink Argument Gating: Only seed sink arguments if the method has a pathway for taint to enter.
                // This requires the method to either take parameters, or contain an explicit source instruction.
                let has_params = !method.parameters.is_empty();
                let has_explicit_source = all_insts.iter().any(|&iid| {
                    self.program.instructions.get(&iid).map_or(false, |inst| {
                        matches!(&inst.kind, InstructionKind::Source { .. })
                    })
                });
                
                if !has_params && !has_explicit_source {
                    continue;
                }
```
This constraint enforces **CWE-502 Sink Argument Gating**, which must be removed/reverted to restore complete compatibility with the RC101A baseline.

---

## 4. Release Readiness Verdict

**NOT READY.** 

Although the unit tests pass and the private method suppression is reverted, the repository **cannot** be declared ready for a full RC101A+ validation run. The presence of the deserialization gating block in `interproc.rs` constitutes leftover RC103-era code that violates the RC101A+ specification. 

*Recommendation:* The gating logic in `interproc.rs:L733-744` must be removed before executing the validation sweep to ensure a true, regression-free RC101A+ validation run.
