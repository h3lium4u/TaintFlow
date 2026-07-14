# RC300: Python v1.0 Master Backlog

## 1. Python Forensic Findings Audit

Auditing the Python validation datasets identifies exactly **3 FNs** (and **0 FPs** on the latest clean validation run).

---

## 2. Root-Cause Forensic Trace

### FN 1 & 2: Match-Case Pattern Matching (CWE-22)
- **Benchmark IDs**: `BenchmarkTest00516`, `BenchmarkTest00737`
- **Trace**:
  `match guess:` -> `case 'A': bar = param` -> `case 'B': bar = 'bob'` -> `codecs.open(..., bar)`
- **Divergence**: The CFG builder fails to extract blocks for Python `match` and `case` syntax nodes, resulting in the compiler dropping the variable mapping to `bar` entirely (missing SSA assignment representation).
- **Subsystem**: CFG / SSA Lowering
- **Rust File**: `crates/cfg/src/builder.rs`
- **Estimated LOC**: ~80 lines.
- **Expected Metrics Change**: +2 TP (removes 2 FNs).
- **Engineering Effort**: 1 day.

### FN 3: Custom Request Wrapper Fields (CWE-78)
- **Benchmark ID**: `BenchmarkTest00899`
- **Trace**:
  `wrapped = request_wrapper(request)` -> `param = wrapped.get_query_parameter(...)` -> `subprocess.run(..., param)`
- **Divergence**: The interprocedural solver does not propagate taint from the constructor argument (`request`) to wrapper fields (`wrapped.request`), causing getter calls on the wrapper to return untainted values.
- **Subsystem**: Solver / Alias Analysis
- **Rust File**: `crates/taint/src/interproc.rs`
- **Estimated LOC**: ~120 lines.
- **Expected Metrics Change**: +1 TP (removes 1 FN).
- **Engineering Effort**: 2 days.

---

## 3. Prioritized Python Backlog (P0 Milestones)

1. **CFG Match-Case Builder Lowering**: Enforces SSA block translation for Python match-case constructs (**Order 1**, 1 day, High ROI).
2. **Dynamic Constructor Taint Propagation**: Propagates taint across custom helper fields during object instantiation (**Order 2**, 2 days, High ROI).
