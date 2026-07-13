# Important Files for Review

These files contain the implementation core of the static analyzer:

1. **`interproc.rs`** (in `crates/taint/src/`):
   * *Purpose*: Houses the core data-flow engine, solver loop, fact propagation, and sanitizer logic.
   * *Size*: ~4,600 LOC.
   * *Review Importance*: Highest. Contains all performance-sensitive code.

2. **`stubs.rs`** (in `crates/taint/src/`):
   * *Purpose*: Library stub matching. Matches standard JDK/Servlet API calls to taint sources/sinks/sanitizers.
   * *Size*: ~1,500 LOC.

3. **`icfg.rs`** (in `crates/cfg/src/`):
   * *Purpose*: Constructs the interprocedural flow graph, linking local CFGs.
   * *Size*: ~500 LOC.

4. **`v2_validation.rs`** (in `crates/cli/src/`):
   * *Purpose*: Driver harness that loads benchmarks and validates metrics.
