# Performance Hotspot Functions

These functions dominate analysis execution time during validation:

### 1. `InterproceduralTaintEngine::run`
* **File**: `crates/taint/src/interproc.rs`
* **Execution Cost**: ~60-70% of total runtime.
* **Why**: Implements the main fixed-point solver loop. Constantly pushes facts across the worklist. Complex control flow cycles cause the solver to exhaust its iteration cap (`1,000,001`).

### 2. `InterproceduralTaintEngine::propagate_fact`
* **File**: `crates/taint/src/interproc.rs`
* **Execution Cost**: ~15-20% of total runtime.
* **Why**: Evaluates how a `TaintFact` propagates across individual instruction kinds (e.g. assignments, calls, map reads/writes). Uses heavy string slicing and keyword searches.

### 3. `InterproceduralCFG::build`
* **File**: `crates/cfg/src/icfg.rs`
* **Execution Cost**: ~5-10% of total runtime.
* **Why**: Allocates and stitches thousands of ICFG nodes and edges. Slowed down by memory allocations on large codebases.
