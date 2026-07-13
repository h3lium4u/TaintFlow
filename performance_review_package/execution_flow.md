# End-to-End Execution Flow

This document traces how a codebase is processed from initialization to validation reports.

## Execution Sequence

### Step 1: Harness Startup & Dataset Loading (`v2-validation`)
* Entry point: `v2_validation.rs` (`v2_validation::main`).
* Loads JSONL dataset metadata containing test case codes, expected CWE classifications, and vulnerability states.

### Step 2: Crate IR Construction & Symbol Registration
* Calls `symbols::global::GlobalSymbolTable::load_file`.
* Parses Java source files into `ir::Program` containing basic blocks and instructions.
* Populates inheritance records (`resolve_inheritance_hierarchy`).

### Step 3: Interprocedural CFG (ICFG) Construction
* Calls `symbols::call_graph::CallGraph::build` to construct the static call graph.
* Calls `cfg::icfg::InterproceduralCFG::build` to build local CFGs and link them via Call/Return edges into the ICFG.

### Step 4: Taint Engine Initialization & Seeding
* Instantiates `taint::InterproceduralTaintEngine`.
* Seeds initial taint sources using `seed_sources()`.

### Step 5: Fixed-Point Propagation Solver (`engine.run()`)
* Runs the core propagation algorithm. Iteratively pushes `TaintFact`s along ICFG edges.
* Re-evaluates taint flows through method calls, sanitizers, and class structures until reaching convergence or the iteration cap (`1,000,001`).

### Step 6: Sink Detection & CWE Assignment
* Calls `check_sink_flow` for nodes matched as sinks.
* Maps clean/unclean flows to target CWEs (CWE-22, CWE-79, CWE-89, CWE-113, CWE-614, etc.) via heuristic and stub registry checks.
* Filters out secure/sanitized paths and records active findings.
