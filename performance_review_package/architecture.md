# Architecture Overview

This document outlines the high-level architecture of the TaintFlow engine for an external reviewer.

## High-Level Crate Structure
* **`ir`**: Defines the intermediate representation of parsed code. Contains structures like `Program`, `Method`, `Instruction`, and `Block`.
* **`cfg`**: Responsible for building local Control Flow Graphs (CFG) and stitching them together into a global Interprocedural Control Flow Graph (ICFG).
* **`symbols`**: Performs symbol resolution, inheritance tree tracking, and call graph construction.
* **`taint`**: The core analysis engine. Houses the interprocedural taint propagation solver, library stubs, sanitization checks, and type-resolution helpers.
* **`cli`**: The execution driver, containing `v2-validation` (the harness that loads benchmarks and drives validation).

## Data Flow & Core Component Interactions
```
[Source Code Files]
        ↓ (parser / normalizer)
   [ir::Program] ──> [symbols::GlobalSymbolTable]
        ↓                      ↓
 [cfg::CFG / ICFG]   [symbols::CallGraph]
        ↓                      ↓
     [taint::InterproceduralTaintEngine]
        ↓
    [Flows / Findings]
```
