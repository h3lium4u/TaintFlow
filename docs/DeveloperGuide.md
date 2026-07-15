# Developer Guide

This guide describes how to extend TaintFlow, write rules, and work with the codebase.

---

## Workspace Layout
- `crates/parser`: tree-sitter parse adapters.
- `crates/normalizer`: AST translation and framework normalization rules.
- `crates/ir`: Instructions block building and SSA versioning.
- `crates/cfg`: Local CFG and Interprocedural CFG builder.
- `crates/taint`: IFDS solver and path-sensitive taint tracking.
- `crates/rules`: CWE matcher algorithms.
- `crates/cli`: CLI commands, output generation, and validation scripts.

---

## Writing Custom Rules
TaintFlow rules are located inside `crates/rules/src/lib.rs`. To write a custom rule:
1. Identify the CWE number.
2. Define source parameters (e.g. method signatures or annotations).
3. Define sink parameters.
4. Implement a custom matcher rule block.

For submission details, refer to [CONTRIBUTING.md](../CONTRIBUTING.md).
