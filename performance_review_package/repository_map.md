# Repository Crate Map

Complete mapping of the Cargo workspace dependencies and purposes:

```
                  [cli] (validation driver)
                 /     \
         [taint]        [features]
        /   |   \        |
   [cfg] [rules] [symbols]
      \    |     /
       \   |    /
         [ir]
```

## Crate Inventory
1. **`ir`**:
   * *Path*: `crates/ir`
   * *Purpose*: Defines compiler data structures. Represents program state in simple SSA-like instruction trees.
2. **`cfg`**:
   * *Path*: `crates/cfg`
   * *Purpose*: Computes control-flow block graphs and links call sites interprocedurally.
3. **`symbols`**:
   * *Path*: `crates/symbols`
   * *Purpose*: Keeps the global type table and resolves method overrides.
4. **`taint`**:
   * *Path*: `crates/taint`
   * *Purpose*: Executes the core static data-flow analysis, tracks sanitization, and applies stubs.
5. **`cli`**:
   * *Path*: `crates/cli`
   * *Purpose*: Hosts validation run binaries and developer debug CLI tools.
