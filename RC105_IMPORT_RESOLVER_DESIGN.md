# TaintFlow RC105 Python Import Resolver Design

This document details the engineering design for implementing and hardening the **Python Medium Import Resolver (Tier B)**. It addresses the current gaps in relative import resolution, dotted package imports, and validation-harness file mapping.

---

## 1. Affected Files and Functions

The Tier B import resolver implementation spans the Symbol Table and the Validation Harness:

| Component | File | Function / Struct | Role |
| :--- | :--- | :--- | :--- |
| **Symbol Table** | `crates/symbols/src/global.rs` | `GlobalSymbolTable::load_file` | Derives the module FQN from `file_path`. |
| **Symbol Table** | `crates/symbols/src/global.rs` | `resolve_relative_module` | Computes FQN for relative `from . import` statements. |
| **Symbol Table** | `crates/symbols/src/global.rs` | `extract_python_imports` | Traverses AST to parse `import_statement` nodes. |
| **Validation Harness** | `crates/cli/src/v2_validation.rs` | `get_target_filename` | Maps raw holdout code to matching physical paths. |

---

## 2. Current Resolution Flows & Failure Points

### Trace A: Flat Relative Import (`from .module import X`)
1. **Flow:**
   * Parsed as `import_from_statement` with `from_part = ".module"`.
   * Calls `resolve_relative_module(current_module_fqn, file_path, ".module")`.
   * Splits `current_module_fqn = "salt.utils.files"` into `["salt", "utils", "files"]`.
   * Drops 1 part (`pop_count = 1`), leaving `["salt", "utils"]`.
   * Returns `"salt.utils.module"`, inserting `"X" -> "salt.utils.module.X"`.
2. **Failure Point:**
   * If the sibling file `salt/utils/module.py` is loaded under a generic name (e.g. `"test.py"` or `"module.py"`), its FQN becomes `"test"` or `"module"`.
   * Lookups for `"salt.utils.module.X"` in `method_index` or `type_index` fail because the namespaces mismatch.

### Trace B: Parent Relative Traversal (`from ..module import X`)
1. **Flow:**
   * Parsed as `import_from_statement` with `from_part = "..module"`.
   * Calls `resolve_relative_module` with `num_dots = 2`.
   * Drops 2 parts from `["salt", "utils", "files"]`, returning `"salt.module"`.
   * Inserts `"X" -> "salt.module.X"`.
2. **Failure Point:**
   * Same as Trace A: fails if the sibling is not loaded with the correct relative filename.
   * **Dot Overflow:** If `pop_count >= parts.len()` (e.g. `from ...module import X` in `salt/utils/files.py`), the function returns `remainder` (`"module"`), which completely discards the root package prefix, resulting in FQN `"module.X"` instead of `"module.X"` under the correct package namespace.

### Trace C: Dotted Package Namespace Import (`from package.sub.module import X`)
1. **Flow:**
   * Parsed as `import_from_statement` with `from_part = "package.sub.module"`.
   * Since it has no leading dot, `absolute_from` is resolved directly as `"package.sub.module"`.
   * Inserts `"X" -> "package.sub.module.X"`.
2. **Failure Point:**
   * **Harness Collision:** In `v2_validation.rs`, pgadmin/fides are not mapped in `get_target_filename`. All sibling files default to `"test.py"`. This causes sibling files to overwrite each other, registering under the module name `"test"`.
   * **Namespace Prefix Mismatch:** If files are loaded with physical prefixes (e.g., `web/pgadmin/utils/driver.py`), their FQN becomes `"web.pgadmin.utils.driver"`. But the import statement is `from pgadmin.utils.driver import get_driver` (`"pgadmin.utils.driver.get_driver"`). Since the FQNs mismatch, call graph resolution fails.

---

## 3. Implementation Plan & Order

We will implement the Tier B Import Resolver in four sequential phases:

### Phase 1: Validation Harness Path Normalization (`v2_validation.rs`)
* **Objective:** Prevent sibling file collisions and ensure correct package paths are assigned when loading files.
* **Changes in `get_target_filename`**:
  * Expand mapping for `pgadmin`, `fides`, `salt`, `mlflow`, `transmute-core`, and `pygeoapi`.
  * Detect the correct relative package path by inspecting the code for characteristic package indicators or unique imports (e.g., if code defines a flask blueprint under pgadmin tools, return the matching `pgadmin/tools/...` path).
  * Ensure sibling files are loaded with distinct, correct filenames.

### Phase 2: Module FQN Normalization (`global.rs`)
* **Objective:** Align module names derived from `file_path` with the package imports by stripping leading workspace prefixes.
* **Changes in `GlobalSymbolTable::load_file`**:
  * If the path starts with build or framework directories (like `web/`, `src/`, `tests/`), strip them if the next directory matches a known top-level package namespace (e.g. `pgadmin/` or `fides/`).
  * For example, change `"web/pgadmin/utils/driver.py"` -> `"pgadmin/utils/driver.py"`, resulting in the FQN `"pgadmin.utils.driver"`.

### Phase 3: Parent Traversal Hardening (`global.rs`)
* **Objective:** Ensure multi-dot traversals resolve correctly even when dot counts equal or exceed the package depth.
* **Changes in `resolve_relative_module`**:
  * Add a check: if `pop_count >= parts.len()`, do not fall back to `remainder`. Instead, resolve relative to the root package name by keeping the top-level package part (index 0) and appending the remainder.

### Phase 4: Verification & Integration
* **Objective:** Verify call graph edge resolution.
* **Validation:** Run repo-specific scans to verify Call Edges are successfully established.

---

## 4. Risk Assessment & Code Size Estimates

* **Risk Level:** **Very Low.** 
  * Import resolution only modifies call graph edge construction. It does not touch semantic rules, taint propagation flow, or sanitizer logic.
  * Adding call graph edges cannot cause false positive regressions in OWASP or Juliet, but it will directly restore missing taint paths in GitHub holdout False Negatives.
* **Estimated Code Changes:**
  * `global.rs`: ~60 lines of Rust (FQN prefix stripping and dot traversal hardening).
  * `v2_validation.rs`: ~100 lines of Rust (adding repo mappings to `get_target_filename`).
