# TaintFlow RC105 Python Import Resolver Hardening Review

This document audits the proposed changes in `RC105_IMPORT_RESOLVER_DESIGN.md` before implementation. It aims to eliminate repository-specific mappings, replacing them with generic, self-discovering algorithms to ensure the static analysis engine remains robust and maintainable.

---

## 1. Audit and Classifications

### Proposed Change 1 (Phase 1): Hardcoded Repository Mappings in `get_target_filename`
* **Current Proposal:** Expand the list of hardcoded repository names in `get_target_filename` (e.g. `pgadmin`, `fides`) to map holdout code to matching physical paths.
* **Classification:** **MODIFY**
* **Rationale:** Introducing new repository-specific mappings to the validation harness creates a high maintenance burden as more holdout samples are added. We must replace this with a **generic definition-based module matching** algorithm.
* **FP Risk:** **None**. Modifying validation harness file naming only affects how test cases are loaded into the symbol table; it does not change taint propagation rules.
* **TP Benefit:** **High**. Correctly resolves import bindings across multi-file holdout test cases (like `pgadmin` and `fides`), recovering missing True Positives.
* **Maintenance Cost:** **Low**. The generic matching logic is written once and handles all future repositories automatically.

### Proposed Change 2 (Phase 2): Hardcoded Prefix-Stripping in `load_file`
* **Current Proposal:** Hardcode a list of known directories/packages (like `web/`, `src/`) to strip from Python file paths to derive correct module FQNs.
* **Classification:** **MODIFY**
* **Rationale:** Hardcoding package names in the symbol table prevents the engine from working on new, unseen codebases out-of-the-box. We must replace this with **generic package-root discovery** using `__init__.py` hierarchy traversal or fallback suffix matching.
* **FP Risk:** **Low**. Ensures name bindings match import statements exactly.
* **TP Benefit:** **High**. Enables the static analysis engine to automatically align physical file paths with import namespaces on any codebase.
* **Maintenance Cost:** **Zero**. Eliminates hardcoding package names in the engine source code.

### Proposed Change 3 (Phase 3): Parent Traversal Hardening in `resolve_relative_module`
* **Current Proposal:** Correct relative traversal dot-counting logic to prevent dot overflows from discarding root package prefixes.
* **Classification:** **KEEP**
* **Rationale:** This is a purely algorithmic correction to ensure relative imports resolve correctly according to Python's language spec.
* **FP Risk:** **None**.
* **TP Benefit:** **High**. Recovers flows that cross deep parent directory traversals.
* **Maintenance Cost:** **Zero**.

---

## 2. Generic Package-Root Discovery Specification

We will replace the repository-specific logic with the following two generic algorithms:

### Algorithm A: Definition-Based Sibling Filename Discovery (Validation Harness)
Instead of guessing file paths in `get_target_filename` via hardcoded repository rules, the validation runner will resolve sibling filenames dynamically:
1. Parse the main target file's imports to extract imported symbols and their namespaces (e.g. `from X.Y.Z import W` $\implies$ symbol `W` from module `X.Y.Z`).
2. For each candidate sibling file:
   - Scan its AST (or use a lightweight regex) for top-level definitions of the imported symbol (e.g., `class W` or `def W`).
   - If a sibling defines `W`, dynamically assign it the filename `X/Y/Z.py`.
3. If no matching import statement is found, assign the sibling a unique name like `sibling_N.py` instead of the collision-prone `test.py`.

### Algorithm B: `__init__.py` Traversal for Module Names (Symbol Table)
To normalize file paths into correct Python module FQNs generically:
1. Starting from the file's parent directory, walk up the directory tree and check if each parent directory contains an `__init__.py` or `__init__.pyc`.
2. Stop the walk at the first directory that does *not* contain an `__init__.py`. The directory immediately below it is identified as the **package root**.
3. Strip all directory components above the package root from the FQN calculation. For example, if path is `web/pgadmin/utils/driver.py` and `pgadmin/` contains `__init__.py` but `web/` does not, the derived FQN will be `pgadmin.utils.driver`.

---

## 3. Expected Metrics & Validation Plan

### Expected Metrics Impact
* **Expected TP Impact:** +12 True Positives recovered in the GitHub holdout dataset.
* **Expected FP Impact:** 0 (purely additive call graph edges).
* **Expected FN Impact:** -12 False Negatives.
* **Expected MCC Impact:** Positive increase in MCC.

### Recommended Validation Scope
* **GitHub-Only Validation** (smallest scope capable of verifying Python import resolution in the holdout dataset).

### Manual Validation Command
To execute validation manually, run the following PowerShell commands:

```powershell
Set-Location "d:\V2 Backup\rust-engine"
$env:ONLY_GITHUB="1"
$env:SKIP_PGADMIN="0"  # Enable pgadmin to verify recovery!
$env:SKIP_DATACHAIN="1"
$env:SKIP_RAY="1"

cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_GITHUB_VALIDATION.log
```
