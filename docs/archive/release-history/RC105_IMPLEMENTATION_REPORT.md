# TaintFlow RC105 Tier B Import Resolver Implementation Report

This report documents the implementation details of the Tier B Python Import Resolver designed to restore ~12 False Negatives in the GitHub holdout dataset.

---

## 1. Summary of Modified Codebase

### Modified Files & Functions

| Crate / File | Target Function / Block | Type of Change | Purpose |
| :--- | :--- | :--- | :--- |
| `crates/symbols/src/global.rs` | `GlobalSymbolTable::load_file` | **Generic package-root discovery** | Walks up parent parts from top-down checking `program.source_files` for `__init__.py` to normalize package FQNs dynamically. |
| `crates/symbols/src/global.rs` | `GlobalSymbolTable::resolve_import_recursive` | **Suffix fallback matching** | Permits resolving package namespace mismatches (e.g. `web.pgadmin...` matching `pgadmin...`) without hardcoded mapping rules. |
| `crates/symbols/src/global.rs` | `resolve_relative_module` | **Parent traversal hardening** | Prevents discarding the top-level package prefix when traversal dot count exceeds FQN parts. |
| `crates/cli/src/v2_validation.rs` | Helper functions added | **Definition-based sibling discovery** | Adds AST-less helpers `extract_imports_from_code`, `code_defines_symbol`, `resolve_sibling_filepath`, and `extract_imported_symbols` to map siblings dynamically. |
| `crates/cli/src/v2_validation.rs` | Sibling match block (lines 924-933) | **Definition-based sibling discovery** | Maps siblings based on imported symbol definitions instead of calling `get_target_filename` or defaulting to `test.py`. |
| `crates/cli/src/v2_validation.rs` | `run_v2_analysis_safe` and diagnostics | **Source file pre-population** | Pre-populates `program.source_files` with all target and sibling paths prior to calling `gst.load_file` to support order-independent root detection. |

---

## 2. Match of Recoveries to Implementation Details

The table below maps the specific expected recoveries from `RC105_EXPECTED_RECOVERIES.md` to the implementation subsystems that enable them:

| Expected Recovery Repo | CWE | Core Blocker | Resolving Mechanism / Code Block |
| :--- | :---: | :--- | :--- |
| `snowflakedb/snowflake-connector-python` | CWE-502 | Target imports relative sibling files which collides with `test.py` naming. | **Definition-based sibling discovery** (v2_validation.rs) correctly maps sibling files to target names (e.g. `snowflake/connector/cache.py`) using symbol definition checks. |
| `snowflakedb/snowflake-connector-python` | CWE-502 | Traverses up parent directories (`..randomize`). | **Parent traversal hardening** preserves package root prefix (`snowflake.connector.randomize`) during resolver traversal evaluation. |
| `PaddlePaddle/Paddle` | CWE-78 | Harness package mismatches and sibling file lookup failures. | **Suffix fallback matching** matches incoming imports to full registered package FQNs, resolving sibling imports. |
| `sybrenstuvel/python-rsa` | CWE-327 | Relative import of package `.` directory. | **Parent traversal hardening** and **Generic package-root discovery** allow `.` package boundaries to be identified and resolved. |
| `OctoPrint/OctoPrint` | CWE-78 | utility file name mapping mismatch. | **Definition-based sibling discovery** routes utility definitions dynamically to their canonical relative paths. |
| `geopython/pygeoapi` | CWE-22 | Sibling file path mismatch. | **Suffix fallback matching** permits binding `pygeometa.core` calls to the resolved parser function. |
| `gitpython-developers/GitPython` | CWE-22 | Package-root mismatch during loading. | **Generic package-root discovery** isolates target library definitions cleanly under the correct namespace. |

---

## 3. Manual Verification Commands

Pursuant to the execution policy in `AGENTS.md`, the model did not run check/test suites locally. Run the following manual verification commands to confirm build and tests are green:

### Step 1: Rust Engine Build Verification
```powershell
Set-Location "d:\V2 Backup\rust-engine"
cargo check
```

### Step 2: Rust Engine Tests Verification
```powershell
cargo test
```
