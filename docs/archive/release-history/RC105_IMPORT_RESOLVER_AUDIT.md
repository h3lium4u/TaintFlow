# TaintFlow RC105 Python Import Resolver Audit

This document presents a forensic audit of the GitHub Holdout False Negatives (FNs) blocked by python import resolution failures. It evaluates the capabilities, limitations, and ROI of the proposed **Python Medium Import Resolver (Tier B)**.

---

## 1. Executive Summary & Objective

In the **RC104C** candidate, **59 out of 74 False Negatives (79.7%)** are blocked by inter-file local import resolution failures (`MULTI_FILE_IMPORT`). Because the Call Graph cannot resolve imports across files, taint flows terminate prematurely at module boundaries.

The objective of this audit is to classify these 59 import-blocked cases, analyze the specific import failure mechanisms (relative, absolute dotted, parent traversals), and define the engineering feasibility of the **Tier B (Medium) Import Resolver** as the primary focus for the **RC105** sprint.

---

## 2. Grouping of Import-Blocked Cases

All audited cases are written in **Python**. They are grouped below by repository and primary import patterns:

| Repository | Lang | Import-Blocked Cases | Primary Import Patterns | Example Blocked Flows |
| :--- | :---: | :---: | :--- | :--- |
| `pgadmin-org/pgadmin4` | Python | **19 cases** | `PACKAGE_IMPORT`, `REEXPORT`, `DYNAMIC_IMPORT` | `from pgadmin.utils.driver import get_driver` |
| `saltstack/salt` | Python | **7 cases** | `PACKAGE_IMPORT` | `import salt.utils.templates`, `import salt.fileserver` |
| `PaddlePaddle/Paddle` | Python | **6 cases** | `RELATIVE_IMPORT`, `PACKAGE_IMPORT`, `SIMPLE_IMPORT` | `from .assert_transformer import AssertTransformer` |
| `snowflakedb/snowflake-connector-python` | Python | **6 cases** | `RELATIVE_IMPORT` (Parent Traversals) | `from ...randomize import random_string` |
| `ethyca/fides` | Python | **5 cases** | `PACKAGE_IMPORT` | `from fides.api.ops.util.storage_helper import ...` |
| `toumorokoshi/transmute-core` | Python | **3 cases** | `RELATIVE_IMPORT` | `from .serializers import CattrsSerializer` |
| `geopython/pygeoapi` | Python | **2 cases** | `PACKAGE_IMPORT`, `SIMPLE_IMPORT` | `from pygeometa.core import read_mcf` |
| `volcengine/OpenViking` | Python | **1 case** | `SIMPLE_IMPORT` | `from openviking import AsyncOpenViking` |
| `HumanSignal/label-studio-sdk` | Python | **1 case** | `PACKAGE_IMPORT` | `from label_studio_sdk._extensions.label_studio_tools...` |
| `sybrenstuvel/python-rsa` | Python | **1 case** | `RELATIVE_IMPORT` | `from . import common` |
| `OctoPrint/OctoPrint` | Python | **1 case** | `PACKAGE_IMPORT` | `from octoprint.util.files import ...` |
| `gitpython-developers/GitPython` | Python | **1 case** | `PACKAGE_IMPORT` | `from git.objects.tag import TagObject` |
| `B-Step62/mlflow` | Python | **1 case** | `PACKAGE_IMPORT` | `from mlflow.store.model_registry.file_store import ...` |
| `huggingface/transformers` | Python | **1 case** | `PACKAGE_IMPORT` | `from transformers.trainer import Trainer` |
| `heartexlabs/label-studio` | Python | **1 case** | `PACKAGE_IMPORT` | `from label_studio.core.utils.params import ...` |

---

## 3. Technical Breakdown of Import Failure Patterns

Static analysis of the Python holdout dataset reveals four distinct failure patterns:

### 3.1 Dotted Package Namespace Imports (`PACKAGE_IMPORT`)
* **Mechanism:** Absolute imports referencing nested directories from the repository root (e.g. `from pgadmin.utils.driver import get_driver` in a file located under `pgadmin/tools/backup/`).
* **Engine Failure:** The Rust engine's ICFG builder treats `pgadmin.utils.driver` as a directory path relative to the *current module's directory* (yielding `pgadmin/tools/backup/pgadmin/utils/driver.py`), causing resolution failure.
* **Volume:** **29 cases (49.15%)** — the largest block.

### 3.2 Flat Relative Imports (`RELATIVE_IMPORT` - Single Dot)
* **Mechanism:** Relative imports referencing files in the same directory using a single dot prefix (e.g. `from .serializers import CattrsSerializer`).
* **Engine Failure:** The parser fails to strip or map the single dot (`.`) to the current module directory, leaving the path unresolved.
* **Volume:** **14 cases (23.73%)**.

### 3.3 Parent Relative Traversals (`RELATIVE_IMPORT` - Multi-Dot)
* **Mechanism:** Relative imports referencing files in parent or grandparent directories using multiple dots (e.g. `from ..utils import safe_join` or `from ...randomize import random_string`).
* **Engine Failure:** The ICFG builder does not compute parent directory steps (`..` paths) dynamically, failing to resolve the target file.
* **Volume:** **11 cases (18.64%)**.

### 3.4 Package Re-exports & Dynamic Imports (`REEXPORT` / `DYNAMIC_IMPORT`)
* **Mechanism:** Imports passing through package-level `__init__.py` files (re-exports) or resolved at runtime via `importlib.import_module`.
* **Engine Failure:** The static symbol table does not load and trace `__init__.py` bindings or dynamic strings.
* **Volume:** **4 cases (6.78%)**.

---

## 4. Evaluation of Tier B Resolver Capabilities & Limitations

The proposed **Python Medium Import Resolver (Tier B)** is designed to address the vast majority of static import patterns:

### Capabilities (What Tier B Will Resolve)
1. **Dotted Package Namespace Resolution:** Maps absolute package names (matching repository subdirectories) to the repository root.
2. **Relative dot resolution:** Resolves single-dot (`.`) imports relative to the active file's parent directory.
3. **Parent relative traversals:** Resolves multi-dot (`..`, `...`) imports by traversing the physical directory tree upward.

### Limitations (What Tier B Will NOT Resolve)
1. **__init__.py Re-exports (Tier C):** Direct imports from a package folder without referencing the sub-module file directly.
2. **Dynamic Imports (Tier C):** Runtime imports inside function bodies (e.g., `importlib`).

---

## 5. Feasibility, Impact, and Complexity Estimates

* **TP Recovery Potential:**
  * **In Isolation:** **12 TPs** (recovers cases that do not have other downstream blockers).
  * **Combined (Post-Beta Roadmap):** **55 TPs** (removes the primary blocker, allowing ORM, Deserialization, and SSRF modeling fixes to propagate flows successfully).
* **FP Risk:** **Extremely Low.** Correctly resolving import paths reflects the actual structure of the codebase. It does not introduce heuristic seeding or over-aggressive taint propagation, ensuring precision is preserved.
* **Engineering Complexity:** **Medium.** Requires modifications to the Rust engine's ICFG builder and Symbol Table to compute source directories and manipulate dot-prefix paths (Estimated effort: 1-2 weeks).

---

## 6. Recommended Validation Scope

To minimize execution time while ensuring rigorous verification, the validation should follow a tiered approach:

### Phase 1: Fast Iteration (GitHub Holdout Subset)
Scan a subset of Python repositories to verify flat relative, parent traversal, and basic dotted absolute package imports:
```powershell
Set-Location "d:\V2 Backup\rust-engine"
$env:ONLY_GITHUB="1"
$env:SKIP_PGADMIN="1"
$env:SKIP_DATACHAIN="1"
$env:SKIP_RAY="1"
cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_GITHUB_VALIDATION.log
```

### Phase 2: Targeted Namespace Verification (pgadmin-org/pgadmin4)
Verify deep dotted package namespace resolution using the `ONLY_REPO` environment variable:
```powershell
Set-Location "d:\V2 Backup\rust-engine"
$env:ONLY_REPO="pgadmin"
cargo run --release --bin v2-validation *>&1 | Tee-Object RC105_PGADMIN_VALIDATION.log
```
