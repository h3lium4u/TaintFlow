# TaintFlow RC105 Expected False Negative Recoveries

This document identifies the specific GitHub False Negative (FN) samples from the holdout dataset that are expected to recover as True Positives (TPs) following the implementation of the **Python Tier B Import Resolver**.

---

## 1. Probability Ranking of Expected Recoveries

The table below ranks the expected recoveries by probability of successful taint path resolution:

| Rank | Repository | CWE | Confidence | Primary Recovery Category | Import Statement |
| :---: | :--- | :---: | :---: | :--- | :--- |
| **1** | `snowflakedb/snowflake-connector-python` | CWE-502 | **HIGH** | Sibling Filename Collision | `from .storage_client import SnowflakeFileEncryptionMaterial` |
| **2** | `snowflakedb/snowflake-connector-python` | CWE-502 | **HIGH** | Sibling Filename Collision | `from .file_transfer_agent import SnowflakeFileMeta, StorageCredential` |
| **3** | `snowflakedb/snowflake-connector-python` | CWE-502 | **HIGH** | Relative Traversal Failure | `from ..randomize import random_string` |
| **4** | `snowflakedb/snowflake-connector-python` | CWE-502 | **HIGH** | Sibling Filename Collision | `from .constants import UTF8, kilobyte` |
| **5** | `PaddlePaddle/Paddle` | CWE-78 | **HIGH** | Sibling Filename Collision | `from .assert_transformer import AssertTransformer` |
| **6** | `PaddlePaddle/Paddle` | CWE-78 | **HIGH** | Sibling Filename Collision | `from dygraph_to_static_utils import Dy2StTestBase` |
| **7** | `PaddlePaddle/Paddle` | CWE-78 | **HIGH** | Package-Root Mismatch | `from paddle.utils.download import get_path_from_url` |
| **8** | `PaddlePaddle/Paddle` | CWE-78 | **HIGH** | Package-Root Mismatch | `from paddle.distributed import ParallelEnv` |
| **9** | `sybrenstuvel/python-rsa` | CWE-327 | **HIGH** | Relative Traversal Failure | `from . import common` |
| **10**| `OctoPrint/OctoPrint` | CWE-78 | **HIGH** | Package-Root Mismatch | `from octoprint.util.files import search_through_file` |
| **11**| `geopython/pygeoapi` | CWE-22 | **HIGH** | Package-Root Mismatch | `from pygeometa.core import read_mcf` |
| **12**| `gitpython-developers/GitPython` | CWE-22 | **HIGH** | Package-Root Mismatch | `from git import Reference, Head` |
| **13**| `B-Step62/mlflow` | CWE-22 | **MEDIUM**| Package-Root Mismatch | `from mlflow.store.tracking.file_store import FileStore` |
| **14**| `ethyca/fides` | CWE-918 | **MEDIUM**| Relative Traversal Failure | `from ..util import get_test_file_path` |

---

## 2. Detailed Recovery Profiles

### Rank 1-4: `snowflakedb/snowflake-connector-python` (CWE-502)
* **Import Statement:**
  * `from .storage_client import SnowflakeFileEncryptionMaterial`
  * `from .file_transfer_agent import SnowflakeFileMeta, StorageCredential`
  * `from ..randomize import random_string`
  * `from .constants import UTF8, kilobyte`
* **Currently Unresolved Module:** `storage_client`, `file_transfer_agent`, `..randomize`, `constants`
* **Expected Resolved Module:** `snowflake.connector.storage_client`, `snowflake.connector.file_transfer_agent`, `snowflake.connector.randomize`, `snowflake.connector.constants`
* **Recovery Category:** **Sibling Filename Collision**, **Package-Root Mismatch**, **Relative Traversal Failure**
* **Confidence:** **HIGH**
* **Rationale:** The snowflake holdout files use relative dot-syntax imports that fail to resolve when sibling files collide on generic names (`test.py`) and lack the correct module namespace. Mapping their paths to the correct FQNs restores the call edges.

### Rank 5-8: `PaddlePaddle/Paddle` (CWE-78)
* **Import Statement:**
  * `from .assert_transformer import AssertTransformer`
  * `from dygraph_to_static_utils import Dy2StTestBase`
  * `from paddle.utils.download import get_path_from_url`
  * `from paddle.distributed import ParallelEnv`
* **Currently Unresolved Module:** `assert_transformer`, `dygraph_to_static_utils`, `paddle.utils.download`, `paddle.distributed`
* **Expected Resolved Module:** `paddle.fluid.dygraph.dygraph_to_static.assert_transformer`, `dygraph_to_static_utils`, `paddle.utils.download`, `paddle.distributed`
* **Recovery Category:** **Sibling Filename Collision** & **Package-Root Mismatch**
* **Confidence:** **HIGH**
* **Rationale:** PaddlePaddle relies on a mix of flat relative imports and absolute package imports that fail due to namespace mismatches and filename collisions. Dynamically registering the correct package paths enables the ICFG builder to link the runner scripts to downloader/transformer implementations.

### Rank 9: `sybrenstuvel/python-rsa` (CWE-327)
* **Import Statement:** `from . import common`
* **Currently Unresolved Module:** `.`
* **Expected Resolved Module:** `rsa.common`
* **Recovery Category:** **Relative Traversal Failure**
* **Confidence:** **HIGH**
* **Rationale:** The relative import `from . import common` inside a package-level module fails because `.` is not evaluated against the current parent FQN. Resolving `.` to the package root namespace correctly registers `rsa.common`.

### Rank 10: `OctoPrint/OctoPrint` (CWE-78)
* **Import Statement:** `from octoprint.util.files import search_through_file`
* **Currently Unresolved Module:** `octoprint.util.files`
* **Expected Resolved Module:** `octoprint.util.files`
* **Recovery Category:** **Package-Root Mismatch**
* **Confidence:** **HIGH**
* **Rationale:** OctoPrint's main file imports utility functions from the package utility module. The harness currently fails to load the utility file with the matching namespace. Assigning the path `octoprint/util/files.py` to the sibling dynamically completes the call graph.

### Rank 11: `geopython/pygeoapi` (CWE-22)
* **Import Statement:** `from pygeometa.core import read_mcf`
* **Currently Unresolved Module:** `pygeometa.core`
* **Expected Resolved Module:** `pygeometa.core`
* **Recovery Category:** **Package-Root Mismatch**
* **Confidence:** **HIGH**
* **Rationale:** Correctly routes calls from pygeoapi providers to the metadata parser `read_mcf` which opens and processes MCF files, successfully tracing the CWE-22 path traversal.

### Rank 12: `gitpython-developers/GitPython` (CWE-22)
* **Import Statement:** `from git import Reference, Head`
* **Currently Unresolved Module:** `git`
* **Expected Resolved Module:** `git`
* **Recovery Category:** **Package-Root Mismatch**
* **Confidence:** **HIGH**
* **Rationale:** Aligns the `git` library references with the test suites by stripping the root folder prefix, linking reference updates directly to command execution sinks.

### Rank 13: `B-Step62/mlflow` (CWE-22)
* **Import Statement:** `from mlflow.store.tracking.file_store import FileStore`
* **Currently Unresolved Module:** `mlflow.store.tracking.file_store`
* **Expected Resolved Module:** `mlflow.store.tracking.file_store`
* **Recovery Category:** **Package-Root Mismatch**
* **Confidence:** **MEDIUM**
* **Rationale:** While import resolution will successfully link the test file to `FileStore`, there is a moderate risk that downstream ORM/store initializers require extra parameter stubs to fully propagate taint through the class instance constructor.

### Rank 14: `ethyca/fides` (CWE-918)
* **Import Statement:** `from ..util import get_test_file_path`
* **Currently Unresolved Module:** `..util`
* **Expected Resolved Module:** `fides.api.ops.util`
* **Recovery Category:** **Relative Traversal Failure**
* **Confidence:** **MEDIUM**
* **Rationale:** Traversing up to parent directories will succeed, but tracing the complete SSRF flow requires the resolved parameters to reach the outbound HTTP requests cleanly.
