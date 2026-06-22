# RC102: GitHub Holdout False Positive Casebook

This casebook documents the forensic analysis of all 53 non-pgAdmin False Positives (FPs) identified in the GitHub Holdout validation dataset. It classifies each case, describes the propagation chain, identifies the location where over-tainting first occurs, and outlines architectural precision-hardening roadmaps.

## Summary Table

| Case ID | Repo | CWE | Root Cause Category | First Location of Over-Tainting | Description |
| :---: | :--- | :--- | :--- | :--- | :--- |
| Case #1 | OpenViking | CWE-22 | `CONTEXT_INSENSITIVE_PROPAGATION` | `openviking.py (import_ovpack entry point)` | The engine propagates taint from test_import_success to test_import_with_force via the shared import_ovpack client method. |
| Case #2 | sagemaker-python-sdk | CWE-502 | `SOURCE_OVERMATCH` | `test_deserializers.py (test_csv_deserializer_array parameter)` | The engine taints the pytest fixture parameter csv_deserializer as an untrusted source, generating a flow to deserialize with a constant string. |
| Case #3 | fides | CWE-22 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #4 | fides | CWE-918 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #5 | fides | CWE-918 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #6 | fides | CWE-918 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #7 | fides | CWE-22 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #8 | fides | CWE-918 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #9 | fides | CWE-918 | `SOURCE_OVERMATCH` | `test_saas_client.py (test parameter/fixture)` | The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code. |
| Case #10 | binderhub | CWE-78 | `SANITIZER_MODELING_GAP` | `git.py (subprocess.run call)` | The engine flags subprocess.run with list arguments without shell=True as command injection, ignoring safe list-based execution. |
| Case #11 | snowflake-connector-python | CWE-502 | `WRAPPER_PROPAGATION_OVERTAINTING` | `file_transfer_agent.py (_open_intermediate_dst_path)` | The engine seeds the mode parameter of a local file helper method as a source, flowing directly into open. |
| Case #12 | snowflake-connector-python | CWE-89 | `SOURCE_OVERMATCH` | `test_write_pandas.py (test parameter)` | The engine taints the test method parameter table_type/index, flowing into execute calls. |
| Case #13 | snowflake-connector-python | CWE-502 | `SINK_ARGUMENT_INSENSITIVITY` | `snowflake/connector/compat.py (os.open)` | The engine taints the flags parameter of owner_rw_opener, which flows to os.open, triggering a false flow due to sink argument insensitivity. |
| Case #14 | snowflake-connector-python | CWE-502 | `FIELD_INSENSITIVE_PROPAGATION` | `snowflake/connector/auth.py (session_parameters)` | The engine merges different keys in the session_parameters dictionary, causing an over-tainting propagation. |
| Case #15 | snowflake-connector-python | CWE-502 | `WRAPPER_PROPAGATION_OVERTAINTING` | `file_transfer_agent.py (encrypt_file)` | The engine seeds parameters of local compression/encryption helper functions as sources. |
| Case #16 | snowflake-connector-python | CWE-502 | `FIELD_INSENSITIVE_PROPAGATION` | `snowflake/connector/auth.py (session_parameters)` | The engine merges different keys in the session_parameters dictionary, causing an over-tainting propagation. |
| Case #17 | snowflake-connector-python | CWE-502 | `WRAPPER_PROPAGATION_OVERTAINTING` | `file_transfer_agent.py (_open_intermediate_dst_path)` | The engine seeds the mode parameter of a local file helper method as a source, flowing directly into open. |
| Case #18 | snowflake-connector-python | CWE-89 | `SOURCE_OVERMATCH` | `test_write_pandas.py (test parameter)` | The engine taints the test method parameter table_type/index, flowing into execute calls. |
| Case #19 | snowflake-connector-python | CWE-502 | `WRAPPER_PROPAGATION_OVERTAINTING` | `file_transfer_agent.py (encrypt_file)` | The engine seeds parameters of local compression/encryption helper functions as sources. |
| Case #20 | snowflake-connector-python | CWE-502 | `FIELD_INSENSITIVE_PROPAGATION` | `snowflake/connector/auth.py (session_parameters)` | The engine merges different keys in the session_parameters dictionary, causing an over-tainting propagation. |
| Case #21 | snowflake-connector-python | CWE-89 | `SOURCE_OVERMATCH` | `test_write_pandas.py (test parameter)` | The engine taints the test method parameter table_type/index, flowing into execute calls. |
| Case #22 | Paddle | CWE-78 | `MOCK_HELPER_FLOW_LEAKAGE` | `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)` | The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation. |
| Case #23 | Paddle | CWE-78 | `MOCK_HELPER_FLOW_LEAKAGE` | `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)` | The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation. |
| Case #24 | Paddle | CWE-78 | `MOCK_HELPER_FLOW_LEAKAGE` | `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)` | The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation. |
| Case #25 | Paddle | CWE-78 | `MOCK_HELPER_FLOW_LEAKAGE` | `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)` | The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation. |
| Case #26 | Paddle | CWE-22 | `WRAPPER_PROPAGATION_OVERTAINTING` | `paddle/dataset/common.py (split)` | The parameter suffix of the split helper function is seeded as a source, flowing directly into open. |
| Case #27 | Paddle | CWE-78 | `MOCK_HELPER_FLOW_LEAKAGE` | `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)` | The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation. |
| Case #28 | Paddle | CWE-78 | `MOCK_HELPER_FLOW_LEAKAGE` | `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)` | The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation. |
| Case #29 | ray | CWE-918 | `WRAPPER_PROPAGATION_OVERTAINTING` | `ray/scripts.py (_ray_start_hook)` | Parameter ray_params in _ray_start_hook helper is seeded as a source. |
| Case #30 | ray | CWE-918 | `WRAPPER_PROPAGATION_OVERTAINTING` | `ray/scripts.py (up)` | Parameter cluster_config_file in up CLI helper is seeded as a source. |
| Case #31 | LLaMA-Factory | CWE-502 | `WRAPPER_PROPAGATION_OVERTAINTING` | `src/llamafactory/extras/baichuan.py (llamafy_baichuan2)` | The parameter input_dir of llamafy_baichuan2 is seeded as a source, flowing into model loading. |
| Case #32 | pygeoapi | CWE-22 | `WRAPPER_PROPAGATION_OVERTAINTING` | `pygeoapi/util.py (get_data_path)` | Parameter data_path of get_data_path helper is seeded as a source. |
| Case #33 | label-studio | CWE-918 | `SANITIZER_MODELING_GAP` | `label_studio/data_import/api.py (load_tasks)` | The engine fails to recognize path sanitization validation checks introduced in load_tasks. |
| Case #34 | mlflow | CWE-22 | `WRAPPER_PROPAGATION_OVERTAINTING` | `mlflow/store/tracking/file_store.py (get_experiment)` | Parameter experiment_id in get_experiment helper is seeded as a source. |
| Case #35 | transformers | CWE-502 | `SANITIZER_MODELING_GAP` | `src/transformers/trainer.py (torch.load)` | The engine ignores weights_only=True safety check passed to torch.load, which prevents arbitrary pickle execution. |
| Case #36 | transformers | CWE-502 | `WRAPPER_PROPAGATION_OVERTAINTING` | `src/transformers/tokenization_utils_base.py (count_file)` | Helper parameter path of count_file is seeded as a source, flowing to open. |
| Case #37 | transformers | CWE-502 | `SANITIZER_MODELING_GAP` | `src/transformers/trainer.py (torch.load)` | The engine ignores weights_only=True safety check passed to torch.load, which prevents arbitrary pickle execution. |
| Case #38 | firefighter-incident | CWE-918 | `WRAPPER_PROPAGATION_OVERTAINTING` | `firefighter/raid/serializers.py (Serializer)` | The serializer constructor parameter data is seeded as a source, flowing to simulated Jira HTTP requests in the stub. |
| Case #39 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #40 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #41 | salt | CWE-22 | `WRAPPER_PROPAGATION_OVERTAINTING` | `salt/utils/jid.py (get_jid)` | Helper parameter jid is seeded as a source, flowing to path operations. |
| Case #42 | salt | CWE-22 | `WRAPPER_PROPAGATION_OVERTAINTING` | `salt/utils/path.py (verify_log_files)` | Parameter files in verify_log_files helper is seeded as a source, flowing to os.makedirs. |
| Case #43 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #44 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #45 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #46 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #47 | salt | CWE-22 | `WRAPPER_PROPAGATION_OVERTAINTING` | `salt/utils/jid.py (get_jid)` | Helper parameter jid is seeded as a source, flowing to path operations. |
| Case #48 | salt | CWE-22 | `SINK_ARGUMENT_INSENSITIVITY` | `salt/utils/atomicfile.py (atomic_open)` | The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments. |
| Case #49 | datachain | CWE-502 | `FIELD_INSENSITIVE_PROPAGATION` | `datachain/query/dataset.py (self.db)` | The engine propagates taint from database helpers through self.db using field-insensitive aliasing. |
| Case #50 | datachain | CWE-502 | `SOURCE_OVERMATCH` | `tests/test_sqlite.py (test parameter)` | The engine taints test parameters in sqlite_db test functions. |
| Case #51 | datachain | CWE-502 | `FIELD_INSENSITIVE_PROPAGATION` | `datachain/query/dataset.py (self.db)` | The engine propagates taint from database helpers through self.db using field-insensitive aliasing. |
| Case #52 | datachain | CWE-502 | `FIELD_INSENSITIVE_PROPAGATION` | `datachain/query/dataset.py (self.db)` | The engine propagates taint from database helpers through self.db using field-insensitive aliasing. |
| Case #53 | datachain | CWE-502 | `SOURCE_OVERMATCH` | `tests/test_sqlite.py (test parameter)` | The engine taints test parameters in sqlite_db test functions. |

---

## Detailed Case Breakdowns

### Case #1: CWE-22 in OpenViking
- **Repository**: [https://github.com/volcengine/OpenViking](https://github.com/volcengine/OpenViking)
- **CWE**: CWE-22
- **Commit**: `46b3e76e28b9b3eee73693720c9ec48820228b72`
- **Root Cause Category**: `CONTEXT_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `openviking.py (import_ovpack entry point)`
- **Reasoning / Description**: The engine propagates taint from test_import_success to test_import_with_force via the shared import_ovpack client method.

#### Forensic Trace Chain
```text
[0] node=7 method='test_import_with_force' var='temp_dir' inst=None
[1] node=21 method='test_import_with_force' var='temp_dir' inst=Some(Assign { dest: "client, uri", src: "client_with_resource" })
[2] node=20 method='test_import_with_force' var='export_path' inst=Some(Assign { dest: "export_path", src: "temp_dir / \"force_test.ovpack\"" })
[3] node=19 method='test_import_with_force' var='export_path' inst=Some(Call { dest: None, callee: "client.export_ovpack", args: ["uri", "str(export_path)"] })
[4] node=18 method='test_import_with_force' var='export_path' inst=Some(Call { dest: None, callee: "client.export_ovpack", args: ["uri", "str(export_path)"] })
[5] node=17 method='test_import_with_force' var='export_path' inst=Some(Call { dest: None, callee: "client.import_ovpack", args: ["str(export_path)", "\"viking://resources/force_test/\"", "vectorize=False"] })
[6] node=25 method='import_ovpack' var='path' inst=None
[7] node=29 method='import_ovpack' var='path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["path", "\"r\""] })
```

#### Code Context
```python
        assert "imported" in import_uri

    async def test_import_with_force(self, client_with_resource, temp_dir: Path):
        """Test force overwrite import"""
        client, uri = client_with_resource

        # Export first
        export_path = temp_dir / "force_test.ovpack"
        await client.export_ovpack(uri, str(export_path))

        # First import
        await client.import_ovpack(
            str(export_path), "viking://resources/force_test/", vectorize=False
        )

        # Second force import (overwrite)
        import_uri = await client.import_ovpack(
            str(export_path), "viking://resources/force_test/", force=True, vectorize=False
        )

```

### Case #2: CWE-502 in sagemaker-python-sdk
- **Repository**: [https://github.com/aws/sagemaker-python-sdk](https://github.com/aws/sagemaker-python-sdk)
- **CWE**: CWE-502
- **Commit**: `72e0c9712aec6fbb82fb40fda091dfc2a42c70a0`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_deserializers.py (test_csv_deserializer_array parameter)`
- **Reasoning / Description**: The engine taints the pytest fixture parameter csv_deserializer as an untrusted source, generating a flow to deserialize with a constant string.

#### Forensic Trace Chain
```text
[0] node=104 method='test_csv_deserializer_array' var='csv_deserializer' inst=None
[1] node=107 method='test_csv_deserializer_array' var='csv_deserializer' inst=Some(Call { dest: Some("result"), callee: "csv_deserializer.deserialize", args: ["io.BytesIO(b\"1,2,3\")", "\"text/csv\""] })
[2] node=106 method='test_csv_deserializer_array' var='csv_deserializer' inst=Some(Call { dest: Some("result"), callee: "csv_deserializer.deserialize", args: ["io.BytesIO(b\"1,2,3\")", "\"text/csv\""] })
```

#### Code Context
```python


def test_csv_deserializer_array(csv_deserializer):
    result = csv_deserializer.deserialize(io.BytesIO(b"1,2,3"), "text/csv")
    assert result == [["1", "2", "3"]]


def test_csv_deserializer_2dimensional(csv_deserializer):
    result = csv_deserializer.deserialize(io.BytesIO(b"1,2,3\n3,4,5"), "text/csv")
    assert result == [["1", "2", "3"], ["3", "4", "5"]]


def test_csv_deserializer_posix_compliant(csv_deserializer):
    result = csv_deserializer.deserialize(io.BytesIO(b"1,2,3\n3,4,5\n"), "text/csv")
    assert result == [["1", "2", "3"], ["3", "4", "5"]]


def test_stream_deserializer():
    deserializer = StreamDeserializer()

```

### Case #3: CWE-22 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-22
- **Commit**: `f526d9ffb176006d701493c9d0eff6b4884e811f`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=37 method='test_non_existent_route_404' var='url' inst=None
[1] node=48 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("auth_header"), callee: "generate_auth_header", args: ["scopes=[PRIVACY_REQUEST_READ]"] })
[2] node=47 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("auth_header"), callee: "generate_auth_header", args: ["scopes=[PRIVACY_REQUEST_READ]"] })
[3] node=46 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("resp"), callee: "api_client.get", args: ["f\"{url}/route/does/not/exist\"", "headers=auth_header"] })
```

#### Code Context
```python
from __future__ import annotations
from fastapi import HTTPException, status
from fides.common.api.scope_registry import SCOPE_REGISTRY as SCOPES
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
)
from typing import List

class DrpActionValidationError(Exception):
    """A resource already exists with this DRP Action."""


class StorageConfigNotFoundException(BaseException):
```

### Case #4: CWE-918 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-918
- **Commit**: `cd344d016b1441662a61d0759e7913e8228ed1ee`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=194 method='test_client_returns_ok_response' var='test_saas_request' inst=None
[1] node=201 method='test_client_returns_ok_response' var='test_saas_request' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[2] node=200 method='test_client_returns_ok_response' var='test_saas_request' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[3] node=199 method='test_client_returns_ok_response' var='test_saas_request' inst=Some(Assign { dest: "test_response.status_code", src: "200" })
[4] node=198 method='test_client_returns_ok_response' var='test_saas_request' inst=Some(Assign { dest: "send.return_value", src: "test_response" })
[5] node=197 method='test_client_returns_ok_response' var='test_saas_request' inst=Some(Call { dest: Some("returned_response"), callee: "test_authenticated_client.send", args: ["test_saas_request"] })
[6] node=196 method='test_client_returns_ok_response' var='test_saas_request' inst=Some(Call { dest: Some("returned_response"), callee: "test_authenticated_client.send", args: ["test_saas_request"] })
```

#### Code Context
```python
        from fides.api.service.authentication.authentication_strategy import (  # pylint: disable=R0401
            AuthenticationStrategy,
        )
    from fides.api.models.connectionconfig import ConnectionConfig
    from fides.api.schemas.limiter.rate_limit_config import RateLimitConfig
    from fides.api.schemas.saas.saas_config import ClientConfig
    from fides.api.schemas.saas.shared_schemas import SaaSRequestParams
from __future__ import annotations
from fides.api.common_exceptions import (
    ClientUnsuccessfulException,
    ConnectionException,
    FidesopsException,
)
from fides.api.service.connectors.limiter.rate_limiter import (
    RateLimiter,
```

### Case #5: CWE-918 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-918
- **Commit**: `cd344d016b1441662a61d0759e7913e8228ed1ee`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=151 method='test_client_retries_429_and_throws' var='test_saas_request' inst=None
[1] node=160 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[2] node=159 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[3] node=158 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Assign { dest: "test_response.status_code", src: "429" })
[4] node=157 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Assign { dest: "send.return_value", src: "test_response" })
[5] node=156 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Call { dest: None, callee: "pytest.raises", args: ["ClientUnsuccessfulException"] })
[6] node=155 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Call { dest: None, callee: "pytest.raises", args: ["ClientUnsuccessfulException"] })
[7] node=154 method='test_client_retries_429_and_throws' var='test_saas_request' inst=Some(Call { dest: None, callee: "test_authenticated_client.send", args: ["test_saas_request"] })
```

#### Code Context
```python
        from fides.api.service.authentication.authentication_strategy import (  # pylint: disable=R0401
            AuthenticationStrategy,
        )
    from fides.api.models.connectionconfig import ConnectionConfig
    from fides.api.schemas.limiter.rate_limit_config import RateLimitConfig
    from fides.api.schemas.saas.saas_config import ClientConfig
    from fides.api.schemas.saas.shared_schemas import SaaSRequestParams
from __future__ import annotations
from fides.api.common_exceptions import (
    ClientUnsuccessfulException,
    ConnectionException,
    FidesopsException,
)
from fides.api.service.connectors.limiter.rate_limiter import (
    RateLimiter,
```

### Case #6: CWE-918 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-918
- **Commit**: `cd344d016b1441662a61d0759e7913e8228ed1ee`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=211 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=None
[1] node=221 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response_1"), callee: "Response", args: [] })
[2] node=220 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response_1"), callee: "Response", args: [] })
[3] node=219 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Assign { dest: "test_response_1.status_code", src: "429" })
[4] node=218 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response_2"), callee: "Response", args: [] })
[5] node=217 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response_2"), callee: "Response", args: [] })
[6] node=216 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Assign { dest: "test_response_2.status_code", src: "200" })
[7] node=215 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Assign { dest: "send.side_effect", src: "[test_response_1, test_response_2]" })
[8] node=214 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Call { dest: Some("returned_response"), callee: "test_authenticated_client.send", args: ["test_saas_request"] })
[9] node=213 method='test_client_retries_429_with_success' var='test_authenticated_client' inst=Some(Call { dest: Some("returned_response"), callee: "test_authenticated_client.send", args: ["test_saas_request"] })
```

#### Code Context
```python
        from fides.api.service.authentication.authentication_strategy import (  # pylint: disable=R0401
            AuthenticationStrategy,
        )
    from fides.api.models.connectionconfig import ConnectionConfig
    from fides.api.schemas.limiter.rate_limit_config import RateLimitConfig
    from fides.api.schemas.saas.saas_config import ClientConfig
    from fides.api.schemas.saas.shared_schemas import SaaSRequestParams
from __future__ import annotations
from fides.api.common_exceptions import (
    ClientUnsuccessfulException,
    ConnectionException,
    FidesopsException,
)
from fides.api.service.connectors.limiter.rate_limiter import (
    RateLimiter,
```

### Case #7: CWE-22 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-22
- **Commit**: `f526d9ffb176006d701493c9d0eff6b4884e811f`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=43 method='test_non_existent_route_404' var='url' inst=None
[1] node=54 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("auth_header"), callee: "generate_auth_header", args: ["scopes=[PRIVACY_REQUEST_READ]"] })
[2] node=53 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("auth_header"), callee: "generate_auth_header", args: ["scopes=[PRIVACY_REQUEST_READ]"] })
[3] node=52 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("resp"), callee: "api_client.get", args: ["f\"{url}/route/does/not/exist\"", "headers=auth_header"] })
[4] node=51 method='test_non_existent_route_404' var='url' inst=Some(Call { dest: Some("resp"), callee: "api_client.get", args: ["f\"{url}/route/does/not/exist\"", "headers=auth_header"] })
```

#### Code Context
```python
from __future__ import annotations
from fastapi import HTTPException, status
from fides.common.api.scope_registry import SCOPE_REGISTRY as SCOPES
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
)
from typing import List

class DrpActionValidationError(Exception):
    """A resource already exists with this DRP Action."""


class StorageConfigNotFoundException(BaseException):
```

### Case #8: CWE-918 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-918
- **Commit**: `cd344d016b1441662a61d0759e7913e8228ed1ee`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=246 method='test_client_returns_ok_response' var='test_authenticated_client' inst=None
[1] node=253 method='test_client_returns_ok_response' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[2] node=252 method='test_client_returns_ok_response' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[3] node=251 method='test_client_returns_ok_response' var='test_authenticated_client' inst=Some(Assign { dest: "test_response.status_code", src: "200" })
[4] node=250 method='test_client_returns_ok_response' var='test_authenticated_client' inst=Some(Assign { dest: "send.return_value", src: "test_response" })
[5] node=249 method='test_client_returns_ok_response' var='test_authenticated_client' inst=Some(Call { dest: Some("returned_response"), callee: "test_authenticated_client.send", args: ["test_saas_request"] })
[6] node=618 method='send' var='self' inst=None
[7] node=641 method='send' var='self' inst=Some(Call { dest: Some("rate_limit_requests"), callee: "self.build_rate_limit_requests", args: [] })
[8] node=305 method='build_rate_limit_requests' var='self' inst=None
[9] node=313 method='build_rate_limit_requests' var='self' inst=Some(Branch { cond: "not self.rate_limit_config or not self.rate_limit_config.enabled", then_block: [InstructionId(111)], else_block: None })
[10] node=314 method='build_rate_limit_requests' var='self' inst=Some(Return { val: Some("[]") })
[11] node=306 method='build_rate_limit_requests' var='self' inst=None
[12] node=640 method='send' var='self' inst=Some(Call { dest: Some("rate_limit_requests"), callee: "self.build_rate_limit_requests", args: [] })
[13] node=639 method='send' var='self' inst=Some(Call { dest: None, callee: "RateLimiter().limit", args: ["rate_limit_requests"] })
[14] node=638 method='send' var='self' inst=Some(Call { dest: None, callee: "RateLimiter().limit", args: ["rate_limit_requests"] })
[15] node=637 method='send' var='self' inst=Some(Call { dest: Some("prepared_request"), callee: "self.get_authenticated_request", args: ["request_params"] })
[16] node=636 method='send' var='self' inst=Some(Call { dest: Some("prepared_request"), callee: "self.get_authenticated_request", args: ["request_params"] })
[17] node=634 method='send' var='self' inst=Some(Branch { cond: "not prepared_request.url", then_block: [InstructionId(125)], else_block: None })
[18] node=633 method='send' var='self' inst=Some(Sanitizer { name: "deny_unsafe_hosts(urlparse(prepared_request.url).netloc)" })
[19] node=632 method='send' var='self' inst=Some(Call { dest: Some("response"), callee: "self.session.send", args: ["prepared_request"] })
[20] node=631 method='send' var='self' inst=Some(Call { dest: Some("response"), callee: "self.session.send", args: ["prepared_request"] })
[21] node=630 method='send' var='self' inst=Some(Call { dest: None, callee: "log_request_and_response_for_debugging", args: ["prepared_request", "response"] })
[22] node=629 method='send' var='self' inst=Some(Call { dest: None, callee: "log_request_and_response_for_debugging", args: ["prepared_request", "response"] })
[23] node=621 method='send' var='self' inst=Some(Branch { cond: "not response.ok", then_block: [InstructionId(130), InstructionId(133), InstructionId(134)], else_block: None })
[24] node=628 method='send' var='self' inst=Some(Call { dest: None, callee: "self._should_ignore_error", args: ["status_code=response.status_code", "errors_to_ignore=ignore_errors"] })
[25] node=294 method='_should_ignore_error' var='this' inst=None
[26] node=301 method='_should_ignore_error' var='this' inst=Some(Branch { cond: "errors_to_ignore is False", then_block: [], else_block: None })
[27] node=300 method='_should_ignore_error' var='this' inst=Some(Branch { cond: "errors_to_ignore is True", then_block: [], else_block: None })
[28] node=299 method='_should_ignore_error' var='this' inst=Some(Call { dest: None, callee: "isinstance", args: ["errors_to_ignore", "list"] })
[29] node=298 method='_should_ignore_error' var='this' inst=Some(Call { dest: None, callee: "isinstance", args: ["errors_to_ignore", "list"] })
[30] node=297 method='_should_ignore_error' var='this' inst=Some(Branch { cond: "isinstance(errors_to_ignore, list)", then_block: [], else_block: None })
[31] node=296 method='_should_ignore_error' var='this' inst=Some(Return { val: Some("False") })
[32] node=295 method='_should_ignore_error' var='this' inst=None
[33] node=627 method='send' var='self' inst=Some(Call { dest: None, callee: "self._should_ignore_error", args: ["status_code=response.status_code", "errors_to_ignore=ignore_errors"] })
[34] node=623 method='send' var='self' inst=Some(Branch { cond: "self._should_ignore_error(\n                status_code=response.status_code,\n                errors_to_ignore=ignore_errors,\n            )", then_block: [InstructionId(131), InstructionId(132)], else_block: None })
[35] node=622 method='send' var='self' inst=Some(Throw { val: "RequestFailureResponseException(response=response)" })
[36] node=619 method='send' var='self' inst=None
[37] node=631 method='send' var='self.session' inst=Some(Call { dest: Some("response"), callee: "self.session.send", args: ["prepared_request"] })
[38] node=67 method='__init__' var='self.session' inst=None
[39] node=229 method='get_authenticated_request' var='self.session' inst=None
[40] node=239 method='get_authenticated_request' var='self.session' inst=Some(Call { dest: Some("req"), callee: "Request(\n            method=request_params.method,\n            url=f\"{self.uri}{request_params.path}\",\n            headers=request_params.headers,\n            params=request_params.query_params,\n            data=request_params.body,\n        ).prepare", args: [] })
[41] node=238 method='get_authenticated_request' var='self.session' inst=Some(Call { dest: Some("req"), callee: "Request(\n            method=request_params.method,\n            url=f\"{self.uri}{request_params.path}\",\n            headers=request_params.headers,\n            params=request_params.query_params,\n            data=request_params.body,\n        ).prepare", args: [] })
[42] node=232 method='get_authenticated_request' var='self.session' inst=Some(Branch { cond: "self.client_config.authentication", then_block: [InstructionId(81), InstructionId(82), InstructionId(83)], else_block: None })
[43] node=231 method='get_authenticated_request' var='self.session' inst=Some(Return { val: Some("req") })
[44] node=230 method='get_authenticated_request' var='self.session' inst=None
[45] node=636 method='send' var='self.session' inst=Some(Call { dest: Some("prepared_request"), callee: "self.get_authenticated_request", args: ["request_params"] })
[46] node=634 method='send' var='self.session' inst=Some(Branch { cond: "not prepared_request.url", then_block: [InstructionId(125)], else_block: None })
[47] node=633 method='send' var='self.session' inst=Some(Sanitizer { name: "deny_unsafe_hosts(urlparse(prepared_request.url).netloc)" })
[48] node=632 method='send' var='self.session' inst=Some(Call { dest: Some("response"), callee: "self.session.send", args: ["prepared_request"] })
```

#### Code Context
```python
        from fides.api.service.authentication.authentication_strategy import (  # pylint: disable=R0401
            AuthenticationStrategy,
        )
    from fides.api.models.connectionconfig import ConnectionConfig
    from fides.api.schemas.limiter.rate_limit_config import RateLimitConfig
    from fides.api.schemas.saas.saas_config import ClientConfig
    from fides.api.schemas.saas.shared_schemas import SaaSRequestParams
from __future__ import annotations
from fides.api.common_exceptions import (
    ClientUnsuccessfulException,
    ConnectionException,
    FidesopsException,
)
from fides.api.service.connectors.limiter.rate_limiter import (
    RateLimiter,
```

### Case #9: CWE-918 in fides
- **Repository**: [https://github.com/ethyca/fides](https://github.com/ethyca/fides)
- **CWE**: CWE-918
- **Commit**: `cd344d016b1441662a61d0759e7913e8228ed1ee`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_saas_client.py (test parameter/fixture)`
- **Reasoning / Description**: The engine taints test parameters or pytest fixtures (url, test_saas_request, test_authenticated_client) in test code.

#### Forensic Trace Chain
```text
[0] node=571 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=None
[1] node=580 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[2] node=579 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Call { dest: Some("test_response"), callee: "Response", args: [] })
[3] node=578 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Assign { dest: "test_response.status_code", src: "429" })
[4] node=577 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Assign { dest: "send.return_value", src: "test_response" })
[5] node=576 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Call { dest: None, callee: "pytest.raises", args: ["ClientUnsuccessfulException"] })
[6] node=575 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Call { dest: None, callee: "pytest.raises", args: ["ClientUnsuccessfulException"] })
[7] node=574 method='test_client_retries_429_and_throws' var='test_authenticated_client' inst=Some(Call { dest: None, callee: "test_authenticated_client.send", args: ["test_saas_request"] })
```

#### Code Context
```python
        from fides.api.service.authentication.authentication_strategy import (  # pylint: disable=R0401
            AuthenticationStrategy,
        )
    from fides.api.models.connectionconfig import ConnectionConfig
    from fides.api.schemas.limiter.rate_limit_config import RateLimitConfig
    from fides.api.schemas.saas.saas_config import ClientConfig
    from fides.api.schemas.saas.shared_schemas import SaaSRequestParams
from __future__ import annotations
from fides.api.common_exceptions import (
    ClientUnsuccessfulException,
    ConnectionException,
    FidesopsException,
)
from fides.api.service.connectors.limiter.rate_limiter import (
    RateLimiter,
```

### Case #10: CWE-78 in binderhub
- **Repository**: [https://github.com/jupyterhub/binderhub](https://github.com/jupyterhub/binderhub)
- **CWE**: CWE-78
- **Commit**: `195caac172690456dcdc8cc7a6ca50e05abf8182`
- **Root Cause Category**: `SANITIZER_MODELING_GAP`
- **First Location of Over-Tainting**: `git.py (subprocess.run call)`
- **Reasoning / Description**: The engine flags subprocess.run with list arguments without shell=True as command injection, ignoring safe list-based execution.

#### Forensic Trace Chain
```text
[0] node=219 method='__init__' var='self.spec' inst=Some(Call { dest: Some("self.spec"), callee: "request.args.get", args: ["'spec'", "''"] })
[1] node=218 method='__init__' var='self.spec' inst=Some(Assign { dest: "self.url", src: "''" })
[2] node=217 method='__init__' var='self.spec' inst=Some(Assign { dest: "self.repo", src: "''" })
[3] node=216 method='__init__' var='self.spec' inst=Some(Assign { dest: "self.unresolved_ref", src: "''" })
[4] node=215 method='__init__' var='self.spec' inst=Some(Assign { dest: "self.resolved_ref", src: "''" })
[5] node=214 method='__init__' var='self.spec' inst=None
[6] node=105 method='__init__' var='self.spec' inst=Some(Call { dest: None, callee: "super().__init__", args: ["*args", "**kwargs"] })
[7] node=104 method='__init__' var='self.url, unresolved_ref' inst=Some(Call { dest: Some("self.url, unresolved_ref"), callee: "self.spec.split", args: ["'/'", "1"] })
[8] node=8 method='get_resolved_ref' var='self.url, unresolved_ref' inst=None
[9] node=53 method='get_repo_url' var='self.url, unresolved_ref' inst=None
[10] node=59 method='get_build_slug' var='self.url, unresolved_ref' inst=None
[11] node=95 method='__init__' var='self.url, unresolved_ref' inst=None
[12] node=162 method='get_resolved_ref_url' var='self.url, unresolved_ref' inst=None
[13] node=226 method='get_resolved_spec' var='self.url, unresolved_ref' inst=None
[14] node=234 method='get_resolved_spec' var='self.url, unresolved_ref' inst=Some(Call { dest: None, callee: "hasattr", args: ["self", "'resolved_ref'"] })
[15] node=233 method='get_resolved_spec' var='self.url, unresolved_ref' inst=Some(Call { dest: None, callee: "hasattr", args: ["self", "'resolved_ref'"] })
[16] node=229 method='get_resolved_spec' var='self.url, unresolved_ref' inst=Some(Branch { cond: "not hasattr(self, 'resolved_ref')", then_block: [InstructionId(67), InstructionId(68)], else_block: None })
[17] node=232 method='get_resolved_spec' var='self.url, unresolved_ref' inst=Some(Call { dest: None, callee: "self.get_resolved_ref", args: [] })
[18] node=8 method='get_resolved_ref' var='this.url, unresolved_ref' inst=None
[19] node=29 method='get_resolved_ref' var='this.url, unresolved_ref' inst=Some(Call { dest: None, callee: "hasattr", args: ["self", "'resolved_ref'"] })
[20] node=28 method='get_resolved_ref' var='this.url, unresolved_ref' inst=Some(Call { dest: None, callee: "hasattr", args: ["self", "'resolved_ref'"] })
[21] node=26 method='get_resolved_ref' var='this.url, unresolved_ref' inst=Some(Branch { cond: "hasattr(self, 'resolved_ref')", then_block: [InstructionId(51)], else_block: None })
[22] node=11 method='get_resolved_ref' var='this.url, unresolved_ref' inst=Some(Try { body: [], catches: [InstructionId(63)], finally: None })
[23] node=12 method='get_resolved_ref' var='unresolved_ref' inst=Some(Catch { exception_var: Some("ValueError"), body: [InstructionId(53), InstructionId(54), InstructionId(56), InstructionId(58), InstructionId(59), InstructionId(60), InstructionId(61), InstructionId(62)] })
[24] node=25 method='get_resolved_ref' var='command' inst=Some(Assign { dest: "command", src: "[\"git\", \"ls-remote\", \"--\", self.repo, self.unresolved_ref]" })
[25] node=24 method='get_resolved_ref' var='subprocess' inst=Some(Call { dest: Some("result"), callee: "subprocess.run", args: ["command", "universal_newlines=True", "stdout=subprocess.PIPE", "stderr=subprocess.PIPE"] })
```

#### Code Context
```python
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url, unresolved_ref = self.spec.split('/', 1)
        self.repo = urllib.parse.unquote(self.url)
        self.unresolved_ref = urllib.parse.unquote(unresolved_ref)
        if not self.unresolved_ref:
            raise ValueError("`unresolved_ref` must be specified as a query parameter for the basic git provider")

    async def get_resolved_ref(self):
        if hasattr(self, 'resolved_ref'):
            return self.resolved_ref

        try:
            # Check if the reference is a valid SHA hash
            self.sha1_validate(self.unresolved_ref)
        except ValueError:
            # The ref is a head/tag and we resolve it using `git ls-remote`
            command = ["git", "ls-remote", "--", self.repo, self.unresolved_ref]
```

### Case #11: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `file_transfer_agent.py (_open_intermediate_dst_path)`
- **Reasoning / Description**: The engine seeds the mode parameter of a local file helper method as a source, flowing directly into open.

#### Forensic Trace Chain
```text
[0] node=922 method='_open_intermediate_dst_path' var='mode' inst=None
[1] node=931 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.exists", args: [] })
[2] node=930 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.exists", args: [] })
[3] node=927 method='_open_intermediate_dst_path' var='mode' inst=Some(Branch { cond: "not self.intermediate_dst_path.exists()", then_block: [InstructionId(234)], else_block: None })
[4] node=926 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.open", args: ["mode"] })
```

#### Code Context
```python
    from .storage_client import SnowflakeFileEncryptionMaterial
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

```

### Case #12: CWE-89 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-89
- **Commit**: `f3f9b666518d29c31a49384bbaa9a65889e72056`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_write_pandas.py (test parameter)`
- **Reasoning / Description**: The engine taints the test method parameter table_type/index, flowing into execute calls.

#### Forensic Trace Chain
```text
[0] node=478 method='test_write_pandas' var='index' inst=None
[1] node=513 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("num_of_chunks"), callee: "math.ceil", args: ["len(sf_connector_version_data) / chunk_size"] })
[2] node=512 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("num_of_chunks"), callee: "math.ceil", args: ["len(sf_connector_version_data) / chunk_size"] })
[3] node=511 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("cnx"), callee: "conn_cnx", args: ["user=db_parameters[\"user\"]", "account=db_parameters[\"account\"]", "password=db_parameters[\"password\"]"] })
[4] node=510 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("cnx"), callee: "conn_cnx", args: ["user=db_parameters[\"user\"]", "account=db_parameters[\"account\"]", "password=db_parameters[\"password\"]"] })
[5] node=509 method='test_write_pandas' var='index' inst=Some(Assign { dest: "table_name", src: "\"driver_versions\"" })
[6] node=500 method='test_write_pandas' var='index' inst=Some(Branch { cond: "quote_identifiers", then_block: [InstructionId(38), InstructionId(39), InstructionId(40)], else_block: Some([InstructionId(41), InstructionId(42), InstructionId(43)]) })
[7] node=504 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("create_sql"), callee: "'CREATE OR REPLACE TABLE \"{}\" (\"name\" STRING, \"newest_version\" STRING)'.format", args: ["table_name"] })
[8] node=503 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("create_sql"), callee: "'CREATE OR REPLACE TABLE \"{}\" (\"name\" STRING, \"newest_version\" STRING)'.format", args: ["table_name"] })
[9] node=502 method='test_write_pandas' var='index' inst=Some(Assign { dest: "select_sql", src: "f'SELECT * FROM \"{table_name}\"'" })
[10] node=501 method='test_write_pandas' var='index' inst=Some(Assign { dest: "drop_sql", src: "f'DROP TABLE IF EXISTS \"{table_name}\"'" })
[11] node=497 method='test_write_pandas' var='index' inst=Some(Branch { cond: "not auto_create_table", then_block: [InstructionId(45)], else_block: None })
[12] node=482 method='test_write_pandas' var='index' inst=Some(Try { body: [InstructionId(47), InstructionId(48), InstructionId(49), InstructionId(54)], catches: [], finally: Some([InstructionId(55)]) })
[13] node=496 method='test_write_pandas' var='index' inst=Some(Call { dest: Some("success, nchunks, nrows, _"), callee: "write_pandas", args: ["cnx", "sf_connector_version_df.get()", "table_name", "compression=compression", "chunk_size=chunk_size", "quote_identifiers=quote_identifiers", "auto_create_table=auto_create_table", "create_temp_table=create_temp_table", "index=index"] })
[14] node=718 method='write_pandas' var='parallel' inst=None
[15] node=870 method='write_pandas' var='parallel' inst=Some(Branch { cond: "database is not None and schema is None", then_block: [InstructionId(371)], else_block: None })
[16] node=869 method='write_pandas' var='parallel' inst=Some(Assign { dest: "compression_map", src: "{\"gzip\": \"auto\", \"snappy\": \"snappy\"}" })
[17] node=868 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "compression_map.keys", args: [] })
[18] node=867 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "compression_map.keys", args: [] })
[19] node=865 method='write_pandas' var='parallel' inst=Some(Branch { cond: "compression not in compression_map.keys()", then_block: [InstructionId(375)], else_block: None })
[20] node=864 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "conn._session_parameters.get", args: ["_PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING", "False"] })
[21] node=863 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "conn._session_parameters.get", args: ["_PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING", "False"] })
[22] node=862 method='write_pandas' var='parallel' inst=Some(Assign { dest: "_use_scoped_temp_object", src: "(\n        conn._session_parameters.get(\n            _PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING, False\n        )\n        if conn._session_parameters\n        else False\n    )" })
[23] node=858 method='write_pandas' var='parallel' inst=Some(Branch { cond: "create_temp_table", then_block: [InstructionId(379), InstructionId(380)], else_block: None })
[24] node=857 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "table_type.lower", args: [] })
[25] node=856 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "table_type.lower", args: [] })
[26] node=854 method='write_pandas' var='parallel' inst=Some(Branch { cond: "table_type and table_type.lower() not in [\"temp\", \"temporary\", \"transient\"]", then_block: [InstructionId(383)], else_block: None })
[27] node=851 method='write_pandas' var='parallel' inst=Some(Branch { cond: "chunk_size is None", then_block: [InstructionId(385)], else_block: None })
[28] node=850 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "isinstance", args: ["df.index", "pandas.RangeIndex"] })
[29] node=849 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "isinstance", args: ["df.index", "pandas.RangeIndex"] })
[30] node=846 method='write_pandas' var='parallel' inst=Some(Branch { cond: "not (\n        isinstance(df.index, pandas.RangeIndex)\n        and 1 == df.index.step\n        and 0 == df.index.start\n    )", then_block: [InstructionId(388)], else_block: None })
[31] node=845 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "any", args: ["[pandas.api.types.is_datetime64tz_dtype(df[c]) for c in df.columns]"] })
[32] node=844 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "any", args: ["[pandas.api.types.is_datetime64tz_dtype(df[c]) for c in df.columns]"] })
[33] node=843 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "pandas.api.types.is_datetime64tz_dtype", args: ["df[c]"] })
[34] node=842 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "pandas.api.types.is_datetime64tz_dtype", args: ["df[c]"] })
[35] node=839 method='write_pandas' var='parallel' inst=Some(Branch { cond: "not use_logical_type and any(\n        [pandas.api.types.is_datetime64tz_dtype(df[c]) for c in df.columns]\n    )", then_block: [InstructionId(392)], else_block: None })
[36] node=836 method='write_pandas' var='parallel' inst=Some(Branch { cond: "use_logical_type is None", then_block: [InstructionId(394)], else_block: Some([InstructionId(395)]) })
[37] node=837 method='write_pandas' var='parallel' inst=Some(Assign { dest: "sql_use_logical_type", src: "\"\"" })
[38] node=835 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("cursor"), callee: "conn.cursor", args: [] })
[39] node=834 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("cursor"), callee: "conn.cursor", args: [] })
[40] node=833 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("stage_location"), callee: "_create_temp_stage", args: ["cursor", "database", "schema", "quote_identifiers", "compression", "auto_create_table", "overwrite", "_use_scoped_temp_object"] })
[41] node=832 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("stage_location"), callee: "_create_temp_stage", args: ["cursor", "database", "schema", "quote_identifiers", "compression", "auto_create_table", "overwrite", "_use_scoped_temp_object"] })
[42] node=831 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("tmp_folder"), callee: "TemporaryDirectory", args: [] })
[43] node=830 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("tmp_folder"), callee: "TemporaryDirectory", args: [] })
[44] node=814 method='write_pandas' var='parallel' inst=Some(Loop { cond: "i, chunk", body: [InstructionId(400), InstructionId(401), InstructionId(402), InstructionId(403), InstructionId(404), InstructionId(405), InstructionId(406), InstructionId(407)] })
[45] node=829 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("chunk"), callee: "chunk_helper", args: ["df", "chunk_size"] })
[46] node=828 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("chunk"), callee: "chunk_helper", args: ["df", "chunk_size"] })
[47] node=827 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("chunk_path"), callee: "os.path.join", args: ["tmp_folder", "f\"file{i}.txt\""] })
[48] node=826 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("chunk_path"), callee: "os.path.join", args: ["tmp_folder", "f\"file{i}.txt\""] })
[49] node=825 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "chunk.to_parquet", args: ["chunk_path", "compression=compression", "**kwargs"] })
[50] node=824 method='write_pandas' var='parallel' inst=Some(Call { dest: None, callee: "chunk.to_parquet", args: ["chunk_path", "compression=compression", "**kwargs"] })
[51] node=823 method='write_pandas' var='parallel' inst=Some(Call { dest: Some("upload_sql"), callee: "(\n                \"PUT /* Python:snowflake.connector.pandas_tools.write_pandas() */ \"\n                \"'file://{path}' ? PARALLEL={parallel}\"\n            ).format", args: ["path=chunk_path.replace(\"\\\\\", \"\\\\\\\\\").replace(\"'\", \"\\\\'\")", "parallel=parallel"] })
[52] node=822 method='write_pandas' var='upload_sql' inst=Some(Call { dest: Some("upload_sql"), callee: "(\n                \"PUT /* Python:snowflake.connector.pandas_tools.write_pandas() */ \"\n                \"'file://{path}' ? PARALLEL={parallel}\"\n            ).format", args: ["path=chunk_path.replace(\"\\\\\", \"\\\\\\\\\").replace(\"'\", \"\\\\'\")", "parallel=parallel"] })
[53] node=821 method='write_pandas' var='upload_sql' inst=Some(Assign { dest: "params", src: "(\"@\" + stage_location,)" })
[54] node=820 method='write_pandas' var='upload_sql' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"uploading files with '{upload_sql}', params: %s\"", "params"] })
[55] node=819 method='write_pandas' var='upload_sql' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"uploading files with '{upload_sql}', params: %s\"", "params"] })
[56] node=818 method='write_pandas' var='upload_sql' inst=Some(Call { dest: None, callee: "cursor.execute", args: ["upload_sql", "_is_internal=True", "_force_qmark_paramstyle=True", "params=params", "num_statements=1"] })
```

#### Code Context
```python
@pytest.mark.parametrize("auto_create_table", [True, False])
@pytest.mark.parametrize("index", [False])
def test_write_pandas_with_overwrite(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    quote_identifiers: bool,
    auto_create_table: bool,
    index: bool,
):
    """Tests whether overwriting table using a Pandas DataFrame works as expected."""
    random_table_name = random_string(5, "userspoints_")
    df1_data = [("John", 10), ("Jane", 20)]
    df1 = pandas.DataFrame(df1_data, columns=["name", "points"])
    df2_data = [("Dash", 50)]
    df2 = pandas.DataFrame(df2_data, columns=["name", "points"])
    df3_data = [(2022, "Jan", 10000), (2022, "Feb", 10220)]
    df3 = pandas.DataFrame(df3_data, columns=["year", "month", "revenue"])
    df4_data = [("Frank", 100)]
    df4 = pandas.DataFrame(df4_data, columns=["name%", "points"])

    if quote_identifiers:
```

### Case #13: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `snowflake/connector/compat.py (os.open)`
- **Reasoning / Description**: The engine taints the flags parameter of owner_rw_opener, which flows to os.open, triggering a false flow due to sink argument insensitivity.

#### Forensic Trace Chain
```text
[0] node=1201 method='owner_rw_opener' var='flags' inst=None
[1] node=1205 method='owner_rw_opener' var='os' inst=Some(Call { dest: None, callee: "os.open", args: ["path", "flags", "mode=0o600"] })
```

#### Code Context
```python
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations
```

### Case #14: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `FIELD_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `snowflake/connector/auth.py (session_parameters)`
- **Reasoning / Description**: The engine merges different keys in the session_parameters dictionary, causing an over-tainting propagation.

#### Forensic Trace Chain
```text
[0] node=1732 method='authenticate' var='session_parameters' inst=None
[1] node=1890 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"authenticate\""] })
[2] node=1889 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"authenticate\""] })
[3] node=1887 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "timeout is None", then_block: [InstructionId(773)], else_block: None })
[4] node=1885 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "session_parameters is None", then_block: [InstructionId(775)], else_block: None })
[5] node=1884 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("request_id"), callee: "str", args: ["uuid.uuid4()"] })
[6] node=1883 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("request_id"), callee: "str", args: ["uuid.uuid4()"] })
[7] node=1882 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "headers", src: "{\n            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,\n            HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,\n            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,\n        }" })
[8] node=1880 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "HTTP_HEADER_SERVICE_NAME in session_parameters", then_block: [InstructionId(779)], else_block: None })
[9] node=1879 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url", src: "\"/session/v1/login-request\"" })
[10] node=1878 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body_template"), callee: "Auth.base_auth_data", args: ["user", "account", "self._rest._connection.application", "self._rest._connection._internal_application_name", "self._rest._connection._internal_application_version", "self._rest._connection._ocsp_mode()", "self._rest._connection.login_timeout", "self._rest._connection._network_timeout", "self._rest._connection._socket_timeout"] })
[11] node=1877 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body_template"), callee: "Auth.base_auth_data", args: ["user", "account", "self._rest._connection.application", "self._rest._connection._internal_application_name", "self._rest._connection._internal_application_version", "self._rest._connection._ocsp_mode()", "self._rest._connection.login_timeout", "self._rest._connection._network_timeout", "self._rest._connection._socket_timeout"] })
[12] node=1876 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body"), callee: "copy.deepcopy", args: ["body_template"] })
[13] node=1875 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body"), callee: "copy.deepcopy", args: ["body_template"] })
[14] node=1874 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "auth_instance.update_body", args: ["body"] })
[15] node=1873 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "auth_instance.update_body", args: ["body"] })
[16] node=1872 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"account=%s, user=%s, database=%s, schema=%s, \"\n            \"warehouse=%s, role=%s, request_id=%s\"", "account", "user", "database", "schema", "warehouse", "role", "request_id"] })
[17] node=1871 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"account=%s, user=%s, database=%s, schema=%s, \"\n            \"warehouse=%s, role=%s, request_id=%s\"", "account", "user", "database", "schema", "warehouse", "role", "request_id"] })
[18] node=1870 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url_parameters", src: "{\"request_id\": request_id}" })
[19] node=1868 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "database is not None", then_block: [InstructionId(787)], else_block: None })
[20] node=1866 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "schema is not None", then_block: [InstructionId(789)], else_block: None })
[21] node=1864 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "warehouse is not None", then_block: [InstructionId(791)], else_block: None })
[22] node=1862 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "role is not None", then_block: [InstructionId(793)], else_block: None })
[23] node=1861 method='authenticate' var='session_parameters' inst=Some(Sanitizer { name: "urlencode(url_parameters)" })
[24] node=1860 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url", src: "url + \"?\" + urlencode(url_parameters)" })
[25] node=1856 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "passcode_in_password", then_block: [InstructionId(797)], else_block: Some([InstructionId(798), InstructionId(799)]) })
[26] node=1857 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "body[\"data\"][\"EXT_AUTHN_DUO_METHOD\"]", src: "\"passcode\"" })
[27] node=1854 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "session_parameters", then_block: [InstructionId(801)], else_block: None })
[28] node=1853 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"body['data']: %s\"", "{\n                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else \"******\"\n                for (k, v) in body[\"data\"].items()\n            }"] })
[29] node=1852 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"body['data']: %s\"", "{\n                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else \"******\"\n                for (k, v) in body[\"data\"].items()\n            }"] })
[30] node=1845 method='authenticate' var='session_parameters' inst=Some(Try { body: [InstructionId(804)], catches: [InstructionId(806), InstructionId(808)], finally: None })
[31] node=1847 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("ret"), callee: "self._rest._post_request", args: ["url", "headers", "json.dumps(body)", "socket_timeout=auth_instance._socket_timeout"] })
[32] node=1846 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("ret"), callee: "self._rest._post_request", args: ["url", "headers", "json.dumps(body)", "socket_timeout=auth_instance._socket_timeout"] })
[33] node=1844 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[34] node=1843 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[35] node=1787 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "ret[\"data\"] and ret[\"data\"].get(\"nextAction\") in (\n            \"EXT_AUTHN_DUO_ALL\",\n            \"EXT_AUTHN_DUO_PUSH_N_PASSCODE\",\n        )", then_block: [InstructionId(811), InstructionId(812), InstructionId(813), InstructionId(814), InstructionId(815), InstructionId(816), InstructionId(817), InstructionId(818), InstructionId(824), InstructionId(825), InstructionId(826), InstructionId(833)], else_block: Some([InstructionId(834), InstructionId(835), InstructionId(843)]) })
[36] node=1842 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[37] node=1841 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[38] node=1840 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "callable", args: ["password_callback"] })
[39] node=1839 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "callable", args: ["password_callback"] })
[40] node=1826 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "callable(password_callback)", then_block: [InstructionId(836), InstructionId(837), InstructionId(838), InstructionId(839), InstructionId(840), InstructionId(841), InstructionId(842)], else_block: None })
[41] node=1786 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"completed authentication\""] })
[42] node=1785 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"completed authentication\""] })
[43] node=1734 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "not ret[\"success\"]", then_block: [InstructionId(846), InstructionId(847), InstructionId(848), InstructionId(850), InstructionId(851), InstructionId(853), InstructionId(854)], else_block: Some([InstructionId(855), InstructionId(856), InstructionId(857), InstructionId(858), InstructionId(860), InstructionId(861), InstructionId(862), InstructionId(864), InstructionId(870), InstructionId(872), InstructionId(873), InstructionId(874)]) })
[44] node=1784 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"token\") is not None\n                    else \"NULL\"\n                )"] })
[45] node=1783 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"token\") is not None\n                    else \"NULL\"\n                )"] })
[46] node=1782 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"master_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"masterToken\") is not None\n                    else \"NULL\"\n                )"] })
[47] node=1781 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"master_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"masterToken\") is not None\n                    else \"NULL\"\n                )"] })
[48] node=1780 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"id_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"idToken\") is not None\n                    else \"NULL\"\n                )"] })
[49] node=1779 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"id_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"idToken\") is not None\n                    else \"NULL\"\n                )"] })
[50] node=1778 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"mfa_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"mfaToken\") is not None\n                    else \"NULL\"\n                )"] })
[51] node=1777 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"mfa_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"mfaToken\") is not None\n                    else \"NULL\"\n                )"] })
[52] node=1774 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "not ret[\"data\"]", then_block: [InstructionId(859)], else_block: None })
[53] node=1773 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self._rest.update_tokens", args: ["ret[\"data\"].get(\"token\")", "ret[\"data\"].get(\"masterToken\")", "master_validity_in_seconds=ret[\"data\"].get(\"masterValidityInSeconds\")", "id_token=ret[\"data\"].get(\"idToken\")", "mfa_token=ret[\"data\"].get(\"mfaToken\")"] })
[54] node=1772 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self._rest.update_tokens", args: ["ret[\"data\"].get(\"token\")", "ret[\"data\"].get(\"masterToken\")", "master_validity_in_seconds=ret[\"data\"].get(\"masterValidityInSeconds\")", "id_token=ret[\"data\"].get(\"idToken\")", "mfa_token=ret[\"data\"].get(\"mfaToken\")"] })
[55] node=1771 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self.write_temporary_credentials", args: ["self._rest._host", "user", "session_parameters", "ret"] })
[56] node=1474 method='write_temporary_credentials' var='session_parameters' inst=None
[57] node=1485 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL", "False"] })
[58] node=1484 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL", "False"] })
[59] node=1481 method='write_temporary_credentials' var='session_parameters' inst=Some(Branch { cond: "(\n            self._rest._connection.auth_class.consent_cache_id_token\n            and session_parameters.get(\n                PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL, False\n            )\n        )", then_block: [InstructionId(907)], else_block: None })
[60] node=1480 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_REQUEST_MFA_TOKEN", "False"] })
```

#### Code Context
```python
    from .storage_client import SnowflakeFileEncryptionMaterial
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

```

### Case #15: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `file_transfer_agent.py (encrypt_file)`
- **Reasoning / Description**: The engine seeds parameters of local compression/encryption helper functions as sources.

#### Forensic Trace Chain
```text
[0] node=1888 method='encrypt_file' var='in_filename' inst=None
[1] node=1902 method='encrypt_file' var='in_filename' inst=Some(Call { dest: Some("logger"), callee: "getLogger", args: ["__name__"] })
[2] node=1901 method='encrypt_file' var='in_filename' inst=Some(Call { dest: Some("logger"), callee: "getLogger", args: ["__name__"] })
[3] node=1900 method='encrypt_file' var='in_filename' inst=Some(Call { dest: Some("temp_output_fd, temp_output_file"), callee: "tempfile.mkstemp", args: ["text=False", "dir=tmp_dir", "prefix=os.path.basename(in_filename) + \"#\""] })
[4] node=1899 method='encrypt_file' var='in_filename' inst=Some(Call { dest: Some("temp_output_fd, temp_output_file"), callee: "tempfile.mkstemp", args: ["text=False", "dir=tmp_dir", "prefix=os.path.basename(in_filename) + \"#\""] })
[5] node=1898 method='encrypt_file' var='in_filename' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"unencrypted file: %s, temp file: %s, tmp_dir: %s\"", "in_filename", "temp_output_file", "tmp_dir"] })
[6] node=1897 method='encrypt_file' var='in_filename' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"unencrypted file: %s, temp file: %s, tmp_dir: %s\"", "in_filename", "temp_output_file", "tmp_dir"] })
[7] node=1896 method='encrypt_file' var='in_filename' inst=Some(Call { dest: Some("infile"), callee: "open", args: ["in_filename", "\"rb\""] })
[8] node=1895 method='encrypt_file' var='in_filename' inst=Some(Call { dest: Some("infile"), callee: "open", args: ["in_filename", "\"rb\""] })
```

#### Code Context
```python

    @staticmethod
    def encrypt_file(
        encryption_material: SnowflakeFileEncryptionMaterial,
        in_filename: str,
        chunk_size: int = 64 * kilobyte,
        tmp_dir: str | None = None,
    ) -> tuple[EncryptionMetadata, str]:
        """Encrypts a file in a temporary directory.

        Args:
            encryption_material: The encryption material for file.
            in_filename: The input file's name.
            chunk_size: The size of read chunks (Default value = block_size * 4 * 1024).
            tmp_dir: Temporary directory to use, optional (Default value = None).

        Returns:
            The encryption metadata and the encrypted file's location.
        """
        logger = getLogger(__name__)
```

### Case #16: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `FIELD_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `snowflake/connector/auth.py (session_parameters)`
- **Reasoning / Description**: The engine merges different keys in the session_parameters dictionary, causing an over-tainting propagation.

#### Forensic Trace Chain
```text
[0] node=1424 method='authenticate' var='session_parameters' inst=None
[1] node=1582 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"authenticate\""] })
[2] node=1581 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"authenticate\""] })
[3] node=1579 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "timeout is None", then_block: [InstructionId(867)], else_block: None })
[4] node=1577 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "session_parameters is None", then_block: [InstructionId(869)], else_block: None })
[5] node=1576 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("request_id"), callee: "str", args: ["uuid.uuid4()"] })
[6] node=1575 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("request_id"), callee: "str", args: ["uuid.uuid4()"] })
[7] node=1574 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "headers", src: "{\n            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,\n            HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,\n            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,\n        }" })
[8] node=1572 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "HTTP_HEADER_SERVICE_NAME in session_parameters", then_block: [InstructionId(873)], else_block: None })
[9] node=1571 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url", src: "\"/session/v1/login-request\"" })
[10] node=1570 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body_template"), callee: "Auth.base_auth_data", args: ["user", "account", "self._rest._connection.application", "self._rest._connection._internal_application_name", "self._rest._connection._internal_application_version", "self._rest._connection._ocsp_mode()", "self._rest._connection.login_timeout", "self._rest._connection._network_timeout", "self._rest._connection._socket_timeout"] })
[11] node=1569 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body_template"), callee: "Auth.base_auth_data", args: ["user", "account", "self._rest._connection.application", "self._rest._connection._internal_application_name", "self._rest._connection._internal_application_version", "self._rest._connection._ocsp_mode()", "self._rest._connection.login_timeout", "self._rest._connection._network_timeout", "self._rest._connection._socket_timeout"] })
[12] node=1568 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body"), callee: "copy.deepcopy", args: ["body_template"] })
[13] node=1567 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body"), callee: "copy.deepcopy", args: ["body_template"] })
[14] node=1566 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "auth_instance.update_body", args: ["body"] })
[15] node=1565 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "auth_instance.update_body", args: ["body"] })
[16] node=1564 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"account=%s, user=%s, database=%s, schema=%s, \"\n            \"warehouse=%s, role=%s, request_id=%s\"", "account", "user", "database", "schema", "warehouse", "role", "request_id"] })
[17] node=1563 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"account=%s, user=%s, database=%s, schema=%s, \"\n            \"warehouse=%s, role=%s, request_id=%s\"", "account", "user", "database", "schema", "warehouse", "role", "request_id"] })
[18] node=1562 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url_parameters", src: "{\"request_id\": request_id}" })
[19] node=1560 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "database is not None", then_block: [InstructionId(881)], else_block: None })
[20] node=1558 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "schema is not None", then_block: [InstructionId(883)], else_block: None })
[21] node=1556 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "warehouse is not None", then_block: [InstructionId(885)], else_block: None })
[22] node=1554 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "role is not None", then_block: [InstructionId(887)], else_block: None })
[23] node=1553 method='authenticate' var='session_parameters' inst=Some(Sanitizer { name: "urlencode(url_parameters)" })
[24] node=1552 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url", src: "url + \"?\" + urlencode(url_parameters)" })
[25] node=1548 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "passcode_in_password", then_block: [InstructionId(891)], else_block: Some([InstructionId(892), InstructionId(893)]) })
[26] node=1549 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "body[\"data\"][\"EXT_AUTHN_DUO_METHOD\"]", src: "\"passcode\"" })
[27] node=1546 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "session_parameters", then_block: [InstructionId(895)], else_block: None })
[28] node=1545 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"body['data']: %s\"", "{\n                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else \"******\"\n                for (k, v) in body[\"data\"].items()\n            }"] })
[29] node=1544 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"body['data']: %s\"", "{\n                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else \"******\"\n                for (k, v) in body[\"data\"].items()\n            }"] })
[30] node=1537 method='authenticate' var='session_parameters' inst=Some(Try { body: [InstructionId(898)], catches: [InstructionId(900), InstructionId(902)], finally: None })
[31] node=1539 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("ret"), callee: "self._rest._post_request", args: ["url", "headers", "json.dumps(body)", "socket_timeout=auth_instance._socket_timeout"] })
[32] node=1538 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("ret"), callee: "self._rest._post_request", args: ["url", "headers", "json.dumps(body)", "socket_timeout=auth_instance._socket_timeout"] })
[33] node=1536 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[34] node=1535 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[35] node=1479 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "ret[\"data\"] and ret[\"data\"].get(\"nextAction\") in (\n            \"EXT_AUTHN_DUO_ALL\",\n            \"EXT_AUTHN_DUO_PUSH_N_PASSCODE\",\n        )", then_block: [InstructionId(905), InstructionId(906), InstructionId(907), InstructionId(908), InstructionId(909), InstructionId(910), InstructionId(911), InstructionId(912), InstructionId(918), InstructionId(919), InstructionId(920), InstructionId(927)], else_block: Some([InstructionId(928), InstructionId(929), InstructionId(937)]) })
[36] node=1534 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[37] node=1533 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[38] node=1532 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "callable", args: ["password_callback"] })
[39] node=1531 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "callable", args: ["password_callback"] })
[40] node=1518 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "callable(password_callback)", then_block: [InstructionId(930), InstructionId(931), InstructionId(932), InstructionId(933), InstructionId(934), InstructionId(935), InstructionId(936)], else_block: None })
[41] node=1478 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"completed authentication\""] })
[42] node=1477 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"completed authentication\""] })
[43] node=1426 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "not ret[\"success\"]", then_block: [InstructionId(940), InstructionId(941), InstructionId(942), InstructionId(944), InstructionId(945), InstructionId(947), InstructionId(948)], else_block: Some([InstructionId(949), InstructionId(950), InstructionId(951), InstructionId(952), InstructionId(954), InstructionId(955), InstructionId(956), InstructionId(958), InstructionId(964), InstructionId(966), InstructionId(967), InstructionId(968)]) })
[44] node=1476 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"token\") is not None\n                    else \"NULL\"\n                )"] })
[45] node=1475 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"token\") is not None\n                    else \"NULL\"\n                )"] })
[46] node=1474 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"master_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"masterToken\") is not None\n                    else \"NULL\"\n                )"] })
[47] node=1473 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"master_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"masterToken\") is not None\n                    else \"NULL\"\n                )"] })
[48] node=1472 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"id_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"idToken\") is not None\n                    else \"NULL\"\n                )"] })
[49] node=1471 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"id_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"idToken\") is not None\n                    else \"NULL\"\n                )"] })
[50] node=1470 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"mfa_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"mfaToken\") is not None\n                    else \"NULL\"\n                )"] })
[51] node=1469 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"mfa_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"mfaToken\") is not None\n                    else \"NULL\"\n                )"] })
[52] node=1466 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "not ret[\"data\"]", then_block: [InstructionId(953)], else_block: None })
[53] node=1465 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self._rest.update_tokens", args: ["ret[\"data\"].get(\"token\")", "ret[\"data\"].get(\"masterToken\")", "master_validity_in_seconds=ret[\"data\"].get(\"masterValidityInSeconds\")", "id_token=ret[\"data\"].get(\"idToken\")", "mfa_token=ret[\"data\"].get(\"mfaToken\")"] })
[54] node=1464 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self._rest.update_tokens", args: ["ret[\"data\"].get(\"token\")", "ret[\"data\"].get(\"masterToken\")", "master_validity_in_seconds=ret[\"data\"].get(\"masterValidityInSeconds\")", "id_token=ret[\"data\"].get(\"idToken\")", "mfa_token=ret[\"data\"].get(\"mfaToken\")"] })
[55] node=1463 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self.write_temporary_credentials", args: ["self._rest._host", "user", "session_parameters", "ret"] })
[56] node=393 method='write_temporary_credentials' var='session_parameters' inst=None
[57] node=404 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL", "False"] })
[58] node=403 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL", "False"] })
[59] node=400 method='write_temporary_credentials' var='session_parameters' inst=Some(Branch { cond: "(\n            self._rest._connection.auth_class.consent_cache_id_token\n            and session_parameters.get(\n                PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL, False\n            )\n        )", then_block: [InstructionId(1001)], else_block: None })
[60] node=399 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_REQUEST_MFA_TOKEN", "False"] })
[61] node=398 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_REQUEST_MFA_TOKEN", "False"] })
```

#### Code Context
```python
    from .storage_client import SnowflakeFileEncryptionMaterial
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

```

### Case #17: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `file_transfer_agent.py (_open_intermediate_dst_path)`
- **Reasoning / Description**: The engine seeds the mode parameter of a local file helper method as a source, flowing directly into open.

#### Forensic Trace Chain
```text
[0] node=2179 method='_open_intermediate_dst_path' var='mode' inst=None
[1] node=2188 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.exists", args: [] })
[2] node=2187 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.exists", args: [] })
[3] node=2184 method='_open_intermediate_dst_path' var='mode' inst=Some(Branch { cond: "not self.intermediate_dst_path.exists()", then_block: [InstructionId(365)], else_block: None })
[4] node=2183 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.open", args: ["mode"] })
[5] node=2182 method='_open_intermediate_dst_path' var='mode' inst=Some(Call { dest: None, callee: "self.intermediate_dst_path.open", args: ["mode"] })
```

#### Code Context
```python
    from .storage_client import SnowflakeFileEncryptionMaterial
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

```

### Case #18: CWE-89 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-89
- **Commit**: `f3f9b666518d29c31a49384bbaa9a65889e72056`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_write_pandas.py (test parameter)`
- **Reasoning / Description**: The engine taints the test method parameter table_type/index, flowing into execute calls.

#### Forensic Trace Chain
```text
[0] node=225 method='test_write_pandas_table_type' var='table_type' inst=None
[1] node=246 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("cnx"), callee: "conn_cnx", args: [] })
[2] node=245 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("cnx"), callee: "conn_cnx", args: [] })
[3] node=244 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("table_name"), callee: "random_string", args: ["5", "\"write_pandas_table_type_\""] })
[4] node=243 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("table_name"), callee: "random_string", args: ["5", "\"write_pandas_table_type_\""] })
[5] node=242 method='test_write_pandas_table_type' var='table_type' inst=Some(Assign { dest: "drop_sql", src: "f\"DROP TABLE IF EXISTS {table_name}\"" })
[6] node=229 method='test_write_pandas_table_type' var='table_type' inst=Some(Try { body: [InstructionId(264), InstructionId(265), InstructionId(266), InstructionId(267), InstructionId(268), InstructionId(271)], catches: [], finally: Some([InstructionId(272)]) })
[7] node=241 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("success, _, _, _"), callee: "write_pandas", args: ["cnx", "sf_connector_version_df.get()", "table_name", "table_type=table_type", "auto_create_table=True"] })
[8] node=864 method='write_pandas' var='value' inst=None
[9] node=866 method='write_pandas' var='value' inst=Some(Return { val: Some("value") })
[10] node=865 method='write_pandas' var='value' inst=None
[11] node=240 method='test_write_pandas_table_type' var='cnx' inst=Some(Call { dest: Some("success, _, _, _"), callee: "write_pandas", args: ["cnx", "sf_connector_version_df.get()", "table_name", "table_type=table_type", "auto_create_table=True"] })
[12] node=239 method='test_write_pandas_table_type' var='cnx' inst=Some(Call { dest: None, callee: "cnx.cursor(DictCursor)\n                .execute(f\"show tables like '{table_name}'\")\n                .fetchall", args: [] })
[13] node=238 method='test_write_pandas_table_type' var='cnx' inst=Some(Call { dest: None, callee: "cnx.cursor(DictCursor)\n                .execute(f\"show tables like '{table_name}'\")\n                .fetchall", args: [] })
[14] node=237 method='test_write_pandas_table_type' var='cnx' inst=Some(Call { dest: None, callee: "cnx.cursor(DictCursor)\n                .execute", args: ["f\"show tables like '{table_name}'\""] })
```

#### Code Context
```python

@pytest.mark.parametrize("table_type", ["", "temp", "temporary", "transient"])
def test_write_pandas_table_type(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    table_type: str,
):
    with conn_cnx() as cnx:
        table_name = random_string(5, "write_pandas_table_type_")
        drop_sql = f"DROP TABLE IF EXISTS {table_name}"
        try:
            success, _, _, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                table_name,
                table_type=table_type,
                auto_create_table=True,
            )
            table_info = (
                cnx.cursor(DictCursor)
                .execute(f"show tables like '{table_name}'")
```

### Case #19: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `file_transfer_agent.py (encrypt_file)`
- **Reasoning / Description**: The engine seeds parameters of local compression/encryption helper functions as sources.

#### Forensic Trace Chain
```text
[0] node=1616 method='compress_file_with_gzip' var='file_name' inst=None
[1] node=1634 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: Some("base_name"), callee: "os.path.basename", args: ["file_name"] })
[2] node=1633 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: Some("base_name"), callee: "os.path.basename", args: ["file_name"] })
[3] node=1632 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: Some("gzip_file_name"), callee: "os.path.join", args: ["tmp_dir", "base_name + \"_c.gz\""] })
[4] node=1631 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: Some("gzip_file_name"), callee: "os.path.join", args: ["tmp_dir", "base_name + \"_c.gz\""] })
[5] node=1630 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"gzip file: %s, original file: %s\"", "gzip_file_name", "file_name"] })
[6] node=1629 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"gzip file: %s, original file: %s\"", "gzip_file_name", "file_name"] })
[7] node=1628 method='compress_file_with_gzip' var='file_name' inst=Some(Call { dest: Some("fr"), callee: "open", args: ["file_name", "\"rb\""] })
```

#### Code Context
```python
    from .storage_client import SnowflakeFileEncryptionMaterial
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

```

### Case #20: CWE-502 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-502
- **Commit**: `3769b43822357c3874c40f5e74068458c2dc79af`
- **Root Cause Category**: `FIELD_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `snowflake/connector/auth.py (session_parameters)`
- **Reasoning / Description**: The engine merges different keys in the session_parameters dictionary, causing an over-tainting propagation.

#### Forensic Trace Chain
```text
[0] node=1184 method='authenticate' var='session_parameters' inst=None
[1] node=1342 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"authenticate\""] })
[2] node=1341 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"authenticate\""] })
[3] node=1339 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "timeout is None", then_block: [InstructionId(867)], else_block: None })
[4] node=1337 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "session_parameters is None", then_block: [InstructionId(869)], else_block: None })
[5] node=1336 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("request_id"), callee: "str", args: ["uuid.uuid4()"] })
[6] node=1335 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("request_id"), callee: "str", args: ["uuid.uuid4()"] })
[7] node=1334 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "headers", src: "{\n            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,\n            HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,\n            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,\n        }" })
[8] node=1332 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "HTTP_HEADER_SERVICE_NAME in session_parameters", then_block: [InstructionId(873)], else_block: None })
[9] node=1331 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url", src: "\"/session/v1/login-request\"" })
[10] node=1330 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body_template"), callee: "Auth.base_auth_data", args: ["user", "account", "self._rest._connection.application", "self._rest._connection._internal_application_name", "self._rest._connection._internal_application_version", "self._rest._connection._ocsp_mode()", "self._rest._connection.login_timeout", "self._rest._connection._network_timeout", "self._rest._connection._socket_timeout"] })
[11] node=1329 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body_template"), callee: "Auth.base_auth_data", args: ["user", "account", "self._rest._connection.application", "self._rest._connection._internal_application_name", "self._rest._connection._internal_application_version", "self._rest._connection._ocsp_mode()", "self._rest._connection.login_timeout", "self._rest._connection._network_timeout", "self._rest._connection._socket_timeout"] })
[12] node=1328 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body"), callee: "copy.deepcopy", args: ["body_template"] })
[13] node=1327 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("body"), callee: "copy.deepcopy", args: ["body_template"] })
[14] node=1326 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "auth_instance.update_body", args: ["body"] })
[15] node=1325 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "auth_instance.update_body", args: ["body"] })
[16] node=1324 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"account=%s, user=%s, database=%s, schema=%s, \"\n            \"warehouse=%s, role=%s, request_id=%s\"", "account", "user", "database", "schema", "warehouse", "role", "request_id"] })
[17] node=1323 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"account=%s, user=%s, database=%s, schema=%s, \"\n            \"warehouse=%s, role=%s, request_id=%s\"", "account", "user", "database", "schema", "warehouse", "role", "request_id"] })
[18] node=1322 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url_parameters", src: "{\"request_id\": request_id}" })
[19] node=1320 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "database is not None", then_block: [InstructionId(881)], else_block: None })
[20] node=1318 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "schema is not None", then_block: [InstructionId(883)], else_block: None })
[21] node=1316 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "warehouse is not None", then_block: [InstructionId(885)], else_block: None })
[22] node=1314 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "role is not None", then_block: [InstructionId(887)], else_block: None })
[23] node=1313 method='authenticate' var='session_parameters' inst=Some(Sanitizer { name: "urlencode(url_parameters)" })
[24] node=1312 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "url", src: "url + \"?\" + urlencode(url_parameters)" })
[25] node=1308 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "passcode_in_password", then_block: [InstructionId(891)], else_block: Some([InstructionId(892), InstructionId(893)]) })
[26] node=1309 method='authenticate' var='session_parameters' inst=Some(Assign { dest: "body[\"data\"][\"EXT_AUTHN_DUO_METHOD\"]", src: "\"passcode\"" })
[27] node=1306 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "session_parameters", then_block: [InstructionId(895)], else_block: None })
[28] node=1305 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"body['data']: %s\"", "{\n                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else \"******\"\n                for (k, v) in body[\"data\"].items()\n            }"] })
[29] node=1304 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"body['data']: %s\"", "{\n                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else \"******\"\n                for (k, v) in body[\"data\"].items()\n            }"] })
[30] node=1297 method='authenticate' var='session_parameters' inst=Some(Try { body: [InstructionId(898)], catches: [InstructionId(900), InstructionId(902)], finally: None })
[31] node=1299 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("ret"), callee: "self._rest._post_request", args: ["url", "headers", "json.dumps(body)", "socket_timeout=auth_instance._socket_timeout"] })
[32] node=1298 method='authenticate' var='session_parameters' inst=Some(Call { dest: Some("ret"), callee: "self._rest._post_request", args: ["url", "headers", "json.dumps(body)", "socket_timeout=auth_instance._socket_timeout"] })
[33] node=1296 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[34] node=1295 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[35] node=1239 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "ret[\"data\"] and ret[\"data\"].get(\"nextAction\") in (\n            \"EXT_AUTHN_DUO_ALL\",\n            \"EXT_AUTHN_DUO_PUSH_N_PASSCODE\",\n        )", then_block: [InstructionId(905), InstructionId(906), InstructionId(907), InstructionId(908), InstructionId(909), InstructionId(910), InstructionId(911), InstructionId(912), InstructionId(918), InstructionId(919), InstructionId(920), InstructionId(927)], else_block: Some([InstructionId(928), InstructionId(929), InstructionId(937)]) })
[36] node=1294 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[37] node=1293 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "ret[\"data\"].get", args: ["\"nextAction\""] })
[38] node=1292 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "callable", args: ["password_callback"] })
[39] node=1291 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "callable", args: ["password_callback"] })
[40] node=1278 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "callable(password_callback)", then_block: [InstructionId(930), InstructionId(931), InstructionId(932), InstructionId(933), InstructionId(934), InstructionId(935), InstructionId(936)], else_block: None })
[41] node=1238 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"completed authentication\""] })
[42] node=1237 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"completed authentication\""] })
[43] node=1186 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "not ret[\"success\"]", then_block: [InstructionId(940), InstructionId(941), InstructionId(942), InstructionId(944), InstructionId(945), InstructionId(947), InstructionId(948)], else_block: Some([InstructionId(949), InstructionId(950), InstructionId(951), InstructionId(952), InstructionId(954), InstructionId(955), InstructionId(956), InstructionId(958), InstructionId(964), InstructionId(966), InstructionId(967), InstructionId(968)]) })
[44] node=1236 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"token\") is not None\n                    else \"NULL\"\n                )"] })
[45] node=1235 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"token\") is not None\n                    else \"NULL\"\n                )"] })
[46] node=1234 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"master_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"masterToken\") is not None\n                    else \"NULL\"\n                )"] })
[47] node=1233 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"master_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"masterToken\") is not None\n                    else \"NULL\"\n                )"] })
[48] node=1232 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"id_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"idToken\") is not None\n                    else \"NULL\"\n                )"] })
[49] node=1231 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"id_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"idToken\") is not None\n                    else \"NULL\"\n                )"] })
[50] node=1230 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"mfa_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"mfaToken\") is not None\n                    else \"NULL\"\n                )"] })
[51] node=1229 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "logger.debug", args: ["\"mfa_token = %s\"", "(\n                    \"******\"\n                    if ret[\"data\"] and ret[\"data\"].get(\"mfaToken\") is not None\n                    else \"NULL\"\n                )"] })
[52] node=1226 method='authenticate' var='session_parameters' inst=Some(Branch { cond: "not ret[\"data\"]", then_block: [InstructionId(953)], else_block: None })
[53] node=1225 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self._rest.update_tokens", args: ["ret[\"data\"].get(\"token\")", "ret[\"data\"].get(\"masterToken\")", "master_validity_in_seconds=ret[\"data\"].get(\"masterValidityInSeconds\")", "id_token=ret[\"data\"].get(\"idToken\")", "mfa_token=ret[\"data\"].get(\"mfaToken\")"] })
[54] node=1224 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self._rest.update_tokens", args: ["ret[\"data\"].get(\"token\")", "ret[\"data\"].get(\"masterToken\")", "master_validity_in_seconds=ret[\"data\"].get(\"masterValidityInSeconds\")", "id_token=ret[\"data\"].get(\"idToken\")", "mfa_token=ret[\"data\"].get(\"mfaToken\")"] })
[55] node=1223 method='authenticate' var='session_parameters' inst=Some(Call { dest: None, callee: "self.write_temporary_credentials", args: ["self._rest._host", "user", "session_parameters", "ret"] })
[56] node=1696 method='write_temporary_credentials' var='session_parameters' inst=None
[57] node=1707 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL", "False"] })
[58] node=1706 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL", "False"] })
[59] node=1703 method='write_temporary_credentials' var='session_parameters' inst=Some(Branch { cond: "(\n            self._rest._connection.auth_class.consent_cache_id_token\n            and session_parameters.get(\n                PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL, False\n            )\n        )", then_block: [InstructionId(1001)], else_block: None })
[60] node=1702 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_REQUEST_MFA_TOKEN", "False"] })
[61] node=1701 method='write_temporary_credentials' var='session_parameters' inst=Some(Call { dest: None, callee: "session_parameters.get", args: ["PARAMETER_CLIENT_REQUEST_MFA_TOKEN", "False"] })
```

#### Code Context
```python
    from .storage_client import SnowflakeFileEncryptionMaterial
from .compat import PKCS5_OFFSET, PKCS5_PAD, PKCS5_UNPAD
from .constants import UTF8, EncryptionMetadata, MaterialDescriptor, kilobyte
from .file_util import owner_rw_opener
from .util_text import random_string
from __future__ import annotations
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from logging import getLogger
from typing import IO, TYPE_CHECKING
import base64
import json
import os
import tempfile

```

### Case #21: CWE-89 in snowflake-connector-python
- **Repository**: [https://github.com/snowflakedb/snowflake-connector-python](https://github.com/snowflakedb/snowflake-connector-python)
- **CWE**: CWE-89
- **Commit**: `f3f9b666518d29c31a49384bbaa9a65889e72056`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `test_write_pandas.py (test parameter)`
- **Reasoning / Description**: The engine taints the test method parameter table_type/index, flowing into execute calls.

#### Forensic Trace Chain
```text
[0] node=328 method='test_write_pandas_table_type' var='table_type' inst=None
[1] node=349 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("cnx"), callee: "conn_cnx", args: [] })
[2] node=348 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("cnx"), callee: "conn_cnx", args: [] })
[3] node=347 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("table_name"), callee: "random_string", args: ["5", "\"write_pandas_table_type_\""] })
[4] node=346 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("table_name"), callee: "random_string", args: ["5", "\"write_pandas_table_type_\""] })
[5] node=345 method='test_write_pandas_table_type' var='table_type' inst=Some(Assign { dest: "drop_sql", src: "f\"DROP TABLE IF EXISTS {table_name}\"" })
[6] node=332 method='test_write_pandas_table_type' var='table_type' inst=Some(Try { body: [InstructionId(93), InstructionId(94), InstructionId(95), InstructionId(96), InstructionId(97), InstructionId(100)], catches: [], finally: Some([InstructionId(101)]) })
[7] node=344 method='test_write_pandas_table_type' var='table_type' inst=Some(Call { dest: Some("success, _, _, _"), callee: "write_pandas", args: ["cnx", "sf_connector_version_df.get()", "table_name", "table_type=table_type", "auto_create_table=True"] })
[8] node=45 method='write_pandas' var='database' inst=None
[9] node=197 method='write_pandas' var='database' inst=Some(Branch { cond: "database is not None and schema is None", then_block: [InstructionId(371)], else_block: None })
[10] node=196 method='write_pandas' var='database' inst=Some(Assign { dest: "compression_map", src: "{\"gzip\": \"auto\", \"snappy\": \"snappy\"}" })
[11] node=195 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "compression_map.keys", args: [] })
[12] node=194 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "compression_map.keys", args: [] })
[13] node=192 method='write_pandas' var='database' inst=Some(Branch { cond: "compression not in compression_map.keys()", then_block: [InstructionId(375)], else_block: None })
[14] node=191 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "conn._session_parameters.get", args: ["_PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING", "False"] })
[15] node=190 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "conn._session_parameters.get", args: ["_PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING", "False"] })
[16] node=189 method='write_pandas' var='database' inst=Some(Assign { dest: "_use_scoped_temp_object", src: "(\n        conn._session_parameters.get(\n            _PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING, False\n        )\n        if conn._session_parameters\n        else False\n    )" })
[17] node=185 method='write_pandas' var='database' inst=Some(Branch { cond: "create_temp_table", then_block: [InstructionId(379), InstructionId(380)], else_block: None })
[18] node=184 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "table_type.lower", args: [] })
[19] node=183 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "table_type.lower", args: [] })
[20] node=181 method='write_pandas' var='database' inst=Some(Branch { cond: "table_type and table_type.lower() not in [\"temp\", \"temporary\", \"transient\"]", then_block: [InstructionId(383)], else_block: None })
[21] node=178 method='write_pandas' var='database' inst=Some(Branch { cond: "chunk_size is None", then_block: [InstructionId(385)], else_block: None })
[22] node=177 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "isinstance", args: ["df.index", "pandas.RangeIndex"] })
[23] node=176 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "isinstance", args: ["df.index", "pandas.RangeIndex"] })
[24] node=173 method='write_pandas' var='database' inst=Some(Branch { cond: "not (\n        isinstance(df.index, pandas.RangeIndex)\n        and 1 == df.index.step\n        and 0 == df.index.start\n    )", then_block: [InstructionId(388)], else_block: None })
[25] node=172 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "any", args: ["[pandas.api.types.is_datetime64tz_dtype(df[c]) for c in df.columns]"] })
[26] node=171 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "any", args: ["[pandas.api.types.is_datetime64tz_dtype(df[c]) for c in df.columns]"] })
[27] node=170 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "pandas.api.types.is_datetime64tz_dtype", args: ["df[c]"] })
[28] node=169 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "pandas.api.types.is_datetime64tz_dtype", args: ["df[c]"] })
[29] node=166 method='write_pandas' var='database' inst=Some(Branch { cond: "not use_logical_type and any(\n        [pandas.api.types.is_datetime64tz_dtype(df[c]) for c in df.columns]\n    )", then_block: [InstructionId(392)], else_block: None })
[30] node=163 method='write_pandas' var='database' inst=Some(Branch { cond: "use_logical_type is None", then_block: [InstructionId(394)], else_block: Some([InstructionId(395)]) })
[31] node=164 method='write_pandas' var='database' inst=Some(Assign { dest: "sql_use_logical_type", src: "\"\"" })
[32] node=162 method='write_pandas' var='database' inst=Some(Call { dest: Some("cursor"), callee: "conn.cursor", args: [] })
[33] node=161 method='write_pandas' var='database' inst=Some(Call { dest: Some("cursor"), callee: "conn.cursor", args: [] })
[34] node=160 method='write_pandas' var='database' inst=Some(Call { dest: Some("stage_location"), callee: "_create_temp_stage", args: ["cursor", "database", "schema", "quote_identifiers", "compression", "auto_create_table", "overwrite", "_use_scoped_temp_object"] })
[35] node=159 method='write_pandas' var='database' inst=Some(Call { dest: Some("stage_location"), callee: "_create_temp_stage", args: ["cursor", "database", "schema", "quote_identifiers", "compression", "auto_create_table", "overwrite", "_use_scoped_temp_object"] })
[36] node=158 method='write_pandas' var='database' inst=Some(Call { dest: Some("tmp_folder"), callee: "TemporaryDirectory", args: [] })
[37] node=157 method='write_pandas' var='database' inst=Some(Call { dest: Some("tmp_folder"), callee: "TemporaryDirectory", args: [] })
[38] node=141 method='write_pandas' var='database' inst=Some(Loop { cond: "i, chunk", body: [InstructionId(400), InstructionId(401), InstructionId(402), InstructionId(403), InstructionId(404), InstructionId(405), InstructionId(406), InstructionId(407)] })
[39] node=131 method='write_pandas' var='database' inst=Some(Branch { cond: "quote_identifiers", then_block: [InstructionId(409), InstructionId(410), InstructionId(411), InstructionId(412)], else_block: Some([InstructionId(413), InstructionId(414)]) })
[40] node=140 method='write_pandas' var='database' inst=Some(Assign { dest: "quote", src: "\"\"" })
[41] node=139 method='write_pandas' var='database' inst=Some(Call { dest: Some("snowflake_column_names"), callee: "list", args: ["df.columns"] })
[42] node=138 method='write_pandas' var='database' inst=Some(Call { dest: Some("snowflake_column_names"), callee: "list", args: ["df.columns"] })
[43] node=130 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "f\"{quote},{quote}\".join", args: ["snowflake_column_names"] })
[44] node=129 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "f\"{quote},{quote}\".join", args: ["snowflake_column_names"] })
[45] node=128 method='write_pandas' var='database' inst=Some(Assign { dest: "columns", src: "quote + f\"{quote},{quote}\".join(snowflake_column_names) + quote" })
[46] node=127 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "object_type.upper", args: [] })
[47] node=126 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "object_type.upper", args: [] })
[48] node=125 method='write_pandas' var='database' inst=Some(Assign { dest: "drop_sql", src: "f\"DROP {object_type.upper()} IF EXISTS identifier(?) /* Python:snowflake.connector.pandas_tools.write_pandas() */\"" })
[49] node=124 method='write_pandas' var='database' inst=Some(Assign { dest: "params", src: "(name,)" })
[50] node=123 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"dropping {object_type} with '{drop_sql}'. params: %s\"", "params"] })
[51] node=122 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"dropping {object_type} with '{drop_sql}'. params: %s\"", "params"] })
[52] node=121 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "cursor.execute", args: ["drop_sql", "_is_internal=True", "_force_qmark_paramstyle=True", "params=params", "num_statements=1"] })
[53] node=120 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "cursor.execute", args: ["drop_sql", "_is_internal=True", "_force_qmark_paramstyle=True", "params=params", "num_statements=1"] })
[54] node=89 method='write_pandas' var='database' inst=Some(Branch { cond: "auto_create_table or overwrite", then_block: [InstructionId(423), InstructionId(424), InstructionId(425), InstructionId(426), InstructionId(427), InstructionId(428), InstructionId(429), InstructionId(430), InstructionId(431), InstructionId(432), InstructionId(433), InstructionId(434), InstructionId(435), InstructionId(436), InstructionId(437)], else_block: Some([InstructionId(438), InstructionId(439), InstructionId(440)]) })
[55] node=119 method='write_pandas' var='database' inst=Some(Call { dest: Some("target_table_location"), callee: "build_location_helper", args: ["database=database", "schema=schema", "name=table_name", "quote_identifiers=quote_identifiers"] })
[56] node=118 method='write_pandas' var='database' inst=Some(Call { dest: Some("target_table_location"), callee: "build_location_helper", args: ["database=database", "schema=schema", "name=table_name", "quote_identifiers=quote_identifiers"] })
[57] node=117 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "\",$1:\".join", args: [] })
[58] node=116 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "\",$1:\".join", args: [] })
[59] node=115 method='write_pandas' var='database' inst=Some(Assign { dest: "parquet_columns", src: "\"$1:\" + \",$1:\".join(\n            f\"{quote}{snowflake_col}{quote}\" for snowflake_col in snowflake_column_names\n        )" })
[60] node=60 method='write_pandas' var='database' inst=Some(Try { body: [InstructionId(446), InstructionId(447), InstructionId(448), InstructionId(449), InstructionId(450), InstructionId(457)], catches: [InstructionId(460)], finally: Some([InstructionId(461), InstructionId(462)]) })
[61] node=78 method='write_pandas' var='database' inst=Some(Branch { cond: "overwrite and (not auto_create_table)", then_block: [InstructionId(442), InstructionId(443), InstructionId(444), InstructionId(445)], else_block: None })
[62] node=77 method='write_pandas' var='database' inst=Some(Assign { dest: "copy_into_sql", src: "(\n            f\"COPY INTO identifier(?) /* Python:snowflake.connector.pandas_tools.write_pandas() */ \"\n            f\"({columns}) \"\n            f\"FROM (SELECT {parquet_columns} FROM @{stage_location}) \"\n            f\"FILE_FORMAT=(\"\n            f\"TYPE=PARQUET \"\n            f\"COMPRESSION={compression_map[compression]}\"\n            f\"{' BINARY_AS_TEXT=FALSE' if auto_create_table or overwrite else ''}\"\n            f\"{sql_use_logical_type}\"\n            f\") \"\n            f\"PURGE=TRUE ON_ERROR=?\"\n        )" })
[63] node=76 method='write_pandas' var='database' inst=Some(Assign { dest: "params", src: "(target_table_location, on_error)" })
[64] node=75 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"copying into with '{copy_into_sql}'. params: %s\"", "params"] })
[65] node=74 method='write_pandas' var='database' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"copying into with '{copy_into_sql}'. params: %s\"", "params"] })
[66] node=73 method='write_pandas' var='database' inst=Some(Call { dest: Some("copy_results"), callee: "cursor.execute(\n            copy_into_sql,\n            _is_internal=True,\n            _force_qmark_paramstyle=True,\n            params=params,\n            num_statements=1,\n        ).fetchall", args: [] })
[67] node=72 method='write_pandas' var='database' inst=Some(Call { dest: Some("copy_results"), callee: "cursor.execute(\n            copy_into_sql,\n            _is_internal=True,\n            _force_qmark_paramstyle=True,\n            params=params,\n            num_statements=1,\n        ).fetchall", args: [] })
[68] node=61 method='write_pandas' var='database' inst=Some(Branch { cond: "overwrite and auto_create_table", then_block: [InstructionId(451), InstructionId(452), InstructionId(453), InstructionId(454), InstructionId(455), InstructionId(456)], else_block: None })
[69] node=71 method='write_pandas' var='database' inst=Some(Call { dest: Some("original_table_location"), callee: "build_location_helper", args: ["database=database", "schema=schema", "name=table_name", "quote_identifiers=quote_identifiers"] })
[70] node=322 method='build_location_helper' var='database' inst=None
[71] node=325 method='build_location_helper' var='database' inst=Some(Branch { cond: "quote_identifiers", then_block: [InstructionId(335)], else_block: Some([InstructionId(336)]) })
[72] node=326 method='build_location_helper' var='location' inst=Some(Assign { dest: "location", src: "(\n            (('\"' + database + '\".') if database else \"\")\n            + (('\"' + schema + '\".') if schema else \"\")\n            + ('\"' + name + '\"')\n        )" })
[73] node=324 method='build_location_helper' var='location' inst=Some(Return { val: Some("location") })
[74] node=323 method='build_location_helper' var='location' inst=None
[75] node=70 method='write_pandas' var='original_table_location' inst=Some(Call { dest: Some("original_table_location"), callee: "build_location_helper", args: ["database=database", "schema=schema", "name=table_name", "quote_identifiers=quote_identifiers"] })
[76] node=69 method='write_pandas' var='original_table_location' inst=Some(Call { dest: None, callee: "drop_object", args: ["original_table_location", "\"table\""] })
[77] node=68 method='write_pandas' var='original_table_location' inst=Some(Call { dest: None, callee: "drop_object", args: ["original_table_location", "\"table\""] })
[78] node=67 method='write_pandas' var='original_table_location' inst=Some(Assign { dest: "rename_table_sql", src: "\"ALTER TABLE identifier(?) RENAME TO identifier(?) /* Python:snowflake.connector.pandas_tools.write_pandas() */\"" })
[79] node=66 method='write_pandas' var='params' inst=Some(Assign { dest: "params", src: "(target_table_location, original_table_location)" })
[80] node=65 method='write_pandas' var='params' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"rename table with '{rename_table_sql}'. params: %s\"", "params"] })
[81] node=64 method='write_pandas' var='params' inst=Some(Call { dest: None, callee: "logger.debug", args: ["f\"rename table with '{rename_table_sql}'. params: %s\"", "params"] })
[82] node=63 method='write_pandas' var='params' inst=Some(Call { dest: None, callee: "cursor.execute", args: ["rename_table_sql", "_is_internal=True", "_force_qmark_paramstyle=True", "params=params", "num_statements=1"] })
```

#### Code Context
```python

@pytest.mark.parametrize("table_type", ["", "temp", "temporary", "transient"])
def test_write_pandas_table_type(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    table_type: str,
):
    with conn_cnx() as cnx:
        table_name = random_string(5, "write_pandas_table_type_")
        drop_sql = f"DROP TABLE IF EXISTS {table_name}"
        try:
            success, _, _, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                table_name,
                table_type=table_type,
                auto_create_table=True,
            )
            table_info = (
                cnx.cursor(DictCursor)
                .execute(f"show tables like '{table_name}'")
```

### Case #22: CWE-78 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-78
- **Commit**: `5ed9478fdef96a06eeec9093f9e768c97b094af3`
- **Root Cause Category**: `MOCK_HELPER_FLOW_LEAKAGE`
- **First Location of Over-Tainting**: `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)`
- **Reasoning / Description**: The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation.

#### Forensic Trace Chain
```text
[0] node=819 method='mkdirs' var='hdfs_path' inst=None
[1] node=822 method='mkdirs' var='hdfs_path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["hdfs_path", "'w'"] })
[2] node=821 method='mkdirs' var='hdfs_path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["hdfs_path", "'w'"] })
```

#### Code Context
```python
from .assert_transformer import AssertTransformer  # noqa: F401
from .ast_transformer import DygraphToStaticAst  # noqa: F401
from .convert_call_func import convert_call as Call  # noqa: F401
from .convert_operators import (  # noqa: F401
    convert_assert as Assert,
    convert_attr as Attr,
    convert_ifelse as IfElse,
    convert_len as Len,
    convert_load as Ld,
    convert_logical_and as And,
    convert_logical_not as Not,
    convert_logical_or as Or,
    convert_pop as Pop,
    convert_shape as Shape,
    convert_var_dtype as AsDtype,
```

### Case #23: CWE-78 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-78
- **Commit**: `49bec176053595975c1941cff9749c55f7203ea9`
- **Root Cause Category**: `MOCK_HELPER_FLOW_LEAKAGE`
- **First Location of Over-Tainting**: `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)`
- **Reasoning / Description**: The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation.

#### Forensic Trace Chain
```text
[0] node=177 method='upload' var='local_path' inst=None
[1] node=181 method='upload' var='cmd' inst=Some(Assign { dest: "cmd", src: "self._hadoop_home + \"/bin/hadoop dfs -put \" + local_path + \" \" + hdfs_path" })
[2] node=180 method='upload' var='cmd' inst=Some(Call { dest: None, callee: "subprocess.run", args: ["cmd", "shell=True"] })
```

#### Code Context
```python
            from paddle.incubate.distributed.fleet.parameter_server.distribute_transpiler import (
                fleet as fleet_transpiler,
            )
            from paddle.incubate.distributed.fleet.parameter_server.pslib import (
                fleet as fleet_pslib,
            )
from . import utils
from paddle import base
from paddle.base.log_helper import get_logger
from paddle.distributed.fleet.utils.fs import HDFSClient
import collections
import json
import logging
import math
import numpy as np
```

### Case #24: CWE-78 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-78
- **Commit**: `5ed9478fdef96a06eeec9093f9e768c97b094af3`
- **Root Cause Category**: `MOCK_HELPER_FLOW_LEAKAGE`
- **First Location of Over-Tainting**: `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)`
- **Reasoning / Description**: The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation.

#### Forensic Trace Chain
```text
[0] node=135 method='makedirs' var='hdfs_path' inst=None
[1] node=138 method='makedirs' var='hdfs_path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["hdfs_path", "'w'"] })
[2] node=137 method='makedirs' var='hdfs_path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["hdfs_path", "'w'"] })
```

#### Code Context
```python
from .assert_transformer import AssertTransformer  # noqa: F401
from .ast_transformer import DygraphToStaticAst  # noqa: F401
from .convert_call_func import convert_call as Call  # noqa: F401
from .convert_operators import (  # noqa: F401
    convert_assert as Assert,
    convert_attr as Attr,
    convert_ifelse as IfElse,
    convert_len as Len,
    convert_load as Ld,
    convert_logical_and as And,
    convert_logical_not as Not,
    convert_logical_or as Or,
    convert_pop as Pop,
    convert_shape as Shape,
    convert_var_dtype as AsDtype,
```

### Case #25: CWE-78 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-78
- **Commit**: `5ed9478fdef96a06eeec9093f9e768c97b094af3`
- **Root Cause Category**: `MOCK_HELPER_FLOW_LEAKAGE`
- **First Location of Over-Tainting**: `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)`
- **Reasoning / Description**: The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation.

#### Forensic Trace Chain
```text
[0] node=409 method='upload' var='local_path' inst=None
[1] node=413 method='upload' var='cmd' inst=Some(Assign { dest: "cmd", src: "self._hadoop_home + \"/bin/hadoop dfs -put \" + local_path + \" \" + hdfs_path" })
[2] node=412 method='upload' var='cmd' inst=Some(Call { dest: None, callee: "subprocess.run", args: ["cmd", "shell=True"] })
```

#### Code Context
```python
from .assert_transformer import AssertTransformer  # noqa: F401
from .ast_transformer import DygraphToStaticAst  # noqa: F401
from .convert_call_func import convert_call as Call  # noqa: F401
from .convert_operators import (  # noqa: F401
    convert_assert as Assert,
    convert_attr as Attr,
    convert_ifelse as IfElse,
    convert_len as Len,
    convert_load as Ld,
    convert_logical_and as And,
    convert_logical_not as Not,
    convert_logical_or as Or,
    convert_pop as Pop,
    convert_shape as Shape,
    convert_var_dtype as AsDtype,
```

### Case #26: CWE-22 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-22
- **Commit**: `5c50d1a8b97b310cbc36560ec36d8377d6f29d7c`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `paddle/dataset/common.py (split)`
- **Reasoning / Description**: The parameter suffix of the split helper function is seeded as a source, flowing directly into open.

#### Forensic Trace Chain
```text
[0] node=497 method='split' var='suffix' inst=None
[1] node=521 method='split' var='suffix' inst=Some(Call { dest: None, callee: "callable", args: ["dumper"] })
[2] node=520 method='split' var='suffix' inst=Some(Call { dest: None, callee: "callable", args: ["dumper"] })
[3] node=518 method='split' var='suffix' inst=Some(Branch { cond: "not callable(dumper)", then_block: [InstructionId(51)], else_block: None })
[4] node=517 method='split' var='suffix' inst=Some(Assign { dest: "lines", src: "[]" })
[5] node=516 method='split' var='suffix' inst=Some(Assign { dest: "indx_f", src: "0" })
[6] node=504 method='split' var='suffix' inst=Some(Loop { cond: "i, d", body: [InstructionId(55), InstructionId(56), InstructionId(61)] })
[7] node=499 method='split' var='suffix' inst=Some(Branch { cond: "lines", then_block: [InstructionId(63), InstructionId(64)], else_block: None })
[8] node=503 method='split' var='suffix' inst=Some(Call { dest: Some("f"), callee: "open", args: ["suffix % indx_f", "\"w\""] })
```

#### Code Context
```python


def split(reader, line_count, suffix="%05d.pickle", dumper=pickle.dump):
    """
    you can call the function as:

    split(paddle.dataset.cifar.train10(), line_count=1000,
        suffix="imikolov-train-%05d.pickle")

    the output files as:

    |-imikolov-train-00000.pickle
    |-imikolov-train-00001.pickle
    |- ...
    |-imikolov-train-00480.pickle

    :param reader: is a reader creator
    :param line_count: line count for each file
    :param suffix: the suffix for the output files, should contain "%d"
                means the id for each file. Default is "%05d.pickle"
```

### Case #27: CWE-78 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-78
- **Commit**: `4c0888d7b8f10405e2e79adc41c224264f93e816`
- **Root Cause Category**: `MOCK_HELPER_FLOW_LEAKAGE`
- **First Location of Over-Tainting**: `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)`
- **Reasoning / Description**: The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation.

#### Forensic Trace Chain
```text
[0] node=549 method='mkdirs' var='hdfs_path' inst=None
[1] node=552 method='mkdirs' var='hdfs_path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["hdfs_path", "'w'"] })
```

#### Code Context
```python
        from pathlib import Path
        from pathlib2 import Path
from paddle.utils.download import get_path_from_url
import os
import shutil
import sys
import zipfile

VAR_DEPENDENCY = 'dependencies'
MODULE_HUBCONF = 'hubconf.py'
HUB_DIR = os.path.expanduser(os.path.join('~', '.cache', 'paddle', 'hub'))


def _remove_if_exists(path):
    if os.path.exists(path):
```

### Case #28: CWE-78 in Paddle
- **Repository**: [https://github.com/PaddlePaddle/Paddle](https://github.com/PaddlePaddle/Paddle)
- **CWE**: CWE-78
- **Commit**: `4c0888d7b8f10405e2e79adc41c224264f93e816`
- **Root Cause Category**: `MOCK_HELPER_FLOW_LEAKAGE`
- **First Location of Over-Tainting**: `paddle/distributed/fleet/utils/fs.py (HDFSClient stub)`
- **Reasoning / Description**: The flow is completely self-contained within the HDFSClient mock helper stub, which is loaded during validation.

#### Forensic Trace Chain
```text
[0] node=288 method='makedirs' var='hdfs_path' inst=None
[1] node=291 method='makedirs' var='hdfs_path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["hdfs_path", "'w'"] })
```

#### Code Context
```python
        from pathlib import Path
        from pathlib2 import Path
from paddle.utils.download import get_path_from_url
import os
import shutil
import sys
import zipfile

VAR_DEPENDENCY = 'dependencies'
MODULE_HUBCONF = 'hubconf.py'
HUB_DIR = os.path.expanduser(os.path.join('~', '.cache', 'paddle', 'hub'))


def _remove_if_exists(path):
    if os.path.exists(path):
```

### Case #29: CWE-918 in ray
- **Repository**: [https://github.com/ray-project/ray](https://github.com/ray-project/ray)
- **CWE**: CWE-918
- **Commit**: `978947083b1e192dba61ef653c863b11d56b0936`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `ray/scripts.py (_ray_start_hook)`
- **Reasoning / Description**: Parameter ray_params in _ray_start_hook helper is seeded as a source.

#### Forensic Trace Chain
```text
[0] node=1057 method='_ray_start_hook' var='ray_params' inst=None
[1] node=1064 method='_ray_start_hook' var='ray_params' inst=Some(Call { dest: None, callee: "os.makedirs", args: ["ray_params.temp_dir", "exist_ok=True"] })
[2] node=1063 method='_ray_start_hook' var='ray_params' inst=Some(Call { dest: None, callee: "os.makedirs", args: ["ray_params.temp_dir", "exist_ok=True"] })
[3] node=1062 method='_ray_start_hook' var='ray_params' inst=Some(Call { dest: Some("f"), callee: "open", args: ["os.path.join(ray_params.temp_dir, \"ray_hook_ok\")", "\"w\""] })
[4] node=1061 method='_ray_start_hook' var='ray_params' inst=Some(Call { dest: Some("f"), callee: "open", args: ["os.path.join(ray_params.temp_dir, \"ray_hook_ok\")", "\"w\""] })
```

#### Code Context
```python
    from ray._private.ray_perf import main
    from ray.autoscaler._private.kuberay.run_autoscaler import run_kuberay_autoscaler
    from ray.dashboard.modules.job.cli import job_cli_group
    from ray.serve.scripts import serve_cli
    from ray.util.state.state_cli import (
        ray_get,
        ray_list,
        logs_state_cli_group,
        summary_state_cli_group,
    )
from datetime import datetime
from ray._private.internal_api import memory_summary
from ray._private.storage import _load_class
from ray._private.usage import usage_lib
from ray._private.utils import (
```

### Case #30: CWE-918 in ray
- **Repository**: [https://github.com/ray-project/ray](https://github.com/ray-project/ray)
- **CWE**: CWE-918
- **Commit**: `978947083b1e192dba61ef653c863b11d56b0936`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `ray/scripts.py (up)`
- **Reasoning / Description**: Parameter cluster_config_file in up CLI helper is seeded as a source.

#### Forensic Trace Chain
```text
[0] node=1094 method='up' var='cluster_config_file' inst=None
[1] node=1122 method='up' var='cluster_config_file' inst=Some(Branch { cond: "disable_usage_stats", then_block: [InstructionId(643)], else_block: None })
[2] node=1119 method='up' var='cluster_config_file' inst=Some(Branch { cond: "restart_only or no_restart", then_block: [InstructionId(645)], else_block: None })
[3] node=1118 method='up' var='cluster_config_file' inst=Some(Call { dest: None, callee: "urllib.parse.urlparse", args: ["cluster_config_file"] })
[4] node=1117 method='up' var='cluster_config_file' inst=Some(Call { dest: None, callee: "urllib.parse.urlparse", args: ["cluster_config_file"] })
[5] node=1098 method='up' var='cluster_config_file' inst=Some(Branch { cond: "urllib.parse.urlparse(cluster_config_file).scheme in (\"http\", \"https\")", then_block: [InstructionId(658)], else_block: None })
[6] node=1099 method='up' var='cluster_config_file' inst=Some(Try { body: [InstructionId(648), InstructionId(649), InstructionId(650), InstructionId(651), InstructionId(652), InstructionId(653), InstructionId(654)], catches: [InstructionId(657)], finally: None })
[7] node=1111 method='up' var='urllib.request' inst=Some(Call { dest: Some("response"), callee: "urllib.request.urlopen", args: ["cluster_config_file", "timeout=5"] })
```

#### Code Context
```python
@add_click_logging_options
@PublicAPI
def up(
    cluster_config_file,
    min_workers,
    max_workers,
    no_restart,
    restart_only,
    yes,
    cluster_name,
    no_config_cache,
    redirect_command_output,
    use_login_shells,
    disable_usage_stats,
):
    """Create or update a Ray cluster."""
    if disable_usage_stats:
        usage_lib.set_usage_stats_enabled_via_env_var(False)

    if restart_only or no_restart:
```

### Case #31: CWE-502 in LLaMA-Factory
- **Repository**: [https://github.com/hiyouga/LLaMA-Factory](https://github.com/hiyouga/LLaMA-Factory)
- **CWE**: CWE-502
- **Commit**: `2989d39239d2f46e584c1e1180ba46b9768afb2a`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `src/llamafactory/extras/baichuan.py (llamafy_baichuan2)`
- **Reasoning / Description**: The parameter input_dir of llamafy_baichuan2 is seeded as a source, flowing into model loading.

#### Forensic Trace Chain
```text
[0] node=84 method='llamafy_baichuan2' var='input_dir' inst=None
[1] node=90 method='llamafy_baichuan2' var='input_dir' inst=Some(Try { body: [InstructionId(46)], catches: [InstructionId(48)], finally: None })
[2] node=92 method='llamafy_baichuan2' var='input_dir' inst=Some(Call { dest: None, callee: "os.makedirs", args: ["output_dir", "exist_ok=False"] })
[3] node=91 method='llamafy_baichuan2' var='input_dir' inst=Some(Call { dest: None, callee: "os.makedirs", args: ["output_dir", "exist_ok=False"] })
[4] node=89 method='llamafy_baichuan2' var='input_dir' inst=Some(Call { dest: None, callee: "save_weight", args: ["input_dir", "output_dir", "shard_size", "save_safetensors"] })
[5] node=19 method='save_weight' var='input_dir' inst=None
[6] node=77 method='save_weight' var='input_dir' inst=Some(Call { dest: Some("baichuan2_state_dict"), callee: "OrderedDict", args: [] })
[7] node=76 method='save_weight' var='input_dir' inst=Some(Call { dest: Some("baichuan2_state_dict"), callee: "OrderedDict", args: [] })
[8] node=62 method='save_weight' var='input_dir' inst=Some(Loop { cond: "filepath", body: [InstructionId(2), InstructionId(3), InstructionId(4), InstructionId(5), InstructionId(8)] })
[9] node=75 method='save_weight' var='input_dir' inst=Some(Call { dest: Some("filepath"), callee: "tqdm", args: ["os.listdir(input_dir)", "desc=\"Load weights\""] })
[10] node=74 method='save_weight' var='input_dir' inst=Some(Call { dest: Some("filepath"), callee: "tqdm", args: ["os.listdir(input_dir)", "desc=\"Load weights\""] })
[11] node=73 method='save_weight' var='input_dir' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["os.path.join(input_dir, filepath)"] })
[12] node=72 method='save_weight' var='input_dir' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["os.path.join(input_dir, filepath)"] })
[13] node=71 method='save_weight' var='input_dir' inst=Some(Call { dest: None, callee: "os.path.join", args: ["input_dir", "filepath"] })
[14] node=70 method='save_weight' var='input_dir' inst=Some(Call { dest: None, callee: "os.path.join", args: ["input_dir", "filepath"] })
[15] node=69 method='save_weight' var='input_dir' inst=Some(Call { dest: None, callee: "filepath.endswith", args: ["\".bin\""] })
[16] node=68 method='save_weight' var='input_dir' inst=Some(Call { dest: None, callee: "filepath.endswith", args: ["\".bin\""] })
[17] node=63 method='save_weight' var='input_dir' inst=Some(Branch { cond: "os.path.isfile(os.path.join(input_dir, filepath)) and filepath.endswith(\".bin\")", then_block: [InstructionId(6), InstructionId(7)], else_block: None })
[18] node=67 method='save_weight' var='input_dir' inst=Some(Call { dest: Some("shard_weight"), callee: "torch.load", args: ["os.path.join(input_dir, filepath)", "map_location=\"cpu\"", "weights_only=True"] })
```

#### Code Context
```python


def llamafy_baichuan2(
    input_dir: str,
    output_dir: str,
    shard_size: str = "2GB",
    save_safetensors: bool = True,
):
    r"""Convert the Baichuan2-7B model in the same format as LLaMA2-7B.

    Usage: python llamafy_baichuan2.py --input_dir input --output_dir output
    Converted model: https://huggingface.co/hiyouga/Baichuan2-7B-Base-LLaMAfied
    """
    try:
        os.makedirs(output_dir, exist_ok=False)
    except Exception as e:
        raise print("Output dir already exists", e)

    save_weight(input_dir, output_dir, shard_size, save_safetensors)
    save_config(input_dir, output_dir)
```

### Case #32: CWE-22 in pygeoapi
- **Repository**: [https://github.com/geopython/pygeoapi](https://github.com/geopython/pygeoapi)
- **CWE**: CWE-22
- **Commit**: `bf25b8695edbdd5476eeffc102b633d1d3e45f52`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `pygeoapi/util.py (get_data_path)`
- **Reasoning / Description**: Parameter data_path of get_data_path helper is seeded as a source.

#### Forensic Trace Chain
```text
[0] node=135 method='get_data_path' var='data_path' inst=Some(Assign { dest: "data_path", src: "self.data + dirpath" })
[1] node=134 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "LOGGER.debug", args: ["f'Data path: {data_path}'"] })
[2] node=133 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "LOGGER.debug", args: ["f'Data path: {data_path}'"] })
[3] node=131 method='get_data_path' var='data_path' inst=Some(Branch { cond: "'/' not in dirpath", then_block: [], else_block: Some([InstructionId(17)]) })
[4] node=130 method='get_data_path' var='data_path' inst=Some(Assign { dest: "content", src: "{\n            'links': [{\n                'rel': 'root',\n                'href': f'{root_link}?f=json',\n                'type': 'application/json'\n                }, {\n                'rel': 'root',\n                'href': root_link,\n                'type': 'text/html'\n                }, {\n                'rel': 'self',\n                'href': f'{thispath}?f=json',\n                'type': 'application/json',\n                }, {\n                'rel': 'self',\n                'href': thispath,\n                'type': 'text/html'\n                }\n            ]\n        }" })
[5] node=129 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "LOGGER.debug", args: ["'Checking if path exists as raw file or directory'"] })
[6] node=128 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "LOGGER.debug", args: ["'Checking if path exists as raw file or directory'"] })
[7] node=127 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "data_path.endswith", args: ["tuple(self.file_types)"] })
[8] node=126 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "data_path.endswith", args: ["tuple(self.file_types)"] })
[9] node=125 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "tuple", args: ["self.file_types"] })
[10] node=124 method='get_data_path' var='data_path' inst=Some(Call { dest: None, callee: "tuple", args: ["self.file_types"] })
[11] node=119 method='get_data_path' var='data_path' inst=Some(Branch { cond: "data_path.endswith(tuple(self.file_types))", then_block: [InstructionId(23)], else_block: Some([InstructionId(24), InstructionId(25)]) })
[12] node=120 method='get_data_path' var='data_path' inst=Some(Assign { dest: "resource_type", src: "'raw_file'" })
[13] node=114 method='get_data_path' var='data_path' inst=Some(Branch { cond: "resource_type is None", then_block: [InstructionId(27), InstructionId(28), InstructionId(29)], else_block: None })
[14] node=75 method='get_data_path' var='data_path' inst=Some(Branch { cond: "resource_type == 'raw_file'", then_block: [InstructionId(31), InstructionId(32), InstructionId(33)], else_block: Some([InstructionId(34), InstructionId(35), InstructionId(36), InstructionId(53)]) })
[15] node=113 method='get_data_path' var='data_path' inst=Some(Assign { dest: "content['type']", src: "'Catalog'" })
[16] node=112 method='get_data_path' var='data_path' inst=Some(Call { dest: Some("dirpath2"), callee: "os.listdir", args: ["data_path"] })
[17] node=111 method='get_data_path' var='data_path' inst=Some(Call { dest: Some("dirpath2"), callee: "os.listdir", args: ["data_path"] })
```

#### Code Context
```python
            raise ProviderConnectionError(msg)

    def get_data_path(self, baseurl, urlpath, dirpath):
        """
        Gets directory listing or file description or raw file dump

        :param baseurl: base URL of endpoint
        :param urlpath: base path of URL
        :param dirpath: directory basepath (equivalent of URL)

        :returns: `dict` of file listing or `dict` of GeoJSON item or raw file
        """

        thispath = os.path.join(baseurl, urlpath)

        resource_type = None
        root_link = None
        child_links = []

        if '..' in dirpath:
```

### Case #33: CWE-918 in label-studio
- **Repository**: [https://github.com/heartexlabs/label-studio](https://github.com/heartexlabs/label-studio)
- **CWE**: CWE-918
- **Commit**: `501142cb815ac964b0c600c491885b67386870c2`
- **Root Cause Category**: `SANITIZER_MODELING_GAP`
- **First Location of Over-Tainting**: `label_studio/data_import/api.py (load_tasks)`
- **Reasoning / Description**: The engine fails to recognize path sanitization validation checks introduced in load_tasks.

#### Forensic Trace Chain
```text
[0] node=153 method='load_tasks' var='request.FILES' inst=Some(Call { dest: None, callee: "check_file_sizes_and_number", args: ["request.FILES"] })
[1] node=144 method='load_tasks' var='request.FILES' inst=Some(Loop { cond: "filename, file", body: [InstructionId(52), InstructionId(53), InstructionId(55), InstructionId(56)] })
[2] node=152 method='load_tasks' var='request.FILES' inst=Some(Call { dest: Some("file"), callee: "request.FILES.items", args: [] })
```

#### Code Context
```python


def load_tasks(request, project):
    """ Load tasks from different types of request.data / request.files
    """
    file_upload_ids, found_formats, data_keys = [], [], set()
    could_be_tasks_lists = False

    # take tasks from request FILES
    if len(request.FILES):
        check_file_sizes_and_number(request.FILES)
        for filename, file in request.FILES.items():
            file_upload = create_file_upload(request, project, file)
            if file_upload.format_could_be_tasks_list:
                could_be_tasks_lists = True
            file_upload_ids.append(file_upload.id)
        tasks, found_formats, data_keys = FileUpload.load_tasks_from_uploaded_files(project, file_upload_ids)

    # take tasks from url address
    elif 'application/x-www-form-urlencoded' in request.content_type:
```

### Case #34: CWE-22 in mlflow
- **Repository**: [https://github.com/B-Step62/mlflow](https://github.com/B-Step62/mlflow)
- **CWE**: CWE-22
- **Commit**: `2e02bc7bb70df243e6eb792689d9b8eba0013161`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `mlflow/store/tracking/file_store.py (get_experiment)`
- **Reasoning / Description**: Parameter experiment_id in get_experiment helper is seeded as a source.

#### Forensic Trace Chain
```text
[0] node=1330 method='get_experiment' var='experiment_id' inst=None
[1] node=1334 method='get_experiment' var='path' inst=Some(Assign { dest: "path", src: "experiment_id" })
[2] node=1333 method='get_experiment' var='path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["path", "\"r\""] })
```

#### Code Context
```python


def get_experiment_impl(request_message):
    response_message = GetExperiment.Response()
    experiment = _get_tracking_store().get_experiment(request_message.experiment_id).to_proto()
    response_message.experiment.MergeFrom(experiment)
    return response_message


@catch_mlflow_exception
@_disable_if_artifacts_only
def _get_experiment_by_name():
    request_message = _get_request_message(
        GetExperimentByName(),
        schema={"experiment_name": [_assert_required, _assert_string]},
    )
    response_message = GetExperimentByName.Response()
    store_exp = _get_tracking_store().get_experiment_by_name(request_message.experiment_name)
    if store_exp is None:
        raise MlflowException(
```

### Case #35: CWE-502 in transformers
- **Repository**: [https://github.com/huggingface/transformers](https://github.com/huggingface/transformers)
- **CWE**: CWE-502
- **Commit**: `1d63b0ec361e7a38f1339385e8a5a855085532ce`
- **Root Cause Category**: `SANITIZER_MODELING_GAP`
- **First Location of Over-Tainting**: `src/transformers/trainer.py (torch.load)`
- **Reasoning / Description**: The engine ignores weights_only=True safety check passed to torch.load, which prevents arbitrary pickle execution.

#### Forensic Trace Chain
```text
[0] node=521 method='__init__' var='pretrained_vocab_file' inst=None
[1] node=591 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "logger.error", args: ["\"`TransfoXL` was deprecated due to security issues linked to `pickle.load` in `TransfoXLTokenizer`. \"\n            \"See more details on this model's documentation page: \"\n            \"`https://github.com/huggingface/transformers/blob/main/docs/source/en/model_doc/transfo-xl.md`.\""] })
[2] node=590 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "logger.error", args: ["\"`TransfoXL` was deprecated due to security issues linked to `pickle.load` in `TransfoXLTokenizer`. \"\n            \"See more details on this model's documentation page: \"\n            \"`https://github.com/huggingface/transformers/blob/main/docs/source/en/model_doc/transfo-xl.md`.\""] })
[3] node=589 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "requires_backends", args: ["self", "\"sacremoses\""] })
[4] node=588 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "requires_backends", args: ["self", "\"sacremoses\""] })
[5] node=586 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "special is None", then_block: [InstructionId(14)], else_block: None })
[6] node=585 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.counter"), callee: "Counter", args: [] })
[7] node=584 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.counter"), callee: "Counter", args: [] })
[8] node=583 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.special", src: "special" })
[9] node=582 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.min_freq", src: "min_freq" })
[10] node=581 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.max_size", src: "max_size" })
[11] node=580 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.lower_case", src: "lower_case" })
[12] node=579 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.delimiter", src: "delimiter" })
[13] node=578 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.vocab_file", src: "vocab_file" })
[14] node=577 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.punctuation_symbols", src: "'!\"#$%&()*+,-./\\\\:;<=>?@[\\\\]^_`{|}~'" })
[15] node=576 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punction_without_space_before_pattern"), callee: "re.compile", args: ["rf\"[^\\s][{self.punctuation_symbols}]\""] })
[16] node=575 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punction_without_space_before_pattern"), callee: "re.compile", args: ["rf\"[^\\s][{self.punctuation_symbols}]\""] })
[17] node=574 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punctuation_with_space_around_pattern"), callee: "self._compile_space_around_punctuation_pattern", args: [] })
[18] node=573 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punctuation_with_space_around_pattern"), callee: "self._compile_space_around_punctuation_pattern", args: [] })
[19] node=572 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.language", src: "language" })
[20] node=571 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_punct_normalizer"), callee: "sm.MosesPunctNormalizer", args: ["language"] })
[21] node=570 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_punct_normalizer"), callee: "sm.MosesPunctNormalizer", args: ["language"] })
[22] node=569 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_tokenizer"), callee: "sm.MosesTokenizer", args: ["language"] })
[23] node=568 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_tokenizer"), callee: "sm.MosesTokenizer", args: ["language"] })
[24] node=567 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_detokenizer"), callee: "sm.MosesDetokenizer", args: ["language"] })
[25] node=566 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_detokenizer"), callee: "sm.MosesDetokenizer", args: ["language"] })
[26] node=565 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.idx2sym", src: "[]" })
[27] node=564 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.sym2idx"), callee: "OrderedDict", args: [] })
[28] node=563 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.sym2idx"), callee: "OrderedDict", args: [] })
[29] node=531 method='__init__' var='pretrained_vocab_file' inst=Some(Try { body: [InstructionId(32), InstructionId(45), InstructionId(51)], catches: [InstructionId(53)], finally: None })
[30] node=560 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "vocab_dict", src: "None" })
[31] node=540 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "pretrained_vocab_file is not None", then_block: [], else_block: Some([InstructionId(33), InstructionId(34), InstructionId(36), InstructionId(37), InstructionId(38), InstructionId(39), InstructionId(44)]) })
[32] node=532 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "vocab_dict is not None", then_block: [InstructionId(49)], else_block: Some([InstructionId(50)]) })
[33] node=533 method='__init__' var='pretrained_vocab_file' inst=Some(Loop { cond: "key, value", body: [InstructionId(46), InstructionId(48)] })
[34] node=528 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "vocab_file is not None", then_block: [InstructionId(55)], else_block: None })
[35] node=527 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "super().__init__", args: ["special=special", "min_freq=min_freq", "max_size=max_size", "lower_case=lower_case", "delimiter=delimiter", "vocab_file=vocab_file", "pretrained_vocab_file=pretrained_vocab_file", "never_split=never_split", "unk_token=unk_token", "eos_token=eos_token", "additional_special_tokens=additional_special_tokens", "language=language", "**kwargs"] })
[36] node=521 method='__init__' var='pretrained_vocab_file' inst=None
[37] node=591 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "logger.error", args: ["\"`TransfoXL` was deprecated due to security issues linked to `pickle.load` in `TransfoXLTokenizer`. \"\n            \"See more details on this model's documentation page: \"\n            \"`https://github.com/huggingface/transformers/blob/main/docs/source/en/model_doc/transfo-xl.md`.\""] })
[38] node=590 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "logger.error", args: ["\"`TransfoXL` was deprecated due to security issues linked to `pickle.load` in `TransfoXLTokenizer`. \"\n            \"See more details on this model's documentation page: \"\n            \"`https://github.com/huggingface/transformers/blob/main/docs/source/en/model_doc/transfo-xl.md`.\""] })
[39] node=589 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "requires_backends", args: ["self", "\"sacremoses\""] })
[40] node=588 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "requires_backends", args: ["self", "\"sacremoses\""] })
[41] node=586 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "special is None", then_block: [InstructionId(14)], else_block: None })
[42] node=585 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.counter"), callee: "Counter", args: [] })
[43] node=584 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.counter"), callee: "Counter", args: [] })
[44] node=583 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.special", src: "special" })
[45] node=582 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.min_freq", src: "min_freq" })
[46] node=581 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.max_size", src: "max_size" })
[47] node=580 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.lower_case", src: "lower_case" })
[48] node=579 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.delimiter", src: "delimiter" })
[49] node=578 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.vocab_file", src: "vocab_file" })
[50] node=577 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.punctuation_symbols", src: "'!\"#$%&()*+,-./\\\\:;<=>?@[\\\\]^_`{|}~'" })
[51] node=576 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punction_without_space_before_pattern"), callee: "re.compile", args: ["rf\"[^\\s][{self.punctuation_symbols}]\""] })
[52] node=575 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punction_without_space_before_pattern"), callee: "re.compile", args: ["rf\"[^\\s][{self.punctuation_symbols}]\""] })
[53] node=574 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punctuation_with_space_around_pattern"), callee: "self._compile_space_around_punctuation_pattern", args: [] })
[54] node=573 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.punctuation_with_space_around_pattern"), callee: "self._compile_space_around_punctuation_pattern", args: [] })
[55] node=572 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.language", src: "language" })
[56] node=571 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_punct_normalizer"), callee: "sm.MosesPunctNormalizer", args: ["language"] })
[57] node=570 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_punct_normalizer"), callee: "sm.MosesPunctNormalizer", args: ["language"] })
[58] node=569 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_tokenizer"), callee: "sm.MosesTokenizer", args: ["language"] })
[59] node=568 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_tokenizer"), callee: "sm.MosesTokenizer", args: ["language"] })
[60] node=567 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_detokenizer"), callee: "sm.MosesDetokenizer", args: ["language"] })
[61] node=566 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.moses_detokenizer"), callee: "sm.MosesDetokenizer", args: ["language"] })
[62] node=565 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "self.idx2sym", src: "[]" })
[63] node=564 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.sym2idx"), callee: "OrderedDict", args: [] })
[64] node=563 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("self.sym2idx"), callee: "OrderedDict", args: [] })
[65] node=531 method='__init__' var='pretrained_vocab_file' inst=Some(Try { body: [InstructionId(32), InstructionId(45), InstructionId(51)], catches: [InstructionId(53)], finally: None })
[66] node=560 method='__init__' var='pretrained_vocab_file' inst=Some(Assign { dest: "vocab_dict", src: "None" })
[67] node=540 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "pretrained_vocab_file is not None", then_block: [], else_block: Some([InstructionId(33), InstructionId(34), InstructionId(36), InstructionId(37), InstructionId(38), InstructionId(39), InstructionId(44)]) })
[68] node=559 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "strtobool", args: ["os.environ.get(\"TRUST_REMOTE_CODE\", \"False\")"] })
[69] node=558 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "strtobool", args: ["os.environ.get(\"TRUST_REMOTE_CODE\", \"False\")"] })
[70] node=557 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "os.environ.get", args: ["\"TRUST_REMOTE_CODE\"", "\"False\""] })
[71] node=556 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: None, callee: "os.environ.get", args: ["\"TRUST_REMOTE_CODE\"", "\"False\""] })
[72] node=554 method='__init__' var='pretrained_vocab_file' inst=Some(Branch { cond: "not strtobool(os.environ.get(\"TRUST_REMOTE_CODE\", \"False\"))", then_block: [InstructionId(35)], else_block: None })
[73] node=553 method='__init__' var='pretrained_vocab_file' inst=Some(Call { dest: Some("f"), callee: "open", args: ["pretrained_vocab_file", "\"rb\""] })
[74] node=552 method='__init__' var='f' inst=Some(Call { dest: Some("f"), callee: "open", args: ["pretrained_vocab_file", "\"rb\""] })
[75] node=551 method='__init__' var='pickle' inst=Some(Call { dest: Some("vocab_dict"), callee: "pickle.load", args: ["f"] })
```

#### Code Context
```python
    model_input_names = ["input_ids"]

    def __init__(
        self,
        special=None,
        min_freq=0,
        max_size=None,
        lower_case=False,
        delimiter=None,
        vocab_file=None,
        pretrained_vocab_file: str = None,
        never_split=None,
        unk_token="<unk>",
        eos_token="<eos>",
        additional_special_tokens=["<formula>"],
        language="en",
        **kwargs,
    ):
        logger.error(
            "`TransfoXL` was deprecated due to security issues linked to `pickle.load` in `TransfoXLTokenizer`. "
```

### Case #36: CWE-502 in transformers
- **Repository**: [https://github.com/huggingface/transformers](https://github.com/huggingface/transformers)
- **CWE**: CWE-502
- **Commit**: `1d63b0ec361e7a38f1339385e8a5a855085532ce`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `src/transformers/tokenization_utils_base.py (count_file)`
- **Reasoning / Description**: Helper parameter path of count_file is seeded as a source, flowing to open.

#### Forensic Trace Chain
```text
[0] node=134 method='count_file' var='path' inst=None
[1] node=154 method='count_file' var='path' inst=Some(Branch { cond: "verbose", then_block: [InstructionId(218)], else_block: None })
[2] node=153 method='count_file' var='path' inst=Some(Call { dest: None, callee: "os.path.exists", args: ["path"] })
[3] node=152 method='count_file' var='path' inst=Some(Call { dest: None, callee: "os.path.exists", args: ["path"] })
[4] node=151 method='count_file' var='path' inst=Some(Assign { dest: "sents", src: "[]" })
[5] node=150 method='count_file' var='path' inst=Some(Call { dest: Some("f"), callee: "open", args: ["path", "\"r\"", "encoding=\"utf-8\""] })
```

#### Code Context
```python
        return re.compile(r"" + look_ahead_for_special_token + look_ahead_to_match_all_except_space)

    def count_file(self, path, verbose=False, add_eos=False):
        if verbose:
            logger.info(f"counting file {path} ...")
        assert os.path.exists(path), f"Input file {path} not found"

        sents = []
        with open(path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                if verbose and idx > 0 and idx % 500000 == 0:
                    logger.info(f"    line {idx}")
                symbols = self.tokenize(line, add_eos=add_eos)
                self.counter.update(symbols)
                sents.append(symbols)

        return sents

    def count_sents(self, sents, verbose=False):
        """
```

### Case #37: CWE-502 in transformers
- **Repository**: [https://github.com/huggingface/transformers](https://github.com/huggingface/transformers)
- **CWE**: CWE-502
- **Commit**: `03c8082ba4594c9b8d6fe190ca9bed0e5f8ca396`
- **Root Cause Category**: `SANITIZER_MODELING_GAP`
- **First Location of Over-Tainting**: `src/transformers/trainer.py (torch.load)`
- **Reasoning / Description**: The engine ignores weights_only=True safety check passed to torch.load, which prevents arbitrary pickle execution.

#### Forensic Trace Chain
```text
[0] node=778 method='_load_rng_state' var='process_index' inst=Some(Assign { dest: "process_index", src: "self.args.process_index" })
[1] node=777 method='_load_rng_state' var='process_index' inst=Some(Call { dest: Some("rng_file"), callee: "os.path.join", args: ["checkpoint", "f\"rng_state_{process_index}.pth\""] })
[2] node=776 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: Some("rng_file"), callee: "os.path.join", args: ["checkpoint", "f\"rng_state_{process_index}.pth\""] })
[3] node=775 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["rng_file"] })
[4] node=774 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["rng_file"] })
[5] node=770 method='_load_rng_state' var='rng_file' inst=Some(Branch { cond: "not os.path.isfile(rng_file)", then_block: [InstructionId(57), InstructionId(58)], else_block: None })
[6] node=768 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: None, callee: "safe_globals", args: [] })
[7] node=767 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: None, callee: "safe_globals", args: [] })
[8] node=766 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: None, callee: "check_torch_load_is_safe", args: [] })
[9] node=765 method='_load_rng_state' var='rng_file' inst=Some(Call { dest: None, callee: "check_torch_load_is_safe", args: [] })
[10] node=764 method='_load_rng_state' var='torch' inst=Some(Call { dest: Some("checkpoint_rng_state"), callee: "torch.load", args: ["rng_file", "weights_only=True"] })
```

#### Code Context
```python
            self.control = self.callback_handler.on_save(self.args, self.state, self.control)

    def _load_rng_state(self, checkpoint):
        # Load RNG states from `checkpoint`
        if checkpoint is None:
            return

        if self.args.world_size > 1:
            process_index = self.args.process_index
            rng_file = os.path.join(checkpoint, f"rng_state_{process_index}.pth")
            if not os.path.isfile(rng_file):
                logger.info(
                    f"Didn't find an RNG file for process {process_index}, if you are resuming a training that "
                    "wasn't launched in a distributed fashion, reproducibility is not guaranteed."
                )
                return
        else:
            rng_file = os.path.join(checkpoint, "rng_state.pth")
            if not os.path.isfile(rng_file):
                logger.info(
```

### Case #38: CWE-918 in firefighter-incident
- **Repository**: [https://github.com/ManoManoTech/firefighter-incident](https://github.com/ManoManoTech/firefighter-incident)
- **CWE**: CWE-918
- **Commit**: `2586679e6f32c12d223668b73e98f4c4de7b771f`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `firefighter/raid/serializers.py (Serializer)`
- **Reasoning / Description**: The serializer constructor parameter data is seeded as a source, flowing to simulated Jira HTTP requests in the stub.

#### Forensic Trace Chain
```text
[0] node=50 method='__init__' var='data' inst=None
[1] node=53 method='__init__' var='data' inst=Some(Assign { dest: "self.data", src: "data" })
[2] node=52 method='__init__' var='self.validated_data' inst=Some(Assign { dest: "self.validated_data", src: "data" })
[3] node=7 method='save' var='self.validated_data' inst=None
[4] node=13 method='save' var='self.validated_data' inst=Some(Call { dest: Some("url"), callee: "self.validated_data.get", args: ["'zoho'", "self.validated_data.get('zendesk', '')"] })
[5] node=12 method='save' var='url' inst=Some(Call { dest: Some("url"), callee: "self.validated_data.get", args: ["'zoho'", "self.validated_data.get('zendesk', '')"] })
[6] node=9 method='save' var='url' inst=Some(Branch { cond: "url", then_block: [InstructionId(37)], else_block: None })
[7] node=11 method='save' var='url' inst=Some(Call { dest: None, callee: "requests.post", args: ["url", "json=self.validated_data"] })
[8] node=10 method='save' var='url' inst=Some(Call { dest: None, callee: "requests.post", args: ["url", "json=self.validated_data"] })
```

#### Code Context
```python
    from rest_framework.request import Request
from __future__ import annotations
from django.conf import settings
from drf_spectacular.utils import OpenApiExample, extend_schema
from firefighter.api.authentication import BearerTokenAuthentication
from firefighter.raid.models import JiraTicket
from firefighter.raid.serializers import (
    JiraWebhookCommentSerializer,
    JiraWebhookUpdateSerializer,
    LandbotIssueRequestSerializer,
)
from rest_framework import generics, mixins, permissions, status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from typing import TYPE_CHECKING, Any, Final, Never
```

### Case #39: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `f7c28ffbf18dbf693a15b1ba9493918de3e88cf3`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=102 method='atomic_open' var='mode' inst=None
[1] node=106 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
        import zmq
    import pwd  # after confirming not running Windows
    import resource
    import salt.utils.path
    import salt.utils.win_dacl
    import salt.utils.win_functions
    import salt.utils.win_reg
    import win32file
from salt._logging import LOG_LEVELS
from salt.exceptions import (
    CommandExecutionError,
    SaltClientError,
    SaltSystemExit,
    SaltValidationError,
)
```

### Case #40: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `e0cdb80b55123f4a024759ffcf2b3f0e0788e7ab`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=113 method='atomic_open' var='mode' inst=None
[1] node=117 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
from tests.support.mock import patch
import pathlib
import pytest
import salt.master
import salt.utils.platform
import time

import pathlib
import time

import pytest

import salt.master
import salt.utils.platform
from tests.support.mock import patch
```

### Case #41: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `4b30218edf1a979855ea191d72b30c89f4a5a582`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `salt/utils/jid.py (get_jid)`
- **Reasoning / Description**: Helper parameter jid is seeded as a source, flowing to path operations.

#### Forensic Trace Chain
```text
[0] node=97 method='get_jid' var='jid' inst=None
[1] node=141 method='get_jid' var='jid' inst=Some(Call { dest: Some("jid_dir"), callee: "salt.utils.jid.jid_dir", args: ["jid", "_job_dir()", "__opts__[\"hash_type\"]"] })
[2] node=454 method='jid_dir' var='value' inst=None
[3] node=456 method='jid_dir' var='value' inst=Some(Return { val: Some("value") })
[4] node=455 method='jid_dir' var='value' inst=None
[5] node=140 method='get_jid' var='jid_dir' inst=Some(Call { dest: Some("jid_dir"), callee: "salt.utils.jid.jid_dir", args: ["jid", "_job_dir()", "__opts__[\"hash_type\"]"] })
[6] node=139 method='get_jid' var='jid_dir' inst=Some(Assign { dest: "ret", src: "{}" })
[7] node=138 method='get_jid' var='jid_dir' inst=Some(Call { dest: None, callee: "os.path.isdir", args: ["jid_dir"] })
[8] node=137 method='get_jid' var='jid_dir' inst=Some(Call { dest: None, callee: "os.path.isdir", args: ["jid_dir"] })
[9] node=135 method='get_jid' var='jid_dir' inst=Some(Branch { cond: "not os.path.isdir(jid_dir)", then_block: [InstructionId(313)], else_block: None })
[10] node=100 method='get_jid' var='jid_dir' inst=Some(Loop { cond: "fn_", body: [InstructionId(315), InstructionId(316), InstructionId(317), InstructionId(336)] })
[11] node=134 method='get_jid' var='os' inst=Some(Call { dest: Some("fn_"), callee: "os.listdir", args: ["jid_dir"] })
[12] node=133 method='get_jid' var='fn_' inst=Some(Call { dest: Some("fn_"), callee: "os.listdir", args: ["jid_dir"] })
[13] node=132 method='get_jid' var='fn_' inst=Some(Call { dest: None, callee: "fn_.startswith", args: ["\".\""] })
[14] node=131 method='get_jid' var='fn_' inst=Some(Call { dest: None, callee: "fn_.startswith", args: ["\".\""] })
[15] node=130 method='get_jid' var='fn_' inst=Some(Branch { cond: "fn_.startswith(\".\")", then_block: [], else_block: None })
[16] node=101 method='get_jid' var='fn_' inst=Some(Branch { cond: "fn_ not in ret", then_block: [InstructionId(318), InstructionId(319), InstructionId(320), InstructionId(321), InstructionId(335)], else_block: None })
[17] node=129 method='get_jid' var='fn_' inst=Some(Call { dest: Some("retp"), callee: "os.path.join", args: ["jid_dir", "fn_", "RETURN_P"] })
[18] node=128 method='get_jid' var='retp' inst=Some(Call { dest: Some("retp"), callee: "os.path.join", args: ["jid_dir", "fn_", "RETURN_P"] })
[19] node=127 method='get_jid' var='retp' inst=Some(Call { dest: Some("outp"), callee: "os.path.join", args: ["jid_dir", "fn_", "OUT_P"] })
[20] node=126 method='get_jid' var='retp' inst=Some(Call { dest: Some("outp"), callee: "os.path.join", args: ["jid_dir", "fn_", "OUT_P"] })
[21] node=125 method='get_jid' var='retp' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["retp"] })
[22] node=124 method='get_jid' var='retp' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["retp"] })
[23] node=123 method='get_jid' var='retp' inst=Some(Branch { cond: "not os.path.isfile(retp)", then_block: [], else_block: None })
[24] node=102 method='get_jid' var='retp' inst=Some(Loop { cond: "fn_ not in ret", body: [InstructionId(334)] })
[25] node=103 method='get_jid' var='retp' inst=Some(Try { body: [InstructionId(322), InstructionId(323), InstructionId(324), InstructionId(325), InstructionId(326), InstructionId(327), InstructionId(330)], catches: [InstructionId(333)], finally: None })
[26] node=118 method='get_jid' var='salt.utils.files' inst=Some(Call { dest: Some("rfh"), callee: "salt.utils.files.fopen", args: ["retp", "\"rb\""] })
[27] node=117 method='get_jid' var='rfh' inst=Some(Call { dest: Some("rfh"), callee: "salt.utils.files.fopen", args: ["retp", "\"rb\""] })
[28] node=116 method='get_jid' var='salt.payload' inst=Some(Call { dest: Some("ret_data"), callee: "salt.payload.load", args: ["rfh"] })
[29] node=115 method='get_jid' var='salt.payload' inst=Some(Call { dest: Some("ret_data"), callee: "salt.payload.load", args: ["rfh"] })
[30] node=114 method='get_jid' var='salt.payload' inst=Some(Call { dest: None, callee: "isinstance", args: ["ret_data", "dict"] })
[31] node=113 method='get_jid' var='salt.payload' inst=Some(Call { dest: None, callee: "isinstance", args: ["ret_data", "dict"] })
[32] node=112 method='get_jid' var='salt.payload' inst=Some(Branch { cond: "not isinstance(ret_data, dict) or \"return\" not in ret_data", then_block: [], else_block: None })
[33] node=111 method='get_jid' var='salt.payload' inst=Some(Assign { dest: "ret[fn_]", src: "ret_data" })
[34] node=110 method='get_jid' var='salt.payload' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["outp"] })
[35] node=109 method='get_jid' var='salt.payload' inst=Some(Call { dest: None, callee: "os.path.isfile", args: ["outp"] })
[36] node=104 method='get_jid' var='salt.payload' inst=Some(Branch { cond: "os.path.isfile(outp)", then_block: [InstructionId(328), InstructionId(329)], else_block: None })
[37] node=108 method='get_jid' var='salt.payload' inst=Some(Call { dest: Some("rfh"), callee: "salt.utils.files.fopen", args: ["outp", "\"rb\""] })
[38] node=107 method='get_jid' var='salt.payload' inst=Some(Call { dest: Some("rfh"), callee: "salt.utils.files.fopen", args: ["outp", "\"rb\""] })
[39] node=106 method='get_jid' var='salt.payload' inst=Some(Call { dest: Some("ret[fn_][\"out\"]"), callee: "salt.payload.load", args: ["rfh"] })
```

#### Code Context
```python
                    import salt.pillar.git_pillar
            import salt.fileserver
        import salt.fileserver
    import resource
from salt.config import DEFAULT_INTERVAL
from salt.defaults import DEFAULT_TARGET_DELIM
from salt.ext.tornado.stack_context import StackContext
from salt.transport import TRANSPORTS
from salt.utils.channel import iter_transport_opts
from salt.utils.ctx import RequestContext
from salt.utils.debug import (
    enable_sigusr1_handler,
    enable_sigusr2_handler,
    inspect_stack,
)
```

### Case #42: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `9445f496fed61b15dc4364818007e5b765b0746f`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `salt/utils/path.py (verify_log_files)`
- **Reasoning / Description**: Parameter files in verify_log_files helper is seeded as a source, flowing to os.makedirs.

#### Forensic Trace Chain
```text
[0] node=901 method='verify_log_files' var='files' inst=None
[1] node=905 method='verify_log_files' var='files' inst=Some(Call { dest: None, callee: "verify_files", args: ["verify_logs_filter(files)", "user"] })
[2] node=179 method='verify_files' var='files' inst=None
[3] node=224 method='verify_files' var='files' inst=Some(Call { dest: None, callee: "salt.utils.platform.is_windows", args: [] })
[4] node=223 method='verify_files' var='files' inst=Some(Call { dest: None, callee: "salt.utils.platform.is_windows", args: [] })
[5] node=221 method='verify_files' var='files' inst=Some(Branch { cond: "salt.utils.platform.is_windows()", then_block: [InstructionId(185)], else_block: None })
[6] node=220 method='verify_files' var='files' inst=Some(Call { dest: Some("pwnam"), callee: "_get_pwnam", args: ["user"] })
[7] node=219 method='verify_files' var='files' inst=Some(Call { dest: Some("pwnam"), callee: "_get_pwnam", args: ["user"] })
[8] node=218 method='verify_files' var='files' inst=Some(Assign { dest: "uid", src: "pwnam[2]" })
[9] node=182 method='verify_files' var='files' inst=Some(Loop { cond: "fn_", body: [InstructionId(189), InstructionId(190), InstructionId(210), InstructionId(211), InstructionId(215)] })
[10] node=217 method='verify_files' var='fn_' inst=Some(Assign { dest: "fn_", src: "files" })
[11] node=216 method='verify_files' var='fn_' inst=Some(Call { dest: Some("dirname"), callee: "os.path.dirname", args: ["fn_"] })
[12] node=215 method='verify_files' var='dirname' inst=Some(Call { dest: Some("dirname"), callee: "os.path.dirname", args: ["fn_"] })
[13] node=190 method='verify_files' var='dirname' inst=Some(Try { body: [InstructionId(195), InstructionId(196), InstructionId(198)], catches: [InstructionId(206), InstructionId(209)], finally: None })
[14] node=196 method='verify_files' var='dirname' inst=Some(Branch { cond: "dirname", then_block: [InstructionId(194)], else_block: None })
[15] node=197 method='verify_files' var='dirname' inst=Some(Try { body: [InstructionId(191)], catches: [InstructionId(193)], finally: None })
[16] node=199 method='verify_files' var='dirname' inst=Some(Call { dest: None, callee: "os.makedirs", args: ["dirname"] })
[17] node=198 method='verify_files' var='dirname' inst=Some(Call { dest: None, callee: "os.makedirs", args: ["dirname"] })
```

#### Code Context
```python
from tests.support.mock import patch
from tests.support.runtests import RUNTIME_VARS
import pathlib
import pytest
import salt.config
import salt.crypt
import salt.master
import salt.utils.files
import salt.utils.platform
import time

import pathlib
import time

import pytest
```

### Case #43: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `4b30218edf1a979855ea191d72b30c89f4a5a582`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=592 method='atomic_open' var='mode' inst=None
[1] node=596 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
[2] node=595 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
                    import salt.pillar.git_pillar
            import salt.fileserver
        import salt.fileserver
    import resource
from salt.config import DEFAULT_INTERVAL
from salt.defaults import DEFAULT_TARGET_DELIM
from salt.ext.tornado.stack_context import StackContext
from salt.transport import TRANSPORTS
from salt.utils.channel import iter_transport_opts
from salt.utils.ctx import RequestContext
from salt.utils.debug import (
    enable_sigusr1_handler,
    enable_sigusr2_handler,
    inspect_stack,
)
```

### Case #44: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `e0cdb80b55123f4a024759ffcf2b3f0e0788e7ab`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=344 method='atomic_open' var='mode' inst=None
[1] node=348 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
[2] node=347 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
from tests.support.mock import patch
import pathlib
import pytest
import salt.master
import salt.utils.platform
import time

import pathlib
import time

import pytest

import salt.master
import salt.utils.platform
from tests.support.mock import patch
```

### Case #45: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `80d90307b07b3703428ecbb7c8bb468e28a9ae6d`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=197 method='atomic_open' var='filepath' inst=None
[1] node=201 method='atomic_open' var='filepath' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
[2] node=200 method='atomic_open' var='filepath' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
        import zmq
    import pwd  # after confirming not running Windows
    import resource
    import salt.utils.win_dacl
    import salt.utils.win_functions
    import win32file
from __future__ import absolute_import
from salt.exceptions import SaltClientError, SaltSystemExit, \
    CommandExecutionError
from salt.log import is_console_configured
from salt.log.setup import LOG_LEVELS
import errno
import logging
import os
import re
```

### Case #46: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `9445f496fed61b15dc4364818007e5b765b0746f`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=804 method='atomic_open' var='mode' inst=None
[1] node=808 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
[2] node=807 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
from tests.support.mock import patch
from tests.support.runtests import RUNTIME_VARS
import pathlib
import pytest
import salt.config
import salt.crypt
import salt.master
import salt.utils.files
import salt.utils.platform
import time

import pathlib
import time

import pytest
```

### Case #47: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `4b30218edf1a979855ea191d72b30c89f4a5a582`
- **Root Cause Category**: `WRAPPER_PROPAGATION_OVERTAINTING`
- **First Location of Over-Tainting**: `salt/utils/jid.py (get_jid)`
- **Reasoning / Description**: Helper parameter jid is seeded as a source, flowing to path operations.

#### Forensic Trace Chain
```text
[0] node=344 method='get_jid' var='jid' inst=None
[1] node=388 method='get_jid' var='jid' inst=Some(Call { dest: Some("jid_dir"), callee: "salt.utils.jid.jid_dir", args: ["jid", "_job_dir()", "__opts__[\"hash_type\"]"] })
[2] node=141 method='jid_dir' var='value' inst=None
[3] node=143 method='jid_dir' var='value' inst=Some(Return { val: Some("value") })
[4] node=142 method='jid_dir' var='value' inst=None
[5] node=387 method='get_jid' var='jid_dir' inst=Some(Call { dest: Some("jid_dir"), callee: "salt.utils.jid.jid_dir", args: ["jid", "_job_dir()", "__opts__[\"hash_type\"]"] })
[6] node=386 method='get_jid' var='jid_dir' inst=Some(Assign { dest: "ret", src: "{}" })
[7] node=385 method='get_jid' var='jid_dir' inst=Some(Call { dest: None, callee: "os.path.isdir", args: ["jid_dir"] })
[8] node=384 method='get_jid' var='jid_dir' inst=Some(Call { dest: None, callee: "os.path.isdir", args: ["jid_dir"] })
[9] node=382 method='get_jid' var='jid_dir' inst=Some(Branch { cond: "not os.path.isdir(jid_dir)", then_block: [InstructionId(338)], else_block: None })
[10] node=347 method='get_jid' var='jid_dir' inst=Some(Loop { cond: "fn_", body: [InstructionId(340), InstructionId(341), InstructionId(342), InstructionId(361)] })
[11] node=381 method='get_jid' var='os' inst=Some(Call { dest: Some("fn_"), callee: "os.listdir", args: ["jid_dir"] })
[12] node=380 method='get_jid' var='os' inst=Some(Call { dest: Some("fn_"), callee: "os.listdir", args: ["jid_dir"] })
```

#### Code Context
```python
                    import salt.pillar.git_pillar
            import salt.fileserver
        import salt.fileserver
    import resource
from salt.config import DEFAULT_INTERVAL
from salt.defaults import DEFAULT_TARGET_DELIM
from salt.ext.tornado.stack_context import StackContext
from salt.transport import TRANSPORTS
from salt.utils.channel import iter_transport_opts
from salt.utils.ctx import RequestContext
from salt.utils.debug import (
    enable_sigusr1_handler,
    enable_sigusr2_handler,
    inspect_stack,
)
```

### Case #48: CWE-22 in salt
- **Repository**: [https://github.com/saltstack/salt](https://github.com/saltstack/salt)
- **CWE**: CWE-22
- **Commit**: `f7c28ffbf18dbf693a15b1ba9493918de3e88cf3`
- **Root Cause Category**: `SINK_ARGUMENT_INSENSITIVITY`
- **First Location of Over-Tainting**: `salt/utils/atomicfile.py (atomic_open)`
- **Reasoning / Description**: The parameter mode of atomic_open flows to open, triggering a false flow because the engine is insensitive to sink arguments.

#### Forensic Trace Chain
```text
[0] node=441 method='atomic_open' var='mode' inst=None
[1] node=445 method='atomic_open' var='mode' inst=Some(Call { dest: None, callee: "open", args: ["filepath", "mode"] })
```

#### Code Context
```python
        import zmq
    import pwd  # after confirming not running Windows
    import resource
    import salt.utils.path
    import salt.utils.win_dacl
    import salt.utils.win_functions
    import salt.utils.win_reg
    import win32file
from salt._logging import LOG_LEVELS
from salt.exceptions import (
    CommandExecutionError,
    SaltClientError,
    SaltSystemExit,
    SaltValidationError,
)
```

### Case #49: CWE-502 in datachain
- **Repository**: [https://github.com/iterative/datachain](https://github.com/iterative/datachain)
- **CWE**: CWE-502
- **Commit**: `914b95610620d50c8d9bee506ccbfa7d4d57fdc0`
- **Root Cause Category**: `FIELD_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `datachain/query/dataset.py (self.db)`
- **Reasoning / Description**: The engine propagates taint from database helpers through self.db using field-insensitive aliasing.

#### Forensic Trace Chain
```text
[0] node=611 method='merge_dataset_rows' var='src_version' inst=None
[1] node=641 method='merge_dataset_rows' var='src_version' inst=Some(Assign { dest: "dst_empty", src: "False" })
[2] node=640 method='merge_dataset_rows' var='self.db' inst=Some(Call { dest: None, callee: "self.db.has_table", args: ["self.dataset_table_name(src, src_version)"] })
[3] node=56 method='create_dataset_rows_table' var='self.db' inst=None
[4] node=123 method='is_ready' var='self.db' inst=None
[5] node=180 method='insert_rows' var='self.db' inst=None
[6] node=382 method='insert_dataset_rows' var='self.db' inst=None
[7] node=405 method='clone_params' var='self.db' inst=None
[8] node=597 method='get_dataset_sources' var='self.db' inst=None
[9] node=611 method='merge_dataset_rows' var='self.db' inst=None
[10] node=724 method='__init__' var='self.db' inst=None
[11] node=734 method='__init__' var='self.db' inst=Some(Call { dest: Some("self.schema"), callee: "DefaultSchema", args: [] })
[12] node=733 method='__init__' var='self.db' inst=Some(Call { dest: Some("self.schema"), callee: "DefaultSchema", args: [] })
[13] node=732 method='__init__' var='self.db' inst=Some(Call { dest: None, callee: "super().__init__", args: [] })
[14] node=589 method='__init__' var='this.db' inst=None
[15] node=7 method='insert_dataframe' var='self.db' inst=None
[16] node=152 method='close' var='self.db' inst=None
[17] node=198 method='get_table' var='self.db' inst=None
[18] node=252 method='execute_str' var='self.db' inst=None
[19] node=257 method='execute_str' var='self.db' inst=Some(Branch { cond: "parameters is None", then_block: [InstructionId(205), InstructionId(206)], else_block: None })
[20] node=260 method='execute_str' var='self.db' inst=Some(Call { dest: None, callee: "self.db.execute", args: ["sql"] })
[21] node=791 method='execute' var='self' inst=None
[22] node=806 method='execute' var='self' inst=Some(Branch { cond: "self.is_closed", then_block: [], else_block: Some([InstructionId(186)]) })
[23] node=801 method='execute' var='self' inst=Some(Branch { cond: "cursor is not None", then_block: [InstructionId(188)], else_block: Some([InstructionId(189)]) })
[24] node=803 method='execute' var='self' inst=Some(Call { dest: Some("result"), callee: "cursor.execute", args: ["*self.compile_to_args(query)"] })
[25] node=802 method='execute' var='self' inst=Some(Call { dest: Some("result"), callee: "cursor.execute", args: ["*self.compile_to_args(query)"] })
[26] node=800 method='execute' var='self' inst=Some(Call { dest: None, callee: "isinstance", args: ["query", "CreateTable"] })
[27] node=799 method='execute' var='self' inst=Some(Call { dest: None, callee: "isinstance", args: ["query", "CreateTable"] })
[28] node=794 method='execute' var='self' inst=Some(Branch { cond: "isinstance(query, CreateTable) and query.element.indexes", then_block: [InstructionId(194)], else_block: None })
[29] node=795 method='execute' var='self' inst=Some(Loop { cond: "index", body: [InstructionId(192), InstructionId(193)] })
[30] node=798 method='execute' var='self' inst=Some(Assign { dest: "index", src: "query.element.indexes" })
[31] node=797 method='execute' var='self' inst=Some(Call { dest: None, callee: "self.execute", args: ["CreateIndex(index, if_not_exists=True)", "cursor=cursor"] })
[32] node=791 method='execute' var='this' inst=None
[33] node=806 method='execute' var='this' inst=Some(Branch { cond: "self.is_closed", then_block: [], else_block: Some([InstructionId(186)]) })
[34] node=801 method='execute' var='this' inst=Some(Branch { cond: "cursor is not None", then_block: [InstructionId(188)], else_block: Some([InstructionId(189)]) })
[35] node=803 method='execute' var='this' inst=Some(Call { dest: Some("result"), callee: "cursor.execute", args: ["*self.compile_to_args(query)"] })
[36] node=802 method='execute' var='this' inst=Some(Call { dest: Some("result"), callee: "cursor.execute", args: ["*self.compile_to_args(query)"] })
[37] node=800 method='execute' var='this' inst=Some(Call { dest: None, callee: "isinstance", args: ["query", "CreateTable"] })
[38] node=799 method='execute' var='this' inst=Some(Call { dest: None, callee: "isinstance", args: ["query", "CreateTable"] })
[39] node=794 method='execute' var='this' inst=Some(Branch { cond: "isinstance(query, CreateTable) and query.element.indexes", then_block: [InstructionId(194)], else_block: None })
[40] node=793 method='execute' var='this' inst=Some(Return { val: Some("result") })
[41] node=792 method='execute' var='this' inst=None
[42] node=796 method='execute' var='self' inst=Some(Call { dest: None, callee: "self.execute", args: ["CreateIndex(index, if_not_exists=True)", "cursor=cursor"] })
[43] node=795 method='execute' var='self' inst=Some(Loop { cond: "index", body: [InstructionId(192), InstructionId(193)] })
[44] node=793 method='execute' var='self' inst=Some(Return { val: Some("result") })
[45] node=792 method='execute' var='self' inst=None
[46] node=477 method='_connect' var='db' inst=Some(Call { dest: None, callee: "db.execute", args: ["\"PRAGMA foreign_keys = ON\""] })
[47] node=476 method='_connect' var='db' inst=Some(Call { dest: None, callee: "db.execute", args: ["\"PRAGMA cache_size = -102400\""] })
[48] node=475 method='_connect' var='db' inst=Some(Call { dest: None, callee: "db.execute", args: ["\"PRAGMA cache_size = -102400\""] })
```

#### Code Context
```python
from datachain.data_storage.serializer import deserialize
from datachain.data_storage.sqlite import (
    SQLiteDatabaseEngine,
    get_db_file_in_memory,
)
from sqlalchemy import Column, Integer, Table
from tests.utils import skip_if_not_sqlite
import base64
import json
import os
import pytest

import base64
import json
import os
```

### Case #50: CWE-502 in datachain
- **Repository**: [https://github.com/iterative/datachain](https://github.com/iterative/datachain)
- **CWE**: CWE-502
- **Commit**: `914b95610620d50c8d9bee506ccbfa7d4d57fdc0`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `tests/test_sqlite.py (test parameter)`
- **Reasoning / Description**: The engine taints test parameters in sqlite_db test functions.

#### Forensic Trace Chain
```text
[0] node=932 method='test_table_in_transaction' var='sqlite_db' inst=None
[1] node=959 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: Some("table"), callee: "Table", args: ["\"test_table\"", "sqlite_db.metadata", "Column(\"id\", Integer, primary_key=True)"] })
[2] node=958 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: Some("table"), callee: "Table", args: ["\"test_table\"", "sqlite_db.metadata", "Column(\"id\", Integer, primary_key=True)"] })
[3] node=957 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: None, callee: "sqlite_db.has_table", args: ["\"test_table\""] })
[4] node=956 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: None, callee: "sqlite_db.has_table", args: ["\"test_table\""] })
[5] node=955 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: None, callee: "sqlite_db.has_table", args: ["\"test_table_2\""] })
[6] node=954 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: None, callee: "sqlite_db.has_table", args: ["\"test_table_2\""] })
[7] node=953 method='test_table_in_transaction' var='sqlite_db' inst=Some(Call { dest: None, callee: "sqlite_db.transaction", args: [] })
[8] node=602 method='transaction' var='self' inst=None
[9] node=606 method='transaction' var='db' inst=Some(Assign { dest: "db", src: "self.db" })
[10] node=605 method='transaction' var='db' inst=Some(Call { dest: None, callee: "db.execute", args: ["\"begin\""] })
[11] node=527 method='execute' var='self' inst=None
[12] node=542 method='execute' var='self' inst=Some(Branch { cond: "self.is_closed", then_block: [], else_block: Some([InstructionId(186)]) })
[13] node=544 method='execute' var='self' inst=Some(Call { dest: None, callee: "self._reconnect", args: [] })
[14] node=1040 method='_reconnect' var='self' inst=None
[15] node=1050 method='_reconnect' var='self' inst=Some(Branch { cond: "not self.is_closed", then_block: [InstructionId(173)], else_block: None })
[16] node=1049 method='_reconnect' var='self' inst=Some(Call { dest: Some("engine, metadata, db, db_file, max_variable_number"), callee: "self._connect", args: ["db_file=self.db_file"] })
[17] node=103 method='_connect' var='db_file' inst=None
[18] node=105 method='_connect' var='db_file' inst=Some(Try { body: [InstructionId(142), InstructionId(143), InstructionId(144), InstructionId(145), InstructionId(146), InstructionId(147), InstructionId(148), InstructionId(149), InstructionId(150), InstructionId(151), InstructionId(152), InstructionId(158), InstructionId(159), InstructionId(161), InstructionId(162), InstructionId(163), InstructionId(164)], catches: [InstructionId(166)], finally: None })
[19] node=146 method='_connect' var='db_file' inst=Some(Catch { exception_var: Some("RuntimeError"), body: [InstructionId(165)] })
[20] node=147 method='_connect' var='db_file' inst=Some(Throw { val: "DataChainError(\"Can't connect to SQLite DB\") from None" })
[21] node=104 method='_connect' var='db_file' inst=None
[22] node=1048 method='_reconnect' var='engine, metadata, db, db_file, max_variable_number' inst=Some(Call { dest: Some("engine, metadata, db, db_file, max_variable_number"), callee: "self._connect", args: ["db_file=self.db_file"] })
[23] node=1047 method='_reconnect' var='engine, metadata, db, db_file, max_variable_number' inst=Some(Assign { dest: "self.engine", src: "engine" })
[24] node=1046 method='_reconnect' var='db' inst=Some(Assign { dest: "self.metadata", src: "metadata" })
[25] node=1045 method='_reconnect' var='self.db' inst=Some(Assign { dest: "self.db", src: "db" })
[26] node=41 method='drop_table' var='self.db' inst=None
[27] node=84 method='get_table' var='self.db' inst=None
[28] node=211 method='cursor' var='self.db' inst=None
[29] node=288 method='has_table' var='self.db' inst=None
[30] node=468 method='close' var='self.db' inst=None
[31] node=509 method='__init__' var='self.db' inst=None
[32] node=517 method='create_table' var='self.db' inst=None
[33] node=527 method='execute' var='self.db' inst=None
[34] node=602 method='transaction' var='self.db' inst=None
[35] node=623 method='executemany' var='self.db' inst=None
[36] node=731 method='rename_table' var='self.db' inst=None
[37] node=748 method='clone' var='self.db' inst=None
[38] node=900 method='insert_dataframe' var='self.db' inst=None
[39] node=911 method='clone_params' var='self.db' inst=None
[40] node=1040 method='_reconnect' var='self.db' inst=None
[41] node=1055 method='execute_str' var='self.db' inst=None
[42] node=1094 method='table_names' var='self.db' inst=None
[43] node=1101 method='table_names' var='self.db' inst=Some(Assign { dest: "query", src: "\"SELECT name FROM sqlite_master WHERE type='table';\"" })
[44] node=1100 method='table_names' var='self.db' inst=Some(Call { dest: None, callee: "self.execute_str(query).fetchall", args: [] })
[45] node=1099 method='table_names' var='self.db' inst=Some(Call { dest: None, callee: "self.execute_str(query).fetchall", args: [] })
[46] node=1098 method='table_names' var='self.db' inst=Some(Call { dest: None, callee: "self.execute_str", args: ["query"] })
[47] node=1055 method='execute_str' var='self.db' inst=None
[48] node=1060 method='execute_str' var='self.db' inst=Some(Branch { cond: "parameters is None", then_block: [InstructionId(205), InstructionId(206)], else_block: None })
[49] node=1063 method='execute_str' var='self.db' inst=Some(Call { dest: None, callee: "self.db.execute", args: ["sql"] })
```

#### Code Context
```python


def test_table_in_transaction(sqlite_db):
    table = Table(
        "test_table", sqlite_db.metadata, Column("id", Integer, primary_key=True)
    )
    assert not sqlite_db.has_table("test_table")
    assert not sqlite_db.has_table("test_table_2")

    with sqlite_db.transaction():
        table.create(sqlite_db.engine)
        assert sqlite_db.has_table("test_table")
        assert not sqlite_db.has_table("test_table_2")

        sqlite_db.rename_table("test_table", "test_table_2")
        assert sqlite_db.has_table("test_table_2")
        assert not sqlite_db.has_table("test_table")

        sqlite_db.drop_table(Table("test_table_2", sqlite_db.metadata))
        assert not sqlite_db.has_table("test_table")
```

### Case #51: CWE-502 in datachain
- **Repository**: [https://github.com/iterative/datachain](https://github.com/iterative/datachain)
- **CWE**: CWE-502
- **Commit**: `914b95610620d50c8d9bee506ccbfa7d4d57fdc0`
- **Root Cause Category**: `FIELD_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `datachain/query/dataset.py (self.db)`
- **Reasoning / Description**: The engine propagates taint from database helpers through self.db using field-insensitive aliasing.

#### Forensic Trace Chain
```text
[0] node=198 method='get_dataset_sources' var='version' inst=None
[1] node=211 method='get_dataset_sources' var='self' inst=Some(Call { dest: Some("dr"), callee: "self.dataset_rows", args: ["dataset", "version"] })
[2] node=210 method='get_dataset_sources' var='dr' inst=Some(Call { dest: Some("dr"), callee: "self.dataset_rows", args: ["dataset", "version"] })
[3] node=209 method='get_dataset_sources' var='dr.select(dr.c("source", column="file"))' inst=Some(Call { dest: Some("query"), callee: "dr.select(dr.c(\"source\", column=\"file\")).distinct", args: [] })
[4] node=208 method='get_dataset_sources' var='query' inst=Some(Call { dest: Some("query"), callee: "dr.select(dr.c(\"source\", column=\"file\")).distinct", args: [] })
[5] node=207 method='get_dataset_sources' var='query' inst=Some(Call { dest: Some("cur"), callee: "self.db.cursor", args: [] })
[6] node=206 method='get_dataset_sources' var='query' inst=Some(Call { dest: Some("cur"), callee: "self.db.cursor", args: [] })
[7] node=205 method='get_dataset_sources' var='query' inst=Some(Assign { dest: "cur.row_factory", src: "sqlite3.Row" })
[8] node=204 method='get_dataset_sources' var='query' inst=Some(Call { dest: None, callee: "StorageURI", args: ["row[\"file__source\"]"] })
[9] node=203 method='get_dataset_sources' var='query' inst=Some(Call { dest: None, callee: "StorageURI", args: ["row[\"file__source\"]"] })
[10] node=202 method='get_dataset_sources' var='query' inst=Some(Call { dest: None, callee: "self.db.execute", args: ["query", "cursor=cur"] })
```

#### Code Context
```python
from datachain.data_storage.serializer import deserialize
from datachain.data_storage.sqlite import (
    SQLiteDatabaseEngine,
    get_db_file_in_memory,
)
from sqlalchemy import Column, Integer, Table
from tests.utils import skip_if_not_sqlite
import base64
import json
import os
import pytest

import base64
import json
import os
```

### Case #52: CWE-502 in datachain
- **Repository**: [https://github.com/iterative/datachain](https://github.com/iterative/datachain)
- **CWE**: CWE-502
- **Commit**: `914b95610620d50c8d9bee506ccbfa7d4d57fdc0`
- **Root Cause Category**: `FIELD_INSENSITIVE_PROPAGATION`
- **First Location of Over-Tainting**: `datachain/query/dataset.py (self.db)`
- **Reasoning / Description**: The engine propagates taint from database helpers through self.db using field-insensitive aliasing.

#### Forensic Trace Chain
```text
[0] node=194 method='merge_dataset_rows' var='src_version' inst=None
[1] node=224 method='merge_dataset_rows' var='src_version' inst=Some(Assign { dest: "dst_empty", src: "False" })
[2] node=223 method='merge_dataset_rows' var='self.db' inst=Some(Call { dest: None, callee: "self.db.has_table", args: ["self.dataset_table_name(src, src_version)"] })
[3] node=44 method='insert_rows' var='self.db' inst=None
[4] node=56 method='get_dataset_sources' var='self.db' inst=None
[5] node=104 method='insert_dataset_rows' var='self.db' inst=None
[6] node=194 method='merge_dataset_rows' var='self.db' inst=None
[7] node=320 method='clone_params' var='self.db' inst=None
[8] node=526 method='clone' var='self.db' inst=None
[9] node=719 method='is_ready' var='self.db' inst=None
[10] node=722 method='prepare_entries' var='self.db' inst=None
[11] node=736 method='__init__' var='self.db' inst=None
[12] node=746 method='__init__' var='self.db' inst=Some(Call { dest: Some("self.schema"), callee: "DefaultSchema", args: [] })
[13] node=745 method='__init__' var='self.db' inst=Some(Call { dest: Some("self.schema"), callee: "DefaultSchema", args: [] })
[14] node=744 method='__init__' var='self.db' inst=Some(Call { dest: None, callee: "super().__init__", args: [] })
[15] node=632 method='__init__' var='this.db' inst=None
[16] node=109 method='clone' var='self.db' inst=None
[17] node=331 method='clone_params' var='self.db' inst=None
[18] node=355 method='rename_table' var='self.db' inst=None
[19] node=420 method='table_names' var='self.db' inst=None
[20] node=498 method='close' var='self.db' inst=None
[21] node=507 method='execute_str' var='self.db' inst=None
[22] node=512 method='execute_str' var='self.db' inst=Some(Branch { cond: "parameters is None", then_block: [InstructionId(205), InstructionId(206)], else_block: None })
[23] node=515 method='execute_str' var='self.db' inst=Some(Call { dest: None, callee: "self.db.execute", args: ["sql"] })
[24] node=1093 method='execute' var='self' inst=None
[25] node=1108 method='execute' var='self' inst=Some(Branch { cond: "self.is_closed", then_block: [], else_block: Some([InstructionId(186)]) })
[26] node=1103 method='execute' var='self' inst=Some(Branch { cond: "cursor is not None", then_block: [InstructionId(188)], else_block: Some([InstructionId(189)]) })
[27] node=1105 method='execute' var='self' inst=Some(Call { dest: Some("result"), callee: "cursor.execute", args: ["*self.compile_to_args(query)"] })
[28] node=1104 method='execute' var='self' inst=Some(Call { dest: Some("result"), callee: "cursor.execute", args: ["*self.compile_to_args(query)"] })
[29] node=1102 method='execute' var='self' inst=Some(Call { dest: None, callee: "isinstance", args: ["query", "CreateTable"] })
[30] node=1101 method='execute' var='self' inst=Some(Call { dest: None, callee: "isinstance", args: ["query", "CreateTable"] })
[31] node=1096 method='execute' var='self' inst=Some(Branch { cond: "isinstance(query, CreateTable) and query.element.indexes", then_block: [InstructionId(194)], else_block: None })
[32] node=1095 method='execute' var='self' inst=Some(Return { val: Some("result") })
[33] node=1094 method='execute' var='self' inst=None
[34] node=514 method='execute_str' var='self.db' inst=Some(Call { dest: None, callee: "self.db.execute", args: ["sql"] })
[35] node=109 method='clone' var='self.db' inst=None
[36] node=331 method='clone_params' var='self.db' inst=None
[37] node=355 method='rename_table' var='self.db' inst=None
[38] node=420 method='table_names' var='self.db' inst=None
[39] node=498 method='close' var='self.db' inst=None
[40] node=507 method='execute_str' var='self.db' inst=None
[41] node=545 method='get_table' var='self.db' inst=None
[42] node=553 method='create_table' var='self.db' inst=None
[43] node=563 method='insert_dataframe' var='self.db' inst=None
[44] node=632 method='__init__' var='self.db' inst=None
[45] node=655 method='executemany' var='self.db' inst=None
[46] node=664 method='executemany' var='self.db' inst=Some(Branch { cond: "cursor", then_block: [InstructionId(197), InstructionId(198)], else_block: None })
[47] node=660 method='executemany' var='self.db' inst=Some(Branch { cond: "conn", then_block: [InstructionId(200), InstructionId(201)], else_block: None })
[48] node=659 method='executemany' var='self.db' inst=Some(Call { dest: None, callee: "self.db.executemany", args: ["self.compile(query).string", "params"] })
[49] node=655 method='executemany' var='self' inst=None
[50] node=664 method='executemany' var='self' inst=Some(Branch { cond: "cursor", then_block: [InstructionId(197), InstructionId(198)], else_block: None })
[51] node=667 method='executemany' var='self' inst=Some(Call { dest: None, callee: "cursor.executemany", args: ["self.compile(query).string", "params"] })
[52] node=655 method='executemany' var='query' inst=None
[53] node=664 method='executemany' var='query' inst=Some(Branch { cond: "cursor", then_block: [InstructionId(197), InstructionId(198)], else_block: None })
[54] node=667 method='executemany' var='query' inst=Some(Call { dest: None, callee: "cursor.executemany", args: ["self.compile(query).string", "params"] })
[55] node=666 method='executemany' var='query' inst=Some(Call { dest: None, callee: "cursor.executemany", args: ["self.compile(query).string", "params"] })
[56] node=665 method='executemany' var='query' inst=Some(Return { val: Some("cursor.executemany(self.compile(query).string, params)") })
[57] node=656 method='executemany' var='query' inst=None
[58] node=666 method='executemany' var='self.compile(query).string' inst=Some(Call { dest: None, callee: "cursor.executemany", args: ["self.compile(query).string", "params"] })
```

#### Code Context
```python
from datachain.data_storage.serializer import deserialize
from datachain.data_storage.sqlite import (
    SQLiteDatabaseEngine,
    get_db_file_in_memory,
)
from sqlalchemy import Column, Integer, Table
from tests.utils import skip_if_not_sqlite
import base64
import json
import os
import pytest

import base64
import json
import os
```

### Case #53: CWE-502 in datachain
- **Repository**: [https://github.com/iterative/datachain](https://github.com/iterative/datachain)
- **CWE**: CWE-502
- **Commit**: `914b95610620d50c8d9bee506ccbfa7d4d57fdc0`
- **Root Cause Category**: `SOURCE_OVERMATCH`
- **First Location of Over-Tainting**: `tests/test_sqlite.py (test parameter)`
- **Reasoning / Description**: The engine taints test parameters in sqlite_db test functions.

#### Forensic Trace Chain
```text
[0] node=361 method='test_serialize' var='sqlite_db' inst=None
[1] node=376 method='test_serialize' var='sqlite_db' inst=Some(Call { dest: Some("serialized"), callee: "sqlite_db.serialize", args: [] })
[2] node=738 method='serialize' var='self' inst=None
[3] node=746 method='serialize' var='self' inst=Some(Call { dest: None, callee: "_ensure_default_callables_registered", args: [] })
[4] node=745 method='serialize' var='self' inst=Some(Call { dest: None, callee: "_ensure_default_callables_registered", args: [] })
[5] node=744 method='serialize' var='self' inst=Some(Call { dest: Some("data"), callee: "self.clone_params", args: [] })
[6] node=743 method='serialize' var='self' inst=Some(Call { dest: Some("data"), callee: "self.clone_params", args: [] })
[7] node=742 method='serialize' var='self' inst=Some(Call { dest: None, callee: "base64.b64encode(json.dumps(self._prepare(data)).encode()).decode", args: [] })
[8] node=741 method='serialize' var='self' inst=Some(Call { dest: None, callee: "base64.b64encode(json.dumps(self._prepare(data)).encode()).decode", args: [] })
[9] node=740 method='serialize' var='self' inst=Some(Return { val: Some("base64.b64encode(json.dumps(self._prepare(data)).encode()).decode()") })
[10] node=739 method='serialize' var='self' inst=None
[11] node=375 method='test_serialize' var='serialized' inst=Some(Call { dest: Some("serialized"), callee: "sqlite_db.serialize", args: [] })
[12] node=374 method='test_serialize' var='serialized' inst=Some(Call { dest: Some("raw"), callee: "base64.b64decode", args: ["serialized.encode()"] })
[13] node=373 method='test_serialize' var='serialized' inst=Some(Call { dest: Some("raw"), callee: "base64.b64decode", args: ["serialized.encode()"] })
[14] node=372 method='test_serialize' var='serialized' inst=Some(Call { dest: Some("data"), callee: "json.loads", args: ["raw.decode()"] })
[15] node=371 method='test_serialize' var='serialized' inst=Some(Call { dest: Some("data"), callee: "json.loads", args: ["raw.decode()"] })
[16] node=370 method='test_serialize' var='serialized' inst=Some(Call { dest: Some("obj3"), callee: "deserialize", args: ["serialized"] })
```

#### Code Context
```python


def test_serialize(sqlite_db):
    # JSON serialization format
    serialized = sqlite_db.serialize()
    assert serialized
    raw = base64.b64decode(serialized.encode())
    data = json.loads(raw.decode())
    assert data["callable"] == "sqlite.from_db_file"
    assert data["args"] == [":memory:"]
    assert data["kwargs"] == {}

    obj3 = deserialize(serialized)
    assert isinstance(obj3, SQLiteDatabaseEngine)
    assert obj3.db_file == ":memory:"
    assert obj3.clone_params() == sqlite_db.clone_params()


def test_table(sqlite_db):
    table = Table(
```


## Architectural Precision-Hardening Roadmap

To resolve these 53 non-pgAdmin False Positives without degrading search recall, the TaintFlow engine requires systematic precision-hardening across four architectural pillars:

### 1. 1-CFA (Context-Sensitive Call Graph Analysis)
- **Problem**: Context-insensitivity causes taint to leak from one method caller to other callers of the same method (e.g. `client.import_ovpack` in Volcano Engine).
- **Hardening**:
  - Implement a **1-CFA (1-Call-Site Context-Sensitive)** algorithm for the Interprocedural Call Graph.
  - Clone call targets based on their immediate caller's call site instruction ID, matching the call stack context and preventing call-return matching leakage across sibling methods.

### 2. Sink-Argument Sensitivity and Gating
- **Problem**: The engine treats a sink call as tainted if *any* parameter is tainted, leading to false positives on safe parameters (e.g. `mode` parameter in `open(filepath, mode)` or `flags` parameter in `os.open(path, flags)`).
- **Hardening**:
  - Refactor sink modeling to be **argument-specific**. Define which parameter indices are actual vulnerability targets (e.g. argument `0` for path traversal in `open`).
  - Introduce **context-aware sanitizers** (e.g. PyTorch `torch.load(..., weights_only=True)` should automatically disable the CWE-502 sink check).

### 3. Test Code Exclusion / Strict Source Seeding
- **Problem**: Treating all function/method parameters in test code as untrusted entry-point sources (e.g. pytest fixtures `url`, `csv_deserializer` in `ethyca/fides` and `aws/sagemaker-python-sdk`).
- **Hardening**:
  - Implement file-pattern filtering or prefix matching (`test_*.py`, classes/methods starting with `Test`/`test_`) to disable automatic parameter source seeding for test suites.
  - Rely exclusively on explicit framework sources (HTTP requests, CLI inputs) in test files rather than generic parameter seeding.

### 4. Stub Isolation / Local Utility Wrapper Filtering
- **Problem**: Mock helper stubs (e.g. `HDFSClient` for PaddlePaddle) contain self-contained flows (e.g. `local_path` -> `subprocess.run` inside `upload`) that leak and register as vulnerabilities for target files that do not even call them.
- **Hardening**:
  - Filter interprocedural flows to verify that the propagation path intersects with the **target source file** being analyzed.
  - Restrict interprocedural path reporting to only include flows where at least one node belongs to the target file.
