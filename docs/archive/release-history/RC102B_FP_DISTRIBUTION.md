# RC102B: False Positive Distribution Analysis

This report quantifies the distribution of all 53 non-pgAdmin False Positives (FPs) identified in the GitHub Holdout validation dataset.

## FP Category Distribution Table

| Root Cause Category | Count | Percentage | Affected Repositories | Affected CWEs |
| :--- | :---: | :---: | :--- | :--- |
| `WRAPPER_PROPAGATION_OVERTAINTING` | 15 | 28.30% | LLaMA-Factory, Paddle, firefighter-incident, mlflow, pygeoapi, ray, salt, snowflake-connector-python, transformers | CWE-22, CWE-502, CWE-918 |
| `SOURCE_OVERMATCH` | 13 | 24.53% | datachain, fides, sagemaker-python-sdk, snowflake-connector-python | CWE-22, CWE-502, CWE-89, CWE-918 |
| `SINK_ARGUMENT_INSENSITIVITY` | 8 | 15.09% | salt, snowflake-connector-python | CWE-22, CWE-502 |
| `MOCK_HELPER_FLOW_LEAKAGE` | 6 | 11.32% | Paddle | CWE-78 |
| `OTHER` (Field / Sanitizer Gaps) | 10 | 18.76% | binderhub, datachain, label-studio, snowflake-connector-python, transformers | CWE-502, CWE-78, CWE-918 |
| **Total** | **53** | **100.00%** | | |

*Note: The `OTHER` category contains 6 cases of `FIELD_INSENSITIVE_PROPAGATION` (datachain, snowflake-connector-python) and 4 cases of `SANITIZER_MODELING_GAP` (binderhub, label-studio, transformers).*

## Simulated Impact of Category Removal

The table below calculates the simulated precision and Matthews Correlation Coefficient (MCC) for both the GitHub dataset and the Combined dataset assuming each category of FPs was resolved perfectly (reducing FP count and increasing TN count proportionally).

| Category Removed | FP Reduction | GitHub Precision | GitHub MCC | Combined Precision | Combined MCC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| *Baseline* | *0* | *0.5328* | *0.1478* | *0.7627* | *0.6051* |
| `CONTEXT_INSENSITIVE_PROPAGATION` | 1 | 0.5372 | 0.1636 | 0.7630 | 0.6054 |
| `SINK_ARGUMENT_INSENSITIVITY` | 8 | 0.5702 | 0.2649 | 0.7657 | 0.6090 |
| `WRAPPER_PROPAGATION_OVERTAINTING` | 15 | 0.6075 | 0.3560 | 0.7683 | 0.6127 |
| `MOCK_HELPER_FLOW_LEAKAGE` | 6 | 0.5603 | 0.2373 | 0.7649 | 0.6080 |
| `SOURCE_OVERMATCH` | 13 | 0.5963 | 0.3307 | 0.7676 | 0.6117 |
| `OTHER` | 10 | 0.5804 | 0.2917 | 0.7664 | 0.6101 |
