# RC102B: Context-Sensitivity Feasibility Study

This study analyzes the actual False Positive traces from the `RC102_FP_CASEBOOK.md` to evaluate the effectiveness and necessity of context-sensitivity (1-CFA), alias analysis, and field sensitivity.

## Technical Feasibility Mapping

| Static Analysis Feature | FPs Resolved | Percentage of Total FPs | Target Cases | Details |
| :--- | :---: | :---: | :--- | :--- |
| **Simple Call-Site Tagging** | 1 | 1.89% | Case #1 (OpenViking) | Filters out mismatched call-return returns without full target cloning. |
| **True 1-CFA** | 1 | 1.89% | Case #1 (OpenViking) | Contextualizes call targets based on caller site. Sufficient but overkill for Case #1. |
| **Alias Analysis** | 6 | 11.32% | Snowflake (Cases #14, #16, #20), Datachain (Cases #49, #51, #52) | Necessary to track separate dictionary pointer variables and member fields. |
| **Field Sensitivity** | 6 | 11.32% | Snowflake (Cases #14, #16, #20), Datachain (Cases #49, #51, #52) | Essential to separate `self.db` or dictionary keys from other properties on the same object. |

## Crucial Insights

1. **Context-Sensitivity Has Low Immediate ROI**:
   - Only **1 FP** in the entire 53-sample set disappears due to pure call-site context-insensitivity (Case #1 OpenViking). 
   - A full interprocedural context-sensitive refactor (1-CFA) would require weeks of engineering but only yield a **+0.0158 GitHub MCC gain**.
2. **Alias and Field Sensitivity are Interdependent**:
   - The 6 FPs under `FIELD_INSENSITIVE_PROPAGATION` (representing Snowflake's `session_parameters` dictionary lookups and Datachain's `self.db` reference) cannot be solved by field sensitivity alone; they require object aliasing awareness to trace back references to target structures.
3. **No Effect on Wrapper/Fixture Over-Tainting**:
   - Context sensitivity, alias analysis, and field sensitivity **do not resolve** the 28 FPs under `WRAPPER_PROPAGATION_OVERTAINTING` and `SOURCE_OVERMATCH`. In these cases, the taint is introduced directly at the local helper boundary or test parameter, so no call-return mismatch or field aliasing is involved.
