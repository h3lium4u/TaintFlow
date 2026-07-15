# RC103 Lost True Positives

This report catalogs the True Positives (TPs) that regressed into False Negatives (FNs) during the RC103 hardening sprint.

## 1. Vul4J Dataset Losses
**Total Lost: 12 TPs**
*   **Repository:** `Vul4J (Various)`
*   **CWEs:** CWE-79, CWE-22, CWE-502, CWE-918
*   **Source:** Public wrapper methods (e.g., `resolve`, `welcome`)
*   **Sink:** Various (e.g., `File()`, SQL queries, URL decoders)
*   **First Failing Stage:** Source Seeding (Entrypoint Discovery)
*   **Root Cause:** `SOURCE_SEEDING_REFINEMENT` / `ENTRYPOINT_DISCOVERY`. The test-file skip logic caused `total_callers` to evaluate to 0 for these methods. Under the new refinement rules, non-constructor methods with 0 callers were aggressively filtered out, preventing any taint from being seeded.

## 2. GitHub Holdout Losses
**Total Lost: ~24 TPs (Net impact: -2 TP, +24 FN due to dataset expansion)**
*   **Repository:** `PaddlePaddle / GitPython`
*   **CWEs:** CWE-78, CWE-22
*   **Source:** Private helper methods (e.g., `def _wget_download()`)
*   **Sink:** `subprocess.Popen`, `os.path.join`
*   **First Failing Stage:** Source Seeding
*   **Root Cause:** `SOURCE_SEEDING_REFINEMENT`. The strict `!method.name.starts_with('_')` check categorically banned all Python private helper methods from acting as entry points, severing valid intra-file taint flows.

*   **Repository:** `Snowflake / Fides`
*   **CWEs:** CWE-502
*   **Source:** Parameter-less loaders / Field initializers
*   **Sink:** `pickle.loads()`, `yaml.load()`
*   **First Failing Stage:** Sink Argument Seeding
*   **Root Cause:** `SINK_ARGUMENT_GATING`. The requirement that a method must possess explicit parameters to force-seed a deserialization sink blocked flows where the configuration state was loaded via `self` attributes or parameter-less initialization.

## 3. OWASP Benchmark Losses
**Total Lost: ~15 TPs**
*   **Repository:** `OWASP`
*   **CWEs:** Mixed
*   **Source:** Test endpoints
*   **Sink:** Various
*   **First Failing Stage:** Source Seeding
*   **Root Cause:** `SOURCE_SEEDING_REFINEMENT`. Peripheral test cases and helper wrappers fell victim to the tightened uncalled-method filters.
