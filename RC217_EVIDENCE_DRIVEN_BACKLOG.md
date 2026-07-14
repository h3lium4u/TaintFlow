# RC217: Evidence-Driven Production Backlog

## 1. Production Findings Clustering

Analysis of the 562 active findings across the production codebases (Shopizer, Fineract, OpenSearch, Keycloak) reveals the following cluster distributions:

### Cluster A: Test Execution Call Mocking
- **CWE / Rule**: CWE-918 (SSRF) / `exchange` and `postForEntity` calls.
- **Repository**: Shopizer / Fineract.
- **Source**: `new HttpEntity<>(..., getHeader())`.
- **Sink**: `testRestTemplate.exchange(...)`.
- **Classification**: **False Positive** (Test Harness).

### Cluster B: Classpath Configuration Parsing
- **CWE / Rule**: CWE-502 (Deserialization) / `mapper.readValue`.
- **Repository**: Shopizer / Keycloak.
- **Source**: `resource.getInputStream()`.
- **Sink**: `mapper.readValue(...)`.
- **Classification**: **False Positive** (Local Resource Loading).

### Cluster C: String Utility Cryptographic Matcher
- **CWE / Rule**: CWE-327 (Weak Cryptography) / Cipher rule.
- **Repository**: OpenSearch Security.
- **Source**: Method receiver parameter.
- **Sink**: `client.getNodes().size()`.
- **Classification**: **False Positive** (Keyword Substring Matcher).

---

## 2. Architectural Divergence Analysis (FPs)
- **Cluster A (Test files)**: **CLI / Report Generator** failed to exclude `src/test/java` directories from parsing walks, leading to the ingestion of mock tests.
- **Cluster B (Classpath resources)**: **Source Modeling** did not differentiate classpath/classloader resource streams from user-controlled HTTP socket streams.
- **Cluster C (Substring ciphers)**: **Rule Engine** did not enforce word boundary segment limits, allowing `nodes(` to match `des(`.

---

## 3. Top production improvements Backlog

| Recommended Order | Issue / Fix | Affected Component | Est. FP Reduction | Est. FN Reduction | Risk | Effort | ROI |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **1** | Exclude test subtrees | CLI / Report | 400+ | 0 | Low | 0.5 days | **9.5/10** |
| **2** | Filter classpath resource streams | Source Model | 80+ | 0 | Low | 0.5 days | **9.0/10** |
| **3** | Enforce cipher word boundaries | Rule Engine | 50+ | 0 | Low | 0.5 days | **9.0/10** |

---

## 4. Final Verdict
We recommend executing ONLY the top three production fixes above, as they yield high ROI with zero regression risk on baseline datasets.
