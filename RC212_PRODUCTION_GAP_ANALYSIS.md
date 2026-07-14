# RC212: Production Gap Analysis

This report documents the forensic evaluation of TaintFlow against five enterprise-grade production Java codebases. The scans were successfully executed using the `taintflow-cli` scanner binary, revealing clear evidence of framework gaps and rule configurations.

---

## 1. Scan Statistics

| Repository | Files Scanned | Active Findings | Runtime (s) | Memory (GB) | Crashes | Parser Gaps |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Spring PetClinic** | 48 | 0 | ~1 | ~0.1 | 0 | 0 |
| **Shopizer** | 1,204 | 64 | ~35 | ~1.5 | 0 | 0 |
| **OpenSearch Security** | 1,133 | 175 | ~25 | ~1.8 | 0 | 0 |
| **Apache Fineract** | 6,507 | 213 | ~55 | ~3.8 | 0 | 0 |
| **Keycloak** | 8,126 | 659 | ~70 | ~4.5 | 0 | 0 |

---

## 2. Findings Classification & Forensic Audit

Auditing the generated logs reveals the following classifications:

### A. Test Directory Noise (Shopizer, Fineract, OpenSearch)
- **Classification**: **False Positive** (Noise)
- **Finding Examples**: `MerchantStoreApiIntegrationTest.java` (Shopizer), `CommandSampleApiTest.java` (Fineract), `SecurityBackwardsCompatibilityIT.java` (OpenSearch).
- **First Architectural Divergence**: **Missing target file filter/exclusion list**. The parser recursively processes `src/test/java` folders, treating test-specific mock HTTP calls and mock credential configs as valid source-to-sink paths.

### B. Local Configuration/Resource Loading (Shopizer, Keycloak)
- **Classification**: **False Positive**
- **Finding Examples**: `ZonesLoader.java` (Shopizer), `PrincipalNameMappingParser.java` (Keycloak).
- **First Architectural Divergence**: **Overly conservative Source Seeding rule**. Reading from local classpath XML/JSON configuration files (e.g. `resource.getInputStream()`, `StaxParserUtil.getAttributeValueRP(...)`) is flagged as untrusted network inputs, whereas these files are static packaged config descriptors.

### C. Rule Specification Defect (OpenSearch Security)
- **Classification**: **False Positive** (Rule bug)
- **Finding Example**: `RestHelper.java` (CWE-327)
- **First Architectural Divergence**: **Inexact regex/keyword matching in rules engine**. The cryptographic rule mapped `client.getNodes().size()` to a weak cryptographic cipher because of the `.size()` name matching block.

---

## 3. Parser & Solver Failures
No parser crashes or memory leaks were encountered. All files lowered successfully to the Intermediate Representation (IR).

---

## 4. Priority-Ranked Production Gap Backlog

### Priority 1: High Production Impact, Low Engineering Cost
1. **Exclude Test Subtrees**: Ignore `src/test/` directory patterns during recursive file collection to eliminate test-runner FPs instantly.
2. **Refine CWE-327 Rule Specification**: Harden rule selectors for cryptography to ensure calls to `.size()` or basic structure properties are not flagged as ciphers.

### Priority 2: High Production Impact, Medium Engineering Cost
1. **Exclude Classpath Resource Streams**: Skip seeding `getInputStream()` if the receiver variable originates from a classloader or jar resources instead of an HTTP Servlet.
