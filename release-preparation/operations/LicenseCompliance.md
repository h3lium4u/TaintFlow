# License Compliance

This document outlines how TaintFlow verifies and enforces open-source license compliance.

---

## Enforcement Methods
We utilize automated checks inside our continuous integration suite:
1. **Verification Job**: Every pull request runs:
   ```bash
   cargo deny check licenses
   ```
2. **Alerts**: Any pull request that attempts to add a dependency with a restricted license (e.g. GPL) is blocked automatically.
Refer to [ThirdPartyLicensesPolicy.md](ThirdPartyLicensesPolicy.md) for details on allowed licenses.
