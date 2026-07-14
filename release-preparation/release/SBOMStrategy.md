# Software Bill of Materials (SBOM) Strategy

To meet enterprise compliance, we publish a Software Bill of Materials (SBOM) listing all dependencies compiled into the TaintFlow engine.

---

## SBOM Standards
- **Format**: SPDX JSON.
- **Specification**: SPDX v2.2.

---

## Generation Procedure
We generate the SBOM during the release build pipeline using `cargo-sbom` or `cargo-spdx`:

1. **Install Generator**:
   ```bash
   cargo install cargo-sbom
   ```
2. **Generate SBOM**:
   ```bash
   cargo sbom --format spdx-json > sbom.spdx.json
   ```
3. **Distribution**:
   Attach the resulting `sbom.spdx.json` to the GitHub release.

See [ChecksumPolicy.md](ChecksumPolicy.md) for checksumming the SBOM.
