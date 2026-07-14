# Compatibility Guarantees

TaintFlow provides the following compatibility commitments across release versions.

---

## Guarantees

- **CLI Compatibility**: Command-line arguments (`scan`, `--format`, `--output`) will remain backward-compatible within a major release version.
- **Rule Engine Compatibility**: Customized taint rules written for v1.0.0 will compile and run on all subsequent v1.y.z versions.
- **Report Schema Compatibility**: SARIF output follows the v2.1.0 specification and will not introduce breaking layout adjustments.
