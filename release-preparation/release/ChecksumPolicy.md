# Checksum Policy

All binary releases must be accompanied by SHA-256 hashes to allow consumers to verify download integrity.

---

## Checksum Standards
- **Hashing Algorithm**: SHA-256 (SHA-1 and MD5 are deprecated).
- **Naming**: The checksums must be compiled in a single `SHA256SUMS` file.

---

## Verification Guide
To verify your downloaded binary archive matches the release build:

```bash
# Verify checksum hashes
sha256sum --check SHA256SUMS
```

See [SigningStrategy.md](SigningStrategy.md) to verify GPG signatures.
