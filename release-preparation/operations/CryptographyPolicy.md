# Cryptography Policy

TaintFlow is an offline static analyzer and does not implement custom transport cryptography.

---

## Policies

- **Core Engine**: TaintFlow does not contain cryptographic algorithms or network transport layers.
- **Rule Verification (CWE-327)**: Weak cryptography rules check for unsafe configurations (e.g. DES, MD5 ciphers) statically within the user's source code.
- **Release Assets**: All release binaries and checksum files are cryptographically signed using GPG (see [SigningStrategy.md](../release/SigningStrategy.md)).
