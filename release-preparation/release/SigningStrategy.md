# Signing Strategy

This document outlines how TaintFlow binaries are signed to ensure integrity and authenticity.

---

## GPG Key Requirements
- **Key Type**: RSA 4096-bit or Ed25519.
- **Key Expiry**: Maximum 2 years.
- **Access**: Managed securely inside GitHub Secrets for release automation or by designated release engineers.

---

## Signing Process

1. **Create Checksums**: Generate the SHA-256 checksums file:
   ```bash
   sha256sum taintflow-cli-*.tar.gz taintflow-cli-*.zip > SHA256SUMS
   ```
2. **Sign Checksums File**: Sign the checksums file using the GPG release key:
   ```bash
   gpg --detach-sign --armor SHA256SUMS
   ```
   This generates `SHA256SUMS.sig`.
3. **Distribution**: Upload `SHA256SUMS` and `SHA256SUMS.sig` to the release attachments.
