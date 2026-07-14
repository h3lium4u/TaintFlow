# Distribution Channels

This document describes the distribution routes for TaintFlow binaries.

---

## Channels

### 1. GitHub Releases (Primary Channel)
- **Target Audience**: Developers compiling from source or downloading raw binary archives.
- **Assets**: Source code zip/tarball, compiled zip/tarball architectures, checksums, GPG signatures, and SBOM.

### 2. Crates.io (crates.io/crates/taintflow-cli)
- **Target Audience**: Rust developers installing via Cargo.
- **Publish Command**:
  ```bash
  cargo publish -p taintflow-cli
  ```

### 3. Package Managers (Future Releases)
- **Homebrew (macOS/Linux)**: We will maintain a `homebrew-taintflow` tap repository containing the installer formula.
- **Scoop (Windows)**: A manifest file will be pushed to the Scoop bucket repository.
