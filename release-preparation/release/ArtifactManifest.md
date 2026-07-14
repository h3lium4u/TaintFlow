# Artifact Manifest

This document outlines all compiled assets generated for a TaintFlow release.

---

## Binary Targets

### Linux (x86_64-unknown-linux-gnu)
- **Archive File**: `taintflow-cli-x86_64-unknown-linux-gnu.tar.gz`
- **Contents**: `taintflow-cli` (binary), `LICENSE`, `README.md`.

### Windows (x86_64-pc-windows-msvc)
- **Archive File**: `taintflow-cli-x86_64-pc-windows-msvc.zip`
- **Contents**: `taintflow-cli.exe` (binary), `LICENSE`, `README.md`.

### macOS (x86_64-apple-darwin & aarch64-apple-darwin)
- **Archive File**: `taintflow-cli-x86_64-apple-darwin.tar.gz` / `taintflow-cli-aarch64-apple-darwin.tar.gz`
- **Contents**: `taintflow-cli` (binary), `LICENSE`, `README.md`.

---

## Metadata Assets
- **`SHA256SUMS`**: Flat text file listing SHA-256 checksums of all binaries.
- **`SHA256SUMS.sig`**: GPG signature verifying `SHA256SUMS`.
- **`sbom.spdx.json`**: Software Bill of Materials (SBOM) for Rust dependencies (see [SBOMStrategy.md](SBOMStrategy.md)).
