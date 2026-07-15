# Troubleshooting Guide

This guide helps you resolve common execution errors.

---

## Common Issues

### 1. `[WARNING] Control Flow Graph node limit exceeded`
- **Cause**: The file being analyzed has a extremely high cyclomatic complexity (exceeding maximum statement nodes limit).
- **Solution**: Split complex files or exclude them from scans using `.taintignore` (see [Configuration.md](Configuration.md)).

### 2. `error: could not find Cargo.toml`
- **Cause**: Trying to compile outside the `rust-engine/` workspace.
- **Solution**: Navigate to the directory containing the cargo project:
  ```bash
  cd taintflow/rust-engine
  cargo build --release
  ```

---

## Obtaining Help
If your issue is not covered here, refer to [SUPPORT.md](../SUPPORT.md) or submit a bug report via GitHub Issues.
