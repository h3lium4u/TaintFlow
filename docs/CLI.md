# CLI Command Reference

This document covers all CLI parameters and flags supported by `taintflow-cli`.

---

## Commands

### `scan`
Scan a codebase directory or single file.
```bash
taintflow-cli scan <path> [options]
```

---

## Options

### `--format`
Specify the output report format.
- **Values**: `text` (default), `json`, `sarif`.
```bash
--format sarif
```

### `--output`
Write findings to a file instead of stdout.
```bash
--output report.sarif
```

### `--severity`
Filter findings by minimum severity level.
- **Values**: `LOW`, `MEDIUM`, `HIGH`.
```bash
--severity HIGH
```

### `--scan-tests`
By default, TaintFlow excludes directories named `test`, `tests`, or `src/test/` to eliminate test-only findings. Pass this flag to include them.
```bash
--scan-tests
```
For more information on output configurations, refer to [SARIF.md](SARIF.md).
