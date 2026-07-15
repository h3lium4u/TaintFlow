# Quick Start Guide

Get up and running with TaintFlow in under 5 minutes.

---

## 1. Scan a Project
To run a security scan over a project directory and print results to the console:
```bash
./taintflow-cli scan /path/to/your/project
```

---

## 2. Exporting to SARIF
To generate a standardized report for GitHub Actions or IDE integration:
```bash
./taintflow-cli scan /path/to/project --format sarif --output report.sarif
```
See [SARIF.md](SARIF.md) for details on the schema structure.

---

## 3. Custom Severity Filtering
Limit findings to high-severity vulnerabilities only:
```bash
./taintflow-cli scan /path/to/project --severity HIGH
```

---

## Next Steps
- Learn how to configure rules in [Configuration.md](Configuration.md).
- View all CLI arguments in [CLI.md](CLI.md).
