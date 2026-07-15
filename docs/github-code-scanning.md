# GitHub Security Code Scanning Integration Guide

This guide details the integration of **TaintFlow SAST** with GitHub Advanced Security (GHAS) Code Scanning.

---

## 1. Setup Instructions

To integrate TaintFlow scans and display findings inside the repository's **Security** tab, configure a workflow file under `.github/workflows/taintflow-security.yml`.

### Example Configuration

```yaml
name: TaintFlow Security Scan

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  taintflow:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run TaintFlow SAST Scan
        uses: h3lium4u/taintflow-action@v1
        with:
          path: .
          format: sarif
          output: taintflow-results.sarif

      - name: Upload SARIF Report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: taintflow-results.sarif
```

---

## 2. Required Permissions

The workflow must run with the following permissions block declared:
- **`security-events: write`**: Grants write access to upload the generated SARIF report to the Code Scanning API.
- **`contents: read`**: Allows the Action runner to check out the repository's file tree.

---

## 3. Viewing Findings in GitHub

Once the workflow finishes:
1. Navigate to the **Security** tab of your repository on GitHub.
2. Select **Code scanning** from the left-hand sidebar menu.
3. Review warnings, vulnerable flows, and CWE classifications mapped directly on your code lines.
