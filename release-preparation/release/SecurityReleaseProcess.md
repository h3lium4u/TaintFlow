# Security Release Process

This document defines the protocols for releasing security patches to TaintFlow.

---

## Process Workflow

### 1. Verification & Patching
- Develop a security fix privately in a local workspace branch.
- **Do NOT push this branch to any public repository.**
- Run unit tests and validation sets locally.

### 2. CVE Assignment
- Request a CVE ID via GitHub Security Advisories (GHSA).
- Draft a private security advisory outlining:
  - Vulnerability class (CWE).
  - Remediation guidance.
  - Affected vs. patched version bounds.

### 3. Release Coordination
- Schedule the release date.
- Push the patch directly to the main production release branch.
- Publish the GHS Advisory and coordinate public disclosure.
- Refer to [Security Policy](../SECURITY.md) for vulnerability reporting.
