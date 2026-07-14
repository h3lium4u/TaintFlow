# Security Policy

TaintFlow is a static analysis security tool. We take the security of this analyzer and the codebases it scans seriously. This document outlines how to report vulnerabilities discovered within TaintFlow itself.

---

## Supported Versions

Only the latest release version of TaintFlow receives active security updates.

| Version | Supported |
| :--- | :---: |
| **v1.0.x** | ✅ Yes |
| **Pre-releases / RC** | ❌ No |

---

## Reporting a Vulnerability

**DO NOT file public GitHub Issues for security vulnerabilities.**

If you discover a security vulnerability in TaintFlow (such as a parser crash exploit, remote code execution vector during code ingestion, or privilege escalation), please report it via private channel:

1. **Email**: Send a detailed report to [security@taintflow.org](mailto:security@taintflow.org).
2. **PGP Key**: Encrypt your message using our security PGP key (available on request).

### What to Include
To help us evaluate and patch the issue quickly, please provide:
- A descriptive title.
- Affected component (e.g. Parser, CLI, Solver).
- A minimal working proof of concept (PoC) codebase that triggers the vulnerability when scanned.
- Estimated impact and severity.

---

## Disclosure Process

1. **Acknowledgment**: We will acknowledge receipt of your report within **24 hours**.
2. **Evaluation & Triage**: Our team will evaluate the impact and reply with a status update within **3 business days**.
3. **Patch Development**: If verified, we will develop a patch.
4. **Coordinated Release**: We aim to release a patched version within **30 days** of triage, accompanied by a public security advisory acknowledging your contribution (if desired).
