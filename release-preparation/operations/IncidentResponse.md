# Incident Response Plan

This document outlines how TaintFlow maintainers respond to security incidents.

---

## Response Steps

### 1. Triage
Verify the incident (e.g. compromised release binary, parser buffer overflow vulnerability). Assign severity level.

### 2. Containment
- Marking affected releases as pre-release or yanking crates.io package versions.
- Notifying downstream users via GitHub security advisory banners.

### 3. Patching & Remediation
Develop a patch privately (see [SecurityReleaseProcess.md](../release/SecurityReleaseProcess.md)) and publish fixed version `v1.x.y` to all distribution channels.
