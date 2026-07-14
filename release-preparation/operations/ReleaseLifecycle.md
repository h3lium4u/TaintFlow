# Release Lifecycle Policy

TaintFlow releases transition through four phases: Active Development, Release Candidates, General Availability (GA), and End-of-Life (EOL).

---

## 1. Phases

### Active Development
- Feature branch builds.
- PR verification runs.

### Release Candidates (RC)
- Feature freeze is declared.
- Iterative RC tags are pushed to verify correctness, compile binaries, and execute the full validation suite.

### General Availability (GA)
- Certified builds tagged as stable.
- Published to crates.io and GitHub Releases.

### End-of-Life (EOL)
- Deprecated versions that receive no further patches or security fixes.
