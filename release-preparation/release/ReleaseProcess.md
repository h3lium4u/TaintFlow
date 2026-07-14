# Release Process Guide

This document describes the process for preparing, testing, and publishing a new release of TaintFlow.

---

## 1. Release Stages

### Stage 1: Stabilization Sprint
- Freeze new features.
- Run the full suite of unit tests (`cargo test`) and lints (`cargo clippy`).
- Certify precision/recall metrics against standard datasets.

### Stage 2: Release Candidate (RC)
- Build optimized bin binaries (`cargo build --release`).
- Tag release candidates using `vX.Y.Z-rcN`.
- Validate binary behaviour on stress tests.

### Stage 3: GA Release
- Draft release notes using the standard template (see [ReleaseNotesTemplate.md](ReleaseNotesTemplate.md)).
- Create a signed Git tag and push to GitHub.
- Publish artifacts to GitHub Releases and distribution channels.

For details on packaging, see [PackagingPlan.md](PackagingPlan.md).
