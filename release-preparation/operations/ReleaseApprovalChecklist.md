# Release Approval Checklist

This checklist must be signed off by the lead release maintainers before publishing any GA release.

---

- [ ] All unit tests pass cleanly (`cargo test`).
- [ ] No Clippy warnings remain (`cargo clippy`).
- [ ] Validation metrics have been run and compared to the baseline (no recall regressions).
- [ ] Known limitations are documented (see [KnownLimitations.md](KnownLimitations.md)).
- [ ] SBOM and SHA256 checksums are successfully generated.
- [ ] Git release tag is GPG-signed.
