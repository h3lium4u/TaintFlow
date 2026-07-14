# Release Checklist

This checklist guides the Release Engineer through preparing and certifying a new release of TaintFlow.

---

## 1. Pre-Release Verification
- [ ] Run cargo formatting checks:
  ```bash
  cargo fmt -- --check
  ```
- [ ] Run cargo linter:
  ```bash
  cargo clippy --all-targets -- -D warnings
  ```
- [ ] Run unit tests:
  ```bash
  cargo test
  ```

---

## 2. Accuracy Validation (Certified Benchmarks)
- [ ] Run the validation harness:
  ```bash
  cargo run --release --bin v2-validation
  ```
- [ ] Compare metrics against the baseline.
- [ ] Verify that recall has not regressed.

---

## 3. Production Hardening
- [ ] Scan the core production repositories (Shopizer, Fineract, Keycloak).
- [ ] Check for any parser crashes or infinite solver loops.
- [ ] Verify that peak memory remains within safe margins.

---

## 4. Release Asset Generation
- [ ] Verify that SARIF JSON schema validation passes.
- [ ] Update [CHANGELOG.md](CHANGELOG.md) with all new items.
- [ ] Bump version numbers in all `Cargo.toml` manifests.
- [ ] Tag the release:
  ```bash
  git tag -a v1.0.0 -m "Release v1.0.0"
  git push origin v1.0.0
  ```
