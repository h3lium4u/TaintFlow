# Contributing to TaintFlow

We welcome contributions from the open-source community to make TaintFlow the most precise and high-performance SAST engine. Please review this guide to understand our development workflow and requirements.

---

## Coding Standards

### Rust Code Style
We enforce strict style checks:
1. **Formatting**: Run `cargo fmt` before submitting your pull request.
2. **Linter**: Ensure your changes are free of warnings by running:
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```
3. **Tests**: All unit tests must pass:
   ```bash
   cargo test
   ```

---

## Pull Request Guidelines

1. **Keep Pull Requests Focused**: Do not batch multiple unrelated changes together. Submit separate PRs for separate issues.
2. **Certified Datasets**: Any changes to core taint propagation logic must undergo validation against our certified datasets (Juliet, Vul4J, OWASP). Ensure your change does not cause regressions in existing True Positives.
3. **Commit Messages**: Write descriptive commit messages following the Conventional Commits style (e.g. `feat: add Spring MVC path variable parsing`, `fix(rules): harden weak crypto boundaries`).

---

## Developer Certificate of Origin (DCO)

We require all contributors to sign their commits to certify that they have the right to submit the code under the Apache 2.0 license:

```bash
git commit -s -m "feat: your change description"
```
