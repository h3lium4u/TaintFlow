# Dependency Management Policy

TaintFlow minimizes third-party dependencies to ensure compiler-level performance and stability.

---

## Guidelines

1. **Rust dependencies**: Monitored via `Cargo.toml`. Avoid adding dependencies unless they are well-audited, highly performant, and necessary.
2. **Lock Files**: `Cargo.lock` must be committed to the repository to guarantee deterministic builds.
3. **Audit Checks**: Weekly automated jobs run `cargo audit` and `cargo deny` to verify licenses and security vulnerabilities.
