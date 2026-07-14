# Deprecation Policy

When a feature, CLI parameter, or modeled library is scheduled to be removed:

---

## Process

1. **Phase 1: Warn**: The feature is marked as deprecated in the release notes and CLI output (printing a warning to stderr).
2. **Phase 2: Maintain**: The deprecated functionality remains active throughout the rest of the current major version lifecycle.
3. **Phase 3: Remove**: The feature is permanently removed in the next major version release.
