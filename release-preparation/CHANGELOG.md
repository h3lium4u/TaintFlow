# Changelog

All notable changes to the TaintFlow project will be documented in this file.

---

## [1.0.0] - 2026-07-13

### Added
- **Python Match-Case Lowering**: Full CFG and SSA compilation support for Python 3.10+ `match-case` blocks, literals, OR patterns, wildcards, and capture variables.
- **Dependency Exclusions**: Added `--scan-tests` CLI flag allowing dynamic exclusion of test files (`src/test/`, `tests/`) from scans.
- **Java Spring MVC & DI Modeling**: Context-sensitive tracking of Java Web MVC endpoints, annotations, autowired fields, and repository persistence method chains.

### Fixed
- **CWE-327 Keyword Boundary Hardening**: Fixed a critical false positive where variable or method names ending in similar subsegments (e.g. `.size()` or `nodes()`) were matched as weak encryption algorithms.
- **Classpath Resource Stream Filtering**: Ignored loader configurations (`ClassLoader.getResource`) to eliminate false positives on package internal resource lookups.

### Changed
- **SARIF Report Enhancements**: Standardized SARIF v2.1.0 JSON format to embed precise source regions, sink regions, and full thread-flow propagation paths.
