# Release Notes Template

This template should be used to draft release notes for each official TaintFlow release.

---

```markdown
# TaintFlow v[VERSION] Release Notes - [DATE]

## Executive Summary
[Provide a high-level summary of the release focus, key improvements, and certified metrics.]

## Changelog

### Added
- [New feature 1]
- [New language or framework support]

### Fixed
- [Bug fix 1, including resolved FP/FN benchmark IDs]
- [Performance or stability improvements]

### Changed
- [Changes to CLI arguments, config options, or default behaviors]

## Accuracy Metrics
| Dataset | TP | FP | TN | FN | Recall | Precision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Juliet** | | | | | | |
| **Vul4J** | | | | | | |
| **OWASP** | | | | | | |

## Artifact Checksums
- `taintflow-cli-x86_64-unknown-linux-gnu.tar.gz`: `[SHA256]`
- `taintflow-cli-x86_64-pc-windows-msvc.zip`: `[SHA256]`
- `taintflow-cli-x86_64-apple-darwin.tar.gz`: `[SHA256]`
```
