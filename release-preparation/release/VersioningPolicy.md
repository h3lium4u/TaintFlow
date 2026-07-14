# Versioning Policy

TaintFlow strictly adheres to **Semantic Versioning (SemVer) 2.0.0**.

---

## Version Format
```text
vMAJOR.MINOR.PATCH
```

- **MAJOR**: Incremented for incompatible API changes (such as changing the SARIF output schema formatting, removing CLI options, or breaking custom rule compatibility).
- **MINOR**: Incremented for new functionality (such as adding Go or TypeScript parsing support, introducing major new framework models) without breaking backward compatibility.
- **PATCH**: Incremented for backward-compatible bug fixes (such as resolving false positives, addressing parser limits, or fixing memory leaks).

Refer to [ReleaseProcess.md](ReleaseProcess.md) for tag execution.
