# GitHub Release Markdown Template

This template is optimized for GitHub Releases Markdown layouts, linking binaries, SBOMs, and changelogs.

---

```markdown
## TaintFlow [VERSION] - Flagship SAST Release

TaintFlow v[VERSION] is officially released. This version delivers major enhancements to [high-level feature].

### 🚀 Highlights
- **[Feature Name]**: [Brief description of the feature].
- **100% Recall Certification**: Verified against Juliet, Vul4J, and OWASP benchmarks.

### 📦 Installation
Download the binary for your platform below, or compile from source:
```bash
cargo install --git https://github.com/taintflow/taintflow.git --tag v[VERSION]
```

### 🔒 Security & Verification
All binaries are cryptographically signed. You can verify checksums and signatures using:
- **Checksums**: See `SHA256SUMS` attached below.
- **Signatures**: Verified with our public GPG Key `[KEY_ID]`.

For full details, read our [Changelog](../CHANGELOG.md).
```
