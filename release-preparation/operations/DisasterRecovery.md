# Disaster Recovery

As TaintFlow is a client-side offline CLI tool, disaster recovery focuses on key release infrastructure and workspace restoration.

---

## Scenarios

### Scenario A: GitHub Action Runner Compromise
1. **Revoke Secrets**: Immediately revoke the GITHUB_TOKEN and any GPG signing keys.
2. **Remove Artifacts**: Delete compromised release drafts or published files.
3. **Audit Commits**: Verify the integrity of the git history and rebuild on a clean local server.

### Scenario B: Crates.io Token Leak
1. **Revoke**: Invalidate the leaked publish token inside the crates.io dashboard.
2. **Yank**: Yank any corrupted or compromised package versions immediately:
   ```bash
   cargo yank --vers 1.0.0
   ```
