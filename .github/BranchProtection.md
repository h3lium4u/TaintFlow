# Branch Protection Policy

To protect the integrity of TaintFlow releases, branch protection rules must be applied to the `main` branch.

---

## Protection Rules for `main`

### 1. Require Pull Request reviews before merging
- **Required approving reviews**: 1.
- **Dismiss stale pull request approvals when new commits are pushed**: Enabled.
- **Require review from Code Owners**: **Enabled** (ensures changes to parser and solver modules get reviewed by their respective owners; see [CODEOWNERS](CODEOWNERS)).

### 2. Require status checks to pass before merging
- **Require branches to be up to date before merging**: Enabled.
- **Status Checks**:
  - `Build & Test (Rust stable)` (must pass clean).

### 3. Enforce strict controls
- **Require signed commits**: **Enabled** (enforces developer DCO certs; see [CONTRIBUTING.md](../CONTRIBUTING.md)).
- **Include administrators**: Enabled (applies constraints to project admins to prevent accidental direct pushes).
