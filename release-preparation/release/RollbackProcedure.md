# Rollback Procedure

In the event of a critical blocker, crash, or regression discovered post-release, follow this procedure.

---

## Action Plan

### Step 1: Flag the Release
Add a warning banner at the top of the GitHub Release description and mark the release as **Pre-release** (or deprecate it) to prevent automated scripts from pulling it down.

### Step 2: Rollback Release Tag
If a hotfix is not immediately available:
1. Revert the version change commit on the main branch.
2. Push a rollback release tag:
   ```bash
   git tag -d v1.0.0
   git push --delete origin v1.0.0
   ```
3. Re-tag the last stable commit as the target release version or increment the patch version (e.g. `v1.0.1`) containing the revert commit.

For standard release steps, see [ReleaseProcess.md](ReleaseProcess.md).
