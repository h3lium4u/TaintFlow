# Backport Policy

We apply backports to ensure users on older minor versions remain secure.

---

## Criteria for Backports
Only critical security fixes (CVEs) and major parser crashes are eligible for backporting.

## Backport Procedure
1. Create a branch from the target minor release tag (e.g. `v1.0.0` -> `branch-1.0`).
2. Cherry-pick the fix commit from the main branch.
3. Verify compilation and run validation tests.
4. Increment patch version (e.g. `v1.0.1`) and release.
