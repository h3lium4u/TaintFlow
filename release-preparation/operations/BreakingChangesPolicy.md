# Breaking Changes Policy

TaintFlow minimizes disruptions to users by strictly controlling breaking changes.

---

## What Constitutes a Breaking Change?
- Removing or renaming CLI commands or flags.
- Altering the default path-refinement behavior such that it requires new configuration parameters to run.
- Modifying custom rule syntax rules in `crates/rules/`.

## Policy Enforcements
All breaking changes are prohibited outside major releases (e.g. v2.0.0). Refer to [SemanticVersioningPolicy.md](SemanticVersioningPolicy.md) for more details.
