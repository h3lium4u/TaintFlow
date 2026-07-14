# API Stability Policy

TaintFlow maintains internal library boundaries as crates.

---

## Stability Classifications

- **CLI Interface (`taintflow-cli`)**: **Stable**. Backward compatibility guaranteed within major releases.
- **Rules API (`crates/rules`)**: **Stable**. Custom rules maintain compatibility across minor releases.
- **Internal Libs (`parser`, `ir`, `cfg`, `taint`)**: **Unstable**. Internal structs, traits, and helper functions can be refactored at any point during active development.
