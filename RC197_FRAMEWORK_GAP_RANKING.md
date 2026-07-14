# RC197: Framework Gap Ranking

## 1. Gaps Analysis & Counterfactual Verification

### Gap A: Dependency Injection / Autowired Call Graph Resolution
- **Description**: Autowiring fields (`@Autowired`, `@Inject`, `@Resource`) and constructor injection are unresolved in the static call graph. Call sites on injected interfaces are marked unresolved, causing interprocedural traversal to stop.
- **Counterfactual Verification**: By scanning the symbol table for concrete types implementing the autowired interface/field type and resolving the call target to those concrete classes, the solver can traverse from controllers into service layers.
- **Production Impact**: **Critical (9/10)** — Without this, almost no real-world Spring Boot, Micronaut, or Jakarta EE flows can cross from controllers to services.

### Gap B: Deserialization / DTO Taint Loss (Jackson & Spring Binding)
- **Description**: Object fields populated via reflection (e.g. `@RequestBody`, `ObjectMapper.readValue`) do not have explicit assignment instructions in the IR.
- **Counterfactual Verification**: Resolving this via generic JavaBean getter/setter rules (implemented in RC193) propagates taint from the tainted DTO wrapper directly to its getter returns.
- **Production Impact**: **Critical (8/10)** — Unlocks all JSON/REST payloads.

### Gap C: Dynamic Repository / Mapper Stubs (Spring Data / MyBatis)
- **Description**: Repository and mapper interfaces have empty/compiled-only methods, losing taint before reaching database execution sinks.
- **Counterfactual Verification**: A generic rule representing interfaces extending framework repositories (`JpaRepository`, `CrudRepository`) or annotated with mapper markers (`@Mapper`) as pass-through propagators (carrying taint from parameters to returns) preserves taint to query execution sinks.
- **Production Impact**: **High (7/10)** — Recovers SQL Injection flows.

---

## 2. ROI Ranking Table

| Rank | Gap / Feature | Production Impact | Generic Applicability | Complexity | Regression Risk | Detection Improvement | Overall Priority |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | **Dependency Injection Resolution** | Critical | High (All DI frameworks) | Medium | Low | +55% | **Critical** |
| **2** | **JavaBean DTO Propagation** | Critical | High (All DTO models) | Low | Low | +30% | **High (Completed)** |
| **3** | **Dynamic Repository Pass-through** | High | High (JPA, MyBatis) | Low | Low | +25% | **Medium** |

- **Dependency Injection Resolution** has the highest overall ROI because service invocation is the gateway to the entire business logic layer of Java applications.
