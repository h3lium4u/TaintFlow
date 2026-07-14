# RC198: Implementation Roadmap

## 1. Smallest Generic Architectural Changes

To support Spring Boot, Micronaut, Quarkus, and Jakarta EE without framework-specific hacks, we recommend two key architectural enhancements to the static analysis pipeline:

### A. Static Dependency Injection (DI) Call Resolution (Next Step)
- **Crate**: `symbols` / `call_graph`
- **Mechanism**:
  - During Call Graph construction (`crates/symbols/src/call_graph.rs`), when resolving a call instruction whose target receiver is a class field:
    - Check if the field is annotated with a DI marker (`@Autowired`, `@Inject`, `@Resource`, etc.) or initialized via constructor injection.
    - Query the global symbol table (`GlobalSymbolTable`) for types implementing or extending the field's declared type.
    - If a single concrete candidate implementation is found (or a set of candidates), add call graph edges from the call site to the candidate implementations.
  - **ROI**: Unlocks controller-to-service-layer taint flows for all Spring Boot, Micronaut, and Jakarta EE applications.

### B. Dynamic Repository Interface Propagation
- **Crate**: `taint` / `stubs`
- **Mechanism**:
  - Extend the stub lookup or call transfer logic. If a method belongs to an interface extending framework classes like `JpaRepository` or marked with `@Repository` / `@Mapper`:
    - Automatically treat it as a generic propagator stub (propagating taint from all arguments to the return value).
  - **ROI**: Unlocks service-to-database flows, completing the path to SQLi sinks.

---

## 2. Risk & Impact Analysis
- **Regression Risk**: Low. Resolving DI call edges simply expands the call graph safely, allowing existing data-flow rules to propagate interprocedurally.
- **Precision Preservation**: High. Only autowired fields and constructor parameters are resolved, preventing arbitrary cross-talk.

---

## 3. Explicit Recommendation

We recommend proceeding with **Static Dependency Injection (DI) Call Resolution** in the Call Graph Builder as the immediate highest-priority milestone.
