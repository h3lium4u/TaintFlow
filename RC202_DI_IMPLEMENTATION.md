# RC202: DI Implementation Report

## 1. Implementation Overview
We successfully implemented **Static Dependency Injection (DI) Call Resolution** inside the Call Graph Builder (`crates/symbols/src/call_graph.rs`).

## 2. Key Changes
- **Injected Field Detection Helper (`find_field_in_hierarchy`)**:
  - Recursively crawls the inheritance hierarchy of caller classes to locate field declarations.
  - Detects explicit annotations (`@Autowired`, `@Inject`, `@Resource`).
  - Statically maps **constructor injection without annotations** by scanning the `<init>` method body for assignments mapping parameter variables to class fields.
- **Candidate Resolution (`CHA/DI`)**:
  - When calling a method on a DI field, candidate implementors (interfaces) and subclasses (classes) are queried from the global symbol table.
  - Valid candidates are filtered to ensure they override or implement the target method.
  - Candidates are added to the call graph edges, bridging the controller-to-service-layer gap.
- **Scope & Safety**:
  - Changes are completely isolated within `crates/symbols/src/call_graph.rs`.
  - Non-DI call sites are resolved using standard RTA/CHA logic.
