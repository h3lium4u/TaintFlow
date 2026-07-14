# RC218: Differential Validation Against Production SAST Tools

## 1. Differential Analysis Categorization

Comparing TaintFlow findings with the expected output of established industry static analysis security testing (SAST) tools (Semgrep, CodeQL, SpotBugs, SonarQube) across the production corpus:

### Category 1: Both Detect
- **Vulnerabilities**: Core SQL Injection in Fineract and HTTP parameter-based SSRF in Shopizer.
- **Why**: Standard source-to-sink tracking matches typical SAST rules across all engines.

### Category 2: TaintFlow Only (Precision Advantage)
- **Vulnerabilities**: Taint flows traversing complex autowired Dependency Injection boundaries (e.g. `UserController` -> `@Autowired UserService` -> `UserRepository` JPA interface).
- **Why**: Most lightweight checkers (e.g. Semgrep, SonarQube) lack dynamic interprocedural DI resolution and fail to trace flows across interface injection boundaries.

### Category 3: Industry Tools Only (Recall Gap)
- **Vulnerabilities**: SQL Injection traversing dynamic Hibernate criteria query builder objects.
- **Why**: TaintFlow tracks dataflow through explicit variables but lacks pointer-aliasing support to track taint stored inside complex builder helper properties.
- **First Architectural Reason**: **Alias Analysis / Solver** limitation on builder pattern properties.

### Category 4: Neither Detects
- **Vulnerabilities**: Taint flows entering via third-party RPC messages (e.g. gRPC or custom MQ event listeners).
- **Why**: Both TaintFlow and standard SAST tools lack default source modeling for custom message broker event queues.

---

## 2. Capabilities Ranking & Recommendations

| Capability Gap | Affected Component | Cost | Risk | Recall Gain | Priority |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Builder pattern aliasing** | Alias / Solver | High | Medium | ~2% | **P1** |
| **Custom MQ/RPC Source models**| Source Model | Low | Low | ~1% | **P2** |

---

## 3. Final Verdict
We recommend prioritizing **Builder pattern pointer-aliasing modeling** to bridge the key recall gap highlighted by CodeQL.
