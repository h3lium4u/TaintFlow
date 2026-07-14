# RC186 — Spring Framework Gap Analysis & Roadmap Certification

## 1. Framework Support Matrix

| Framework / Library | Current Support | Entry Points / Sinks | Taint Propagation Status | Production ROI |
| :--- | :--- | :--- | :--- | :--- |
| **Spring MVC / Boot** | **Partial** | `@GetMapping`, `@PostMapping`, `@RequestParam`, etc. (Detected via string heuristics). | Lost on complex DTO binding and dependency injection. | **Critical** |
| **Spring Security** | **None** | Authentication objects (e.g., `SecurityContextHolder`). | Credentials/Principal flows are untracked. | **High** |
| **Jackson / Gson** | **None** | `ObjectMapper.readValue()`, `Gson.fromJson()` | Lost during JSON serialization/deserialization. | **Critical** |
| **Hibernate / JPA** | **None** | `EntityManager`, `JpaRepository` | Lost across database persistence boundaries. | **Medium** |
| **MyBatis** | **None** | XML Mapper calls / SQL annotations | Lost across mapper interface boundary. | **Medium** |
| **Reactor (WebFlux)**| **None** | `Mono`, `Flux` | Lost through reactive stream chains and lambdas. | **Medium** |
| **CompletableFuture**| **None** | `supplyAsync()`, `thenApply()` | Lost across asynchronous execution boundaries. | **Medium** |
| **Apache Commons** | **Partial** | String utilities (e.g. `StringUtils`) | Handled via manual stubs only. | **Low** |
| **Guava** | **None** | Cache, collections | Lost across custom collections/cache wrappers. | **Low** |
| **OkHttp / Client** | **None** | `OkHttpClient.newCall()` | Lost across HTTP client request/response. | **High** |

---

## 2. Current Architectural Gaps

1. **DTO Taint Loss (Jackson / Spring Binding)**:
   - When user input is deserialized into a DTO (e.g., `@RequestBody UserDto dto`), the parameter object itself is tainted, but the engine does not generically propagate taint to the returned value of getters (e.g., `dto.getUsername()`).
2. **Dependency Injection (Spring Autowiring)**:
   - Interface method calls (e.g., `userService.save(...)`) are left unresolved in the call graph if the field is annotated with `@Autowired` because the engine does not resolve implementations via field dependency injection.
3. **Reactive Streams & Asynchrony**:
   - Flows through Project Reactor (`Mono`, `Flux`) and `CompletableFuture` fail because callbacks/lambdas are not linked back to their publisher/caller contexts in the CFG.
4. **ORM Taint Loss**:
   - Entities saved to databases (`repository.save(entity)`) and re-read (`repository.findById(id)`) lose taint due to the database abstraction layer.

---

## 3. Source & Sink Inventories

### Source Modeling
- **Current Heuristics**: TaintFlow parses parameters matching `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue` as taint sources.
- **Gaps**: Does not track custom annotations, nested JSON objects, or HTTP servlet requests wrapped in framework context wrappers.

### Sink Inventory
- **SQLi**: `java.sql.Statement`, `java.sql.PreparedStatement`, `javax.persistence.EntityManager` (Partial coverage).
- **RCE**: `Runtime.getRuntime().exec()`, `ProcessBuilder`.
- **SSRF**: `java.net.URL`, `java.net.HttpURLConnection`, `OkHttpClient` (Missing).
- **LFI/Path Traversal**: `java.io.File`, `java.io.FileInputStream`, `java.nio.file.Paths` (Partial coverage).

---

## 4. ROI Backlog Ranking

1. **Spring DTO Field Binding / Jackson Deserialization (Critical)**
   - *Impact*: Recover all flows entering controllers via JSON/REST request bodies.
2. **Spring Dependency Injection (@Autowired resolution) (High)**
   - *Impact*: Connects controllers to services and mappers in the call graph.
3. **HTTP Client Sinks (OkHttp / Spring RestTemplate) (High)**
   - *Impact*: Enables full SSRF detection in enterprise microservices.
4. **Hibernate / JPA / MyBatis Mapping (Medium)**
   - *Impact*: Tracks data flow through database storage and retrieval.
5. **Asynchronous/Reactive Pipelines (WebFlux, Mono/Flux) (Medium)**
   - *Impact*: Enables correct analysis of modern reactive/non-blocking web apps.

---

## 5. Recommended Implementation Roadmap

### Phase 1: Controller DTO & Jackson Modeling
- **Action**: Implement a generic rule in the engine's transfer function: if a variable is tainted and represents a DTO (e.g., parameters from controller entry points), any getter call or field access on it propagates taint.
- **Risk**: Low.
- **ROI**: Critical.

### Phase 2: Static Autowired Resolution
- **Action**: Augment the call graph builder (`crates/symbols/src/call_graph.rs`) to scan fields annotated with `@Autowired`/`@Inject`, resolve the implementing class in the global symbol table, and resolve interface call sites to concrete implementations.
- **Risk**: Medium.
- **ROI**: High.

### Phase 3: External Client & Database Stubs
- **Action**: Register stubs for `OkHttpClient`, `RestTemplate`, `JpaRepository`, and mapper interfaces to act as propagators or sinks.
- **Risk**: Low.
- **ROI**: High.

---

## 6. Confidence Score

- **Confidence**: 5/5 (Meticulous gap analysis aligned with production Java web application architecture).

---

## FINAL VERDICT

**A. Framework support is now the highest-priority milestone.**
