# RC196: Spring Production Audit

## 1. Reference Production Taint Flow
A representative Spring Boot MVC application utilizes the following end-to-end data flow:
```
HTTP Request (JSON payload)
    ↓
Spring Controller (@PostMapping with @RequestBody UserDto)
    ↓ (Jackson deserializes request body into UserDto)
UserDto Object Binding
    ↓
UserService (Spring Service, injected via Dependency Injection)
    ↓
UserRepository (Spring JPA Repository / MyBatis Mapper interface)
    ↓
SQL Sink (Database query execution)
```

### Reference Code
```java
// Controller
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/search")
    public ResponseEntity<List<User>> searchUsers(@RequestBody UserDto searchDto) {
        return ResponseEntity.ok(userService.findUsers(searchDto));
    }
}

// DTO
public class UserDto {
    private String query;
    public String getQuery() { return this.query; }
    public void setQuery(String q) { this.query = q; }
}

// Service
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public List<User> findUsers(UserDto dto) {
        String queryVal = dto.getQuery();
        return userRepository.searchByNameRaw(queryVal);
    }
}

// Repository (JPA / Spring Data)
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query(value = "SELECT * FROM users WHERE name = :name", nativeQuery = true)
    List<User> searchByNameRaw(String name);
}
```

---

## 2. Divergence Trace Analysis

We tracked the propagation of taint originating from the controller request payload. Taint is lost at multiple architectural points in the engine:

### Gap 1: Jackson Deserialization and Object Instantiation
- **Divergence Point**: Jackson deserializes the JSON string from the HTTP request into a `UserDto` object reflectively.
- **Engine Behavior**: The `@RequestBody UserDto searchDto` parameter is seeded as a source, so the `searchDto` variable is marked tainted.
- **Taint Loss**: When `dto.getQuery()` is called, the solver enters the getter. However, since the setter was called reflectively by Jackson (unseen by TaintFlow), the field `this.query` contains no taint. Thus, the getter returns an untainted value.
- **Category**: `D. Missing framework modeling` combined with `B. Missing propagation rule` (solved by Generic DTO / JavaBean getter rules).

### Gap 2: Dependency Injection (@Autowired Field Injection)
- **Divergence Point**: `private UserService userService;` is annotated with `@Autowired`. The controller calls `userService.findUsers(searchDto)`.
- **Engine Behavior**: The call site invokes the interface/field type (`UserService.findUsers`). If `UserService` is an interface or concrete class, but the engine fails to resolve the implementation injected into the `@Autowired` field, the call edge is missing or unresolved.
- **Taint Loss**: The solver fails to traverse from `UserController.searchUsers` to `UserService.findUsers` in the Call Graph.
- **Category**: `C. Missing call graph resolution` (dependency injection wire-up).

### Gap 3: JPA Repository and Interface Queries
- **Divergence Point**: `userRepository.searchByNameRaw(queryVal)` is invoked.
- **Engine Behavior**: `UserRepository` is an interface extending `JpaRepository`. At compile time, Spring Data dynamically generates the implementation. In the static AST/IR, the method body for `searchByNameRaw` is empty/bytecode-only.
- **Taint Loss**: Since there is no concrete method body and no stub for the custom native query interface method, the solver treats it as an unresolved call. Taint fails to propagate from `queryVal` to the query sink.
- **Category**: `A. Missing stub` / `D. Missing framework modeling`.

---

## 3. Root Cause Categorization Matrix

| Taint Loss Point | Exact Code Location | Architectural Root Cause | Category |
| :--- | :--- | :--- | :---: |
| DTO Getter | `UserService.java: findUsers` | Taint is not propagated to getter return when DTO is instantiated reflectively | **B / D** |
| Service Injection | `UserController.java: private UserService` | Interface/field autowiring leaves call site unresolved in ICFG | **C** |
| Repository Interface | `UserService.java: searchByNameRaw` | Interface queries have empty bodies and lack stubs/propagators | **A / D** |
