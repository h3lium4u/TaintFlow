# Supported Frameworks & Library Modeling

To achieve high-quality taint analysis, TaintFlow models the sources, sinks, and sanitizers of common frameworks.

---

## Java Ecosystem

### 1. Spring Framework
- **Spring MVC**: Maps annotations such as `@RestController`, `@GetMapping`, `@PostMapping`, `@RequestParam`, `@PathVariable`, and `@RequestBody` as taint sources.
- **Dependency Injection**: Statically resolves `@Autowired`, `@Component`, `@Service`, and `@Repository` fields to trace flows across interface layers.
- **Spring Data JPA**: Tracks data propagation through JPA repository interfaces (e.g. `save()`, `findById()`).

### 2. Serialization & Utility
- **Jackson / ObjectMapper**: Tracks propagation through `readValue()` and `writeValue()` calls.
- **Servlets**: Identifies `HttpServletRequest.getParameter` and `getInputStream` as source origins.

---

## Python Ecosystem
- **Flask**: Identifies `request.args`, `request.form`, `request.json`, and HTTP headers as taint sources.
- **Standard Library Sinks**: Models database connectors (SQLite, MySQL), file-system APIs (`codecs.open`, `open`), and execution shells (`subprocess.run`).

For rule configurations, refer to [RuleCatalog.md](RuleCatalog.md).
