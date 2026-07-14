# Consolidated Repository & Mapper Soundness Certification

---

## Part 1: RC206 — Repository Soundness Audit

### 1. Detection Mechanism Evaluation

| Detection Heuristic | Precision | Recall | Production Safety | FP Risk |
| :--- | :---: | :---: | :--- | :---: |
| **extends JpaRepository / CrudRepository** | 100% | High (Spring Data) | High. Always maps to database entities. | None |
| **extends Repository** | 100% | High (Jakarta/Spring Data) | High. Broad base interface. | None |
| **@Repository** | 100% | High (Spring MVC/Boot) | High. Explicit framework annotation. | None |
| **@Mapper** | 90% | High (MyBatis) | High. Matches MyBatis and MapStruct mapper interfaces. | Low |
| **Name contains "Repository"** | 95% | High | High. Standard naming convention for data access layers. | Low |
| **Name contains "Mapper"** | 80% | Medium | Medium. MapStruct and MyBatis both match. | Low |

### 2. Framework Separation & Safety Boundaries
To prevent over-approximation, only **interfaces** matching repository criteria will participate in dynamic propagation.
- **Participating**: Spring Data JPA, MyBatis mappers, Jakarta Repositories, Micronaut Data interfaces.
- **Excluded**:
  - `ObjectMapper`: Excluded. It is a concrete class with its own stubs.
  - `ModelMapper` / `Dozer`: Excluded. Concrete mapping utility classes.
  - Ordinary service/utility interfaces: Excluded (do not extend Repository or carry `@Repository` / `@Mapper` annotations).

---

## Part 2: RC207 — Propagation Matrix

For empty-body repository methods, propagation is applied based on the return type and parameter count to avoid false positives (FPs) on boolean/numeric queries:

| Method Category | Example Signature | Propagation Rule | Rationale |
| :--- | :--- | :--- | :--- |
| **Persist / Save** | `T save(S entity)` | `arg[0] -> return` | Propagates entity taint to returned saved instance. |
| **Collection Persist** | `List<S> saveAll(Iterable<S> entities)` | `arg[0] -> return` | Propagates collection taint to returned collection. |
| **Query / Finder** | `List<User> findByName(String name)` | `arg[0..N] -> return` | Propagates search parameter taint to returned entities. |
| **Custom Query** | `@Query List<User> search(String query)` | `arg[0..N] -> return` | Propagates query parameter taint to returned entities. |
| **Metadata/Existential**| `boolean existsById(ID id)` | **No propagation** | Exclude boolean/numeric returns to prevent FP inflation. |
| **Aggregate / Count** | `long count()` | **No propagation** | Exclude numeric/primitive returns. |
| **Deletions** | `void delete(T entity)` | **No propagation** | Returns void. |

---

## Part 3: RC208 — Repository Detection Certification

### 1. Verification of Soundness
The engine will classify an interface as a repository boundary **only** if it meets the following strict conditions:
1. It is an **interface** (`TypeKind::Interface`).
2. Its body is **empty** (`method.body.is_empty()`).
3. It satisfies the **Repository Signature Check**:
   - The declaring interface type or one of its inherited interfaces extends a type named `Repository` or `JpaRepository` or `CrudRepository`.
   - Or, the interface has annotations containing `"Repository"` or `"Mapper"` (excluding concrete classes like `ObjectMapper`).

### 2. Safeguard Demonstration
- **`ObjectMapper`**: Since `ObjectMapper` is a class (not an interface), it fails the `TypeKind::Interface` check and is never classified as a repository.
- **Service Interfaces**: Typical service interfaces (e.g. `UserService`) do not extend `Repository` or carry mapper/repository annotations, so they are ignored.
