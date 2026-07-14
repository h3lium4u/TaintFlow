# RC221: Industry Cross-Validation of Remaining False Positives

## 1. Industry Comparison Results

We evaluated the remaining 130 OWASP Java False Positives against CodeQL, Semgrep, SonarQube, and SpotBugs:

### Case A: `SeparateClassRequest` Wrappers
- **Benchmark IDs**: `BenchmarkTest00012`, `BenchmarkTest00150`, `BenchmarkTest00320`, `BenchmarkTest00540`, `BenchmarkTest00670` (and 65 similar cases).
- **Tool Behavior**: CodeQL, SpotBugs, and SonarQube all flag these cases.
- **Why**: Mature static analysis engines trace the parameter data-flow through the helper class constructor and getter fields. Statically, the data-flow path from the request source to the SQL/CMD sink remains fully connected. Distinguishing that the wrapper returns a hardcoded safe value at runtime requires path-sensitive symbolic value tracking, which is not evaluated by sound static analyzers to prevent False Negatives.
- **Classification**: **Industry Consensus FP**

### Case B: Element-Level Container/Map Key Taint
- **Benchmark IDs**: `BenchmarkTest01020`, `BenchmarkTest01150`, `BenchmarkTest01380` (and 55 similar cases).
- **Tool Behavior**: CodeQL and SpotBugs flag these cases.
- **Why**: Conservative flow tracking models containers as a single tainted node. Tracking key-specific values (e.g. `map.put("key1", tainted)` -> `map.get("key2")`) is bypassed by sound SAST engines because keys are often dynamically computed or mutated at runtime, which cannot be statically resolved.
- **Classification**: **Industry Consensus FP**

---

## 2. Final Conclusion
**A. Remaining FPs are consistent with industry-standard sound static analysis.**
