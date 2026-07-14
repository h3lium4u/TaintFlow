# RC193: Hybrid JavaBean Propagation Implementation Report

## Overview
This report details the implementation of the Hybrid JavaBean Propagation rule in the TaintFlow engine. The feature has been implemented using an IR-first, semantics-first architecture that prioritizes structural inspection of method bodies over naming heuristics.

## Implementation Details

### 1. New Component: `JavaBeanClassifier`
A dedicated component, `JavaBeanClassifier`, has been created inside `crates/taint/src/interproc.rs`. It provides structural classification of method signatures and bodies into three kinds:
- `JavaBeanKind::Getter`
- `JavaBeanKind::Setter`
- `JavaBeanKind::None`

### 2. High-Priority Semantic Inspection
Whenever a method body (IR) is available, the classifier evaluates:
- **Semantic Getter**:
  - Receives `this`.
  - Zero arguments/parameters.
  - Non-void return type.
  - Method body is exactly 1 instruction returning a field belonging to `this` (recursively resolved via the declaring class or any of its superclasses).
- **Semantic Setter**:
  - Receives `this`.
  - Exactly 1 argument/parameter.
  - Method body is exactly 1 instruction assigning the parameter to a field belonging to `this` (recursively resolved).

If any additional logic, branches, loops, allocations, or calls exist in the body, semantic classification rejects the method.

### 3. Naming Fallback
When the callee body is unavailable (e.g., Lombok-generated code, external bytecode libraries, or unparsed jar files), the classifier falls back to strict naming conventions:
- **Getter**: Starts with `get` / `is`, 0 parameters, non-void return.
- **Setter**: Starts with `set` / `with`, 1 parameter.
- **Blocklist**: Standard utility and structural methods such as `size`, `length`, `hashcode`, `clone`, `equals`, `getclass`, `getconnection`, `getmetadata` are explicitly rejected to prevent precision loss.
- **Package Blocklist**: Core classes under `java.util.*`, `java.sql.*`, `java.io.*`, `java.net.*`, `java.lang.ThreadLocal`, `java.lang.System`, and `java.lang.Class` are excluded from naming-based propagation.

### 4. Efficient Caching
To ensure optimal performance, classifications are cached per `MethodId` in a `RefCell<HashMap<MethodId, JavaBeanKind>>` (`javabean_cache`) residing on `InterproceduralTaintEngine`. This guarantees that each method is analyzed at most once per task, avoiding redundant AST/IR traversals.

### 5. Integration
The call transfer function (`eval_call`) has been updated to query the classifier immediately after the explicit `StubRegistry` check, ensuring stubs still take the highest precedence.
