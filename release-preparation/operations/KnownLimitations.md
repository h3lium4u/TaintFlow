# Known Limitations

This document lists the limitations of TaintFlow v1.0.0.

---

## Technical Limitations

### 1. Pointer Alias Depth
The interprocedural solver uses a bounded alias depth limit to prevent infinite loops during complex pointer evaluations.
- **Impact**: Code with deeply nested pointer loops may miss some propagation routes.

### 2. Third-Party RPC Models
Data entering through custom RPC, gRPC, or messaging queues (e.g. Kafka ingress) is not automatically detected as a source by default in v1.0.0.
- **Impact**: Requires manual rule modeling inside `crates/rules/`.

Refer to the [Roadmap](../ROADMAP.md) for planned improvements.
