# RC201: Risk Certification

## 1. Safety Checks
- **Ordinary Virtual/Static Dispatch**: Unaffected, as the resolution logic falls back to standard Java/Python dispatch if the receiver field has no DI markers/constructor mapping.
- **Explicit Static Dispatch**: Static methods or direct class instantiation (`new X()`) bypass field injection checks entirely.
- **Stub Registry**: Taint propagation lookup matches the fully qualified name (FQN) of the resolved target; increasing call graph edge count does not alter StubRegistry lookup logic.
- **JavaBean & Receiver Mutation Propagation**: Unaffected. These are solver transfer functions operating during analysis; the Call Graph only provides reachability pathways.
- **Python Analysis**: Ordinary Python calls are untouched because Python classes do not declare fields with Java annotations or use `<init>` constructor field assignment patterns in the same manner.

## 2. Regression Risk
- **Risk Rating**: **Very Low**.
- **Mitigation**: Standard Java RTA fallback ensures that if DI resolution results in zero candidates, we preserve the original behavior.
- **Isolation**: Changes are entirely isolated within `crates/symbols/src/call_graph.rs`. No other crates are modified.
