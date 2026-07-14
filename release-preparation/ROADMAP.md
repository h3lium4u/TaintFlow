# TaintFlow Release Roadmap

This document outlines the planned direction of TaintFlow. Our main focus is improving precision and recall, performance scaling, and expanding parser coverage.

---

## v1.1.0 — Third-Party API Modeling & Builder Support

### Precision & Recall
- **Builder Pattern Pointer Aliasing**: Track taint values propagated through fluid API builders (e.g. Hibernate Criteria, Lombok `@Builder`).
- **MQ Ingress Source Modeling**: Enable built-in modeling of messages entering via Apache Kafka and RabbitMQ handlers.

### Developer Experience
- **Interactive Configuration Generator**: CLI tool (`taintflow init`) to interactively create custom rules and ignore filters.

---

## v1.2.0 — Extended Language Bindings

### Language Expansion
- **TypeScript Support**: Leverage tree-sitter-typescript to support React, Node.js, and browser-facing applications.
- **Go Support**: Support Go module tracking and concurrency channel taint flow propagation.
