# Terminology Style Guide

This document defines standard technical terms for TaintFlow documentation.

---

## 1. Pipeline Terms

### Normalizer
Lowers source AST nodes into TaintFlow's unified Intermediate Representation.

### Interprocedural Solver
Traces security data flow tracks across method bounds and class hierarchies.

### Path Refiner
A satisfiability check executing branch constraint evaluations.

---

## 2. Accuracy Terms

### Recall
The ratio of correctly flagged true vulnerabilities to the total number of true vulnerabilities.
- **Goal**: Maintain **1.0000 (100% recall)**.

### Precision
The ratio of true vulnerabilities flagged to all flagged findings.
