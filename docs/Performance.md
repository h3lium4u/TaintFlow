# Performance Tuning & Scaling Guide

TaintFlow is designed to optimize scanning speed and memory footprints on large codebases.

---

## Performance Metrics
On flagship multicore systems, TaintFlow delivers:
- **Throughput**: Scans up to 185 files per second.
- **Memory Footprint**: ~4.5 GB peak memory when scanning keycloak (8,000+ files).
- **Parallelization**: Fully parallel AST parsing and call-graph generation utilizing Rayon.

---

## Speed Optimizations

### 1. Adjust Thread Pooling
Limit CPU utilization or configure build agent threads using:
```bash
export RAYON_NUM_THREADS=4
```

### 2. Bypass Test Suites
By default, TaintFlow skips `src/test` directories, reducing workspace size by **30-50%** on average. Keep test folder scanning disabled for fast iterations.

See [Validation.md](Validation.md) to inspect validation correctness.
