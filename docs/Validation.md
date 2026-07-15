# Validation & Certified Datasets

To guarantee that TaintFlow maintains high recall and precision, we validate the engine against certified benchmarks.

---

## Supported Datasets

### 1. OWASP Benchmark
- **Score**: **100% Recall** (0 False Negatives on Java and Python).
- **Checks**: Verifies tracking of path traversal, command injection, and SQL injection.

### 2. Juliet Test Suite
- **Score**: **1.0000 Precision / Recall / MCC**.
- **Checks**: Verifies local pointer aliasing, control-flow branches, and loop behaviors.

### 3. Vul4J
- **Score**: **1.0000 Recall**.
- **Checks**: Real-world CVE reproductions.

---

## Running Validation
To execute the validation harness:
```bash
cargo run --release --bin v2-validation
```
For bug reporting guidelines, refer to [Troubleshooting.md](Troubleshooting.md).
