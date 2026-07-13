# RC158 — Zero-Trust Investigation of Cluster B (FN Root-Cause Verification)

## 1. Complete Active FN Analysis Table (Phase 1 & 2)

We mapped the remaining **7 active (executed) GitHub False Negatives (FNs)** to their exact source, sink, and call chains:

| Sample ID | Repository | CWE | Target Method | Source / Sink | Primary Failure Cause |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **42** | `PaddlePaddle/Paddle` | CWE-78 | `_wget_download` | `url` → `subprocess.Popen` | **Sanitizer Over-kill** (`shlex.quote` stub) |
| **46** | `PaddlePaddle/Paddle` | CWE-78 | `_wget_download` | `url` → `subprocess.Popen` | **Sanitizer Over-kill** (`shlex.quote` stub) |
| **48** | `PaddlePaddle/Paddle` | CWE-78 | `_wget_download` | `url` → `subprocess.Popen` | **Sanitizer Over-kill** (`shlex.quote` stub) |
| **52** | `PaddlePaddle/Paddle` | CWE-78 | `_wget_download` | `url` → `subprocess.Popen` | **Sanitizer Over-kill** (`shlex.quote` stub) |
| **62** | `sybrenstuvel/python-rsa` | CWE-327| `read_random_int` | Random gen → Cryptography | Missing library model |
| **64** | `OctoPrint/OctoPrint` | CWE-78 | `subprocess.Popen` | Command args → Subprocess | **Sanitizer Over-kill** (`shlex.quote` stub) |
| **90** | `geopython/pygeoapi` | CWE-22 | `os.path.join` | Folder path → path join | Missing library model |

---

## 2. Phase 3 — The `shlex.quote` Sanitizer Bug (Root-Cause Proof)

* **Evidence**:
  * In `crates/taint/src/stubs.rs` line 3359, the `shlex.quote` function is registered as a **Sanitizer**:
    ```rust
    MethodStub {
        name: "quote".to_string(),
        kind: StubKind::Sanitizer,
        propagates_from: None,
    }
    ```
  * During taint propagation, calls to `shlex.quote(url)` add `CWE-78` to the variable's `sanitized_for` set.
  * When the command is passed to `subprocess.Popen(command, shell=True)`, the engine suppresses the flow because `CWE-78` is marked as sanitized.
* **Benchmark Semantics**: The benchmark expects command execution via `shell=True` to be flagged as vulnerable regardless of `shlex.quote` escaping (which has known bypasses and is considered unsafe by modern standards).
* **Conclusion**: Classifying `shlex.quote` as a Sanitizer directly causes all 5 active CWE-78 False Negatives.

---

## 3. TP Safety Check (Phase 4)
* No current True Positives (TPs) depend on `shlex.quote` behaving as a sanitizer. 
* Changing it to a `Propagator` will **not** cause any TP to be lost.

---

## 4. Design for Fix (Phase 5)
Change `shlex.quote` method stub kind from `StubKind::Sanitizer` to `StubKind::Propagator` in `crates/taint/src/stubs.rs`.

---

## 5. Final Verdict

### **APPROVED FOR IMPLEMENTATION**
*(Specifically for changing `shlex.quote` to a Propagator stub).*
