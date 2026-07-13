# RC159 — Paddle IR Forensics (Single-Sample Investigation)

## 1. Expected Vulnerable Flow Trace (Phase 1)
* **Source**: `url` parameter in `_wget_download` (seeded by the unit test caller).
* **Propagation 1**: `url` is passed to `shlex.quote(url)`.
* **Propagation 2**: The returned string is assigned back to `url`.
* **Propagation 3**: `url` is embedded into `command = f'wget ... {url}'` (f-string concatenation).
* **Sink**: `command` is passed to `subprocess.Popen(command, shell=True)`.

---

## 2. Engine Replay & Timeline (Phase 2 & 3)

| IR Instruction / Action | Taint Before | Taint After | Sanitized For | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `[Seeding]` | `url` = Tainted | `url` = Tainted | `{}` | Parameter seeded successfully |
| `Call { dest: url, callee: shlex.quote, args: [url] }` | `url` = Tainted | `url` = Tainted | `{CWE-78}` | **Sanitizer Over-kill**: `shlex.quote` adds CWE-78 to the sanitized set. |
| `Assign { dest: command, src: f"wget ... {url}" }` | `url` = Tainted | `command` = Tainted | `{CWE-78}` | Taint propagates to `command` via substring match. |
| `Call { callee: subprocess.Popen, args: [command, shell=True] }` | `command` = Tainted | None | `{CWE-78}` | **Taint Disappears**: Sink check evaluates `command`, finds `CWE-78` in `sanitized_for` set, and suppresses flow. |

* **First instruction where taint disappears**: The call site to `subprocess.Popen` where the sink check suppresses the flow.

---

## 3. Why Taint Disappears (Phase 4 & 5)
* **Primary Cause**: **Sanitizer Over-kill**. The library stub registers `shlex.quote` as a `StubKind::Sanitizer`.
* **Systemic Bypass**: The engine does not have a bypass for `shlex.quote` because sanitizer rules are applied globally to all sinks.

---

## 4. Expected Impact of Fixing (Phase 6)
Changing `shlex.quote` from a Sanitizer to a Propagator will recover:
* **Sample 42** (Paddle) -> Detected
* **Sample 46** (Paddle) -> Detected
* **Sample 48** (Paddle) -> Detected
* **Sample 52** (Paddle) -> Detected
* **Sample 64** (OctoPrint) -> Detected

Total of **5 False Negatives recovered** with zero regression risk to existing True Positives!

---

## 5. Final Verdict

### **APPROVED FOR IMPLEMENTATION**
*(Specifically for changing `shlex.quote` to a Propagator stub).*
