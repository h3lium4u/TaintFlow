# Rule Catalog

This catalog outlines standard rules checked by TaintFlow.

---

## CWE-89: SQL Injection
- **Severity**: HIGH
- **Source**: HTTP parameter requests, JSON request bodies.
- **Sink**: `Statement.execute*`, `Connection.prepareStatement`, `EntityManager.createQuery`.
- **Sanitizer**: Prepared statement parameter binding.

---

## CWE-78: Command Injection
- **Severity**: HIGH
- **Source**: User-controlled request strings.
- **Sink**: `Runtime.getRuntime().exec`, `ProcessBuilder.start`, `subprocess.run`, `os.system`.
- **Sanitizer**: Input parameter escaping/validation.

---

## CWE-327: Weak Cryptographic Algorithms
- **Severity**: MEDIUM
- **Source**: Instantiation parameters or ciphers.
- **Sink**: `Cipher.getInstance("DES")`, `MessageDigest.getInstance("MD5")`.
- **Match Mechanism**: Word-boundary validated cipher segment matching (excluding variables like `.size()`).

See [SARIF.md](SARIF.md) to parse results.
