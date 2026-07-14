# Configuration Guide

Configure TaintFlow scan limits, rules, and folder exclusions.

---

## Ignore Configuration (`.taintignore`)
Create a `.taintignore` file in the root of your project directory to exclude specific directories or files from the scanner.

```text
# Exclude build targets
target/
build/
bin/

# Exclude dependencies
node_modules/
vendor/

# Exclude legacy files
src/main/java/com/legacy/OldClass.java
```

---

## Environment Variables
The following environment variables configure the execution of TaintFlow:
- **`RAYON_NUM_THREADS`**: Controls the parallel thread pool size (defaults to available logical CPU cores).
```bash
export RAYON_NUM_THREADS=4
```
For architecture details, refer to [Architecture.md](Architecture.md).
