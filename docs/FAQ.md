# Frequently Asked Questions (FAQ)

## 1. Why does TaintFlow report findings inside my test folders?
By default, TaintFlow excludes directories named `test/`, `tests/`, or `src/test/`. If you are seeing findings inside test files, verify that the directories are not named differently. You can enforce strict exclusions using `.taintignore` (see [Configuration.md](Configuration.md)).

---

## 2. Does TaintFlow support dynamic JavaScript/NodeJS?
Not in v1.0. TaintFlow v1.0 is certified for Java and Python. Go and TypeScript bindings are planned for upcoming releases (see [ROADMAP.md](../ROADMAP.md)).

---

## 3. Can I run TaintFlow on a CI/CD agent?
Yes. Generate findings in SARIF format using the `--format sarif` argument and upload the file to your code hosting service (GitHub Actions/GitLab). See [SARIF.md](SARIF.md).
