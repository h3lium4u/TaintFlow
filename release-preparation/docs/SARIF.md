# SARIF Output Format

TaintFlow generates standardized, fully-compliant SARIF (Static Analysis Results Interchange Format) reports according to the **v2.1.0** specification.

---

## Output Fields

### `sourceRegion`
Highlights the exact line, column, and file location where the user-controlled taint was introduced.

### `sinkRegion`
Highlights the exact line and location where the tainted data reaches an unsanitized execution block.

### `codeFlows`
Includes a detailed array of sequential steps representing how data moves through the codebase (variables, parameter arguments, and method returns).

---

## Integrations
Upload the output `.sarif` file to:
- **GitHub Security**: Displays security warnings directly in Pull Request reviews under "Code Scanning Alerts".
- **GitLab SAST**: Integrate findings into merge request reports.
- **VS Code Extension**: View trace markers directly inside the code editor.
