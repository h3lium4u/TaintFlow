# TAINTFLOW PROJECT AGENT INSTRUCTIONS

This file acts as the persistent project instruction manual for all future TaintFlow development work. Any AI agent operating on this codebase must adhere strictly to these rules, policies, and workflows.

---

## Validation Execution Policy

The user performs all validations manually.

**Never execute the following commands or tasks:**
- `cargo run`
- `cargo test`
- `cargo check`
- Benchmark suites
- Validation harnesses
- Repository scans
- Any long-running background execution jobs

**Instead, the agent must:**
- Generate exact PowerShell commands for the user.
- Recommend target validation scope.
- Wait for user-provided logs/reports.
- Analyze existing artifacts only.

When validation is required, the agent must only provide the instructions and commands for manual execution.

---

## Validation Scope Policy

Always prefer the smallest validation scope capable of answering the question to optimize cycle time and compute resources.

### Priority Level
1. **Repository-Specific Validation**: Scan only the target repository under analysis.
2. **GitHub-Only Validation**: Scan only the GitHub holdout dataset.
3. **Vul4J-Only Validation**: Scan only the Vul4J dataset.
4. **OWASP-Only Validation**: Scan only the OWASP Benchmark datasets.
5. **Juliet-Only Validation**: Scan only the Juliet test suites.
6. **Full Validation**: Scan all datasets.

### When to Use Full Validation
Only request full validation when:
- Creating a Release Candidate (RC)
- Establishing a new metrics baseline
- Merging multiple architectural changes
- Modifying global taint propagation logic
- Modifying core source/sink/sanitizer infrastructure

---

## Validation Performance Policy

All performance optimizations must preserve semantic correctness. Under no circumstances should precision, recall, or MCC metrics be degraded for speed.

### Allowed Optimizations
- Rayon sample-level parallelism
- Lock-free map/reduce aggregation
- Dataset-level parallelism
- Validation harness execution/runner optimizations

### Disallowed Optimizations
- Propagation depth or step caps
- Reduced iteration limits
- `stop_on_first_match` shortcuts
- Timeout reductions
- Heuristic pruning of search space
- Any optimization that alters detection behavior or suppresses flows

---

## Development Workflow

Every sprint/change must follow this loop:
1. **Review**: Analyze the requested change or error log.
2. **Estimate**: Predict the impact on metrics.
3. **Recommend Scope**: Propose the smallest validation scope.
4. **Provide Commands**: Give the user the exact manual validation command.
5. **User Run**: The user runs the validation manually and provides the log.
6. **Analyze**: Inspect the returned log/report.
7. **Iterate**: Recommend the next corrective or finalizing action.

*Never run validation automatically.*

---

## Release Candidate Workflow

- **Development Phase**: Use targeted validation only.
- **Release Phase**:
  1. Recommend a full manual validation run.
  2. Compare the output metrics against the latest approved baseline.
  3. Produce a detailed release report.

---

## Reporting Requirements

For every sprint/feature proposal, the agent must provide:
- Expected True Positive (TP) impact
- Expected False Positive (FP) impact
- Expected False Negative (FN) impact
- Expected MCC impact
- Recommended validation scope
- Manual PowerShell commands to execute

---

## TaintFlow Priorities

All design and bugfix decisions must prioritize these goals in order:
1. Precision improvements
2. MCC improvements
3. OWASP XSS False Positive reduction
4. GitHub False Positive reduction
5. Recall preservation

*Avoid sacrificing MCC for small, localized recall gains.*

---

## Agent Behavior

- **Never** wait for validation completion.
- **Never** execute validation.
- **Never** execute cargo commands.
- **Always** provide exact commands for manual execution.
- **Always** analyze logs and reports provided by the user.

---

## Validation Acceleration Policy

**Goal**: Reduce validation runtime while preserving identical metrics.

Any optimization must preserve:
- True Positive (TP)
- False Positive (FP)
- True Negative (TN)
- False Negative (FN)
- Precision
- Recall
- F1 Score
- MCC

### Preferred Optimizations
1. Rayon sample-level parallelism
2. Lock-free map/reduce aggregation
3. Dataset-level parallelism
4. Safe caching of reusable validation artifacts

### Disallowed Optimizations
- Propagation caps
- Reduced fixpoint iterations
- `stop_on_first_match`
- Timeout reductions
- Heuristic pruning
- Any change that alters detection semantics

### Action when validation runtime becomes a bottleneck:
1. Audit the validation harness first.
2. Prefer performance improvements before reducing validation coverage.
3. Explain why metrics remain identical.

---

## Validation Log Policy

Validation is always executed manually by the user.

When validation is required:
- Provide exact PowerShell commands.
- Save output using `Tee-Object`.
- Use descriptive log names.

### Examples:
- `RC104_PHASE1_VALIDATION.log`
- `RC104B_OWASP_VALIDATION.log`
- `RC105_GITHUB_VALIDATION.log`

Never execute validation automatically. Assume the user will provide log files, reports, and metrics summaries for analysis.

---

## Optimization Rule

Always choose the smallest validation scope capable of answering the question.

### Preferred Order
1. Repository-specific validation
2. GitHub-only validation
3. OWASP-only validation
4. Vul4J-only validation
5. Juliet-only validation

### Use Full Validation only for:
- Release candidates
- Baseline creation
- Major architectural changes
- Global source/sink/sanitizer modifications

---

## Standard Validation Commands

### GitHub Holdout Validation (Fast Iteration)

Use this command template when a change affects only GitHub metrics or GitHub-specific regressions:

```powershell
Set-Location "d:\V2 Backup\rust-engine"

$env:ONLY_GITHUB="1"
$env:SKIP_PGADMIN="1"
$env:SKIP_DATACHAIN="1"
$env:SKIP_RAY="1"

cargo run --release --bin v2-validation *>&1 |
Tee-Object RCXXXX_GITHUB_VALIDATION.log
```
