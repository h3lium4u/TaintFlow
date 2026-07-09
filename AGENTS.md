# TAINTFLOW PROJECT AGENT INSTRUCTIONS

This file acts as the persistent project instruction manual for all future TaintFlow development work. Any AI agent operating on this codebase must adhere strictly to these rules, policies, and workflows.

---

# Validation Execution Policy

The user performs all validations manually.

## Automatic Compilation Policy

Compilation is permitted because it is a fast static verification step and does not execute the validation harness.

The agent **MAY** execute:

* `cargo build`
* `cargo build --release`
* `cargo check` (when only compile verification is required)

Compilation may be used to:

* Detect compiler errors
* Detect borrow checker issues
* Detect type mismatches
* Detect missing imports
* Detect lifetime errors
* Verify that a patch compiles before requesting validation

Compilation **must never** be used as a substitute for validation.

---

## Manual Validation Policy

The agent **MUST NEVER** execute:

* `cargo run`
* Validation harnesses
* Benchmark suites
* Repository scans
* Long-running background validation jobs
* Any command that executes the validation datasets

Instead, the agent must:

* Generate exact PowerShell commands for the user.
* Recommend the smallest validation scope.
* Wait for user-provided logs/reports.
* Analyze existing artifacts only.

Whenever validation is required, the agent must provide only the required PowerShell commands and wait for the user's results.

---

# Validation Scope Policy

Always prefer the smallest validation scope capable of answering the question to optimize cycle time and compute resources.

## Priority Level

1. Repository-Specific Validation
2. GitHub-Only Validation
3. Vul4J-Only Validation
4. OWASP-Only Validation
5. Juliet-Only Validation
6. Full Validation

## When to Use Full Validation

Use full validation **only** when:

* Creating a Release Candidate (RC)
* Establishing a new metrics baseline
* Merging multiple architectural changes
* Modifying global taint propagation logic
* Modifying core source/sink/sanitizer infrastructure

---

# Validation Performance Policy

All performance optimizations must preserve semantic correctness.

Never sacrifice:

* TP
* FP
* TN
* FN
* Precision
* Recall
* F1
* MCC

### Allowed Optimizations

* Rayon sample-level parallelism
* Lock-free aggregation
* Dataset-level parallelism
* Validation harness optimizations
* Safe caching

### Disallowed Optimizations

* Propagation caps
* Reduced iteration limits
* `stop_on_first_match`
* Timeout reductions
* Search-space pruning
* Any optimization that changes detection behavior

---

# Development Workflow

Every engineering iteration must follow this sequence:

1. Review the requested change.
2. Estimate expected metric impact.
3. Implement the change.
4. **Compile automatically** to verify correctness.
5. Recommend the smallest validation scope.
6. Provide the exact PowerShell validation command.
7. Wait for the user to execute validation.
8. Analyze the returned validation log.
9. Decide:

   * ACCEPT
   * ROLLBACK
   * ITERATE

---

# Release Candidate Workflow

Development Phase:

* Use targeted validation only.

Release Phase:

1. Recommend one manual full validation.
2. Compare against the certified baseline.
3. Produce the release report.

---

# Reporting Requirements

Every engineering proposal must include:

* Expected TP impact
* Expected FP impact
* Expected FN impact
* Expected MCC impact
* Recommended validation scope
* Required manual PowerShell commands

---

# TaintFlow Priorities

Engineering priorities are:

1. Precision
2. MCC
3. OWASP XSS FP reduction
4. GitHub FP reduction
5. Recall preservation

Never trade significant MCC for a small localized recall gain.

---

# Agent Behavior

The agent **MAY**:

* Compile the project.
* Perform static code inspection.
* Analyze source code.
* Analyze compiler output.
* Analyze validation logs.

The agent **MUST NEVER**:

* Execute validation.
* Execute benchmark suites.
* Execute dataset scans.
* Execute `cargo run`.
* Wait for validation to finish.

The user always performs validation manually.

---

# Validation Acceleration Policy

Goal:

Reduce validation runtime while preserving identical detection metrics.

Always preserve:

* TP
* FP
* TN
* FN
* Precision
* Recall
* F1
* MCC

Preferred optimizations:

1. Rayon sample-level parallelism
2. Lock-free aggregation
3. Dataset-level parallelism
4. Safe caching

Never use:

* Propagation caps
* Reduced fixpoint iterations
* Timeout reductions
* Heuristic pruning
* Any semantic shortcut

---

# Validation Log Policy

Validation is always executed manually by the user.

When validation is required:

* Provide exact PowerShell commands.
* Save output using `Tee-Object`.
* Use descriptive log names.

Examples:

* `RC104_PHASE1_VALIDATION.log`
* `RC104B_OWASP_VALIDATION.log`
* `RC105_GITHUB_VALIDATION.log`

Never execute validation automatically.

---

# Optimization Rule

Always choose the smallest validation scope capable of answering the engineering question.

Preferred order:

1. Repository-specific
2. GitHub
3. OWASP
4. Vul4J
5. Juliet

Use Full Validation only for:

* Release candidates
* Baseline creation
* Major architectural changes
* Global source/sink/sanitizer changes

---

# Standard Compilation Command

The agent may execute this automatically after every implementation:

```powershell
Set-Location "d:\V2 Backup\rust-engine"

cargo build --release --bin v2-validation *>&1 |
Tee-Object COMPILE.log
```

---

# Standard Validation Commands

## GitHub Holdout Validation (Fast Iteration)

```powershell
Set-Location "d:\V2 Backup\rust-engine"

$env:ONLY_GITHUB="1"
$env:SKIP_PGADMIN="1"
$env:SKIP_DATACHAIN="1"
$env:SKIP_RAY="1"

cargo run --release --bin v2-validation *>&1 |
Tee-Object RCXXXX_GITHUB_VALIDATION.log
```

The agent must never execute this command. It must only provide it for the user to run manually.
