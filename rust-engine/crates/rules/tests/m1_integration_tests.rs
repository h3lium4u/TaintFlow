//! M1 mandatory acceptance tests and integration verification.
//! Implements TEST-SAN-02, TEST-SAN-05, TEST-SAN-03, and TEST-PAR-01.

use normalizer::Normalizer;
use parser::UnifiedParser;
use rules::{evaluate_rules_recursive, Finding, RuleEngine};
use std::sync::Arc;
use taint::models::ActiveModelRegistry;
use taint::{TaintEngine, CWE};

fn ext_sanitizer_pack() -> &'static str {
    r#"{
  "schema_version": 1,
  "pack_id": "test-sanitizer",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "san1",
      "kind": "sanitizer",
      "callee": "ExtSan.clean",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": []
    }
  ]
}"#
}

fn ext_sink_pack() -> &'static str {
    r#"{
  "schema_version": 1,
  "pack_id": "test-sink",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "sink1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#
}

fn combined_pack() -> &'static str {
    r#"{
  "schema_version": 1,
  "pack_id": "test-combined",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "san1",
      "kind": "sanitizer",
      "callee": "ExtSan.clean",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": []
    },
    {
      "id": "sink1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#
}

fn build_registry(json: &str) -> Arc<ActiveModelRegistry> {
    let entries = ActiveModelRegistry::load_pack_from_str(json, "test.json").unwrap();
    let mut reg = ActiveModelRegistry::new();
    reg.entries = entries;
    Arc::new(reg)
}

fn run_pipeline(code: &str, registry: Option<Arc<ActiveModelRegistry>>) -> Vec<Finding> {
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.language = Some("java".to_string());
    if let Some(ref reg) = registry {
        taint_engine.model_registry = Some(reg.clone());
    }
    taint_engine.propagate_node(&normalized);

    let mut rule_engine = RuleEngine::new();
    rule_engine.language = Some("java".to_string());
    if let Some(ref reg) = registry {
        rule_engine.model_registry = Some(reg.clone());
    }
    evaluate_rules_recursive(&mut rule_engine, "test.java", &normalized, &taint_engine);

    rule_engine.get_findings()
}

// ── TEST-SAN-02 ───────────────────────────────────────────────────────────────
/// MANDATORY RELEASE BLOCKER: Built-in sink immunity after assignment.
///
/// Flow:
/// 1. `id = request.getParameter("id")` (known built-in source)
/// 2. `safe = ExtSan.clean(id)` (modeled external sanitizer)
/// 3. `stmt.executeQuery(safe)` (known built-in SQL sink)
///
/// Requirement: Built-in CWE-89 finding MUST still be emitted because
/// built-in sinks check ONLY `sanitized_for`, which is isolated from
/// `external_sanitized_for`.
#[test]
fn test_san02_builtin_sink_immunity_after_assignment() {
    let registry = build_registry(ext_sanitizer_pack());
    let code = r#"
String id = request.getParameter("id");
String safe = ExtSan.clean(id);
stmt.executeQuery(safe);
"#;
    let findings = run_pipeline(code, Some(registry));

    let has_cwe89 = findings
        .iter()
        .any(|f| f.cwe == "CWE89" || f.cwe == "CWE-89");
    assert!(
        has_cwe89,
        "TEST-SAN-02 FAILED: Built-in CWE-89 finding was suppressed by external sanitizer on assignment RHS! \
         Built-in sinks must read only sanitized_for, not external_sanitized_for."
    );
}

// ── TEST-SAN-05 ───────────────────────────────────────────────────────────────
/// MANDATORY RELEASE BLOCKER: Built-in sink immunity after standalone sanitizer call.
///
/// Flow:
/// 1. `id = request.getParameter("id")` (known built-in source)
/// 2. `ExtSan.clean(id)` (modeled external sanitizer standalone call)
/// 3. `stmt.executeQuery(id)` (known built-in SQL sink)
///
/// Requirement: Built-in CWE-89 finding MUST still be emitted because
/// external standalone sanitizer calls do NOT clear the `tainted` flag
/// and do NOT populate `sanitized_for`.
#[test]
fn test_san05_builtin_sink_immunity_after_standalone() {
    let registry = build_registry(ext_sanitizer_pack());
    let code = r#"
String id = request.getParameter("id");
ExtSan.clean(id);
stmt.executeQuery(id);
"#;
    let findings = run_pipeline(code, Some(registry));

    let has_cwe89 = findings
        .iter()
        .any(|f| f.cwe == "CWE89" || f.cwe == "CWE-89");
    assert!(
        has_cwe89,
        "TEST-SAN-05 FAILED: Built-in CWE-89 finding was suppressed by external standalone sanitizer! \
         External standalone calls must not clear the tainted flag or pollute sanitized_for."
    );
}

// ── TEST-SAN-03 ───────────────────────────────────────────────────────────────
/// Original unsanitized variable reaching external sink produces finding;
/// sanitized destination variable suppresses external sink.
#[test]
fn test_san03_original_var_reaches_external_sink_and_suppression() {
    let registry = build_registry(combined_pack());

    // Case A: Unsanitized original variable flows to external sink -> FINDING
    let code_unsanitized = r#"
String id = request.getParameter("id");
String safe = ExtSan.clean(id);
CustomDb.rawExec(id);
"#;
    let findings_unsan = run_pipeline(code_unsanitized, Some(registry.clone()));
    let has_external_finding = findings_unsan
        .iter()
        .any(|f| f.cwe == "CWE89" && f.description.contains("CustomDb.rawExec"));
    assert!(
        has_external_finding,
        "TEST-SAN-03: Original unsanitized 'id' flowing to external sink CustomDb.rawExec must emit finding"
    );

    // Case B: Sanitized destination variable flows to external sink -> SUPPRESSED
    let code_sanitized = r#"
String id = request.getParameter("id");
String safe = ExtSan.clean(id);
CustomDb.rawExec(safe);
"#;
    let findings_san = run_pipeline(code_sanitized, Some(registry));
    let has_suppressed_external = findings_san
        .iter()
        .any(|f| f.description.contains("CustomDb.rawExec"));
    assert!(
        !has_suppressed_external,
        "TEST-SAN-03: Sanitized destination 'safe' flowing to external sink CustomDb.rawExec must be suppressed"
    );
}

// ── TEST-PAR-01 (Logic-level parity) ──────────────────────────────────────────
/// Empty-registry parity:
/// Running with NO registry vs running with an EMPTY registry must produce
/// identical findings (count, CWE, line number, severity).
#[test]
fn test_par01_empty_registry_logic_parity() {
    let code = r#"
String id = request.getParameter("id");
stmt.executeQuery(id);
"#;
    // Run 1: No registry
    let findings_none = run_pipeline(code, None);

    // Run 2: Empty registry
    let empty_reg = Arc::new(ActiveModelRegistry::new());
    let findings_empty = run_pipeline(code, Some(empty_reg));

    assert_eq!(
        findings_none.len(),
        findings_empty.len(),
        "TEST-PAR-01: Finding count must match between no-registry and empty-registry"
    );
    for (f1, f2) in findings_none.iter().zip(findings_empty.iter()) {
        assert_eq!(f1.cwe, f2.cwe, "CWE mismatch");
        assert_eq!(f1.severity, f2.severity, "Severity mismatch");
        assert_eq!(f1.line_number, f2.line_number, "Line number mismatch");
        assert_eq!(f1.file_path, f2.file_path, "File path mismatch");
    }
}
