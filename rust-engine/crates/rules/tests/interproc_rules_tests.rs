//! Milestone 1: Interprocedural intra-file end-to-end rule evaluation tests.
//!
//! Verifies that findings are correctly generated (or suppressed) by `RuleEngine`
//! across local function boundaries and propagator models.

use normalizer::Normalizer;
use parser::UnifiedParser;
use rules::{evaluate_rules_recursive, Finding, RuleEngine};
use std::sync::Arc;
use taint::models::ActiveModelRegistry;
use taint::TaintEngine;

fn build_registry(json: &str) -> Arc<ActiveModelRegistry> {
    let entries = ActiveModelRegistry::load_pack_from_str(json, "rules_test.json").unwrap();
    let mut reg = ActiveModelRegistry::new();
    reg.entries = entries;
    Arc::new(reg)
}

fn scan(code: &str, registry: Option<Arc<ActiveModelRegistry>>) -> Vec<Finding> {
    let ast = UnifiedParser::parse(code, "java").expect("Java parsing failed");
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
    evaluate_rules_recursive(&mut rule_engine, "sample.java", &normalized, &taint_engine);
    rule_engine.get_findings()
}

// ── TEST 1: Taint flowing into helper produces finding inside helper ─────────
#[test]
fn test_interproc_finding_in_helper() {
    let code = r#"
void executeHelper(String q) {
    stmt.executeQuery(q);
}
String id = request.getParameter("id");
executeHelper(id);
"#;
    let findings = scan(code, None);
    let cwe89 = findings.iter().any(|f| f.cwe == "CWE89");
    assert!(
        cwe89,
        "Expected CWE-89 finding in executeHelper when called with tainted 'id'"
    );
}

// ── TEST 2: Parameter independence produces ZERO findings ────────────────────
#[test]
fn test_interproc_parameter_independence_zero_findings() {
    let code = r#"
void process(String safeParam, String taintedParam) {
    stmt.executeQuery(safeParam);
}
String id = request.getParameter("id");
process("clean_data", id);
"#;
    let findings = scan(code, None);
    assert_eq!(
        findings.len(),
        0,
        "Expected 0 findings: sink in process only uses safeParam, but got {:?}",
        findings
    );
}

// ── TEST 3: Multi-hop call chain produces finding ────────────────────────────
#[test]
fn test_interproc_multihop_finding() {
    let code = r#"
void helperB(String b) {
    stmt.executeQuery(b);
}
void helperA(String a) {
    helperB(a);
}
String id = request.getParameter("id");
helperA(id);
"#;
    let findings = scan(code, None);
    let cwe89 = findings.iter().any(|f| f.cwe == "CWE89");
    assert!(
        cwe89,
        "Expected CWE-89 finding in helperB via multi-hop call chain helperA -> helperB"
    );
}

// ── TEST 4: Helper constant return produces ZERO findings ────────────────────
#[test]
fn test_interproc_constant_return_zero_findings() {
    let code = r#"
String getConstant(String input) {
    return "SELECT 1 FROM DUAL";
}
String id = request.getParameter("id");
String sql = getConstant(id);
stmt.executeQuery(sql);
"#;
    let findings = scan(code, None);
    assert_eq!(
        findings.len(),
        0,
        "Expected 0 findings: getConstant returns safe constant, but got {:?}",
        findings
    );
}

// ── TEST 5: External model propagator flowing to sink produces finding ────────
#[test]
fn test_interproc_propagator_to_sink_finding() {
    let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-prop-flow",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop1",
      "kind": "propagator",
      "callee": "CustomProp.transform",
      "languages": ["java"],
      "input_args": [0],
      "propagates_to": "return"
    }
  ]
}"#;
    let registry = build_registry(pack_json);
    let code = r#"
String id = request.getParameter("id");
String transformed = CustomProp.transform(id);
stmt.executeQuery(transformed);
"#;
    let findings = scan(code, Some(registry));
    let cwe89 = findings.iter().any(|f| f.cwe == "CWE89");
    assert!(
        cwe89,
        "Expected CWE-89 finding after taint propagates through external propagator model"
    );
}

// ── TEST 6: Context independence in both execution orders ────────────────────
#[test]
fn test_interproc_context_independence_both_orderings() {
    // Tainted call first, safe call second
    let code1 = r#"
String identity(String p) {
    return p;
}
String id = request.getParameter("id");
String tainted_res = identity(id);
stmt.executeQuery(tainted_res);

String safe_res = identity("safe_data");
stmt.executeQuery(safe_res);
"#;
    let findings1 = scan(code1, None);
    // Exactly 1 finding for tainted_res, 0 for safe_res
    let cwe89_count = findings1.iter().filter(|f| f.cwe == "CWE89").count();
    assert_eq!(
        cwe89_count, 1,
        "Expected exactly 1 CWE-89 finding (tainted_res), but got {}",
        cwe89_count
    );

    // Safe call first, tainted call second
    let code2 = r#"
String identity(String p) {
    return p;
}
String safe_res = identity("safe_data");
stmt.executeQuery(safe_res);

String id = request.getParameter("id");
String tainted_res = identity(id);
stmt.executeQuery(tainted_res);
"#;
    let findings2 = scan(code2, None);
    let cwe89_count2 = findings2.iter().filter(|f| f.cwe == "CWE89").count();
    assert_eq!(
        cwe89_count2, 1,
        "Expected exactly 1 CWE-89 finding (tainted_res), but got {}",
        cwe89_count2
    );
}

// ── TEST 7: Built-in sanitizer inside helper suppresses finding ───────────────
#[test]
fn test_interproc_sanitizer_in_helper() {
    let code = r#"
void safeHelper(String q) {
    String clean = ESAPI.encoder().encodeForSQL(q);
    stmt.executeQuery(clean);
}
String id = request.getParameter("id");
safeHelper(id);
"#;
    let findings = scan(code, None);
    assert_eq!(
        findings.len(),
        0,
        "Expected 0 findings when helper sanitizes input before sink, but got {:?}",
        findings
    );
}
