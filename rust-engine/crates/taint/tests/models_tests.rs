//! M1 model registry taint propagation unit tests.
//! Tests run against actual TaintEngine code paths without needing external crates.

use normalizer::Normalizer;
use parser::UnifiedParser;
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

fn ext_multi_arg_sanitizer_pack() -> &'static str {
    r#"{
  "schema_version": 1,
  "pack_id": "test-multi-sanitizer",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "san_multi",
      "kind": "sanitizer",
      "callee": "CalledSan.clean",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0, 1]
    }
  ]
}"#
}

fn ext_source_pack() -> &'static str {
    r#"{
  "schema_version": 1,
  "pack_id": "test-source",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "src1",
      "kind": "source",
      "callee": "CustomInput.readUntrusted",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": []
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

fn propagate(code: &str, registry: Option<Arc<ActiveModelRegistry>>) -> TaintEngine {
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");
    let mut engine = TaintEngine::new(10, 5, 200);
    engine.language = Some("java".to_string());
    if let Some(r) = registry {
        engine.model_registry = Some(r);
    }
    engine.propagate_node(&normalized);
    engine
}

// ── TEST-SAN-01 ───────────────────────────────────────────────────────────────
/// External sanitizer on assignment RHS:
/// - Destination variable `safe` gets `tainted = true` and `external_sanitized_for = {CWE89}`.
/// - Original variable `id` is NOT modified (remains tainted, external_sanitized_for is empty).
/// - `safe.sanitized_for` remains empty (built-in field untouched).
#[test]
fn test_san01_assignment_rhs_external_sanitizer() {
    let registry = build_registry(ext_sanitizer_pack());
    let code = r#"
String id = request.getParameter("id");
String safe = ExtSan.clean(id);
"#;
    let engine = propagate(code, Some(registry));

    // Check safe destination variable
    let state = engine.get_taint("safe").expect("safe should be tracked");
    assert!(
        state.tainted,
        "safe should remain tracked as tainted for dataflow"
    );
    assert!(
        state.external_sanitized_for.contains(&CWE::CWE89),
        "safe.external_sanitized_for should contain CWE89"
    );
    assert!(
        state.sanitized_for.is_empty(),
        "safe.sanitized_for must be empty — external sanitizers must not touch built-in field"
    );

    // Check id source variable: must remain completely unmodified
    let id_state = engine.get_taint("id").expect("id should be tracked");
    assert!(id_state.tainted, "id must remain tainted");
    assert!(
        id_state.external_sanitized_for.is_empty(),
        "id.external_sanitized_for must be empty — assignment sanitizer only affects destination"
    );
    assert!(
        id_state.sanitized_for.is_empty(),
        "id.sanitized_for must be empty"
    );
}

// ── TEST-SAN-04 ───────────────────────────────────────────────────────────────
/// Standalone external sanitizer call:
/// - Argument `id` gets `external_sanitized_for = {CWE89}`.
/// - Argument `id.tainted` remains TRUE (critically, not cleared, preserving built-in immunity).
/// - Argument `id.sanitized_for` remains empty.
#[test]
fn test_san04_standalone_call_preserves_tainted_flag() {
    let registry = build_registry(ext_sanitizer_pack());
    let code = r#"
String id = request.getParameter("id");
ExtSan.clean(id);
"#;
    let engine = propagate(code, Some(registry));
    let state = engine.get_taint("id").expect("id should be tracked");
    assert!(
        state.tainted,
        "id.tainted must remain true after standalone external sanitizer call"
    );
    assert!(
        state.external_sanitized_for.contains(&CWE::CWE89),
        "id.external_sanitized_for should contain CWE89"
    );
    assert!(
        state.sanitized_for.is_empty(),
        "id.sanitized_for must remain empty"
    );
}

// ── TEST-SAN-06 ───────────────────────────────────────────────────────────────
/// Sanitizer that handles multiple arguments:
/// Both argument variables receive `external_sanitized_for`.
#[test]
fn test_san06_multi_argument_sanitizer() {
    let registry = build_registry(ext_multi_arg_sanitizer_pack());
    let code = r#"
String a = request.getParameter("a");
String b = request.getParameter("b");
CalledSan.clean(a, b);
"#;
    let engine = propagate(code, Some(registry));

    let state_a = engine.get_taint("a").expect("a should be tracked");
    assert!(state_a.tainted);
    assert!(state_a.external_sanitized_for.contains(&CWE::CWE89));

    let state_b = engine.get_taint("b").expect("b should be tracked");
    assert!(state_b.tainted);
    assert!(state_b.external_sanitized_for.contains(&CWE::CWE89));
}

// ── External source model test ────────────────────────────────────────────────
#[test]
fn test_external_source_model_seeds_taint() {
    let registry = build_registry(ext_source_pack());
    let code = r#"
String payload = CustomInput.readUntrusted();
"#;
    let engine = propagate(code, Some(registry));
    let state = engine
        .get_taint("payload")
        .expect("payload should be tracked from external source");
    assert!(
        state.tainted,
        "payload should be tainted by external source rule"
    );
}
