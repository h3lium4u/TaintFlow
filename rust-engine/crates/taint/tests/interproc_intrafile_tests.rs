//! Milestone 1: Interprocedural intra-file taint analysis acceptance tests.
//!
//! Covers:
//! 1. Parameter-to-sink propagation in local helper functions
//! 2. Return-value taint propagation from local helpers
//! 3. Multi-hop call chains (A -> B -> sink)
//! 4. Parameter independence (safe actual argument does not get tainted)
//! 5. Constant / safe return values (no blanket taint)
//! 6. Boolean predicate call suppression (is*, has*, check, validate)
//! 7. Call context independence (multiple calls with different arguments)
//! 8. External propagator models with `propagates_to: "return"`
//! 9. External propagator models with `propagates_to: "receiver"`
//! 10. Recursion termination budget and cycle detection

use normalizer::Normalizer;
use parser::UnifiedParser;
use std::sync::Arc;
use taint::models::ActiveModelRegistry;
use taint::TaintEngine;

fn build_registry(json: &str) -> Arc<ActiveModelRegistry> {
    let entries = ActiveModelRegistry::load_pack_from_str(json, "test_pack.json").unwrap();
    let mut reg = ActiveModelRegistry::new();
    reg.entries = entries;
    Arc::new(reg)
}

fn propagate(code: &str, registry: Option<Arc<ActiveModelRegistry>>) -> (TaintEngine, usize) {
    let ast = UnifiedParser::parse(code, "java").expect("Java parsing failed");
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");
    let mut engine = TaintEngine::new(10, 5, 200);
    engine.language = Some("java".to_string());
    if let Some(r) = registry {
        engine.model_registry = Some(r);
    }
    engine.propagate_node(&normalized);
    let span_lines = normalized.span.end_line;
    (engine, span_lines)
}

// ── TEST 1: Parameter-to-sink in local helper ────────────────────────────────
#[test]
fn test_helper_sql_sink_propagation() {
    let code = r#"
void executeHelper(String q) {
    stmt.executeQuery(q);
}
String id = request.getParameter("id");
executeHelper(id);
"#;
    let (engine, _) = propagate(code, None);
    assert!(
        engine.function_defs.contains_key("executehelper"),
        "executeHelper should be indexed"
    );
    let helper_def = engine.function_defs.get("executehelper").unwrap();
    let sink_line = helper_def.start_line + 1; // inside executeHelper
    let q_taint = engine.is_symbol_tainted_at("q", sink_line);
    assert!(
        q_taint.is_some() && q_taint.unwrap().tainted,
        "Formal parameter 'q' should be tainted inside executeHelper at sink line"
    );
    assert!(
        engine.validated_paths_count >= 1,
        "Sink executeQuery inside helper should be reached with tainted data"
    );
}

// ── TEST 2: Helper return value propagation ──────────────────────────────────
#[test]
fn test_helper_return_value_propagation() {
    let code = r#"
String formatQuery(String input) {
    return input;
}
String id = request.getParameter("id");
String sql = formatQuery(id);
"#;
    let (engine, _) = propagate(code, None);
    let sql_state = engine.get_taint("sql");
    assert!(
        sql_state.is_some() && sql_state.unwrap().tainted,
        "Variable 'sql' should be tainted from formatQuery(id) return value"
    );
}

// ── TEST 3: Multi-hop helper call chain ──────────────────────────────────────
#[test]
fn test_multihop_helper_chain() {
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
    let (engine, _) = propagate(code, None);
    assert!(
        engine.function_defs.contains_key("helperb"),
        "helperB should be indexed"
    );
    let def_b = engine.function_defs.get("helperb").unwrap();
    let sink_line = def_b.start_line + 1;
    let b_taint = engine.is_symbol_tainted_at("b", sink_line);
    assert!(
        b_taint.is_some() && b_taint.unwrap().tainted,
        "Formal parameter 'b' in helperB should be tainted via multi-hop call chain"
    );
    assert!(
        engine.validated_paths_count >= 1,
        "Multi-hop call chain should reach executeQuery sink"
    );
}

// ── TEST 4: Parameter independence (negative control) ────────────────────────
#[test]
fn test_parameter_independence_negative() {
    let code = r#"
void process(String safeParam, String taintedParam) {
    stmt.executeQuery(safeParam);
}
String id = request.getParameter("id");
process("clean_data", id);
"#;
    let (engine, _) = propagate(code, None);
    let def = engine
        .function_defs
        .get("process")
        .expect("process should be indexed");
    let sink_line = def.start_line + 1;

    let safe_taint = engine.is_symbol_tainted_at("safeParam", sink_line);
    assert!(
        safe_taint.is_none(),
        "safeParam must NOT be tainted inside process: parameter independence violated"
    );

    let tainted_taint = engine.is_symbol_tainted_at("taintedParam", sink_line);
    assert!(
        tainted_taint.is_some() && tainted_taint.unwrap().tainted,
        "taintedParam should be tainted inside process"
    );

    assert_eq!(
        engine.validated_paths_count, 0,
        "No sink should be reached with tainted data when only safeParam is passed to sink"
    );
}

// ── TEST 5: Constant return value (negative control) ─────────────────────────
#[test]
fn test_helper_constant_return_negative() {
    let code = r#"
String getConstant(String input) {
    return "SELECT 1 FROM DUAL";
}
String id = request.getParameter("id");
String sql = getConstant(id);
"#;
    let (engine, _) = propagate(code, None);
    let sql_state = engine.get_taint("sql");
    assert!(
        sql_state.is_none(),
        "Constant return value must not propagate taint to 'sql'"
    );
}

// ── TEST 6: Boolean predicate call suppression (negative control) ─────────────
#[test]
fn test_boolean_predicate_not_tainted() {
    let code = r#"
String id = request.getParameter("id");
boolean valid = isValid(id);
"#;
    let (engine, _) = propagate(code, None);
    let valid_state = engine.get_taint("valid");
    assert!(
        valid_state.is_none(),
        "Boolean predicate method 'isValid' must not propagate data taint"
    );
}

// ── TEST 7: Call context independence ────────────────────────────────────────
#[test]
fn test_helper_call_context_independence() {
    let code = r#"
String identity(String p) {
    return p;
}
String safe_val = identity("safe_data");
String id = request.getParameter("id");
String tainted_val = identity(id);
"#;
    let (engine, _) = propagate(code, None);
    let safe_state = engine.get_taint("safe_val");
    assert!(
        safe_state.is_none(),
        "safe_val must remain untainted from the safe call"
    );

    let tainted_state = engine.get_taint("tainted_val");
    assert!(
        tainted_state.is_some() && tainted_state.unwrap().tainted,
        "tainted_val must be tainted from the tainted call"
    );
}

// ── TEST 8: External propagator model -> return target ───────────────────────
#[test]
fn test_external_propagator_return() {
    let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-propagator",
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
String out = CustomProp.transform(id);
"#;
    let (engine, _) = propagate(code, Some(registry));
    let out_state = engine.get_taint("out");
    assert!(
        out_state.is_some() && out_state.unwrap().tainted,
        "Propagator with 'return' target should taint destination variable 'out'"
    );
}

// ── TEST 9: External propagator model -> receiver target ─────────────────────
#[test]
fn test_external_propagator_receiver() {
    let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-propagator-receiver",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop2",
      "kind": "propagator",
      "callee": "CustomBuilder.append",
      "languages": ["java"],
      "input_args": [0],
      "propagates_to": "receiver"
    }
  ]
}"#;
    let registry = build_registry(pack_json);
    let code = r#"
String id = request.getParameter("id");
builder.append(id);
"#;
    let (engine, _) = propagate(code, Some(registry));
    let builder_state = engine.get_taint("builder");
    assert!(
        builder_state.is_some() && builder_state.unwrap().tainted,
        "Propagator with 'receiver' target should taint receiver 'builder'"
    );
}

// ── TEST 10: Recursion budget and cycle termination ──────────────────────────
#[test]
fn test_recursive_helper_terminates() {
    let code = r#"
void recurse(String p) {
    recurse(p);
}
String id = request.getParameter("id");
recurse(id);
"#;
    // Must complete cleanly without stack overflow or infinite loop
    let (engine, _) = propagate(code, None);
    assert!(
        engine.function_defs.contains_key("recurse"),
        "Recursive helper should be indexed and terminated cleanly"
    );
}

// ── TEST 11: Call context independence — tainted call first, safe second ──────
#[test]
fn test_helper_call_context_independence_reversed_order() {
    let code = r#"
String identity(String p) {
    return p;
}
String id = request.getParameter("id");
String tainted_val = identity(id);
String safe_val = identity("safe_data");
"#;
    let (engine, _) = propagate(code, None);
    let safe_state = engine.get_taint("safe_val");
    assert!(
        safe_state.is_none(),
        "safe_val must remain untainted even when identity is called with safe data after a tainted call"
    );

    let tainted_state = engine.get_taint("tainted_val");
    assert!(
        tainted_state.is_some() && tainted_state.unwrap().tainted,
        "tainted_val must be tainted from the tainted call"
    );
}

// ── TEST 12: Multi-hop return chain (B returns to A returns to caller) ────────
#[test]
fn test_multihop_return_chain() {
    let code = r#"
String helperB(String b) {
    return b;
}
String helperA(String a) {
    return helperB(a);
}
String id = request.getParameter("id");
String result = helperA(id);
"#;
    let (engine, _) = propagate(code, None);
    let res_state = engine.get_taint("result");
    assert!(
        res_state.is_some() && res_state.unwrap().tainted,
        "result must be tainted via multi-hop return chain: helperB -> helperA -> caller"
    );
}

// ── TEST 13: Unknown external call dataflow precision ─────────────────────────
#[test]
fn test_unknown_external_call_preserves_taint_and_safe_data() {
    let code = r#"
String id = request.getParameter("id");
String tainted_res = SomeExternalLib.process(id);
String safe_res = SomeExternalLib.process("clean_literal");
"#;
    let (engine, _) = propagate(code, None);
    let tainted_state = engine.get_taint("tainted_res");
    assert!(
        tainted_state.is_some() && tainted_state.unwrap().tainted,
        "tainted_res must preserve taint across unknown library transformations"
    );

    let safe_state = engine.get_taint("safe_res");
    assert!(
        safe_state.is_none(),
        "safe_res must remain untainted: unknown calls on safe literals must not invent taint"
    );
}
