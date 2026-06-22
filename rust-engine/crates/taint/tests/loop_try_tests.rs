use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_nested_loops_taint() {
    let code = r#"
user = request.args["id"]
for i in range(10):
    for j in range(5):
        x = user
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.is_symbol_tainted("x");
    assert!(x_state.is_some(), "x should be tracked");
    assert!(x_state.unwrap().tainted, "x should be tainted");
}

#[test]
fn test_try_catch_finally_taint() {
    let code = r#"
try:
    user = request.args["id"]
except Exception as e:
    pass
finally:
    x = user
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.is_symbol_tainted("x");
    assert!(x_state.is_some(), "x should be tracked");
    assert!(x_state.unwrap().tainted, "x should be tainted");
}
