use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_assignment_taint_propagation() {
    let code = r#"
user = request.args["id"]
x = user
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let user_state = engine.is_symbol_tainted("user");
    assert!(user_state.is_some(), "user should be tracked");
    assert!(user_state.unwrap().tainted, "user should be tainted");

    let x_state = engine.is_symbol_tainted("x");
    assert!(x_state.is_some(), "x should be tracked");
    assert!(x_state.unwrap().tainted, "x should be tainted");
}
