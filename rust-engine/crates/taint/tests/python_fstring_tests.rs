use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_python_fstring_taint() {
    let code = r#"
user = request.args["id"]
query = f"SELECT * FROM users WHERE id={user}"
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let query_state = engine.get_taint("query");
    assert!(query_state.is_some());
    assert!(
        query_state.unwrap().tainted,
        "f-string output must propagate taint"
    );
}
