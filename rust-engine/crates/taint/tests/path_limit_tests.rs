use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_path_limits_enforced() {
    let code = r#"
x = request.args["id"]
y = x
z = y
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    // Enforce 1-path strict limit
    let mut engine = TaintEngine::new(10, 5, 1);
    engine.propagate_node(&normalized);

    assert_eq!(
        engine.paths_explored, 1,
        "Should stop propagation when path limits are hit"
    );
}
