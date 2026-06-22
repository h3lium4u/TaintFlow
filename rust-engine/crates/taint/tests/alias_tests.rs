use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_alias_taint_propagation() {
    let code = r#"
user = request.args["id"]
a = user
b = a
c = b
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    assert!(engine.get_taint("a").unwrap().tainted);
    assert!(engine.get_taint("b").unwrap().tainted);
    assert!(engine.get_taint("c").unwrap().tainted);
}
