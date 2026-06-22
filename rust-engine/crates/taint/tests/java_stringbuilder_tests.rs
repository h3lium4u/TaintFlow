use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_java_stringbuilder_taint() {
    let code = r#"
String user = request.getParameter("id");
StringBuilder sb = new StringBuilder();
sb.append(user);
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let sb_state = engine.get_taint("sb");
    assert!(sb_state.is_some());
    assert!(
        sb_state.unwrap().tainted,
        "StringBuilder.append(tainted) should taint container"
    );
}
