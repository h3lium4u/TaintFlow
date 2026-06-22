use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_java_list_taint() {
    let code = r#"
String user = request.getParameter("id");
List<String> list = new ArrayList<>();
list.add(user);
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let list_state = engine.get_taint("list");
    assert!(list_state.is_some());
    assert!(
        list_state.unwrap().tainted,
        "List.add(tainted) should taint list container"
    );
}
