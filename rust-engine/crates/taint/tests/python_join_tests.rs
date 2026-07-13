use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_python_join_taint() {
    let code = r#"
user = request.args["id"]
items = [user]
query = ",".join(items)
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    println!("JOIN TEST NORMALIZED AST:");
    println!("{:#?}", normalized);

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.tainted_symbols.insert(
        "items".to_string(),
        taint::TaintState {
            tainted: true,
            sanitized_for: std::collections::HashSet::new(),
            source_line: None,
            source_var: None,
        },
    );
    engine.propagate_node(&normalized);

    println!("JOIN TEST TAINTED SYMBOLS AFTER PROPAGATION:");
    println!("{:#?}", engine.tainted_symbols);

    let query_state = engine.is_symbol_tainted("query");
    assert!(query_state.is_some());
    assert!(
        query_state.unwrap().tainted,
        "string join using tainted container must propagate taint"
    );
}
