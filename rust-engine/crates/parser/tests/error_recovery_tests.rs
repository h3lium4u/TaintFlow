use parser::{AstNode, UnifiedParser};

#[test]
fn test_python_error_recovery() {
    let broken_code = r#"
def test(
    print("broken")
"#;

    let result = UnifiedParser::parse(broken_code, "python");
    assert!(
        result.is_ok(),
        "Parser should not crash or panic on syntax errors"
    );

    let root = result.unwrap();

    // Check if the parser recovered and generated nodes for the readable parts
    let mut has_print_call = false;

    fn check_nodes(node: &AstNode, has_print: &mut bool) {
        if node.raw.contains("print(\"broken\")") {
            *has_print = true;
        }
        for child in &node.children {
            check_nodes(child, has_print);
        }
    }

    check_nodes(&root, &mut has_print_call);
    assert!(
        has_print_call,
        "Error recovery should locate and build a partial AST for the inner print call"
    );
}
