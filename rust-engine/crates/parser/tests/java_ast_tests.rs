use parser::{AstNode, NodeKind, UnifiedParser};

#[test]
fn test_java_ast_generation() {
    let code = r#"
String user = request.getParameter("id");
stmt.executeQuery("SELECT * FROM users WHERE id=" + user);
"#;

    let result = UnifiedParser::parse(code, "java");
    assert!(
        result.is_ok(),
        "Failed to parse Java code: {:?}",
        result.err()
    );

    let root = result.unwrap();

    let mut found_declarator = false;
    let mut found_parameter_call = false;
    let mut found_execute_call = false;
    let mut found_identifier = false;

    fn traverse(
        node: &AstNode,
        decl: &mut bool,
        param_call: &mut bool,
        exec_call: &mut bool,
        ident: &mut bool,
    ) {
        match &node.kind {
            NodeKind::VariableDeclarator => {
                if node.raw.contains("user = request.getParameter") {
                    *decl = true;
                }
            }
            NodeKind::CallExpression => {
                if node.raw.contains("request.getParameter") {
                    *param_call = true;
                }
                if node.raw.contains("stmt.executeQuery") {
                    *exec_call = true;
                }
            }
            NodeKind::Identifier => {
                if node.raw == "user" {
                    *ident = true;
                }
            }
            _ => {}
        }
        for child in &node.children {
            traverse(child, decl, param_call, exec_call, ident);
        }
    }

    traverse(
        &root,
        &mut found_declarator,
        &mut found_parameter_call,
        &mut found_execute_call,
        &mut found_identifier,
    );

    assert!(found_declarator, "Should map Java variable declarator");
    assert!(found_parameter_call, "Should map request.getParameter call");
    assert!(found_execute_call, "Should map stmt.executeQuery call");
    assert!(found_identifier, "Should resolve 'user' identifier");
}
