use parser::{AstNode, NodeKind, UnifiedParser};

#[test]
fn test_python_ast_generation() {
    let code = r#"
user = request.args.get("id")
query = f"SELECT * FROM users WHERE id={user}"
cursor.execute(query)
"#;

    let result = UnifiedParser::parse(code, "python");
    assert!(
        result.is_ok(),
        "Failed to parse Python code: {:?}",
        result.err()
    );

    let root = result.unwrap();

    // Find the assignment node for 'user'
    let mut found_assignment = false;
    let mut found_call = false;
    let mut found_query_assignment = false;
    let mut found_execute_call = false;

    fn traverse(
        node: &AstNode,
        user_assign: &mut bool,
        call_expr: &mut bool,
        query_assign: &mut bool,
        execute_call: &mut bool,
    ) {
        match &node.kind {
            NodeKind::AssignmentExpression => {
                if node.raw.contains("user =") {
                    *user_assign = true;
                }
                if node.raw.contains("query =") {
                    *query_assign = true;
                }
            }
            NodeKind::CallExpression => {
                if node.raw.contains("request.args.get") {
                    *call_expr = true;
                }
                if node.raw.contains("cursor.execute") {
                    *execute_call = true;
                }
            }
            _ => {}
        }
        for child in &node.children {
            traverse(child, user_assign, call_expr, query_assign, execute_call);
        }
    }

    traverse(
        &root,
        &mut found_assignment,
        &mut found_call,
        &mut found_query_assignment,
        &mut found_execute_call,
    );

    assert!(found_assignment, "Should map user assignment");
    assert!(found_call, "Should map request.args.get call");
    assert!(found_query_assignment, "Should map query assignment");
    assert!(found_execute_call, "Should map cursor.execute call");
}
