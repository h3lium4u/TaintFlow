use parser::{AstNode, UnifiedParser};

#[test]
fn test_span_coordinates_accuracy() {
    // Multi-line code block to check spans
    let code = "x = (\n  get_value(\n    \"secret_id\"\n  )\n)";

    let result = UnifiedParser::parse(code, "python");
    assert!(result.is_ok());
    let root = result.unwrap();

    // Traverse and inspect spans
    fn verify_spans(node: &AstNode) {
        // Root or any node must have valid start and end positions
        assert!(
            node.span.start_line <= node.span.end_line,
            "Start line must be before or equal to end line"
        );
        if node.span.start_line == node.span.end_line {
            assert!(
                node.span.start_column <= node.span.end_column,
                "Start column must be before or equal to end column on same line"
            );
        }

        // Verify nested elements like get_value call span
        if node.raw.contains("get_value") && matches!(node.kind, parser::NodeKind::CallExpression) {
            // Should start around line 2, col 2 and end around line 4, col 3
            assert!(node.span.start_line >= 2);
            assert!(node.span.end_line <= 4);
        }

        for child in &node.children {
            verify_spans(child);
        }
    }

    verify_spans(&root);
}
