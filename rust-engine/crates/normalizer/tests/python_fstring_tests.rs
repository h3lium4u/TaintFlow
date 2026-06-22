use normalizer::{NormalizedKind, Normalizer};
use parser::UnifiedParser;

#[test]
fn test_python_fstring_normalization() {
    let code = "f\"SELECT * FROM users WHERE id={user}\"";
    let ast = UnifiedParser::parse(code, "python").unwrap();

    let mut normalizer = Normalizer::new();
    let norm = normalizer.normalize(&ast, "python");

    // Check that f-string is rewritten to Concat
    // F-strings under parsing may be children of expression or module, we traverse to find Concat
    let mut found_concat = false;

    fn check_node(node: &normalizer::NormalizedNode, found: &mut bool) {
        if let NormalizedKind::Concat { parts } = &node.kind {
            *found = true;
            assert_eq!(parts.len(), 2);
            assert!(matches!(&parts[0].kind, NormalizedKind::Literal(_)));
            assert!(matches!(&parts[1].kind, NormalizedKind::Identifier(_)));
        }

        match &node.kind {
            NormalizedKind::Block(children) => {
                for child in children {
                    check_node(child, found);
                }
            }
            _ => {}
        }
    }

    check_node(&norm, &mut found_concat);
    assert!(found_concat, "F-string should be normalized to Concat kind");
}
