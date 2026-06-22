use normalizer::{NormalizedKind, Normalizer};
use parser::UnifiedParser;

#[test]
fn test_java_symbol_mapping() {
    let code = "String user = request.getParameter(\"id\");";
    let ast = UnifiedParser::parse(code, "java").unwrap();

    let mut normalizer = Normalizer::new();
    let norm = normalizer.normalize(&ast, "java");

    let mut found_decl = false;

    fn check_node(node: &normalizer::NormalizedNode, found: &mut bool) {
        if let NormalizedKind::TypeDeclaration {
            name,
            declared_type,
        } = &node.kind
        {
            *found = true;
            assert_eq!(name, "user");
            assert_eq!(declared_type, "String");
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

    check_node(&norm, &mut found_decl);
    assert!(
        found_decl,
        "Variable declarators should be mapped to symbols"
    );
    assert_eq!(
        normalizer.get_type("user").map(|s| s.as_str()),
        Some("String")
    );
}
