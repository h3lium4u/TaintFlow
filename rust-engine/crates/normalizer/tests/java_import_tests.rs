use normalizer::{NormalizedKind, Normalizer};
use parser::UnifiedParser;

#[test]
fn test_java_import_resolution() {
    let code = "import java.util.List;";
    let ast = UnifiedParser::parse(code, "java").unwrap();

    let mut normalizer = Normalizer::new();
    let norm = normalizer.normalize(&ast, "java");

    let mut found_import = false;

    fn check_node(node: &normalizer::NormalizedNode, found: &mut bool) {
        if let NormalizedKind::Import {
            class_name,
            full_path,
        } = &node.kind
        {
            *found = true;
            assert_eq!(class_name, "List");
            assert_eq!(full_path, "java.util.List");
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

    check_node(&norm, &mut found_import);
    assert!(
        found_import,
        "Import declaration should be resolved and stored"
    );
    assert_eq!(
        normalizer.get_import_path("List").map(|s| s.as_str()),
        Some("java.util.List")
    );
}
