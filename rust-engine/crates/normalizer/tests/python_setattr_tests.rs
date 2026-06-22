use normalizer::{NormalizedKind, Normalizer};
use parser::UnifiedParser;

#[test]
fn test_python_setattr_normalization() {
    let code = "setattr(obj, \"name\", user_input)";
    let ast = UnifiedParser::parse(code, "python").unwrap();

    let mut normalizer = Normalizer::new();
    let norm = normalizer.normalize(&ast, "python");

    let mut found_assignment = false;

    fn check_node(node: &normalizer::NormalizedNode, found: &mut bool) {
        if let NormalizedKind::Assignment { lhs, rhs } = &node.kind {
            *found = true;
            assert_eq!(lhs.raw, "obj.name");
            assert_eq!(rhs.raw, "user_input");
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

    check_node(&norm, &mut found_assignment);
    assert!(
        found_assignment,
        "setattr should be normalized to Assignment kind"
    );
}
