use normalizer::{NormalizedKind, Normalizer};
use parser::UnifiedParser;

#[test]
fn test_python_args_normalization() {
    let code = "func(*values)";
    let ast = UnifiedParser::parse(code, "python").unwrap();

    let mut normalizer = Normalizer::new();
    let norm = normalizer.normalize(&ast, "python");

    let mut found_call = false;

    fn check_node(node: &normalizer::NormalizedNode, found: &mut bool) {
        if let NormalizedKind::Call {
            callee,
            arguments,
            star_args,
            kw_args,
        } = &node.kind
        {
            *found = true;
            assert_eq!(callee, "func");
            assert_eq!(star_args.as_deref(), Some("values"));
            assert_eq!(kw_args, &None);
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

    check_node(&norm, &mut found_call);
    assert!(found_call, "Call with *args should be parsed and captured");
}
