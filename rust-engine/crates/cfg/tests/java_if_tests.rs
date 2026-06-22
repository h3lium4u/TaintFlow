use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_java_if_else_cfg() {
    let code = r#"
if (a) {
    x();
} else {
    y();
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    let has_branch = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Branch));
    assert!(has_branch, "Java CFG must contain a Branch node");
}
