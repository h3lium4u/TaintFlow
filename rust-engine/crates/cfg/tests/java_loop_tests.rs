use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_java_loop_cfg() {
    let code = r#"
while (a) {
    x();
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    let has_loop = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Loop));
    assert!(has_loop, "Java CFG must contain a Loop node");
}
