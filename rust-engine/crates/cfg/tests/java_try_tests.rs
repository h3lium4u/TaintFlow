use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_java_try_catch_finally_cfg() {
    let code = r#"
try {
    x();
} catch (Exception e) {
    y();
} finally {
    z();
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    let has_try = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Try));
    let has_catch = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Catch));
    let has_finally = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Finally));

    assert!(has_try, "Java CFG must contain a Try node");
    assert!(has_catch, "Java CFG must contain a Catch node");
    assert!(has_finally, "Java CFG must contain a Finally node");
}
