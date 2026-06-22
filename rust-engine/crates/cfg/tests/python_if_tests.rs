use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_python_if_else_cfg() {
    let code = r#"
if user:
    execute()
else:
    log()
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    // Verify presence of Branch
    let has_branch = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Branch));
    assert!(has_branch, "CFG must contain a Branch node");

    // Entry connects to Branch, Branch connects to statements or exits
    assert!(
        graph.edges.len() >= 3,
        "CFG should have edges for both branches"
    );
}
