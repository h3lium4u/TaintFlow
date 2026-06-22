use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_return_statement_cfg() {
    let code = r#"
def test():
    return value
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    // Verify Return node exists and connects to Exit node (id: 1)
    let return_node = graph
        .nodes
        .iter()
        .find(|n| matches!(n.kind, CfgNodeKind::Return));
    assert!(return_node.is_some(), "CFG must contain a Return node");

    let ret_id = return_node.unwrap().id;
    let has_edge_to_exit = graph.edges.iter().any(|e| e.from == ret_id && e.to == 1);
    assert!(
        has_edge_to_exit,
        "Return node must connect directly to Exit node (id: 1)"
    );
}
