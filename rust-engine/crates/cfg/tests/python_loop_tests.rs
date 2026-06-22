use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_python_loop_cfg() {
    let code = r#"
while a:
    x()
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    // Verify Loop Node
    let has_loop = graph
        .nodes
        .iter()
        .any(|n| matches!(n.kind, CfgNodeKind::Loop));
    assert!(has_loop, "CFG must contain a Loop node");

    // Loop should connect to body and body must connect back to loop
    let mut back_edge_found = false;
    for edge in &graph.edges {
        let from_node = &graph.nodes[edge.from as usize];
        let to_node = &graph.nodes[edge.to as usize];
        if matches!(from_node.kind, CfgNodeKind::Statement)
            && matches!(to_node.kind, CfgNodeKind::Loop)
        {
            back_edge_found = true;
        }
    }
    assert!(
        back_edge_found,
        "CFG must contain a back-edge from body to loop header"
    );
}
