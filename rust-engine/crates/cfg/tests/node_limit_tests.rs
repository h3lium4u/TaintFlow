use cfg::CfgBuilder;
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_node_limits_safety() {
    let code = r#"
x = 1
y = 2
z = 3
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    // Force strict limit of 3 nodes (Entry, Exit + max 1 Statement node)
    let mut builder = CfgBuilder::new(3);
    let graph = builder.build(&normalized);

    // Graph nodes must be capped at 3
    assert!(
        graph.nodes.len() <= 3,
        "CFG should not exceed maximum capacity bounds"
    );
}
