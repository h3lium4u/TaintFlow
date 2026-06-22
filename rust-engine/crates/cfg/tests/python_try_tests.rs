use cfg::{CfgBuilder, CfgNodeKind};
use normalizer::Normalizer;
use parser::UnifiedParser;

#[test]
fn test_python_try_except_finally_cfg() {
    let code = r#"
try:
    x()
except:
    y()
finally:
    z()
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut builder = CfgBuilder::new(100);
    let graph = builder.build(&normalized);

    // Verify Try, Catch, and Finally nodes exist
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

    assert!(has_try, "CFG must contain a Try node");
    assert!(has_catch, "CFG must contain a Catch node");
    assert!(has_finally, "CFG must contain a Finally node");
}
