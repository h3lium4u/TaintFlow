use normalizer::{NormalizedKind, Normalizer};
use parser::UnifiedParser;

#[test]
fn test_java_type_propagation() {
    let code = "StringBuilder sb = new StringBuilder();";
    let ast = UnifiedParser::parse(code, "java").unwrap();

    let mut normalizer = Normalizer::new();
    let norm = normalizer.normalize(&ast, "java");

    // Check that 'sb' is mapped to StringBuilder type
    assert_eq!(
        normalizer.get_type("sb").map(|s| s.as_str()),
        Some("StringBuilder")
    );
}
