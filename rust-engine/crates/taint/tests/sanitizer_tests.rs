use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::{TaintEngine, CWE};

#[test]
fn test_cwe_specific_sanitization() {
    let code = r#"
user = request.args["id"]
safe_user = escape_string(user)
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let state = engine.get_taint("safe_user");
    assert!(state.is_some(), "safe_user should be tracked");
    let state = state.unwrap();
    assert!(
        state.tainted,
        "safe_user should still be tainted (but sanitized)"
    );
    assert!(
        state.sanitized_for.contains(&CWE::CWE89),
        "safe_user should be sanitized for CWE-89"
    );
    assert!(
        !state.sanitized_for.contains(&CWE::CWE78),
        "safe_user should NOT be sanitized for CWE-78"
    );
}

#[test]
fn test_conditional_validation_consequent() {
    let code = r#"
user = request.args["id"]
if is_valid_url(user):
    url = user
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    // Let's check the taint status of "url"
    let state = engine.get_taint("url");
    assert!(state.is_some(), "url should be tracked");
    let state = state.unwrap();
    assert!(
        state.sanitized_for.contains(&CWE::CWE918),
        "url should be sanitized for CWE-918 in consequent"
    );
}

#[test]
fn test_conditional_validation_negated_return() {
    let code = r#"
def process(user):
    if not is_valid_url(user):
        return
    url = user
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    // Since we pass user as a parameter, let's taint it initially in our engine
    let mut engine = TaintEngine::new(10, 5, 200);
    engine
        .tainted_symbols
        .insert("user".to_string(), taint::TaintState::new(true));
    engine.propagate_node(&normalized);

    // After the if block, "user" should be sanitized at the line of "url = user"
    // Let's get the state of "url"
    let state = engine.get_taint("url");
    assert!(state.is_some(), "url should be tracked");
    let state = state.unwrap();
    assert!(
        state.sanitized_for.contains(&CWE::CWE918),
        "url should be sanitized for CWE-918 after negated check with return"
    );
}

#[test]
fn test_conditional_validation_alternate() {
    let code = r#"
user = request.args["id"]
if not is_valid_url(user):
    pass
else:
    url = user
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    // Let's check the taint status of "url" inside else
    let state = engine.get_taint("url");
    assert!(state.is_some(), "url should be tracked");
    let state = state.unwrap();
    assert!(
        state.sanitized_for.contains(&CWE::CWE918),
        "url should be sanitized for CWE-918 in alternate of negated check"
    );
}
