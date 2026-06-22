use symbols::{ScopeKind, SymbolKind, SymbolTable};

#[test]
fn test_python_scopes_and_parameters() {
    let mut table = SymbolTable::new();

    // Global scope
    table.insert(
        "request",
        SymbolKind::Variable,
        Some("FlaskRequest".to_string()),
    );

    // Enter module scope
    table.enter_scope(ScopeKind::Module);
    table.insert("user", SymbolKind::Variable, None);

    // Enter function scope
    table.enter_scope(ScopeKind::Function);
    table.insert("name", SymbolKind::Parameter, Some("String".to_string()));

    // Lookups
    let param = table.lookup("name");
    assert!(param.is_some());
    assert_eq!(param.unwrap().kind, SymbolKind::Parameter);

    let var = table.lookup("user");
    assert!(var.is_some());
    assert_eq!(var.unwrap().kind, SymbolKind::Variable);

    let global_var = table.lookup("request");
    assert!(global_var.is_some());
    assert_eq!(
        global_var.unwrap().type_name.as_deref(),
        Some("FlaskRequest")
    );
}
