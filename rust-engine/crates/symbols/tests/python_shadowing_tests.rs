use symbols::{ScopeKind, SymbolKind, SymbolTable};

#[test]
fn test_python_variable_shadowing() {
    let mut table = SymbolTable::new();

    // Outer scope 'user = "a"'
    table.insert("user", SymbolKind::Variable, Some("OuterType".to_string()));

    // Inner function scope
    table.enter_scope(ScopeKind::Function);

    // Shadowing 'user = "b"'
    table.insert("user", SymbolKind::Variable, Some("InnerType".to_string()));

    // Lookup must return nearest/inner symbol
    let resolved = table.lookup("user").unwrap();
    assert_eq!(resolved.type_name.as_deref(), Some("InnerType"));

    // Exit scope
    table.exit_scope().unwrap();

    // Lookup must return outer symbol now
    let outer = table.lookup("user").unwrap();
    assert_eq!(outer.type_name.as_deref(), Some("OuterType"));
}
