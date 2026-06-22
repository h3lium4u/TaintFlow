use symbols::{ScopeKind, SymbolKind, SymbolTable};

#[test]
fn test_java_method_and_block_scopes() {
    let mut table = SymbolTable::new();

    // Class scope (Module-level equivalent)
    table.enter_scope(ScopeKind::Module);
    table.insert("className", SymbolKind::Field, Some("String".to_string()));

    // Method scope
    table.enter_scope(ScopeKind::Function);
    table.insert("param", SymbolKind::Parameter, Some("int".to_string()));

    // Block scope (e.g. within an IF statement)
    table.enter_scope(ScopeKind::Block);
    table.insert("local", SymbolKind::Variable, Some("boolean".to_string()));

    assert!(table.lookup("local").is_some());
    assert!(table.lookup("param").is_some());
    assert!(table.lookup("className").is_some());

    // Exit block
    table.exit_scope().unwrap();
    assert!(table.lookup("local").is_none());
    assert!(table.lookup("param").is_some());
}
