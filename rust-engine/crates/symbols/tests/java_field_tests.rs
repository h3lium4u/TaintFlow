use symbols::{ScopeKind, SymbolKind, SymbolTable};

#[test]
fn test_java_fields_mapping() {
    let mut table = SymbolTable::new();

    // Class scope
    table.enter_scope(ScopeKind::Module);
    table.insert(
        "dbConnection",
        SymbolKind::Field,
        Some("java.sql.Connection".to_string()),
    );

    let sym = table.lookup("dbConnection").unwrap();
    assert_eq!(sym.kind, SymbolKind::Field);
    assert_eq!(sym.type_name.as_deref(), Some("java.sql.Connection"));
}
