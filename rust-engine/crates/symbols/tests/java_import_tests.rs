use symbols::{SymbolKind, SymbolTable};

#[test]
fn test_java_imports_binding() {
    let mut table = SymbolTable::new();

    // Bind java.util.List
    table.insert_import("List", "java.util.List");

    let path = table.resolve_import("List");
    assert_eq!(path.map(|s| s.as_str()), Some("java.util.List"));

    let sym = table.lookup("List").unwrap();
    assert_eq!(sym.kind, SymbolKind::Import);
}
