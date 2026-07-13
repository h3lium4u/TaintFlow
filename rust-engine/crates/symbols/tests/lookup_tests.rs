use symbols::{ScopeKind, SymbolKind, SymbolTable};

#[test]
fn test_lookup_hierarchy() {
    let mut table = SymbolTable::new();

    // Global scope
    table.insert("global_var", SymbolKind::Variable, None);

    // Module scope
    table.enter_scope(ScopeKind::Module);
    table.insert("module_var", SymbolKind::Variable, None);

    // Function scope
    table.enter_scope(ScopeKind::Function);
    table.insert("func_var", SymbolKind::Variable, None);

    // Block scope
    table.enter_scope(ScopeKind::Block);
    table.insert("block_var", SymbolKind::Variable, None);

    // Resolve all variables from inside the deepest Block scope
    assert!(table.lookup("block_var").is_some());
    assert!(table.lookup("func_var").is_some());
    assert!(table.lookup("module_var").is_some());
    assert!(table.lookup("global_var").is_some());
}

#[test]
fn test_java_parse() {
    let code = "public class Render { public String welcome(String user) { return \"<div>Hello \" + user + \"</div>\"; } }";
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();

    let res = gst.load_file(&mut program, code, "Render.java", "java");
    assert!(res.is_ok());

    // There should be exactly 1 method: "welcome" (no fallback "main" method should be created)
    assert_eq!(program.methods.len(), 1);
    let method = program.methods.values().next().unwrap();
    assert_eq!(method.name, "welcome");
    assert_eq!(method.parameters, vec!["String user".to_string()]);
}
