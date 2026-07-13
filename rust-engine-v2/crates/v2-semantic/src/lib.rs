use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use v2_common::Span;
use v2_parser::CstNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScopeKind {
    Global,
    Class,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    Variable,
    Class,
    Method,
    Parameter,
    Import,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: usize,
    pub kind: ScopeKind,
    pub name: String,
    pub symbols: HashMap<String, Symbol>,
    pub parent_id: Option<usize>,
    pub children_ids: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticInfo {
    pub scopes: HashMap<usize, Scope>,
    pub global_scope_id: usize,
    pub types_hierarchy: HashMap<String, Option<String>>, // Class name -> Superclass name
    next_scope_id: usize,
}

impl SemanticInfo {
    pub fn new() -> Self {
        let global_id = 0;
        let global_scope = Scope {
            id: global_id,
            kind: ScopeKind::Global,
            name: "global".to_string(),
            symbols: HashMap::new(),
            parent_id: None,
            children_ids: Vec::new(),
        };

        let mut scopes = HashMap::new();
        scopes.insert(global_id, global_scope);

        Self {
            scopes,
            global_scope_id: global_id,
            types_hierarchy: HashMap::new(),
            next_scope_id: 1,
        }
    }

    pub fn alloc_scope(&mut self, kind: ScopeKind, name: String, parent_id: usize) -> usize {
        let id = self.next_scope_id;
        self.next_scope_id += 1;

        let scope = Scope {
            id,
            kind,
            name,
            symbols: HashMap::new(),
            parent_id: Some(parent_id),
            children_ids: Vec::new(),
        };

        self.scopes.insert(id, scope);
        if let Some(parent) = self.scopes.get_mut(&parent_id) {
            parent.children_ids.push(id);
        }

        id
    }

    pub fn insert_symbol(&mut self, scope_id: usize, symbol: Symbol) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.symbols.insert(symbol.name.clone(), symbol);
        }
    }

    pub fn lookup(&self, name: &str, mut scope_id: usize) -> Option<&Symbol> {
        loop {
            if let Some(scope) = self.scopes.get(&scope_id) {
                if let Some(sym) = scope.symbols.get(name) {
                    return Some(sym);
                }
                if let Some(parent) = scope.parent_id {
                    scope_id = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        None
    }
}

pub fn resolve_semantics(root: &dyn CstNode) -> SemanticInfo {
    let mut info = SemanticInfo::new();
    let global_scope = info.global_scope_id;
    walk_node(root, &mut info, global_scope);
    info
}

fn walk_node(node: &dyn CstNode, info: &mut SemanticInfo, current_scope_id: usize) {
    match node.kind() {
        "ClassDefinition" => {
            let name = find_child_identifier(node).unwrap_or_else(|| "UnknownClass".to_string());
            let parent_class = find_parent_class(node);
            info.types_hierarchy.insert(name.clone(), parent_class);

            let sym = Symbol {
                name: name.clone(),
                kind: SymbolKind::Class,
                span: node.span(),
            };
            info.insert_symbol(current_scope_id, sym);

            let new_scope_id = info.alloc_scope(ScopeKind::Class, name, current_scope_id);
            for child in node.children() {
                // Walk the children of ClassDefinition under the Class scope
                walk_node(child, info, new_scope_id);
            }
        }
        "FunctionDefinition" => {
            let name = find_child_identifier(node).unwrap_or_else(|| "unknown_func".to_string());
            let sym = Symbol {
                name: name.clone(),
                kind: SymbolKind::Method,
                span: node.span(),
            };
            info.insert_symbol(current_scope_id, sym);

            let new_scope_id = info.alloc_scope(ScopeKind::Function, name, current_scope_id);

            // Resolve parameters
            if let Some(params_node) = node.children().iter().find(|c| c.kind() == "parameters") {
                for param in params_node.children() {
                    let param_name = param.raw().trim().to_string();
                    if !param_name.is_empty() && param.kind() == "Identifier" {
                        let param_sym = Symbol {
                            name: param_name,
                            kind: SymbolKind::Parameter,
                            span: param.span(),
                        };
                        info.insert_symbol(new_scope_id, param_sym);
                    }
                }
            }

            for child in node.children() {
                if child.kind() != "parameters" {
                    walk_node(child, info, new_scope_id);
                }
            }
        }
        "AssignmentExpression" => {
            if let Some(lhs) = node.children().first() {
                collect_assignment_targets(*lhs, info, current_scope_id);
            }
            if node.children().len() >= 2 {
                for child in &node.children()[1..] {
                    walk_node(*child, info, current_scope_id);
                }
            }
        }
        "ImportStatement" => {
            // Find all identifiers or raw imports
            collect_imports(node, info, current_scope_id);
        }
        _ => {
            for child in node.children() {
                walk_node(child, info, current_scope_id);
            }
        }
    }
}

fn find_child_identifier(node: &dyn CstNode) -> Option<String> {
    node.children()
        .iter()
        .find(|c| c.kind() == "Identifier")
        .map(|c| c.raw().trim().to_string())
}

fn find_parent_class(node: &dyn CstNode) -> Option<String> {
    node.children()
        .iter()
        .find(|c| c.kind() == "argument_list" || c.kind() == "parameters")
        .and_then(|c| {
            c.children()
                .first()
                .map(|first_arg| first_arg.raw().trim().to_string())
        })
}

fn collect_assignment_targets(node: &dyn CstNode, info: &mut SemanticInfo, scope_id: usize) {
    if node.kind() == "Identifier" {
        let name = node.raw().trim().to_string();
        if info.scopes.get(&scope_id).unwrap().symbols.get(&name).is_none() {
            let sym = Symbol {
                name,
                kind: SymbolKind::Variable,
                span: node.span(),
            };
            info.insert_symbol(scope_id, sym);
        }
    } else {
        for child in node.children() {
            collect_assignment_targets(child, info, scope_id);
        }
    }
}

fn collect_imports(node: &dyn CstNode, info: &mut SemanticInfo, scope_id: usize) {
    // Collect imported names and register them
    for child in node.children() {
        if child.kind() == "dotted_name" || child.kind() == "Identifier" || child.kind() == "aliased_import" {
            let name = child.raw().trim().to_string();
            let sym = Symbol {
                name,
                kind: SymbolKind::Import,
                span: child.span(),
            };
            info.insert_symbol(scope_id, sym);
        } else {
            collect_imports(child, info, scope_id);
        }
    }
}

pub fn init() {
    println!("v2-semantic initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_parser::parse_python;

    #[test]
    fn test_resolve_nested_scopes() {
        let code = r#"
class Account(BaseModel):
    def set_balance(self, amount):
        balance = amount
        return balance
"#;
        let cst = parse_python(code).unwrap();
        let info = resolve_semantics(cst.as_ref());

        // We expect: Global -> Account (Class) -> set_balance (Function)
        assert_eq!(info.types_hierarchy.get("Account").unwrap(), &Some("BaseModel".to_string()));

        // Lookup set_balance in Global
        let global_scope = info.scopes.get(&info.global_scope_id).unwrap();
        assert!(global_scope.symbols.contains_key("Account"));

        // Find Class Scope
        let class_scope_id = *global_scope.children_ids.first().unwrap();
        let class_scope = info.scopes.get(&class_scope_id).unwrap();
        assert_eq!(class_scope.name, "Account");
        assert!(class_scope.symbols.contains_key("set_balance"));

        // Find Method Scope
        let method_scope_id = *class_scope.children_ids.first().unwrap();
        let method_scope = info.scopes.get(&method_scope_id).unwrap();
        assert_eq!(method_scope.name, "set_balance");
        assert!(method_scope.symbols.contains_key("self"));
        assert!(method_scope.symbols.contains_key("amount"));
        assert!(method_scope.symbols.contains_key("balance"));
    }
}
