pub mod call_graph;
pub mod global;

pub use call_graph::{CallEdge, CallGraph, CallNode, EdgeType};
pub use global::{FieldInfo, GlobalSymbolTable, MethodInfo, ModuleInfo, TypeInfo, TypeKind};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolId(pub u32);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SymbolKind {
    Variable,
    Parameter,
    Function,
    Import,
    Field,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub kind: SymbolKind,
    pub type_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeKind {
    Global,
    Module,
    Function,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub id: usize,
    pub parent_id: Option<usize>,
    pub kind: ScopeKind,
    pub symbols: HashMap<String, Symbol>,
}

pub struct SymbolTable {
    pub scopes: Vec<Scope>,
    pub current_scope_id: usize,
    next_symbol_id: u32,
    import_bindings: HashMap<String, String>, // Short name -> Full path (Java)
}

impl SymbolTable {
    pub fn new() -> Self {
        let global_scope = Scope {
            id: 0,
            parent_id: None,
            kind: ScopeKind::Global,
            symbols: HashMap::new(),
        };

        Self {
            scopes: vec![global_scope],
            current_scope_id: 0,
            next_symbol_id: 0,
            import_bindings: HashMap::new(),
        }
    }

    pub fn enter_scope(&mut self, kind: ScopeKind) -> usize {
        let new_id = self.scopes.len();
        let scope = Scope {
            id: new_id,
            parent_id: Some(self.current_scope_id),
            kind,
            symbols: HashMap::new(),
        };
        self.scopes.push(scope);
        self.current_scope_id = new_id;
        new_id
    }

    pub fn exit_scope(&mut self) -> Result<(), String> {
        let parent_id = self.scopes[self.current_scope_id]
            .parent_id
            .ok_or_else(|| "Cannot exit root global scope".to_string())?;
        self.current_scope_id = parent_id;
        Ok(())
    }

    pub fn insert(&mut self, name: &str, kind: SymbolKind, type_name: Option<String>) -> SymbolId {
        let sym_id = SymbolId(self.next_symbol_id);
        self.next_symbol_id += 1;

        let symbol = Symbol {
            id: sym_id,
            name: name.to_string(),
            kind,
            type_name,
        };

        self.scopes[self.current_scope_id]
            .symbols
            .insert(name.to_string(), symbol);
        sym_id
    }

    pub fn lookup(&self, name: &str) -> Option<&Symbol> {
        self.lookup_from(name, self.current_scope_id)
    }

    pub fn lookup_from(&self, name: &str, start_scope_id: usize) -> Option<&Symbol> {
        let mut curr_id = start_scope_id;
        loop {
            let scope = &self.scopes[curr_id];
            if let Some(sym) = scope.symbols.get(name) {
                return Some(sym);
            }
            if let Some(parent) = scope.parent_id {
                curr_id = parent;
            } else {
                break;
            }
        }
        None
    }

    pub fn insert_import(&mut self, short_name: &str, full_path: &str) {
        self.import_bindings
            .insert(short_name.to_string(), full_path.to_string());
        self.insert(short_name, SymbolKind::Import, Some(full_path.to_string()));
    }

    pub fn resolve_import(&self, short_name: &str) -> Option<&String> {
        self.import_bindings.get(short_name)
    }
}
