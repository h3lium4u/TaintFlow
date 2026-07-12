use ir::{FieldId, InstructionKind, MethodId, ModuleId, Program, TypeId};
use parser::{AstNode, NodeKind};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: ModuleId,
    pub name: String,
    pub file_path: String,
    pub package_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TypeKind {
    Class,
    Interface,
    Enum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeInfo {
    pub id: TypeId,
    pub name: String,
    pub fqn: String,
    pub kind: TypeKind,
    pub module_id: ModuleId,
    pub annotations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    pub id: MethodId,
    pub name: String,
    pub fqn: String,
    pub parent_type_id: Option<TypeId>,
    pub module_id: ModuleId,
    pub return_type: Option<String>,
    pub parameters: Vec<String>,
    pub visibility: Option<String>,
    pub is_static: bool,
    pub annotations: Vec<String>, // Decorators in Python, Annotations in Java
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub id: FieldId,
    pub name: String,
    pub fqn: String,
    pub parent_type_id: TypeId,
    pub annotations: Vec<String>,
    pub field_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramIndex {
    pub modules: HashMap<ModuleId, ModuleInfo>,
    pub types: HashMap<TypeId, TypeInfo>,
    pub methods: HashMap<MethodId, MethodInfo>,
    pub fields: HashMap<FieldId, FieldInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIndex {
    pub file_path_to_id: HashMap<String, ModuleId>,
    pub name_to_id: HashMap<String, ModuleId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeIndex {
    pub fqn_to_id: HashMap<String, TypeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodIndex {
    pub fqn_to_id: HashMap<String, MethodId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldIndex {
    pub fqn_to_id: HashMap<String, FieldId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportIndex {
    pub imports_by_module: HashMap<ModuleId, HashMap<String, String>>,
    pub wildcards_by_module: HashMap<ModuleId, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSymbolTable {
    pub program_index: ProgramIndex,
    pub module_index: ModuleIndex,
    pub type_index: TypeIndex,
    pub method_index: MethodIndex,
    pub field_index: FieldIndex,
    pub import_index: ImportIndex,

    // Inheritance
    pub child_to_parent: HashMap<TypeId, String>, // TypeId -> superclass raw name
    pub parent_to_children: HashMap<TypeId, Vec<TypeId>>, // Parent TypeId -> list of subclass TypeIds
    pub type_implements: HashMap<TypeId, Vec<String>>,    // TypeId -> interface raw names
    pub interface_to_implementors: HashMap<String, Vec<TypeId>>, // Interface FQN -> implementing subclass TypeIds
}

impl GlobalSymbolTable {
    pub fn new() -> Self {
        Self {
            program_index: ProgramIndex {
                modules: HashMap::new(),
                types: HashMap::new(),
                methods: HashMap::new(),
                fields: HashMap::new(),
            },
            module_index: ModuleIndex {
                file_path_to_id: HashMap::new(),
                name_to_id: HashMap::new(),
            },
            type_index: TypeIndex {
                fqn_to_id: HashMap::new(),
            },
            method_index: MethodIndex {
                fqn_to_id: HashMap::new(),
            },
            field_index: FieldIndex {
                fqn_to_id: HashMap::new(),
            },
            import_index: ImportIndex {
                imports_by_module: HashMap::new(),
                wildcards_by_module: HashMap::new(),
            },
            child_to_parent: HashMap::new(),
            parent_to_children: HashMap::new(),
            type_implements: HashMap::new(),
            interface_to_implementors: HashMap::new(),
        }
    }

    pub fn load_file(
        &mut self,
        program: &mut Program,
        code: &str,
        file_path: &str,
        language: &str,
    ) -> Result<ModuleId, String> {
        program.source_files.insert(file_path.to_string(), code.to_string());
        let root = parser::UnifiedParser::parse(code, language)?;
        let module_name = if language.to_lowercase() == "python" {
            let path_without_ext = if file_path.ends_with(".py") {
                &file_path[..file_path.len() - 3]
            } else if file_path.ends_with(".pyc") {
                &file_path[..file_path.len() - 4]
            } else {
                file_path
            };
            let normalized = path_without_ext.replace('\\', "/");
            let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
            let parts_init = if parts.last() == Some(&"__init__") {
                &parts[..parts.len() - 1]
            } else {
                &parts[..]
            };
            
            // Generic package-root discovery using __init__.py traversal in program.source_files
            let mut package_start_idx = 0;
            for i in 1..=parts_init.len() {
                let parent_dir = parts_init[..i].join("/");
                let init_py = format!("{}/__init__.py", parent_dir);
                let init_pyc = format!("{}/__init__.pyc", parent_dir);
                if program.source_files.contains_key(&init_py) || program.source_files.contains_key(&init_pyc) {
                    package_start_idx = i.saturating_sub(1);
                    break;
                }
            }
            
            let final_parts = &parts_init[package_start_idx..];
            if final_parts.is_empty() {
                "module".to_string()
            } else {
                final_parts.join(".")
            }
        } else {
            std::path::Path::new(file_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("main")
                .to_string()
        };

        let module_id = if let Some(&existing_mid) = self.module_index.name_to_id.get(&module_name) {
            if let Some(m) = program.modules.get_mut(&existing_mid) {
                m.file_path = file_path.to_string();
            }
            existing_mid
        } else {
            program.alloc_module(module_name.clone(), file_path.to_string())
        };

        if language.to_lowercase() == "java" {
            let (package_name, imports, wildcards) = extract_java_imports_and_package(&root);

            let module_info = ModuleInfo {
                id: module_id,
                name: module_name.clone(),
                file_path: file_path.to_string(),
                package_name: package_name.clone(),
            };
            self.program_index.modules.insert(module_id, module_info);
            self.module_index
                .file_path_to_id
                .insert(file_path.to_string(), module_id);
            self.module_index
                .name_to_id
                .insert(module_name.clone(), module_id);
            self.import_index
                .imports_by_module
                .insert(module_id, imports);
            self.import_index
                .wildcards_by_module
                .insert(module_id, wildcards);

            self.traverse_java(&root, program, module_id, &package_name, None);

            let has_methods = program
                .modules
                .get(&module_id)
                .map_or(false, |m| !m.methods.is_empty());
            if !has_methods {
                let insts = program.lower_statements(&root);
                if !insts.is_empty() {
                    let method_name = "main".to_string();
                    let parameters = vec![
                        "url".to_string(),
                        "input".to_string(),
                        "data".to_string(),
                        "p".to_string(),
                    ];
                    let method_id = program.alloc_method(
                        method_name.clone(),
                        None,
                        parameters.clone(),
                        Some(module_id),
                    );
                    if let Some(m) = program.methods.get_mut(&method_id) {
                        m.body = insts;
                    }

                    let fqn = format!("{}.{}", module_name, method_name);
                    let method_info = MethodInfo {
                        id: method_id,
                        name: method_name,
                        fqn: fqn.clone(),
                        parent_type_id: None,
                        module_id,
                        return_type: None,
                        parameters,
                        visibility: None,
                        is_static: true,
                        annotations: Vec::new(),
                    };
                    self.program_index.methods.insert(method_id, method_info);
                    self.method_index.fqn_to_id.insert(fqn, method_id);
                }
            }
        } else if language.to_lowercase() == "python" {
            let (imports, wildcards) = extract_python_imports(&root, &module_name, file_path);

            let module_info = ModuleInfo {
                id: module_id,
                name: module_name.clone(),
                file_path: file_path.to_string(),
                package_name: None,
            };
            self.program_index.modules.insert(module_id, module_info);
            self.module_index
                .file_path_to_id
                .insert(file_path.to_string(), module_id);
            self.module_index
                .name_to_id
                .insert(module_name.clone(), module_id);
            self.import_index
                .imports_by_module
                .insert(module_id, imports);
            self.import_index
                .wildcards_by_module
                .insert(module_id, wildcards);

            self.traverse_python(&root, program, module_id, &module_name, None, Vec::new());

            // RC89: Synthesize pass-through stubs for all external imports that don't
            // already resolve to known methods. This enables single-file taint analysis
            // to follow cross-module import chains.
            self.synthesize_python_import_stubs(program, module_id);
        } else {
            return Err(format!("Unsupported language for GST: {}", language));
        }

        Ok(module_id)
    }

    /// Load additional code into an **existing** module context.
    /// This enables RC44 inter-file resolution: when a benchmark snippet references
    /// classes defined in helper files, those can be registered into the same GST
    /// so that type resolution and call graph construction succeed.
    ///
    /// Unlike `load_file`, this does NOT create a new module — it reuses the provided
    /// `module_id` so that import resolution and type FQNs remain coherent.
    pub fn load_code_fragment(
        &mut self,
        program: &mut Program,
        code: &str,
        module_id: ModuleId,
        language: &str,
    ) {
        let root = match parser::UnifiedParser::parse(code, language) {
            Ok(r) => r,
            Err(_) => return,
        };

        // Retrieve the package name from the existing module
        let package_name = self
            .program_index
            .modules
            .get(&module_id)
            .and_then(|m| m.package_name.clone());

        if language.to_lowercase() == "java" {
            self.traverse_java(&root, program, module_id, &package_name, None);
        } else if language.to_lowercase() == "python" {
            let module_name = self
                .program_index
                .modules
                .get(&module_id)
                .map(|m| m.name.clone())
                .unwrap_or_else(|| "module".to_string());
            self.traverse_python(&root, program, module_id, &module_name, None, Vec::new());
        }
    }

    fn traverse_java(
        &mut self,
        node: &AstNode,
        program: &mut Program,
        module_id: ModuleId,
        current_package: &Option<String>,
        current_class: Option<(TypeId, String)>,
    ) {
        let node_type = match &node.kind {
            NodeKind::Unknown(t) => t.as_str(),
            _ => "",
        };

        match node_type {
            "class_declaration" | "interface_declaration" | "enum_declaration" => {
                let kind = match node_type {
                    "interface_declaration" => TypeKind::Interface,
                    "enum_declaration" => TypeKind::Enum,
                    _ => TypeKind::Class,
                };

                let name = find_decl_name(node);
                let fqn = match &current_class {
                    Some((_, parent_fqn)) => format!("{}.{}", parent_fqn, name),
                    None => match current_package {
                        Some(pkg) => format!("{}.{}", pkg, name),
                        None => name.clone(),
                    },
                };

                let super_class = node
                    .children
                    .iter()
                    .find(|c| {
                        let t = match &c.kind {
                            NodeKind::Unknown(typ) => typ.as_str(),
                            _ => "",
                        };
                        t == "superclass"
                    })
                    .map(|c| {
                        let raw = c.raw.trim();
                        if raw.starts_with("extends ") {
                            raw["extends ".len()..].trim().to_string()
                        } else {
                            raw.to_string()
                        }
                    });

                let mut interfaces = Vec::new();
                if let Some(interfaces_node) = node.children.iter().find(|c| {
                    let t = match &c.kind {
                        NodeKind::Unknown(typ) => typ.as_str(),
                        _ => "",
                    };
                    t == "interfaces" || t == "extends_interfaces" || t == "super_interfaces"
                }) {
                    let raw = interfaces_node.raw.trim();
                    let prefix = if raw.starts_with("implements ") {
                        "implements "
                    } else if raw.starts_with("extends ") {
                        "extends "
                    } else {
                        ""
                    };
                    let clean = &raw[prefix.len()..];
                    for part in clean.split(',') {
                        interfaces.push(part.trim().to_string());
                    }
                }

                let annotations = extract_annotations(node);
                let class_id = program.alloc_type(name.clone(), super_class.clone(), module_id);

                let type_info = TypeInfo {
                    id: class_id,
                    name: name.clone(),
                    fqn: fqn.clone(),
                    kind,
                    module_id,
                    annotations,
                };
                self.program_index.types.insert(class_id, type_info);
                self.type_index.fqn_to_id.insert(fqn.clone(), class_id);

                if let Some(ref sc) = super_class {
                    self.child_to_parent.insert(class_id, sc.clone());
                }
                if !interfaces.is_empty() {
                    self.type_implements.insert(class_id, interfaces);
                }

                for child in &node.children {
                    self.traverse_java(
                        child,
                        program,
                        module_id,
                        current_package,
                        Some((class_id, fqn.clone())),
                    );
                }
            }
            "method_declaration" | "constructor_declaration" => {
                let name = find_decl_name(node);
                let fqn = match &current_class {
                    Some((_, parent_fqn)) => format!("{}.{}", parent_fqn, name),
                    None => match current_package {
                        Some(pkg) => format!("{}.{}", pkg, name),
                        None => name.clone(),
                    },
                };

                let mut params = Vec::new();
                if let Some(params_node) = node.children.iter().find(|c| {
                    let t = match &c.kind {
                        NodeKind::Unknown(typ) => typ.as_str(),
                        _ => "",
                    };
                    t == "formal_parameters" || t == "parameters"
                }) {
                    for param in &params_node.children {
                        let t = match &param.kind {
                            NodeKind::Identifier => "identifier",
                            NodeKind::Unknown(typ) => typ.as_str(),
                            _ => "",
                        };
                        if t == "identifier" || t == "formal_parameter" || t.contains("parameter") {
                            params.push(param.raw.clone());
                        }
                    }
                }

                let return_type = extract_java_return_type(node);
                let (visibility, is_static) = extract_java_modifiers(node);
                let annotations = extract_annotations(node);
                let parent_type_id = current_class.as_ref().map(|c| c.0);

                let method_id = program.alloc_method(
                    name.clone(),
                    parent_type_id,
                    params.clone(),
                    Some(module_id),
                );

                let method_info = MethodInfo {
                    id: method_id,
                    name: name.clone(),
                    fqn: fqn.clone(),
                    parent_type_id,
                    module_id,
                    return_type,
                    parameters: params,
                    visibility: Some(visibility),
                    is_static,
                    annotations,
                };
                self.program_index.methods.insert(method_id, method_info);
                self.method_index.fqn_to_id.insert(fqn, method_id);

                if let Some(body_node) = node.children.iter().find(|c| {
                    let child_typ = match &c.kind {
                        NodeKind::Unknown(t) => t.as_str(),
                        _ => "",
                    };
                    c.kind == NodeKind::Block || child_typ == "block"
                }) {
                    let insts = program.lower_statements(body_node);
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body = insts;
                    }
                }
            }
            "field_declaration" => {
                if let Some((class_id, ref class_fqn)) = current_class {
                    let name = find_field_name(node);
                    let fqn = format!("{}.{}", class_fqn, name);
                    let annotations = extract_annotations(node);
                    let field_id = program.alloc_field(name.clone(), class_id);

                    let field_type = extract_java_field_type(node);
                    let field_info = FieldInfo {
                        id: field_id,
                        name: name.clone(),
                        fqn: fqn.clone(),
                        parent_type_id: class_id,
                        annotations,
                        field_type,
                    };
                    self.program_index.fields.insert(field_id, field_info);
                    self.field_index.fqn_to_id.insert(fqn, field_id);
                }
            }
            _ => {
                for child in &node.children {
                    self.traverse_java(
                        child,
                        program,
                        module_id,
                        current_package,
                        current_class.clone(),
                    );
                }
            }
        }
    }

    fn traverse_python(
        &mut self,
        node: &AstNode,
        program: &mut Program,
        module_id: ModuleId,
        module_name: &str,
        current_class: Option<(TypeId, String)>,
        decorators: Vec<String>,
    ) {
        let node_type = match &node.kind {
            NodeKind::Unknown(t) => t.as_str(),
            _ => "",
        };

        match node_type {
            "decorated_definition" => {
                let mut decs = Vec::new();
                let mut inner_def = None;
                for child in &node.children {
                    let ct = match &child.kind {
                        NodeKind::Unknown(t) => t.as_str(),
                        _ => "",
                    };
                    if ct == "decorator" {
                        decs.push(child.raw.clone());
                    } else if ct == "class_definition" || ct == "function_definition" {
                        inner_def = Some(child);
                    }
                }
                if let Some(inner) = inner_def {
                    self.traverse_python(
                        inner,
                        program,
                        module_id,
                        module_name,
                        current_class,
                        decs,
                    );
                }
            }
            "class_definition" => {
                let name = find_decl_name(node);
                let fqn = match &current_class {
                    Some((_, parent_fqn)) => format!("{}.{}", parent_fqn, name),
                    None => format!("{}.{}", module_name, name),
                };

                let super_class = node
                    .children
                    .iter()
                    .find(|c| {
                        let t = match &c.kind {
                            NodeKind::Unknown(typ) => typ.as_str(),
                            _ => "",
                        };
                        t == "argument_list"
                    })
                    .map(|c| {
                        c.raw
                            .trim_matches(|ch| {
                                ch == '(' || ch == ')' || ch == ' ' || ch == '\r' || ch == '\n'
                            })
                            .to_string()
                    });

                let class_id = program.alloc_type(name.clone(), super_class.clone(), module_id);

                let type_info = TypeInfo {
                    id: class_id,
                    name: name.clone(),
                    fqn: fqn.clone(),
                    kind: TypeKind::Class,
                    module_id,
                    annotations: decorators,
                };
                self.program_index.types.insert(class_id, type_info);
                self.type_index.fqn_to_id.insert(fqn.clone(), class_id);

                if let Some(ref sc) = super_class {
                    self.child_to_parent.insert(class_id, sc.clone());
                }

                for child in &node.children {
                    self.traverse_python(
                        child,
                        program,
                        module_id,
                        module_name,
                        Some((class_id, fqn.clone())),
                        Vec::new(),
                    );
                }
            }
            "function_definition" => {
                let name = find_decl_name(node);
                let fqn = match &current_class {
                    Some((_, parent_fqn)) => format!("{}.{}", parent_fqn, name),
                    None => format!("{}.{}", module_name, name),
                };

                let mut params = Vec::new();
                if let Some(params_node) = node.children.iter().find(|c| {
                    let t = match &c.kind {
                        NodeKind::Unknown(typ) => typ.as_str(),
                        _ => "",
                    };
                    t == "parameters"
                }) {
                    for param in &params_node.children {
                        let t = match &param.kind {
                            NodeKind::Identifier => "identifier",
                            NodeKind::Unknown(typ) => typ.as_str(),
                            _ => "",
                        };
                        if t == "identifier"
                            || t == "typed_parameter"
                            || t == "default_parameter"
                            || t == "typed_default_parameter"
                            || t.contains("parameter")
                        {
                            params.push(param.raw.clone());
                        }
                    }
                }

                let parent_type_id = current_class.as_ref().map(|c| c.0);
                let method_id = program.alloc_method(
                    name.clone(),
                    parent_type_id,
                    params.clone(),
                    Some(module_id),
                );

                let method_info = MethodInfo {
                    id: method_id,
                    name: name.clone(),
                    fqn: fqn.clone(),
                    parent_type_id,
                    module_id,
                    return_type: None,
                    parameters: params,
                    visibility: None,
                    is_static: false,
                    annotations: decorators,
                };
                self.program_index.methods.insert(method_id, method_info);
                self.method_index.fqn_to_id.insert(fqn, method_id);

                if let Some(body_node) = node.children.iter().find(|c| {
                    let child_typ = match &c.kind {
                        NodeKind::Unknown(t) => t.as_str(),
                        _ => "",
                    };
                    c.kind == NodeKind::Block || child_typ == "block"
                }) {
                    let insts = program.lower_statements(body_node);
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body = insts;
                    }
                }
            }
            _ => {
                for child in &node.children {
                    self.traverse_python(
                        child,
                        program,
                        module_id,
                        module_name,
                        current_class.clone(),
                        Vec::new(),
                    );
                }
            }
        }
    }

    pub fn resolve_import(&self, module_id: ModuleId, short_name: &str) -> Option<String> {
        let mut visited = HashSet::new();
        self.resolve_import_recursive(module_id, short_name, &mut visited)
    }

    fn resolve_import_recursive(
        &self,
        module_id: ModuleId,
        short_name: &str,
        visited: &mut HashSet<(ModuleId, String)>,
    ) -> Option<String> {
        let state = (module_id, short_name.to_string());
        if visited.contains(&state) {
            return None;
        }
        visited.insert(state);

        if let Some(module_imports) = self.import_index.imports_by_module.get(&module_id) {
            if let Some(fqn) = module_imports.get(short_name) {
                let parts: Vec<&str> = fqn.split('.').collect();
                if parts.len() > 1 {
                    let symbol = parts.last().unwrap();
                    let module_part = parts[..parts.len() - 1].join(".");
                    let mut next_module_id_opt = self.module_index.name_to_id.get(&module_part).copied();
                    if next_module_id_opt.is_none() {
                        let dot_suffix = format!(".{}", module_part);
                        for (m_name, &m_id) in &self.module_index.name_to_id {
                            if m_name.ends_with(&dot_suffix) {
                                next_module_id_opt = Some(m_id);
                                break;
                            }
                        }
                    }
                    if let Some(next_module_id) = next_module_id_opt {
                        if let Some(resolved_fqn) = self.resolve_import_recursive(next_module_id, symbol, visited) {
                            return Some(resolved_fqn);
                        }
                    }
                }
                return Some(fqn.clone());
            }
        }
        None
    }

    pub fn resolve_type(&self, module_id: ModuleId, type_name: &str) -> Option<TypeId> {
        if let Some(&id) = self.type_index.fqn_to_id.get(type_name) {
            return Some(id);
        }

        if let Some(fqn) = self.resolve_import(module_id, type_name) {
            if let Some(&id) = self.type_index.fqn_to_id.get(&fqn) {
                return Some(id);
            }
        }

        if type_name.contains('.') {
            let parts: Vec<&str> = type_name.split('.').collect();
            for k in (1..parts.len()).rev() {
                let prefix = parts[..k].join(".");
                let suffix = parts[k..].join(".");
                if let Some(resolved_prefix) = self.resolve_import(module_id, &prefix) {
                    let candidate = format!("{}.{}", resolved_prefix, suffix);
                    if let Some(&id) = self.type_index.fqn_to_id.get(&candidate) {
                        return Some(id);
                    }
                }
            }
        }

        if let Some(wildcards) = self.import_index.wildcards_by_module.get(&module_id) {
            for prefix in wildcards {
                let candidate = format!("{}.{}", prefix, type_name);
                if let Some(&id) = self.type_index.fqn_to_id.get(&candidate) {
                    return Some(id);
                }
            }
        }

        if let Some(module_info) = self.program_index.modules.get(&module_id) {
            if let Some(ref pkg) = module_info.package_name {
                let candidate = format!("{}.{}", pkg, type_name);
                if let Some(&id) = self.type_index.fqn_to_id.get(&candidate) {
                    return Some(id);
                }
            } else {
                let candidate = format!("{}.{}", module_info.name, type_name);
                if let Some(&id) = self.type_index.fqn_to_id.get(&candidate) {
                    return Some(id);
                }
            }
        }

        let java_lang_candidate = format!("java.lang.{}", type_name);
        if let Some(&id) = self.type_index.fqn_to_id.get(&java_lang_candidate) {
            return Some(id);
        }

        None
    }

    pub fn resolve_method(&self, type_id: TypeId, method_name: &str) -> Option<MethodId> {
        if let Some(type_info) = self.program_index.types.get(&type_id) {
            let fqn = format!("{}.{}", type_info.fqn, method_name);
            if let Some(&method_id) = self.method_index.fqn_to_id.get(&fqn) {
                return Some(method_id);
            }

            if let Some(parent_id) = self.child_to_parent.get(&type_id) {
                if let Some(resolved_parent_id) = self.resolve_type(type_info.module_id, parent_id)
                {
                    if let Some(method_id) = self.resolve_method(resolved_parent_id, method_name) {
                        return Some(method_id);
                    }
                }
            }

            if let Some(interfaces) = self.type_implements.get(&type_id) {
                for iface_name in interfaces {
                    if let Some(resolved_iface_id) =
                        self.resolve_type(type_info.module_id, iface_name)
                    {
                        if let Some(method_id) = self.resolve_method(resolved_iface_id, method_name)
                        {
                            return Some(method_id);
                        }
                    }
                }
            }
        }
        None
    }

    /// RC89: Tier B Python Import Resolver — Synthetic Stub Injection
    ///
    /// When a single Python file is loaded that contains import statements referencing
    /// external modules (e.g. `from pgadmin.utils.driver import get_driver`), those
    /// imported symbols are recorded in the import index but no corresponding methods
    /// exist in the program (since only one file is loaded).
    ///
    /// This method synthesizes lightweight pass-through stub methods for each imported
    /// symbol that does not already resolve to a known method or type. These stubs
    /// enable the call graph builder to create Call edges for imported function calls,
    /// allowing the taint engine to propagate through them correctly.
    ///
    /// The synthetic stubs use a single `value` parameter to allow taint to flow
    /// from arguments to return values.
    /// Helper to get or create a stub module for a dot-separated module path.
    fn get_or_create_stub_module(&mut self, program: &mut Program, module_name: &str) -> ModuleId {
        if let Some(&existing_mid) = self.module_index.name_to_id.get(module_name) {
            existing_mid
        } else {
            let new_module_id = program.alloc_module(
                module_name.to_string(),
                format!("{}.py", module_name.replace('.', "/")),
            );
            let module_info = ModuleInfo {
                id: new_module_id,
                name: module_name.to_string(),
                file_path: format!("{}.py", module_name.replace('.', "/")),
                package_name: None,
            };
            self.program_index.modules.insert(new_module_id, module_info);
            self.module_index.name_to_id.insert(module_name.to_string(), new_module_id);
            self.module_index.file_path_to_id.insert(
                format!("{}.py", module_name.replace('.', "/")),
                new_module_id,
            );
            new_module_id
        }
    }

    /// Helper to get or create a stub type for a FQN.
    fn get_or_create_stub_type(&mut self, program: &mut Program, type_fqn: &str, module_id: ModuleId) -> TypeId {
        if let Some(&class_id) = self.type_index.fqn_to_id.get(type_fqn) {
            class_id
        } else {
            let short_name = type_fqn.split('.').last().unwrap_or(type_fqn).to_string();
            // Get the module name from type FQN
            let module_parts: Vec<&str> = type_fqn.split('.').collect();
            let stub_module_id = if module_parts.len() >= 2 {
                let mod_name = module_parts[..module_parts.len() - 1].join(".");
                self.get_or_create_stub_module(program, &mod_name)
            } else {
                module_id
            };

            let class_id = program.alloc_type(short_name.clone(), None, stub_module_id);
            let type_info = TypeInfo {
                id: class_id,
                name: short_name.clone(),
                fqn: type_fqn.to_string(),
                kind: TypeKind::Class,
                module_id: stub_module_id,
                annotations: Vec::new(),
            };
            self.program_index.types.insert(class_id, type_info);
            self.type_index.fqn_to_id.insert(type_fqn.to_string(), class_id);
            class_id
        }
    }

    /// Helper to get or create a stub method.
    fn get_or_create_stub_method(
        &mut self,
        program: &mut Program,
        method_fqn: &str,
        parent_type_fqn: Option<&str>,
        return_type_fqn: Option<String>,
        module_id: ModuleId,
    ) -> MethodId {
        if let Some(&method_id) = self.method_index.fqn_to_id.get(method_fqn) {
            // Update return type if it wasn't set but is now provided
            if let Some(ref ret_type) = return_type_fqn {
                if let Some(m) = self.program_index.methods.get_mut(&method_id) {
                    if m.return_type.is_none() {
                        m.return_type = Some(ret_type.clone());
                    }
                }
            }
            method_id
        } else {
            let parts: Vec<&str> = method_fqn.split('.').collect();
            let method_name = parts.last().unwrap_or(&method_fqn).to_string();

            let parent_type_id = if let Some(parent_fqn) = parent_type_fqn {
                Some(self.get_or_create_stub_type(program, parent_fqn, module_id))
            } else {
                None
            };

            let stub_module_id = if parts.len() >= 2 {
                let mod_name = parts[..parts.len() - 1].join(".");
                self.get_or_create_stub_module(program, &mod_name)
            } else {
                module_id
            };

            let stub_method_id = program.alloc_method(
                method_name.clone(),
                parent_type_id,
                vec!["value".to_string()],
                Some(stub_module_id),
            );

            let ret_inst_id = program.alloc_instruction(
                InstructionKind::Return {
                    val: Some("value".to_string()),
                },
                0,
            );
            if let Some(m) = program.methods.get_mut(&stub_method_id) {
                m.body = vec![ret_inst_id];
            }

            let method_info = MethodInfo {
                id: stub_method_id,
                name: method_name.clone(),
                fqn: method_fqn.to_string(),
                parent_type_id,
                module_id: stub_module_id,
                return_type: return_type_fqn,
                parameters: vec!["value".to_string()],
                visibility: None,
                is_static: true,
                annotations: Vec::new(),
            };
            self.program_index.methods.insert(stub_method_id, method_info);
            self.method_index.fqn_to_id.insert(method_fqn.to_string(), stub_method_id);
            stub_method_id
        }
    }

    pub fn synthesize_python_import_stubs(&mut self, program: &mut Program, module_id: ModuleId) {
        // Collect all imports for this module
        let imports = match self.import_index.imports_by_module.get(&module_id) {
            Some(m) => m.clone(),
            None => return,
        };

        let module_name = match self.program_index.modules.get(&module_id) {
            Some(m) => m.name.clone(),
            None => return,
        };

        // Only apply to Python modules (check for dot-separated module names or known Python patterns)
        // We detect Python by checking if the module came from a .py file path
        let is_python = match self.program_index.modules.get(&module_id) {
            Some(m) => m.file_path.ends_with(".py") || m.file_path.ends_with(".pyc"),
            None => false,
        };
        if !is_python {
            return;
        }

        // Helper closures to check for standard libraries or sanitizers
        let is_stdlib = |fqn: &str| {
            let fqn_lower = fqn.to_lowercase();
            fqn_lower.starts_with("os.")
                || fqn_lower.starts_with("sys.")
                || fqn_lower.starts_with("re.")
                || fqn_lower.starts_with("json.")
                || fqn_lower.starts_with("logging.")
                || fqn_lower.starts_with("collections.")
                || fqn_lower.starts_with("pathlib.")
                || fqn_lower.starts_with("datetime.")
                || fqn_lower.starts_with("typing.")
                || fqn_lower.starts_with("abc.")
                || fqn_lower == "os"
                || fqn_lower == "sys"
                || fqn_lower == "re"
                || fqn_lower == "json"
                || fqn_lower == "logging"
                || fqn_lower == "collections"
                || fqn_lower == "pathlib"
                || fqn_lower == "datetime"
                || fqn_lower == "typing"
                || fqn_lower == "abc"
                || fqn_lower.starts_with("io.")
        };

        let is_sanitizer = |short_name: &str| {
            let short_lower = short_name.to_lowercase();
            short_lower.contains("escape")
                || short_lower.contains("sanitize")
                || short_lower.contains("encode")
                || short_lower.contains("urlencode")
        };

        // 1. Synthesize direct stubs for all imports
        for (short_name, import_fqn) in &imports {
            if is_stdlib(import_fqn) || is_sanitizer(short_name) {
                continue;
            }

            // Synthesize class Type if not already present
            self.get_or_create_stub_type(program, import_fqn, module_id);

            // Synthesize direct function stub if not already present
            let func_ret_fqn = format!("{}_Ret", import_fqn);
            self.get_or_create_stub_method(
                program,
                import_fqn,
                None,
                Some(func_ret_fqn),
                module_id,
            );

            // Also register the short name locally in method index if it maps to the import
            let local_fqn = format!("{}.{}", module_name, short_name);
            if let Some(&stub_method_id) = self.method_index.fqn_to_id.get(import_fqn) {
                if !self.method_index.fqn_to_id.contains_key(&local_fqn) {
                    self.method_index.fqn_to_id.insert(local_fqn, stub_method_id);
                }
            }
        }

        // 2. Perform Local Type Inference & Sequential Member/Instance Method synthesis
        let mut local_types: HashMap<String, String> = std::collections::HashMap::new();

        // Get method IDs belonging to this module
        let method_ids = if let Some(module) = program.modules.get(&module_id) {
            module.methods.clone()
        } else {
            Vec::new()
        };

        for m_id in method_ids {
            // Process instructions in order
            let insts = if let Some(method) = program.methods.get(&m_id) {
                method.body.clone()
            } else {
                Vec::new()
            };

            for inst_id in insts {
                let inst_kind = if let Some(inst) = program.instructions.get(&inst_id) {
                    Some(inst.kind.clone())
                } else {
                    None
                };

                if let Some(kind) = inst_kind {
                    match kind {
                        InstructionKind::Call { dest, callee, .. } => {
                            let mut inferred_ret_type: Option<String> = None;

                            if callee.contains('.') {
                                // Member call: obj.method or obj.method1.method2...
                                let parts: Vec<&str> = callee.split('.').collect();
                                let obj_name = parts[0];

                                // Determine receiver type by looking for the longest matching prefix of parts in imports
                                let mut matching_prefix_len = 0;
                                let mut current_type_fqn = None;
                                for len in (1..=parts.len()).rev() {
                                    let prefix = parts[..len].join(".");
                                    if let Some(import_fqn) = imports.get(&prefix) {
                                        current_type_fqn = Some(import_fqn.clone());
                                        matching_prefix_len = len;
                                        break;
                                    }
                                }

                                if current_type_fqn.is_none() {
                                    if let Some(inferred) = local_types.get(obj_name) {
                                        current_type_fqn = Some(inferred.clone());
                                        matching_prefix_len = 1;
                                    }
                                }

                                if let Some(mut type_fqn) = current_type_fqn {
                                    let method_parts = &parts[matching_prefix_len..];
                                    // Walk each method part in the chain and resolve/synthesize the method and its return type
                                    for &method_name in method_parts {
                                        if is_stdlib(&type_fqn) {
                                            break;
                                        }

                                        let method_fqn = format!("{}.{}", type_fqn, method_name);
                                        let return_fqn = if method_fqn.starts_with("base64.b64decode") || method_fqn.starts_with("base64.urlsafe_b64decode") {
                                            "bytes".to_string()
                                        } else if method_fqn.starts_with("global.open_Ret.read") || method_fqn.starts_with("builtins.open_Ret.read") {
                                            "bytes".to_string()
                                        } else {
                                            format!("{}_Ret", method_fqn)
                                        };

                                        // Synthesize return class type
                                        self.get_or_create_stub_type(program, &return_fqn, module_id);

                                        // Synthesize member method on current_type
                                        self.get_or_create_stub_method(
                                            program,
                                            &method_fqn,
                                            Some(&type_fqn),
                                            Some(return_fqn.clone()),
                                            module_id,
                                        );

                                        type_fqn = return_fqn;
                                    }
                                    inferred_ret_type = Some(type_fqn);
                                }
                            } else {
                                // Direct call: constructor or function
                                let callee_fqn = if let Some(import_fqn) = imports.get(&callee) {
                                    Some(import_fqn.clone())
                                } else if self.type_index.fqn_to_id.contains_key(&callee) {
                                    Some(callee.clone())
                                } else {
                                    None
                                };

                                if let Some(fqn) = callee_fqn {
                                    // Check if it is a constructor (type) or function
                                    if self.type_index.fqn_to_id.contains_key(&fqn) {
                                        // Constructor returns the type itself
                                        inferred_ret_type = Some(fqn);
                                    } else {
                                        let func_ret_fqn = if fqn.starts_with("base64.b64decode") || fqn.starts_with("base64.urlsafe_b64decode") {
                                            "bytes".to_string()
                                        } else {
                                            format!("{}_Ret", fqn)
                                        };
                                        self.get_or_create_stub_type(program, &func_ret_fqn, module_id);
                                        self.get_or_create_stub_method(
                                            program,
                                            &fqn,
                                            None,
                                            Some(func_ret_fqn.clone()),
                                            module_id,
                                        );
                                        inferred_ret_type = Some(func_ret_fqn);
                                    }
                                }
                            }

                            // If we inferred a return type and have a destination variable, update environment
                            if let (Some(dest_var), Some(ret_type)) = (dest, inferred_ret_type) {
                                local_types.insert(dest_var, ret_type);
                            }
                        }
                        InstructionKind::Assign { dest, src } => {
                            if let Some(ty) = local_types.get(&src).cloned() {
                                local_types.insert(dest, ty);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn resolve_inheritance_hierarchy(&mut self) {
        let mut resolved_subclasses = HashMap::new();
        let mut resolved_implementors = HashMap::new();

        let child_parent_clone: Vec<(TypeId, String)> = self
            .child_to_parent
            .iter()
            .map(|(&c, p)| (c, p.clone()))
            .collect();

        for (type_id, parent_name) in child_parent_clone {
            if let Some(type_info) = self.program_index.types.get(&type_id) {
                if let Some(parent_type_id) = self.resolve_type(type_info.module_id, &parent_name) {
                    resolved_subclasses
                        .entry(parent_type_id)
                        .or_insert_with(Vec::new)
                        .push(type_id);
                }
            }
        }

        let type_implements_clone: Vec<(TypeId, Vec<String>)> = self
            .type_implements
            .iter()
            .map(|(&t, ifaces)| (t, ifaces.clone()))
            .collect();

        for (type_id, interfaces) in type_implements_clone {
            if let Some(type_info) = self.program_index.types.get(&type_id) {
                for iface_name in interfaces {
                    if let Some(iface_type_id) = self.resolve_type(type_info.module_id, &iface_name)
                    {
                        if let Some(iface_info) = self.program_index.types.get(&iface_type_id) {
                            resolved_implementors
                                .entry(iface_info.fqn.clone())
                                .or_insert_with(Vec::new)
                                .push(type_id);
                        }
                    } else {
                        resolved_implementors
                            .entry(iface_name)
                            .or_insert_with(Vec::new)
                            .push(type_id);
                    }
                }
            }
        }

        self.parent_to_children = resolved_subclasses;
        self.interface_to_implementors = resolved_implementors;
    }
}

fn find_identifier(node: &AstNode) -> Option<String> {
    if node.kind == NodeKind::Identifier {
        return Some(node.raw.clone());
    }
    for child in &node.children {
        if let Some(name) = find_identifier(child) {
            return Some(name);
        }
    }
    None
}

fn find_direct_identifier(node: &AstNode) -> Option<String> {
    node.children
        .iter()
        .find(|c| c.kind == NodeKind::Identifier)
        .map(|c| c.raw.clone())
}

fn find_decl_name(node: &AstNode) -> String {
    find_direct_identifier(node)
        .or_else(|| find_identifier(node))
        .unwrap_or_else(|| "unknown".to_string())
}

fn find_field_name(node: &AstNode) -> String {
    if let Some(vd) = node.children.iter().find(|c| match &c.kind {
        NodeKind::VariableDeclarator => true,
        NodeKind::Unknown(t) => t == "variable_declarator",
        _ => false,
    }) {
        if let Some(name) = find_identifier(vd) {
            return name;
        }
    }
    find_identifier(node).unwrap_or_else(|| "unknown_field".to_string())
}

fn extract_annotations(node: &AstNode) -> Vec<String> {
    let mut anns = Vec::new();
    if let Some(modifiers) = node.children.iter().find(|c| match &c.kind {
        NodeKind::Unknown(t) => t == "modifiers",
        _ => false,
    }) {
        for child in &modifiers.children {
            let t = match &child.kind {
                NodeKind::Unknown(typ) => typ.as_str(),
                _ => "",
            };
            if t == "annotation" || t == "marker_annotation" {
                anns.push(child.raw.clone());
            }
        }
    }
    for child in &node.children {
        let t = match &child.kind {
            NodeKind::Unknown(typ) => typ.as_str(),
            _ => "",
        };
        if t == "annotation" || t == "marker_annotation" {
            anns.push(child.raw.clone());
        }
    }
    anns
}

fn extract_java_return_type(node: &AstNode) -> Option<String> {
    let mut type_raw = None;
    for (i, child) in node.children.iter().enumerate() {
        if child.kind == NodeKind::Identifier {
            if i > 0 {
                let prev = &node.children[i - 1];
                let prev_type = match &prev.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                if prev_type.ends_with("_type")
                    || prev_type == "void_type"
                    || prev_type == "type_identifier"
                    || prev_type == "scoped_type_identifier"
                    || prev_type == "generic_type"
                {
                    type_raw = Some(prev.raw.clone());
                }
            }
            break;
        }
    }
    type_raw
}

fn extract_java_modifiers(node: &AstNode) -> (String, bool) {
    let mut visibility = "package-private".to_string();
    let mut is_static = false;
    if let Some(modifiers) = node.children.iter().find(|c| match &c.kind {
        NodeKind::Unknown(t) => t == "modifiers",
        _ => false,
    }) {
        let raw = modifiers.raw.clone();
        if raw.contains("public") {
            visibility = "public".to_string();
        } else if raw.contains("private") {
            visibility = "private".to_string();
        } else if raw.contains("protected") {
            visibility = "protected".to_string();
        }
        if raw.contains("static") {
            is_static = true;
        }
    }
    (visibility, is_static)
}

fn extract_java_imports_and_package(
    root: &AstNode,
) -> (Option<String>, HashMap<String, String>, Vec<String>) {
    let mut package_name = None;
    let mut imports = HashMap::new();
    let mut wildcards = Vec::new();

    fn walk_java_meta(
        node: &AstNode,
        package_name: &mut Option<String>,
        imports: &mut HashMap<String, String>,
        wildcards: &mut Vec<String>,
    ) {
        let t = match &node.kind {
            NodeKind::Unknown(typ) => typ.as_str(),
            _ => "",
        };
        if t == "package_declaration" {
            let raw = node.raw.trim();
            if raw.starts_with("package ") {
                let pkg = raw["package ".len()..]
                    .trim_matches(|c| c == ';' || c == ' ' || c == '\r' || c == '\n');
                *package_name = Some(pkg.to_string());
            }
        } else if t == "import_declaration" {
            let raw = node.raw.trim();
            if raw.starts_with("import ") {
                let is_static = raw.starts_with("import static ");
                let prefix = if is_static {
                    "import static "
                } else {
                    "import "
                };
                let path = raw[prefix.len()..]
                    .trim_matches(|c| c == ';' || c == ' ' || c == '\r' || c == '\n');
                if path.ends_with(".*") {
                    let wildcard = path[..path.len() - 2].to_string();
                    wildcards.push(wildcard);
                } else {
                    let parts: Vec<&str> = path.split('.').collect();
                    if let Some(short_name) = parts.last() {
                        imports.insert(short_name.to_string(), path.to_string());
                    }
                }
            }
        }
        for child in &node.children {
            walk_java_meta(child, package_name, imports, wildcards);
        }
    }

    walk_java_meta(root, &mut package_name, &mut imports, &mut wildcards);
    (package_name, imports, wildcards)
}

fn resolve_relative_module(current_module_fqn: &str, file_path: &str, relative_path: &str) -> String {
    let num_dots = relative_path.chars().take_while(|&c| c == '.').count();
    if num_dots == 0 {
        return relative_path.to_string();
    }
    
    let remainder = &relative_path[num_dots..];
    let parts: Vec<&str> = current_module_fqn.split('.').collect();
    
    let is_init = file_path.ends_with("__init__.py") || file_path.ends_with("__init__.pyc");
    
    let pop_count = if is_init {
        num_dots.saturating_sub(1)
    } else {
        num_dots
    };
    
    if pop_count >= parts.len() {
        if !parts.is_empty() {
            let root_prefix = parts[0];
            if remainder.is_empty() {
                root_prefix.to_string()
            } else {
                format!("{}.{}", root_prefix, remainder)
            }
        } else {
            remainder.to_string()
        }
    } else {
        let keep_parts = &parts[..parts.len() - pop_count];
        if remainder.is_empty() {
            keep_parts.join(".")
        } else {
            format!("{}.{}", keep_parts.join("."), remainder)
        }
    }
}

fn extract_python_imports(
    root: &AstNode,
    current_module_fqn: &str,
    file_path: &str,
) -> (HashMap<String, String>, Vec<String>) {
    let mut imports = HashMap::new();
    let mut wildcards = Vec::new();

    fn walk_imports(
        node: &AstNode,
        current_module_fqn: &str,
        file_path: &str,
        imports: &mut HashMap<String, String>,
        wildcards: &mut Vec<String>,
    ) {
        let t = match &node.kind {
            NodeKind::Unknown(typ) => typ.as_str(),
            _ => "",
        };
        if t == "import_statement" {
            let raw = node.raw.trim();
            if raw.starts_with("import ") {
                let clean = &raw["import ".len()..];
                for part in clean.split(',') {
                    let part = part.trim();
                    if part.contains(" as ") {
                        let subparts: Vec<&str> = part.split(" as ").collect();
                        if subparts.len() == 2 {
                            imports.insert(
                                subparts[1].trim().to_string(),
                                subparts[0].trim().to_string(),
                            );
                        }
                    } else {
                        let parts: Vec<&str> = part.split('.').collect();
                        if let Some(last) = parts.last() {
                            imports.insert(last.to_string(), part.to_string());
                        }
                        imports.insert(part.to_string(), part.to_string());
                    }
                }
            }
        } else if t == "import_from_statement" {
            let raw = node.raw.trim();
            if raw.starts_with("from ") {
                if let Some(import_idx) = raw.find(" import ") {
                    let from_part = raw["from ".len()..import_idx].trim();
                    let mut import_part = raw[import_idx + " import ".len()..].trim();
                    if import_part.starts_with('(') && import_part.ends_with(')') {
                        import_part = import_part[1..import_part.len() - 1].trim();
                    }
                    
                    let absolute_from = if from_part.starts_with('.') {
                        resolve_relative_module(current_module_fqn, file_path, from_part)
                    } else {
                        from_part.to_string()
                    };

                    if import_part == "*" {
                        wildcards.push(absolute_from);
                    } else {
                        for part in import_part.split(',') {
                            let part = part.trim();
                            if part.contains(" as ") {
                                let subparts: Vec<&str> = part.split(" as ").collect();
                                if subparts.len() == 2 {
                                    let fqn = format!("{}.{}", absolute_from, subparts[0].trim());
                                    imports.insert(subparts[1].trim().to_string(), fqn);
                                }
                            } else {
                                let fqn = format!("{}.{}", absolute_from, part);
                                imports.insert(part.to_string(), fqn);
                            }
                        }
                    }
                }
            }
        }
        for child in &node.children {
            walk_imports(child, current_module_fqn, file_path, imports, wildcards);
        }
    }

    walk_imports(root, current_module_fqn, file_path, &mut imports, &mut wildcards);
    (imports, wildcards)
}

fn extract_java_field_type(node: &AstNode) -> Option<String> {
    for child in &node.children {
        let t = match &child.kind {
            NodeKind::Unknown(typ) => typ.as_str(),
            _ => "",
        };
        if t.ends_with("_type")
            || t == "type_identifier"
            || t == "scoped_type_identifier"
            || t == "generic_type"
            || t == "integral_type"
            || t == "floating_point_type"
            || t == "boolean_type"
        {
            return Some(child.raw.clone());
        }
    }
    None
}
