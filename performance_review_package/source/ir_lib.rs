use parser::{AstNode, NodeKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProgramId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModuleId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstructionId(pub u32);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstructionKind {
    Assign {
        dest: String,
        src: String,
    },
    Call {
        dest: Option<String>,
        callee: String,
        args: Vec<String>,
    },
    Return {
        val: Option<String>,
    },
    Branch {
        cond: String,
        then_block: Vec<InstructionId>,
        else_block: Option<Vec<InstructionId>>,
    },
    Loop {
        cond: String,
        body: Vec<InstructionId>,
    },
    Try {
        body: Vec<InstructionId>,
        catches: Vec<InstructionId>,
        finally: Option<Vec<InstructionId>>,
    },
    Catch {
        exception_var: Option<String>,
        body: Vec<InstructionId>,
    },
    Throw {
        val: String,
    },
    Source {
        name: String,
    },
    Sink {
        name: String,
    },
    Sanitizer {
        name: String,
    },
}

// ─── RC31: Precise IR-level sink/source/sanitizer classification ──────────────
//
// These helpers replace the prior broad `callee.contains("execute")` heuristic.
// Only exact, canonical method names belonging to known dangerous APIs are
// classified at IR lowering time. All other call sites become InstructionKind::Call
// and are evaluated at taint-propagation time against the stub registry.

/// Returns true only for known taint-source method names.
fn is_ir_taint_source(callee: &str) -> bool {
    let m = callee.split('.').last().unwrap_or(callee);
    matches!(
        m,
        "getParameter"
            | "getHeader"
            | "getCookies"
            | "getQueryString"
            | "getInputStream"
            | "getReader"
            | "getRequestURI"
            | "getRequestURL"
            | "getPathInfo"
            | "getServerName"
            | "getRemoteAddr"
            | "getRemoteHost"
            | "readLine"
            | "nextLine"
    )
}

/// Returns true only for well-known SQL / command sink method names.
/// Deliberately narrow — ExecutorService.execute, Runnable.run, etc. are NOT sinks.
fn is_ir_precise_sink(method_lower: &str) -> bool {
    matches!(
        method_lower,
        // SQL sinks — exact method names only
        // "execute" alone is deliberately EXCLUDED at IR level:
        // ExecutorService.execute, Runnable.execute, etc. are not SQL sinks.
        // They are handled by the stub registry in check_sink_flow instead.
        "executequery"
            | "executeupdate"
            | "executebatch"
            | "executelargeupdate"    // correct spelling
            | "executelargeupdates"   // plural variant
            | "createquery"
            | "createnativequery"
            | "nativequery"
            | "rawsql"
            // Command-injection sinks (exact names only)
            | "popen"
            | "os_popen"
    )
}

/// Returns true for known sanitizer / encoding method names.
fn is_ir_sanitizer(method_lower: &str) -> bool {
    matches!(
        method_lower,
        "urlencode"
            | "htmlescape"
            | "escapehtml"
            | "escapehtml4"
            | "htmlencode"
            | "encode"
            | "escape"
            | "sanitize"
            | "strip_tags"
            | "encodeforhtml"
            | "encodeforuri"
            | "encodeforurl"
            | "encodeforjavascript"
            | "encodeforhtmlattribute"
            | "deny_unsafe_hosts"
            | "safe_build_path"
            | "clean_path"
    )
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Instruction {
    pub id: InstructionId,
    pub kind: InstructionKind,
    pub file_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub id: FieldId,
    pub name: String,
    pub parent_type_id: TypeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Method {
    pub id: MethodId,
    pub name: String,
    pub parent_type_id: Option<TypeId>,
    pub parameters: Vec<String>,
    pub body: Vec<InstructionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Type {
    pub id: TypeId,
    pub name: String,
    pub parent_type: Option<String>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub id: ModuleId,
    pub name: String,
    pub file_path: String,
    pub types: Vec<TypeId>,
    pub methods: Vec<MethodId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub id: ProgramId,
    pub modules: HashMap<ModuleId, Module>,
    pub types: HashMap<TypeId, Type>,
    pub methods: HashMap<MethodId, Method>,
    pub fields: HashMap<FieldId, Field>,
    pub instructions: HashMap<InstructionId, Instruction>,
    pub source_files: HashMap<String, String>,

    next_module_id: u32,
    next_type_id: u32,
    next_method_id: u32,
    next_field_id: u32,
    next_instruction_id: u32,
}

impl Program {
    pub fn new() -> Self {
        Self {
            id: ProgramId(1),
            modules: HashMap::new(),
            types: HashMap::new(),
            methods: HashMap::new(),
            fields: HashMap::new(),
            instructions: HashMap::new(),
            source_files: HashMap::new(),
            next_module_id: 1,
            next_type_id: 1,
            next_method_id: 1,
            next_field_id: 1,
            next_instruction_id: 1,
        }
    }

    pub fn alloc_module(&mut self, name: String, file_path: String) -> ModuleId {
        let id = ModuleId(self.next_module_id);
        self.next_module_id += 1;
        let module = Module {
            id,
            name,
            file_path,
            types: Vec::new(),
            methods: Vec::new(),
        };
        self.modules.insert(id, module);
        id
    }

    pub fn alloc_type(
        &mut self,
        name: String,
        parent_type: Option<String>,
        module_id: ModuleId,
    ) -> TypeId {
        let id = TypeId(self.next_type_id);
        self.next_type_id += 1;
        let ty = Type {
            id,
            name,
            parent_type,
            fields: Vec::new(),
            methods: Vec::new(),
        };
        self.types.insert(id, ty);
        if let Some(m) = self.modules.get_mut(&module_id) {
            m.types.push(id);
        }
        id
    }

    pub fn alloc_method(
        &mut self,
        name: String,
        parent_type_id: Option<TypeId>,
        parameters: Vec<String>,
        module_id: Option<ModuleId>,
    ) -> MethodId {
        let id = MethodId(self.next_method_id);
        self.next_method_id += 1;
        let method = Method {
            id,
            name,
            parent_type_id,
            parameters,
            body: Vec::new(),
        };
        self.methods.insert(id, method);
        if let Some(t_id) = parent_type_id {
            if let Some(ty) = self.types.get_mut(&t_id) {
                ty.methods.push(id);
            }
        }
        if let Some(m_id) = module_id {
            if let Some(m) = self.modules.get_mut(&m_id) {
                m.methods.push(id);
            }
        }
        id
    }

    pub fn alloc_field(&mut self, name: String, parent_type_id: TypeId) -> FieldId {
        let id = FieldId(self.next_field_id);
        self.next_field_id += 1;
        let field = Field {
            id,
            name,
            parent_type_id,
        };
        self.fields.insert(id, field);
        if let Some(ty) = self.types.get_mut(&parent_type_id) {
            ty.fields.push(id);
        }
        id
    }

    pub fn alloc_instruction(&mut self, kind: InstructionKind, file_line: usize) -> InstructionId {
        let id = InstructionId(self.next_instruction_id);
        self.next_instruction_id += 1;
        let inst = Instruction {
            id,
            kind,
            file_line,
        };
        self.instructions.insert(id, inst);
        id
    }

    pub fn lower_file(
        &mut self,
        code: &str,
        file_path: &str,
        language: &str,
    ) -> Result<ModuleId, String> {
        let root = parser::UnifiedParser::parse(code, language)?;
        let module_name = std::path::Path::new(file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("main")
            .to_string();

        let module_id = self.alloc_module(module_name, file_path.to_string());

        if language.to_lowercase() == "java" {
            self.traverse_java(&root, module_id, None);
        } else if language.to_lowercase() == "python" {
            self.traverse_python(&root, module_id, None);
        } else {
            return Err(format!("Unsupported language for V2 IR: {}", language));
        }

        Ok(module_id)
    }

    fn traverse_java(
        &mut self,
        node: &AstNode,
        module_id: ModuleId,
        current_class: Option<TypeId>,
    ) {
        let node_typ = match &node.kind {
            NodeKind::Unknown(t) => t.as_str(),
            _ => "",
        };

        if node_typ == "class_declaration" {
            let class_name = find_identifier(node).unwrap_or_else(|| "UnknownClass".to_string());
            let parent_type = node
                .children
                .iter()
                .find(|c| match &c.kind {
                    NodeKind::Unknown(t) => t == "extends_interfaces" || t == "superclass",
                    _ => false,
                })
                .map(|c| c.raw.clone());
            let class_id = self.alloc_type(class_name, parent_type, module_id);

            for child in &node.children {
                self.traverse_java(child, module_id, Some(class_id));
            }
        } else if node_typ == "method_declaration" {
            let method_name = find_identifier(node).unwrap_or_else(|| "unknown_method".to_string());

            let mut params = Vec::new();
            if let Some(params_node) = node.children.iter().find(|c| {
                let child_typ = match &c.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                child_typ == "formal_parameters" || child_typ == "parameters"
            }) {
                for param in &params_node.children {
                    if param.kind == NodeKind::Identifier {
                        params.push(param.raw.clone());
                    } else if let NodeKind::Unknown(t) = &param.kind {
                        if t == "formal_parameter" {
                            params.push(param.raw.clone());
                        }
                    }
                }
            }

            let method_id = self.alloc_method(method_name, current_class, params, Some(module_id));

            if let Some(body_node) = node.children.iter().find(|c| {
                let child_typ = match &c.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                c.kind == NodeKind::Block || child_typ == "block"
            }) {
                let instructions = self.lower_statements(body_node);
                if let Some(method) = self.methods.get_mut(&method_id) {
                    method.body = instructions;
                }
            }
        } else if node_typ == "field_declaration" {
            if let Some(class_id) = current_class {
                let field_name =
                    find_identifier(node).unwrap_or_else(|| "unknown_field".to_string());
                self.alloc_field(field_name, class_id);
            }
        } else {
            for child in &node.children {
                self.traverse_java(child, module_id, current_class);
            }
        }
    }

    fn traverse_python(
        &mut self,
        node: &AstNode,
        module_id: ModuleId,
        current_class: Option<TypeId>,
    ) {
        let node_typ = match &node.kind {
            NodeKind::Unknown(t) => t.as_str(),
            _ => "",
        };

        if node_typ == "class_definition" {
            let class_name = find_identifier(node).unwrap_or_else(|| "UnknownClass".to_string());
            let parent_type = node
                .children
                .iter()
                .find(|c| {
                    let t = match &c.kind {
                        NodeKind::Unknown(typ) => typ.as_str(),
                        _ => "",
                    };
                    t == "argument_list"
                })
                .map(|c| c.raw.clone());
            let class_id = self.alloc_type(class_name, parent_type, module_id);

            for child in &node.children {
                self.traverse_python(child, module_id, Some(class_id));
            }
        } else if node_typ == "function_definition" {
            let func_name = find_identifier(node).unwrap_or_else(|| "unknown_function".to_string());

            let mut params = Vec::new();
            if let Some(params_node) = node.children.iter().find(|c| {
                let child_typ = match &c.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                child_typ == "parameters"
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

            let method_id = self.alloc_method(func_name, current_class, params, Some(module_id));

            if let Some(body_node) = node.children.iter().find(|c| {
                let child_typ = match &c.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                c.kind == NodeKind::Block || child_typ == "block"
            }) {
                let instructions = self.lower_statements(body_node);
                if let Some(method) = self.methods.get_mut(&method_id) {
                    method.body = instructions;
                }
            }
        } else {
            for child in &node.children {
                self.traverse_python(child, module_id, current_class);
            }
        }
    }

    pub fn lower_statements(&mut self, block_node: &AstNode) -> Vec<InstructionId> {
        let mut insts = Vec::new();
        self.collect_statements(block_node, &mut insts);
        insts
    }

    fn lower_assignment(
        &mut self,
        dest: String,
        rhs: &AstNode,
        insts: &mut Vec<InstructionId>,
        file_line: usize,
    ) {
        if rhs.kind == NodeKind::CallExpression {
            let callee = extract_callee_name(rhs);
            let mut args = Vec::new();
            if let Some(arg_list) = rhs.children.iter().find(|c| {
                let t = match &c.kind {
                    NodeKind::Unknown(typ) => typ.as_str(),
                    _ => "",
                };
                t == "argument_list" || t == "formal_parameters"
            }) {
                for arg in &arg_list.children {
                    args.push(arg.raw.clone());
                }
            }
            let inst_id = self.alloc_instruction(
                InstructionKind::Call {
                    dest: Some(dest),
                    callee,
                    args,
                },
                file_line,
            );
            insts.push(inst_id);
        } else if is_ternary_expression(rhs) {
            self.lower_ternary_assignment(dest, rhs, insts, file_line);
        } else {
            let mut nested_calls = Vec::new();
            find_call_expressions(rhs, &mut nested_calls);
            for call_node in nested_calls {
                self.collect_statements(&call_node, insts);
            }
            let inst_id = self.alloc_instruction(
                InstructionKind::Assign {
                    dest,
                    src: rhs.raw.clone(),
                },
                file_line,
            );
            insts.push(inst_id);
        }
    }

    fn lower_ternary_assignment(
        &mut self,
        dest: String,
        rhs: &AstNode,
        insts: &mut Vec<InstructionId>,
        file_line: usize,
    ) {
        if rhs.children.len() >= 3 {
            let is_python = rhs.raw.contains(" if ") || rhs.raw.contains("\tif ") || rhs.raw.contains("\nif ");
            let (cond_node, then_node, else_node) = if is_python {
                (&rhs.children[1], &rhs.children[0], &rhs.children[2])
            } else {
                (&rhs.children[0], &rhs.children[1], &rhs.children[2])
            };

            let mut then_block = Vec::new();
            self.lower_assignment(dest.clone(), then_node, &mut then_block, file_line);

            let mut else_block = Vec::new();
            self.lower_assignment(dest, else_node, &mut else_block, file_line);

            let branch_inst_id = self.alloc_instruction(
                InstructionKind::Branch {
                    cond: cond_node.raw.clone(),
                    then_block,
                    else_block: Some(else_block),
                },
                file_line,
            );
            insts.push(branch_inst_id);
        } else {
            let inst_id = self.alloc_instruction(
                InstructionKind::Assign {
                    dest,
                    src: rhs.raw.clone(),
                },
                file_line,
            );
            insts.push(inst_id);
        }
    }

    fn collect_statements(&mut self, node: &AstNode, insts: &mut Vec<InstructionId>) {
        let file_line = node.span.start_line;
        match &node.kind {
            NodeKind::AssignmentExpression => {
                let lhs_raw = node
                    .children
                    .first()
                    .map(|c| c.raw.clone())
                    .unwrap_or_default();
                let rhs_node = if node.children.len() >= 3 {
                    node.children.get(2)
                } else {
                    node.children.get(1)
                };

                if let Some(rhs) = rhs_node {
                    self.lower_assignment(lhs_raw, rhs, insts, file_line);
                }
            }
            NodeKind::VariableDeclarator => {
                let name = node
                    .children
                    .first()
                    .map(|c| c.raw.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                if node.children.len() >= 2 {
                    let init = &node.children[1];
                    self.lower_assignment(name, init, insts, file_line);
                }
            }
            NodeKind::CallExpression => {
                let callee = extract_callee_name(node);
                let mut args = Vec::new();
                if let Some(arg_list) = node.children.iter().find(|c| {
                    let t = match &c.kind {
                        NodeKind::Unknown(typ) => typ.as_str(),
                        _ => "",
                    };
                    t == "argument_list" || t == "formal_parameters"
                }) {
                    for arg in &arg_list.children {
                        args.push(arg.raw.clone());
                    }
                }
                // RC31: Precise sink lowering — only exact known SQL/command sink methods
                // are lowered to InstructionKind::Sink at the IR level. Broad patterns
                // like "execute" would incorrectly tag ExecutorService.execute(), etc.
                let callee_method = callee.split('.').last().unwrap_or(&callee);
                let callee_method_lower = callee_method.to_lowercase();
                let kind = if is_ir_taint_source(&callee) {
                    InstructionKind::Source {
                        name: format!("{}({})", callee, args.join(", ")),
                    }
                } else if is_ir_precise_sink(&callee_method_lower) {
                    InstructionKind::Sink {
                        name: format!("{}({})", callee, args.join(", ")),
                    }
                } else if is_ir_sanitizer(&callee_method_lower) {
                    InstructionKind::Sanitizer {
                        name: format!("{}({})", callee, args.join(", ")),
                    }
                } else {
                    InstructionKind::Call {
                        dest: None,
                        callee,
                        args,
                    }
                };
                let inst_id = self.alloc_instruction(kind, file_line);
                insts.push(inst_id);
            }
            NodeKind::ReturnStatement => {
                let val_node = node.children.first();
                if let Some(vn) = val_node {
                    if vn.kind == NodeKind::CallExpression {
                        let callee = extract_callee_name(vn);
                        let mut args = Vec::new();
                        if let Some(arg_list) = vn.children.iter().find(|c| {
                            let t = match &c.kind {
                                NodeKind::Unknown(typ) => typ.as_str(),
                                _ => "",
                            };
                            t == "argument_list" || t == "formal_parameters"
                        }) {
                            for arg in &arg_list.children {
                                args.push(arg.raw.clone());
                            }
                        }
                        let call_inst = self.alloc_instruction(
                            InstructionKind::Call {
                                dest: None,
                                callee,
                                args,
                            },
                            file_line,
                        );
                        insts.push(call_inst);
                    } else {
                        let mut nested_calls = Vec::new();
                        find_call_expressions(vn, &mut nested_calls);
                        for call_node in nested_calls {
                            self.collect_statements(&call_node, insts);
                        }
                    }
                }
                let val = val_node.map(|c| c.raw.clone());
                let inst_id = self.alloc_instruction(InstructionKind::Return { val }, file_line);
                insts.push(inst_id);
            }
            NodeKind::IfStatement => {
                let cond_node = node.children.first();
                if let Some(cn) = cond_node {
                    let mut nested_calls = Vec::new();
                    find_call_expressions(cn, &mut nested_calls);
                    for call_node in nested_calls {
                        self.collect_statements(&call_node, insts);
                    }
                }
                let cond = cond_node
                    .map(|c| c.raw.clone())
                    .unwrap_or_default();
                let mut then_insts = Vec::new();
                if node.children.len() >= 2 {
                    self.collect_statements(&node.children[1], &mut then_insts);
                }
                let mut else_insts = Vec::new();
                if node.children.len() >= 3 {
                    self.collect_statements(&node.children[2], &mut else_insts);
                }
                let else_block = if else_insts.is_empty() {
                    None
                } else {
                    Some(else_insts)
                };
                let inst_id = self.alloc_instruction(
                    InstructionKind::Branch {
                        cond,
                        then_block: then_insts,
                        else_block,
                    },
                    file_line,
                );
                insts.push(inst_id);
            }
            NodeKind::ForStatement => {
                let (loop_var, iterator_expr, body_node) = if node.children.len() == 3 {
                    // Python: loop_var is child 0, iterator is child 1, body is child 2
                    (Some(node.children[0].raw.clone()), Some(node.children[1].raw.clone()), Some(&node.children[2]))
                } else if node.children.len() == 4 && node.raw.contains(':') {
                    // Java enhanced: loop_var is child 1, iterator is child 2, body is child 3
                    (Some(node.children[1].raw.clone()), Some(node.children[2].raw.clone()), Some(&node.children[3]))
                } else {
                    // Standard C-style:
                    (None, None, node.children.last())
                };

                let cond = node
                    .children
                    .first()
                    .map(|c| c.raw.clone())
                    .unwrap_or_default();

                let mut body_insts = Vec::new();

                // Generate implicit assignment/call for enhanced loops to trace taint flow
                if let (Some(var_name), Some(iter_expr)) = (loop_var, iterator_expr) {
                    let clean_var = clean_var_name(&var_name);
                    
                    // Check if iterator expression is a CallExpression
                    let iter_node = if node.children.len() == 3 {
                        &node.children[1]
                    } else {
                        &node.children[2]
                    };

                    let is_call = iter_node.kind == NodeKind::CallExpression;

                    let inst_kind = if is_call {
                        let callee = extract_callee_name(iter_node);
                        let mut args = Vec::new();
                        if let Some(arg_list) = iter_node.children.iter().find(|c| {
                            let t = match &c.kind {
                                NodeKind::Unknown(typ) => typ.as_str(),
                                _ => "",
                            };
                            t == "argument_list" || t == "formal_parameters"
                        }) {
                            for arg in &arg_list.children {
                                args.push(arg.raw.clone());
                            }
                        }
                        InstructionKind::Call {
                            dest: Some(clean_var),
                            callee,
                            args,
                        }
                    } else {
                        InstructionKind::Assign {
                            dest: clean_var,
                            src: iter_expr,
                        }
                    };

                    let assign_inst_id = self.alloc_instruction(inst_kind, file_line);
                    body_insts.push(assign_inst_id);
                }

                if let Some(body) = body_node {
                    self.collect_statements(body, &mut body_insts);
                }

                let inst_id = self.alloc_instruction(
                    InstructionKind::Loop {
                        cond,
                        body: body_insts,
                    },
                    file_line,
                );
                insts.push(inst_id);
            }
            NodeKind::WhileStatement | NodeKind::DoWhileStatement => {
                let cond_node = node.children.first();
                if let Some(cn) = cond_node {
                    let mut nested_calls = Vec::new();
                    find_call_expressions(cn, &mut nested_calls);
                    for call_node in nested_calls {
                        self.collect_statements(&call_node, insts);
                    }
                }
                let cond = cond_node
                    .map(|c| c.raw.clone())
                    .unwrap_or_default();
                let mut body_insts = Vec::new();
                if let Some(body_node) = node.children.last() {
                    self.collect_statements(body_node, &mut body_insts);
                }
                let inst_id = self.alloc_instruction(
                    InstructionKind::Loop {
                        cond,
                        body: body_insts,
                    },
                    file_line,
                );
                insts.push(inst_id);
            }
            NodeKind::TryStatement => {
                let mut try_insts = Vec::new();
                if !node.children.is_empty() {
                    self.collect_statements(&node.children[0], &mut try_insts);
                }
                let mut catch_insts = Vec::new();
                let mut finally_insts = Vec::new();
                for child in node.children.iter().skip(1) {
                    if child.kind == NodeKind::CatchClause || child.raw.starts_with("except") {
                        let mut catch_body_insts = Vec::new();
                        let exception_var = child.children.first().map(|c| c.raw.clone());
                        if let Some(body) = child.children.last() {
                            self.collect_statements(body, &mut catch_body_insts);
                        }
                        let catch_inst_id = self.alloc_instruction(
                            InstructionKind::Catch {
                                exception_var,
                                body: catch_body_insts,
                            },
                            child.span.start_line,
                        );
                        catch_insts.push(catch_inst_id);
                    } else if child.raw.starts_with("finally") {
                        self.collect_statements(child, &mut finally_insts);
                    }
                }
                let finally = if finally_insts.is_empty() {
                    None
                } else {
                    Some(finally_insts)
                };
                let inst_id = self.alloc_instruction(
                    InstructionKind::Try {
                        body: try_insts,
                        catches: catch_insts,
                        finally,
                    },
                    file_line,
                );
                insts.push(inst_id);
            }
            NodeKind::WithItem => {
                let mut lhs_node = None;
                let mut rhs_node = None;

                if let Some(as_pat) = node.children.iter().find(|c| {
                    if let NodeKind::Unknown(t) = &c.kind {
                        t == "as_pattern"
                    } else {
                        false
                    }
                }) {
                    if as_pat.children.len() >= 2 {
                        rhs_node = Some(&as_pat.children[0]);
                        lhs_node = Some(&as_pat.children[1]);
                    }
                } else if node.children.len() >= 2 {
                    rhs_node = Some(&node.children[0]);
                    lhs_node = Some(&node.children[1]);
                }

                if let (Some(lhs), Some(rhs)) = (lhs_node, rhs_node) {
                    let lhs_raw = clean_var_name(&lhs.raw);
                    if rhs.kind == NodeKind::CallExpression {
                        let callee = extract_callee_name(rhs);
                        let mut args = Vec::new();
                        if let Some(arg_list) = rhs.children.iter().find(|c| {
                            let t = match &c.kind {
                                NodeKind::Unknown(typ) => typ.as_str(),
                                _ => "",
                            };
                            t == "argument_list" || t == "formal_parameters"
                        }) {
                            for arg in &arg_list.children {
                                args.push(arg.raw.clone());
                            }
                        }
                        let inst_id = self.alloc_instruction(
                            InstructionKind::Call {
                                dest: Some(lhs_raw),
                                callee,
                                args,
                            },
                            file_line,
                        );
                        insts.push(inst_id);
                    } else {
                        let mut nested_calls = Vec::new();
                        find_call_expressions(rhs, &mut nested_calls);
                        for call_node in nested_calls {
                            self.collect_statements(&call_node, insts);
                        }

                        let inst_id = self.alloc_instruction(
                            InstructionKind::Assign {
                                dest: lhs_raw,
                                src: rhs.raw.clone(),
                            },
                            file_line,
                        );
                        insts.push(inst_id);
                    }
                } else if !node.children.is_empty() {
                    self.collect_statements(&node.children[0], insts);
                }
            }
            NodeKind::Block => {
                for child in &node.children {
                    self.collect_statements(child, insts);
                }
            }
            _ => {
                let node_typ = match &node.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                if node_typ == "switch_expression" || node_typ == "switch_statement" {
                    let expr_raw = if let Some(expr_node) = node.children.first() {
                        let r = expr_node.raw.trim();
                        if r.starts_with('(') && r.ends_with(')') {
                            r[1..r.len()-1].trim().to_string()
                        } else {
                            r.to_string()
                        }
                    } else {
                        "switch_expr".to_string()
                    };

                    let switch_block = node.children.iter().find(|c| {
                        match &c.kind {
                            NodeKind::Unknown(t) => t == "switch_block",
                            _ => false,
                        }
                    });

                    let mut groups = Vec::new();
                    if let Some(block) = switch_block {
                        for child in &block.children {
                            let is_group = match &child.kind {
                                NodeKind::Unknown(t) => t == "switch_block_statement_group",
                                _ => false,
                            };
                            if is_group {
                                groups.push(child);
                            }
                        }
                    }

                    let switch_insts = self.build_switch_branches(&groups, 0, &expr_raw);
                    insts.extend(switch_insts);
                } else if node_typ == "throw_statement"
                    || node.raw.starts_with("throw ")
                    || node.raw.starts_with("raise ")
                {
                    let val = node
                        .raw
                        .replace("throw ", "")
                        .replace("raise ", "")
                        .replace(";", "");
                    let inst_id = self.alloc_instruction(InstructionKind::Throw { val }, file_line);
                    insts.push(inst_id);
                } else {
                    for child in &node.children {
                        self.collect_statements(child, insts);
                    }
                }
            }
        }
    }

    fn collect_fallthrough_statements(
        &mut self,
        groups: &[&AstNode],
        mut index: usize,
        insts: &mut Vec<InstructionId>,
    ) {
        while index < groups.len() {
            let group = groups[index];
            let mut group_insts = Vec::new();
            for child in &group.children {
                let kind_name = match &child.kind {
                    NodeKind::Unknown(t) => t.as_str(),
                    _ => "",
                };
                if kind_name != "switch_label" {
                    self.collect_statements(child, &mut group_insts);
                }
            }
            insts.extend(group_insts);
            if group_has_terminator(group) {
                break;
            }
            index += 1;
        }
    }

    fn build_switch_branches(
        &mut self,
        groups: &[&AstNode],
        index: usize,
        expr_raw: &str,
    ) -> Vec<InstructionId> {
        if index >= groups.len() {
            return Vec::new();
        }

        let group = groups[index];
        let mut group_insts = Vec::new();
        let mut conditions = Vec::new();
        let mut is_default = false;

        for child in &group.children {
            let kind_name = match &child.kind {
                NodeKind::Unknown(t) => t.as_str(),
                _ => "",
            };
            if kind_name == "switch_label" {
                let trimmed = child.raw.trim().trim_end_matches(':').trim();
                if trimmed == "default" {
                    is_default = true;
                } else if trimmed.starts_with("case ") {
                    let val = trimmed["case ".len()..].trim();
                    conditions.push(format!("{} == {}", expr_raw, val));
                }
            } else {
                self.collect_statements(child, &mut group_insts);
            }
        }

        let has_term = group_has_terminator(group);

        if is_default {
            let mut res = group_insts;
            if !has_term {
                self.collect_fallthrough_statements(groups, index + 1, &mut res);
            }
            res
        } else {
            let cond_str = if conditions.is_empty() {
                format!("{} == case", expr_raw)
            } else if conditions.len() == 1 {
                conditions[0].clone()
            } else {
                format!("({})", conditions.join(" || "))
            };

            let else_insts = self.build_switch_branches(groups, index + 1, expr_raw);
            let else_block = if else_insts.is_empty() {
                None
            } else {
                Some(else_insts)
            };

            if !has_term {
                self.collect_fallthrough_statements(groups, index + 1, &mut group_insts);
            }

            let inst_id = self.alloc_instruction(
                InstructionKind::Branch {
                    cond: cond_str,
                    then_block: group_insts,
                    else_block,
                },
                group.span.start_line,
            );
            vec![inst_id]
        }
    }
}

fn group_has_terminator(node: &AstNode) -> bool {
    match &node.kind {
        NodeKind::ReturnStatement => return true,
        NodeKind::Unknown(t) if t == "break_statement" || t == "return_statement" || t == "throw_statement" => return true,
        _ => {}
    }
    let raw = node.raw.trim();
    if raw.starts_with("break;") || raw.ends_with("break;") || raw.contains(" break;") || raw.contains("\nbreak;") || raw.contains("\rbreak;") {
        return true;
    }
    if raw.starts_with("return") || raw.contains(" return") || raw.contains("\nreturn") || raw.contains("\rreturn") {
        return true;
    }
    if raw.starts_with("throw") || raw.contains(" throw") || raw.contains("\nthrow") || raw.contains("\rthrow") {
        return true;
    }
    for child in &node.children {
        if group_has_terminator(child) {
            return true;
        }
    }
    false
}

fn clean_var_name(var: &str) -> String {
    // 1. If Python-style with type hint or default value, extract the name before `:` or `=`
    let base = if let Some(idx) = var.find(':').or_else(|| var.find('=')) {
        &var[..idx]
    } else {
        var
    };
    
    // 2. Extract the last word
    let last = base.split_whitespace().last().unwrap_or(base);
    
    // 3. Clean up
    last.replace("[]", "")
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_string()
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

fn extract_callee_name(node: &AstNode) -> String {
    let arg_list = node.children.iter().rev().find(|c| {
        let t = match &c.kind {
            NodeKind::Unknown(typ) => typ.as_str(),
            _ => "",
        };
        t == "argument_list" || t == "formal_parameters" || c.raw.starts_with('(')
    });

    if let Some(arg_list) = arg_list {
        let raw_stripped = if node.raw.ends_with(&arg_list.raw) {
            node.raw[..node.raw.len() - arg_list.raw.len()].trim()
        } else {
            let idx = node.raw.rfind(&arg_list.raw);
            match idx {
                Some(i) => node.raw[..i].trim(),
                None => {
                    let paren_idx = node.raw.find('(');
                    match paren_idx {
                        Some(pi) => node.raw[..pi].trim(),
                        None => node.raw.trim(),
                    }
                }
            }
        };
        raw_stripped.to_string()
    } else {
        if let Some(paren_idx) = node.raw.find('(') {
            node.raw[..paren_idx].trim().to_string()
        } else {
            node.raw.trim().to_string()
        }
    }
}

fn find_call_expressions(node: &AstNode, calls: &mut Vec<AstNode>) {
    let t = match &node.kind {
        NodeKind::Unknown(typ) => typ.as_str(),
        _ => "",
    };
    if node.kind == NodeKind::CallExpression || t == "call" {
        calls.push(node.clone());
    }
    for child in &node.children {
        find_call_expressions(child, calls);
    }
}

fn is_ternary_expression(node: &AstNode) -> bool {
    match &node.kind {
        NodeKind::Unknown(t) => t == "conditional_expression" || t == "ternary_expression",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_java_lowering() {
        let code = r#"
            public class BenchmarkTest00009 {
                private String param;
                
                public void doPost(HttpServletRequest request) {
                    String data = request.getParameter("val");
                    String sql = "SELECT * FROM users WHERE name = " + data;
                    db.execute(sql);
                }
            }
        "#;

        let mut program = Program::new();
        let _module_id = program
            .lower_file(code, "BenchmarkTest00009.java", "java")
            .unwrap();

        assert_eq!(program.modules.len(), 1);
        assert_eq!(program.types.len(), 1);

        let ty = program.types.values().next().unwrap();
        assert_eq!(ty.name, "BenchmarkTest00009");
        assert_eq!(ty.fields.len(), 1);
        assert_eq!(ty.methods.len(), 1);

        let method = program.methods.values().next().unwrap();
        assert_eq!(method.name, "doPost");
        assert_eq!(method.parameters.len(), 1);

        // Let's verify instructions were produced
        assert!(method.body.len() >= 2);
    }

    #[test]
    fn test_python_lowering() {
        let code = r#"
            class TestHandler:
                def process(self, request):
                    param = request.get_parameter("name")
                    clean = escape(param)
                    return clean
        "#;

        let mut program = Program::new();
        let _module_id = program.lower_file(code, "handler.py", "python").unwrap();

        assert_eq!(program.modules.len(), 1);
        assert_eq!(program.types.len(), 1);

        let ty = program.types.values().next().unwrap();
        assert_eq!(ty.name, "TestHandler");
        assert_eq!(ty.methods.len(), 1);

        let method = program.methods.values().next().unwrap();
        assert_eq!(method.name, "process");
        assert!(method.body.len() >= 2);
    }

    #[test]
    fn test_python_for_loop_lowering() {
        let code = "def init(app):\n\n\t@app.route('/benchmark/pathtraver-00/BenchmarkTest00610', methods=['GET'])\n\tdef BenchmarkTest00610_get():\n\t\treturn BenchmarkTest00610_post()\n\n\t@app.route('/benchmark/pathtraver-00/BenchmarkTest00610', methods=['POST'])\n\tdef BenchmarkTest00610_post():\n\t\tRESPONSE = \"\"\n\n\t\timport helpers.utils\n\t\tparam = \"\"\n\t\t\n\t\tfor name in request.headers.keys():\n\t\t\tif name.lower() in helpers.utils.commonHeaderNames:\n\t\t\t\tcontinue\n\t\t\n\t\t\tif request.headers.get_all(name):\n\t\t\t\tparam = name\n\t\t\t\tbreak\n\n\t\tbar = \"This should never happen\"\n\t\tif 'should' in bar:\n\t\t\tbar = param\n\n\t\timport codecs\n\t\timport helpers.utils\n\n\t\ttry:\n\t\t\tfileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')\n\t\texcept:\n\t\t\tpass";
        
        let root = parser::UnifiedParser::parse(code, "python").unwrap();
        fn print_ast(node: &parser::AstNode, depth: usize) {
            let indent = "  ".repeat(depth);
            println!("{}{:?} (raw: '{}', children: {})", indent, node.kind, node.raw.replace("\n", "\\n").replace("\t", "\\t"), node.children.len());
            for child in &node.children {
                print_ast(child, depth + 1);
            }
        }
        print_ast(&root, 0);

        let mut program = Program::new();
        let _module_id = program.lower_file(code, "test.py", "python").unwrap();
        for (id, inst) in &program.instructions {
            println!("INST {:?}: {:?}", id, inst.kind);
        }
    }

    #[test]
    fn test_java_ternary_lowering() {
        let code = r#"
            public class TernaryTest {
                public void test(String param) {
                    String bar = (7 * 18) > 200 ? "yes" : param;
                }
            }
        "#;

        let root = parser::UnifiedParser::parse(code, "java").unwrap();
        fn print_ast(node: &parser::AstNode, depth: usize) {
            let indent = "  ".repeat(depth);
            println!("{}{:?} (raw: '{}', children: {})", indent, node.kind, node.raw.replace("\n", "\\n").replace("\t", "\\t"), node.children.len());
            for child in &node.children {
                print_ast(child, depth + 1);
            }
        }
        print_ast(&root, 0);

        let mut program = Program::new();
        let _module_id = program
            .lower_file(code, "TernaryTest.java", "java")
            .unwrap();

        assert_eq!(program.methods.len(), 1);
        let method = program.methods.values().next().unwrap();

        // The body should contain the branch instruction
        let mut has_branch = false;
        for &inst_id in &method.body {
            if let Some(inst) = program.instructions.get(&inst_id) {
                if let InstructionKind::Branch { cond, then_block, else_block } = &inst.kind {
                    assert!(cond.contains("(7 * 18) > 200"));
                    assert_eq!(then_block.len(), 1);
                    assert_eq!(else_block.as_ref().unwrap().len(), 1);
                    has_branch = true;
                }
            }
        }
        assert!(has_branch, "Lowering should produce a Branch instruction for the ternary operator");
    }

    #[test]
    fn test_python_ternary_lowering() {
        let code = r#"
class TernaryTest:
    def test(self, param):
        bar = "yes" if (7 * 18) > 200 else param
"#;

        let mut program = Program::new();
        let _module_id = program
            .lower_file(code, "TernaryTest.py", "python")
            .unwrap();

        assert_eq!(program.methods.len(), 1);
        let method = program.methods.values().next().unwrap();

        let mut has_branch = false;
        for &inst_id in &method.body {
            if let Some(inst) = program.instructions.get(&inst_id) {
                if let InstructionKind::Branch { cond, then_block, else_block } = &inst.kind {
                    assert!(cond.contains("(7 * 18) > 200"));
                    assert_eq!(then_block.len(), 1);
                    assert_eq!(else_block.as_ref().unwrap().len(), 1);
                    has_branch = true;
                }
            }
        }
        assert!(has_branch, "Lowering should produce a Branch instruction for Python inline conditional");
    }

    #[test]
    fn test_java_source_lowering() {
        let code = r#"
            public class SourceTest {
                public void test(javax.servlet.http.HttpServletRequest request) {
                    String param = request.getParameter("x");
                    request.getParameter("x");
                }
            }
        "#;

        let mut program = Program::new();
        let _module_id = program
            .lower_file(code, "SourceTest.java", "java")
            .unwrap();

        assert_eq!(program.methods.len(), 1);
        let method = program.methods.values().next().unwrap();

        let mut has_call = false;
        let mut has_source = false;

        for &inst_id in &method.body {
            if let Some(inst) = program.instructions.get(&inst_id) {
                match &inst.kind {
                    InstructionKind::Call { dest, callee, args } => {
                        if callee.contains("getParameter") {
                            assert_eq!(dest.as_deref(), Some("param"));
                            assert_eq!(args, &vec!["\"x\"".to_string()]);
                            has_call = true;
                        }
                    }
                    InstructionKind::Source { name } => {
                        if name.contains("getParameter") {
                            has_source = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(has_call, "Assignment call should produce a Call instruction with a destination variable");
        assert!(has_source, "Standalone call should produce a Source instruction");
    }
}


