use v2_frontend_base::LanguageFrontend;
use v2_ir::{Constant, InstructionKind, MethodId, ModuleId, Operand, Program, TypeId, Label};
use v2_parser::{CstNode, parse_python};
use v2_semantic::{SemanticInfo, SymbolKind};

pub struct PythonFrontend;

impl LanguageFrontend for PythonFrontend {
    fn lower(
        &self,
        code: &str,
        semantic_info: &SemanticInfo,
        file_path: &std::path::Path,
    ) -> Result<Program, String> {
        let cst = parse_python(code)?;
        let mut program = Program::new();
        let name = file_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("main")
            .to_string();
        let module_id = program.alloc_module(name, file_path.to_string_lossy().to_string());
        let mut translator = Translator::new(semantic_info, module_id);
        
        translator.translate_root(cst.as_ref(), &mut program)?;
        Ok(program)
    }
}

struct Translator<'a> {
    semantic_info: &'a SemanticInfo,
    module_id: ModuleId,
    current_class_id: Option<TypeId>,
    current_method_id: Option<MethodId>,
    temp_counter: u32,
    label_counter: u32,
}

impl<'a> Translator<'a> {
    fn new(semantic_info: &'a SemanticInfo, module_id: ModuleId) -> Self {
        Self {
            semantic_info,
            module_id,
            current_class_id: None,
            current_method_id: None,
            temp_counter: 1,
            label_counter: 1,
        }
    }

    fn next_temp(&mut self) -> u32 {
        let t = self.temp_counter;
        self.temp_counter += 1;
        t
    }

    fn next_label(&mut self) -> Label {
        let l = self.label_counter;
        self.label_counter += 1;
        Label(l)
    }

    fn translate_root(&mut self, root: &dyn CstNode, program: &mut Program) -> Result<(), String> {
        // Synthesize a top-level entry-point method that captures all module-level
        // statements (assignments, calls, etc.).  Without this, every statement guard
        // `if let Some(method_id) = self.current_method_id` silently drops module-level
        // code, making the IFDS solver see an empty body and produce zero findings.
        let module_method_id = program.alloc_method(
            "__module__".to_string(),
            None,
            Vec::new(),
            Some(self.module_id),
        );
        self.current_method_id = Some(module_method_id);
        self.walk_node(root, program)
    }

    fn walk_node(&mut self, node: &dyn CstNode, program: &mut Program) -> Result<(), String> {
        let children = node.children();
        match node.kind() {
            "ClassDefinition" => {
                let class_name = find_child_identifier(node).unwrap_or_else(|| "UnknownClass".to_string());
                let parent_class = find_parent_class(node);
                
                let class_id = program.alloc_type(class_name, parent_class, self.module_id);
                let prev_class = self.current_class_id;
                self.current_class_id = Some(class_id);
                
                for child in children {
                    self.walk_node(child, program)?;
                }
                
                self.current_class_id = prev_class;
            }
            "FunctionDefinition" => {
                let func_name = find_child_identifier(node).unwrap_or_else(|| "unknown_func".to_string());
                
                let mut params = Vec::new();
                if let Some(params_node) = children.iter().find(|c| c.kind() == "parameters") {
                    for param in params_node.children() {
                        if param.kind() == "Identifier" {
                            params.push(param.raw().trim().to_string());
                        }
                    }
                }
                
                let method_id = program.alloc_method(
                    func_name,
                    self.current_class_id,
                    params,
                    Some(self.module_id),
                );
                
                let prev_method = self.current_method_id;
                self.current_method_id = Some(method_id);
                
                self.temp_counter = 1;
                
                for child in children {
                    if child.kind() != "parameters" {
                        self.walk_node(child, program)?;
                    }
                }
                
                self.current_method_id = prev_method;
            }
            "AssignmentExpression" => {
                if let Some(method_id) = self.current_method_id {
                    let lhs = children.first().ok_or("Missing LHS in assignment")?;
                    let rhs = if children.len() >= 3 {
                        children.get(2).ok_or("Missing RHS in assignment")?
                    } else {
                        children.get(1).ok_or("Missing RHS in assignment")?
                    };
                    
                    let rhs_op = self.lower_expr(*rhs, program)?;
                    let span = Some(node.span());
                    
                    if lhs.kind() == "Identifier" {
                        let dest = Operand::Var(lhs.raw().trim().to_string());
                        let inst_id = program.alloc_instruction(
                            InstructionKind::Assign { dest, src: rhs_op },
                            span,
                        );
                        if let Some(method) = program.methods.get_mut(&method_id) {
                            method.body.push(inst_id);
                        }
                    } else if lhs.kind() == "attribute" {
                        let lhs_children = lhs.children();
                        let base_node = lhs_children.first().ok_or("Missing base in attribute assignment")?;
                        let base_op = self.lower_expr(*base_node, program)?;
                        let field_name = find_child_identifier(*lhs).ok_or("Missing field in attribute assignment")?;
                        
                        let inst_id = program.alloc_instruction(
                            InstructionKind::HeapStore {
                                base: base_op,
                                field: field_name,
                                src: rhs_op,
                            },
                            span,
                        );
                        if let Some(method) = program.methods.get_mut(&method_id) {
                            method.body.push(inst_id);
                        }
                    }
                }
            }
            "ReturnStatement" => {
                if let Some(method_id) = self.current_method_id {
                    let val_node = children.first();
                    let val_op = if let Some(vn) = val_node {
                        Some(self.lower_expr(*vn, program)?)
                    } else {
                        None
                    };
                    
                    let inst_id = program.alloc_instruction(
                        InstructionKind::Return { val: val_op },
                        Some(node.span()),
                    );
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(inst_id);
                    }
                }
            }
            "IfStatement" => {
                if let Some(method_id) = self.current_method_id {
                    let cond_node = children.first().ok_or("Missing condition in IfStatement")?;
                    let cond_op = self.lower_expr(*cond_node, program)?;
                    
                    let true_label = self.next_label();
                    let exit_label = self.next_label();
                    
                    let branch_inst = program.alloc_instruction(
                        InstructionKind::Branch { cond: cond_op, target: true_label },
                        Some(cond_node.span()),
                    );
                    
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(branch_inst);
                    }
                    
                    let has_else = children.len() >= 3;
                    if has_else {
                        let else_node = children[2];
                        self.walk_node(else_node, program)?;
                    }
                    
                    let jump_exit = program.alloc_instruction(
                        InstructionKind::Jump { target: exit_label },
                        None,
                    );
                    let label_true = program.alloc_instruction(
                        InstructionKind::Label(true_label),
                        None,
                    );
                    
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(jump_exit);
                        method.body.push(label_true);
                    }
                    
                    if children.len() >= 2 {
                        let then_node = children[1];
                        self.walk_node(then_node, program)?;
                    }
                    
                    let label_exit = program.alloc_instruction(
                        InstructionKind::Label(exit_label),
                        None,
                    );
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(label_exit);
                    }
                }
            }
            "WhileStatement" => {
                if let Some(method_id) = self.current_method_id {
                    let start_label = self.next_label();
                    let body_label = self.next_label();
                    let exit_label = self.next_label();
                    
                    let label_start = program.alloc_instruction(
                        InstructionKind::Label(start_label),
                        None,
                    );
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(label_start);
                    }
                    
                    let cond_node = children.first().ok_or("Missing condition in WhileStatement")?;
                    let cond_op = self.lower_expr(*cond_node, program)?;
                    
                    let branch_inst = program.alloc_instruction(
                        InstructionKind::Branch { cond: cond_op, target: body_label },
                        Some(cond_node.span()),
                    );
                    let jump_exit = program.alloc_instruction(
                        InstructionKind::Jump { target: exit_label },
                        None,
                    );
                    let label_body = program.alloc_instruction(
                        InstructionKind::Label(body_label),
                        None,
                    );
                    
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(branch_inst);
                        method.body.push(jump_exit);
                        method.body.push(label_body);
                    }
                    
                    if children.len() >= 2 {
                        let body_node = children[1];
                        self.walk_node(body_node, program)?;
                    }
                    
                    let jump_start = program.alloc_instruction(
                        InstructionKind::Jump { target: start_label },
                        None,
                    );
                    let label_exit = program.alloc_instruction(
                        InstructionKind::Label(exit_label),
                        None,
                    );
                    
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(jump_start);
                        method.body.push(label_exit);
                    }
                }
            }
            // Standalone call statement: eval(x), os.system(x), etc.
            // lower_expr handles the CallExpression and adds the instruction.
            "CallExpression" => {
                if self.current_method_id.is_some() {
                    let _ = self.lower_expr(node, program);
                }
            }
            _ => {
                for child in children {
                    self.walk_node(child, program)?;
                }
            }
        }
        Ok(())
    }

    fn lower_expr(&mut self, node: &dyn CstNode, program: &mut Program) -> Result<Operand, String> {
        let span = Some(node.span());
        let children = node.children();
        match node.kind() {
            "Identifier" => {
                Ok(Operand::Var(node.raw().trim().to_string()))
            }
            "Literal" => {
                let raw = node.raw().trim();
                let constant = if raw.starts_with('"') || raw.starts_with('\'') {
                    Constant::String(raw[1..raw.len()-1].to_string())
                } else if raw == "True" || raw == "true" {
                    Constant::Bool(true)
                } else if raw == "False" || raw == "false" {
                    Constant::Bool(false)
                } else if raw == "None" || raw == "none" || raw == "null" {
                    Constant::Null
                } else if let Ok(val) = raw.parse::<i64>() {
                    Constant::Int(val)
                } else {
                    Constant::Float(raw.to_string())
                };
                Ok(Operand::Const(constant))
            }
            "CallExpression" => {
                let callee = extract_callee_name(node);
                
                let is_alloc = self.semantic_info.lookup(&callee, 0)
                    .map(|sym| sym.kind == SymbolKind::Class)
                    .unwrap_or(false);
                
                let mut args = Vec::new();
                if let Some(arg_list) = children.iter().find(|c| c.kind() == "argument_list") {
                    for arg in arg_list.children() {
                        args.push(self.lower_expr(arg, program)?);
                    }
                }
                
                let temp = Operand::Temp(self.next_temp());
                
                if let Some(method_id) = self.current_method_id {
                    if is_alloc {
                        let alloc_inst = program.alloc_instruction(
                            InstructionKind::Alloc {
                                dest: temp.clone(),
                                type_name: callee.clone(),
                            },
                            span.clone(),
                        );
                        if let Some(method) = program.methods.get_mut(&method_id) {
                            method.body.push(alloc_inst);
                        }
                    } else {
                        let call_inst = program.alloc_instruction(
                            InstructionKind::Call {
                                dest: Some(temp.clone()),
                                callee,
                                args,
                            },
                            span,
                        );
                        if let Some(method) = program.methods.get_mut(&method_id) {
                            method.body.push(call_inst);
                        }
                    }
                }
                
                Ok(temp)
            }
            "attribute" => {
                let base_node = children.first().ok_or("Missing base in attribute")?;
                let base_op = self.lower_expr(*base_node, program)?;
                let field_name = find_child_identifier(node).ok_or("Missing field in attribute")?;
                
                let temp = Operand::Temp(self.next_temp());
                if let Some(method_id) = self.current_method_id {
                    let inst_id = program.alloc_instruction(
                        InstructionKind::HeapLoad {
                            dest: temp.clone(),
                            base: base_op,
                            field: field_name,
                        },
                        span,
                    );
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(inst_id);
                    }
                }
                
                Ok(temp)
            }
            "binary_operator" | "comparison_operator" => {
                let lhs_node = children.first().ok_or("Missing left operand in binop")?;
                let rhs_node = if children.len() >= 3 {
                    children.get(2)
                } else {
                    children.get(1)
                }.ok_or("Missing right operand in binop")?;
                let op = if children.len() >= 3 {
                    children[1].raw().trim().to_string()
                } else {
                    "+".to_string()
                };
                
                let lhs = self.lower_expr(*lhs_node, program)?;
                let rhs = self.lower_expr(*rhs_node, program)?;
                
                let temp = Operand::Temp(self.next_temp());
                if let Some(method_id) = self.current_method_id {
                    let inst_id = program.alloc_instruction(
                        InstructionKind::BinaryOp {
                            dest: temp.clone(),
                            op,
                            lhs,
                            rhs,
                        },
                        span,
                    );
                    if let Some(method) = program.methods.get_mut(&method_id) {
                        method.body.push(inst_id);
                    }
                }
                
                Ok(temp)
            }
            _ => {
                if !children.is_empty() {
                    self.lower_expr(children[0], program)
                } else {
                    Ok(Operand::Const(Constant::Null))
                }
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

fn extract_callee_name(node: &dyn CstNode) -> String {
    let children = node.children();
    if let Some(first_child) = children.first() {
        first_child.raw().trim().to_string()
    } else {
        "callee".to_string()
    }
}

pub fn init() {
    println!("v2-frontend-python initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_semantic::resolve_semantics;

    #[test]
    fn test_lower_python_tac() {
        let code = r#"
class User:
    def greet(self):
        msg = "Hello"
        x = msg + " World"
        return x
"#;
        let cst = parse_python(code).unwrap();
        let semantic_info = resolve_semantics(cst.as_ref());
        let frontend = PythonFrontend;
        let program = frontend.lower(code, &semantic_info, std::path::Path::new("main.py")).unwrap();

        // The frontend now also synthesizes a __module__ entry-point method,
        // so there are 2 methods total: __module__ and greet.
        assert_eq!(program.methods.len(), 2);
        let method = program.methods.values()
            .find(|m| m.name == "greet")
            .expect("greet method not found");
        assert_eq!(method.name, "greet");
        assert_eq!(method.parameters.len(), 1);

        assert!(method.body.len() >= 3);
        
        let inst1 = program.instructions.get(&method.body[0]).unwrap();
        if let InstructionKind::Assign { dest, src } = &inst1.kind {
            assert_eq!(dest, &Operand::Var("msg".to_string()));
            assert_eq!(src, &Operand::Const(Constant::String("Hello".to_string())));
        } else {
            panic!("Expected Assign instruction");
        }
    }
}
