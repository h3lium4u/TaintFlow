use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use v2_common::Span;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Label(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Constant {
    Int(i64),
    Float(String), // Use String to ensure Eq and Hash support
    String(String),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operand {
    Var(String),
    Temp(u32),
    Const(Constant),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstructionKind {
    /// dest = src
    Assign { dest: Operand, src: Operand },

    /// dest = op arg
    UnaryOp { dest: Operand, op: String, arg: Operand },

    /// dest = lhs op rhs
    BinaryOp { dest: Operand, op: String, lhs: Operand, rhs: Operand },

    /// dest = alloc type_name
    Alloc { dest: Operand, type_name: String },

    /// dest = base.field
    HeapLoad { dest: Operand, base: Operand, field: String },

    /// base.field = src
    HeapStore { base: Operand, field: String, src: Operand },

    /// if cond goto target
    Branch { cond: Operand, target: Label },

    /// goto target
    Jump { target: Label },

    /// Label marker
    Label(Label),

    /// dest = phi(incoming_vals) where each incoming is (val, from_label)
    Phi { dest: Operand, incoming: Vec<(Operand, Label)> },

    /// [dest =] call callee(args)
    Call { dest: Option<Operand>, callee: String, args: Vec<Operand> },

    /// return [val]
    Return { val: Option<Operand> },
}



#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub id: InstructionId,
    pub kind: InstructionKind,
    pub span: Option<Span>,
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

    pub fn alloc_instruction(&mut self, kind: InstructionKind, span: Option<Span>) -> InstructionId {
        let id = InstructionId(self.next_instruction_id);
        self.next_instruction_id += 1;
        let inst = Instruction {
            id,
            kind,
            span,
        };
        self.instructions.insert(id, inst);
        id
    }
}

pub fn init() {
    println!("v2-ir initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_tac_constructors() {
        let mut program = Program::new();
        let module_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let type_id = program.alloc_type("User".to_string(), None, module_id);
        let method_id = program.alloc_method("get_name".to_string(), Some(type_id), vec!["self".to_string()], Some(module_id));

        // Create instructions
        // t1 = alloc User
        let inst1_id = program.alloc_instruction(
            InstructionKind::Alloc {
                dest: Operand::Temp(1),
                type_name: "User".to_string(),
            },
            None,
        );

        // t1.name = "John"
        let inst2_id = program.alloc_instruction(
            InstructionKind::HeapStore {
                base: Operand::Temp(1),
                field: "name".to_string(),
                src: Operand::Const(Constant::String("John".to_string())),
            },
            None,
        );

        // t2 = t1.name
        let inst3_id = program.alloc_instruction(
            InstructionKind::HeapLoad {
                dest: Operand::Temp(2),
                base: Operand::Temp(1),
                field: "name".to_string(),
            },
            None,
        );

        // return t2
        let inst4_id = program.alloc_instruction(
            InstructionKind::Return {
                val: Some(Operand::Temp(2)),
            },
            None,
        );

        if let Some(method) = program.methods.get_mut(&method_id) {
            method.body.extend([inst1_id, inst2_id, inst3_id, inst4_id]);
        }

        assert_eq!(program.modules.len(), 1);
        assert_eq!(program.types.len(), 1);
        assert_eq!(program.methods.len(), 1);
        assert_eq!(program.instructions.len(), 4);
    }

    #[test]
    fn test_serialization() {
        let mut program = Program::new();
        let inst_id = program.alloc_instruction(
            InstructionKind::Call {
                dest: Some(Operand::Var("x".to_string())),
                callee: "system".to_string(),
                args: vec![Operand::Const(Constant::String("whoami".to_string()))],
            },
            Some(Span {
                start_line: 10,
                start_col: 4,
                end_line: 10,
                end_col: 22,
            }),
        );

        let json = serde_json::to_string(&program.instructions.get(&inst_id).unwrap()).unwrap();
        let deserialized: Instruction = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, inst_id);
        if let InstructionKind::Call { dest, callee, args } = deserialized.kind {
            assert_eq!(dest, Some(Operand::Var("x".to_string())));
            assert_eq!(callee, "system");
            assert_eq!(args.len(), 1);
        } else {
            panic!("Expected Call instruction");
        }
    }
}
