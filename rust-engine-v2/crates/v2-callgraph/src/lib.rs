use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use v2_ir::{MethodId, InstructionId, Program};
use v2_semantic::SemanticInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallSiteId(pub InstructionId);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallEdge {
    pub callsite: CallSiteId,
    pub caller: MethodId,
    pub callee: MethodId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    pub caller_to_edges: HashMap<MethodId, Vec<CallEdge>>,
    pub callee_to_edges: HashMap<MethodId, Vec<CallEdge>>,
    pub callsite_to_callees: HashMap<CallSiteId, Vec<MethodId>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            caller_to_edges: HashMap::new(),
            callee_to_edges: HashMap::new(),
            callsite_to_callees: HashMap::new(),
        }
    }

    pub fn add_edge(&mut self, edge: CallEdge) {
        self.caller_to_edges.entry(edge.caller).or_default().push(edge.clone());
        self.callee_to_edges.entry(edge.callee).or_default().push(edge.clone());
        self.callsite_to_callees.entry(edge.callsite).or_default().push(edge.callee);
        self.edges.push(edge);
    }
}

pub trait CallResolver {
    fn resolve(
        &self,
        program: &Program,
        semantic_info: &SemanticInfo,
        caller: MethodId,
        callsite: CallSiteId,
        callee_name: &str,
        instantiated_types: &HashSet<String>, // API preparation for future RTA
    ) -> Vec<MethodId>;
}

pub struct PythonResolver;

impl CallResolver for PythonResolver {
    fn resolve(
        &self,
        program: &Program,
        semantic_info: &SemanticInfo,
        caller: MethodId,
        _callsite: CallSiteId,
        callee_name: &str,
        _instantiated_types: &HashSet<String>,
    ) -> Vec<MethodId> {
        let mut targets = Vec::new();
        
        // 1. Constructor / Class allocation check
        let is_class = program.types.values().any(|t| t.name == callee_name);
        if is_class {
            for (&id, method) in &program.methods {
                if method.name == "__init__" {
                    if let Some(parent_id) = method.parent_type_id {
                        if let Some(parent_type) = program.types.get(&parent_id) {
                            if parent_type.name == callee_name {
                                targets.push(id);
                            }
                        }
                    }
                }
            }
            if !targets.is_empty() {
                return targets;
            }
        }

        // 2. Direct global function check
        for (&id, method) in &program.methods {
            if method.name == callee_name && method.parent_type_id.is_none() {
                targets.push(id);
            }
        }
        if !targets.is_empty() {
            return targets;
        }

        // 3. Method call: obj.method
        if callee_name.contains('.') {
            let parts: Vec<&str> = callee_name.split('.').collect();
            if parts.len() == 2 {
                let receiver = parts[0];
                let method_name = parts[1];

                // Attempt to resolve receiver type using symbol table
                let mut resolved_class_name = None;
                if let Some(caller_method) = program.methods.get(&caller) {
                    for scope in semantic_info.scopes.values() {
                        if scope.name == caller_method.name {
                            if let Some(sym) = scope.symbols.get(receiver) {
                                resolved_class_name = Some(sym.name.clone());
                            }
                        }
                    }
                }

                if let Some(class_name) = resolved_class_name {
                    for (&id, method) in &program.methods {
                        if method.name == method_name {
                            if let Some(parent_id) = method.parent_type_id {
                                if let Some(parent_type) = program.types.get(&parent_id) {
                                    if parent_type.name == class_name {
                                        targets.push(id);
                                    }
                                }
                            }
                        }
                    }
                }

                // Dynamic lookup fallback (name-based)
                if targets.is_empty() {
                    for (&id, method) in &program.methods {
                        if method.name == method_name {
                            targets.push(id);
                        }
                    }
                }
            }
        }

        targets
    }
}

pub struct JavaResolver;

impl CallResolver for JavaResolver {
    fn resolve(
        &self,
        program: &Program,
        semantic_info: &SemanticInfo,
        _caller: MethodId,
        _callsite: CallSiteId,
        callee_name: &str,
        _instantiated_types: &HashSet<String>,
    ) -> Vec<MethodId> {
        let mut targets = Vec::new();

        if !callee_name.contains('.') {
            for (&id, method) in &program.methods {
                if method.name == callee_name {
                    targets.push(id);
                }
            }
            return targets;
        }

        let parts: Vec<&str> = callee_name.split('.').collect();
        if parts.len() != 2 {
            return targets;
        }

        let class_name = parts[0];
        let method_name = parts[1];

        // Locate static type T
        let mut base_class_id = None;
        for (&id, ty) in &program.types {
            if ty.name == class_name {
                base_class_id = Some(id);
                break;
            }
        }

        let base_class_id = match base_class_id {
            Some(id) => id,
            None => {
                // Static type not found: name-based fallback
                for (&id, method) in &program.methods {
                    if method.name == method_name {
                        targets.push(id);
                    }
                }
                return targets;
            }
        };

        // Class Hierarchy Analysis (CHA)
        // 1. Find method in T or its superclasses
        let mut current_class_id = Some(base_class_id);
        while let Some(curr_id) = current_class_id {
            let mut found = false;
            for &m_id in &program.types.get(&curr_id).unwrap().methods {
                if let Some(method) = program.methods.get(&m_id) {
                    if method.name == method_name {
                        targets.push(m_id);
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
            
            let curr_type = program.types.get(&curr_id).unwrap();
            if let Some(ref parent_name) = curr_type.parent_type {
                current_class_id = None;
                for (&p_id, p_type) in &program.types {
                    if &p_type.name == parent_name {
                        current_class_id = Some(p_id);
                        break;
                    }
                }
            } else {
                current_class_id = None;
            }
        }

        // 2. Overriding methods in all subclasses of T
        let mut subclasses = Vec::new();
        find_all_subclasses(class_name, semantic_info, &mut subclasses);

        for sub_name in subclasses {
            let mut sub_id = None;
            for (&id, ty) in &program.types {
                if ty.name == sub_name {
                    sub_id = Some(id);
                    break;
                }
            }

            if let Some(s_id) = sub_id {
                for &m_id in &program.types.get(&s_id).unwrap().methods {
                    if let Some(method) = program.methods.get(&m_id) {
                        if method.name == method_name {
                            if !targets.contains(&m_id) {
                                targets.push(m_id);
                            }
                        }
                    }
                }
            }
        }

        targets
    }
}

fn find_all_subclasses(base_class: &str, semantic_info: &SemanticInfo, out: &mut Vec<String>) {
    for (class_name, superclass) in &semantic_info.types_hierarchy {
        if let Some(ref s) = superclass {
            if s == base_class {
                if !out.contains(class_name) {
                    out.push(class_name.clone());
                    find_all_subclasses(class_name, semantic_info, out);
                }
            }
        }
    }
}

pub struct CallGraphBuilder<'a> {
    program: &'a Program,
    semantic_info: &'a SemanticInfo,
}

impl<'a> CallGraphBuilder<'a> {
    pub fn new(program: &'a Program, semantic_info: &'a SemanticInfo) -> Self {
        Self {
            program,
            semantic_info,
        }
    }

    pub fn build(&self, resolver: &dyn CallResolver) -> CallGraph {
        let mut cg = CallGraph::new();
        let instantiated_types = HashSet::new();

        for (&caller_id, method) in &self.program.methods {
            for &inst_id in &method.body {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    if let v2_ir::InstructionKind::Call { callee, .. } = &inst.kind {
                        let callsite = CallSiteId(inst_id);
                        let targets = resolver.resolve(
                            self.program,
                            self.semantic_info,
                            caller_id,
                            callsite,
                            callee,
                            &instantiated_types,
                        );

                        for target in targets {
                            cg.add_edge(CallEdge {
                                callsite,
                                caller: caller_id,
                                callee: target,
                            });
                        }
                    }
                }
            }
        }

        cg
    }
}

pub fn init() {
    println!("v2-callgraph initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_ir::{InstructionKind, Program};

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_direct_and_recursive_calls() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        
        // Define function recursive_greet() which calls itself:
        let m_greet = program.alloc_method("recursive_greet".to_string(), None, Vec::new(), Some(m_id));
        let call_inst = program.alloc_instruction(
            InstructionKind::Call {
                dest: None,
                callee: "recursive_greet".to_string(),
                args: Vec::new(),
            },
            None,
        );
        program.methods.get_mut(&m_greet).unwrap().body.push(call_inst);

        let sem_info = SemanticInfo::new();
        let builder = CallGraphBuilder::new(&program, &sem_info);
        let resolver = PythonResolver;
        let cg = builder.build(&resolver);

        assert_eq!(cg.edges.len(), 1);
        let edge = &cg.edges[0];
        assert_eq!(edge.caller, m_greet);
        assert_eq!(edge.callee, m_greet);
    }

    #[test]
    fn test_cha_virtual_dispatch() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());

        // Base class: Shape
        let t_shape = program.alloc_type("Shape".to_string(), None, m_id);
        let m_draw_shape = program.alloc_method("draw".to_string(), Some(t_shape), Vec::new(), Some(m_id));

        // Subclass 1: Circle extends Shape
        let t_circle = program.alloc_type("Circle".to_string(), Some("Shape".to_string()), m_id);
        let m_draw_circle = program.alloc_method("draw".to_string(), Some(t_circle), Vec::new(), Some(m_id));

        // Subclass 2: Square extends Shape
        let t_square = program.alloc_type("Square".to_string(), Some("Shape".to_string()), m_id);
        let m_draw_square = program.alloc_method("draw".to_string(), Some(t_square), Vec::new(), Some(m_id));

        // Caller function
        let m_caller = program.alloc_method("render".to_string(), None, Vec::new(), Some(m_id));
        let callsite = program.alloc_instruction(
            InstructionKind::Call {
                dest: None,
                callee: "Shape.draw".to_string(),
                args: Vec::new(),
            },
            None,
        );
        program.methods.get_mut(&m_caller).unwrap().body.push(callsite);

        let mut sem_info = SemanticInfo::new();
        // Record inheritance hierarchy in semantic info
        sem_info.types_hierarchy.insert("Circle".to_string(), Some("Shape".to_string()));
        sem_info.types_hierarchy.insert("Square".to_string(), Some("Shape".to_string()));

        let builder = CallGraphBuilder::new(&program, &sem_info);
        let resolver = JavaResolver;
        let cg = builder.build(&resolver);

        // Under CHA, calling Shape.draw resolves to: Shape.draw, Circle.draw, Square.draw
        assert_eq!(cg.edges.len(), 3);
        
        let callees: Vec<MethodId> = cg.edges.iter().map(|e| e.callee).collect();
        assert!(callees.contains(&m_draw_shape));
        assert!(callees.contains(&m_draw_circle));
        assert!(callees.contains(&m_draw_square));
    }
}
