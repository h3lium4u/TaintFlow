use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use v2_ir::{MethodId, InstructionId, Program, InstructionKind};
use v2_cfg::{ControlFlowGraph, BlockId};
use v2_callgraph::CallGraph;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IcfgNode {
    Entry(MethodId),
    Exit(MethodId),
    Instruction(InstructionId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IcfgEdgeKind {
    Normal,
    Call,
    Return,
    CallToReturn,
    Exception,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IcfgEdge {
    pub from: IcfgNode,
    pub to: IcfgNode,
    pub kind: IcfgEdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralFlowGraph {
    pub edges: Vec<IcfgEdge>,
    pub successors: HashMap<IcfgNode, Vec<(IcfgNode, IcfgEdgeKind)>>,
    pub predecessors: HashMap<IcfgNode, Vec<(IcfgNode, IcfgEdgeKind)>>,
}

impl InterproceduralFlowGraph {
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            successors: HashMap::new(),
            predecessors: HashMap::new(),
        }
    }

    pub fn add_edge(&mut self, edge: IcfgEdge) {
        self.successors
            .entry(edge.from)
            .or_default()
            .push((edge.to, edge.kind));
        self.predecessors
            .entry(edge.to)
            .or_default()
            .push((edge.from, edge.kind));
        self.edges.push(edge);
    }
}

pub struct IcfgBuilder<'a> {
    program: &'a Program,
    call_graph: &'a CallGraph,
    cfgs: &'a HashMap<MethodId, ControlFlowGraph>,
}

impl<'a> IcfgBuilder<'a> {
    pub fn new(
        program: &'a Program,
        call_graph: &'a CallGraph,
        cfgs: &'a HashMap<MethodId, ControlFlowGraph>,
    ) -> Self {
        Self {
            program,
            call_graph,
            cfgs,
        }
    }

    pub fn build(&self) -> InterproceduralFlowGraph {
        let mut icfg = InterproceduralFlowGraph::new();

        // 1. Build intraprocedural paths for each method
        for (&method_id, method) in &self.program.methods {
            let cfg = match self.cfgs.get(&method_id) {
                Some(c) => c,
                None => continue,
            };

            // Link synthetic Entry to the start of the first basic block
            let first_block_id = cfg.edges.iter()
                .find(|e| e.from == BlockId(0))
                .map(|e| e.to);
                
            if let Some(fb_id) = first_block_id {
                if let Some(fb) = cfg.blocks.get(&fb_id) {
                    if let Some(&first_inst) = fb.instructions.first() {
                        icfg.add_edge(IcfgEdge {
                            from: IcfgNode::Entry(method_id),
                            to: IcfgNode::Instruction(first_inst),
                            kind: IcfgEdgeKind::Normal,
                        });
                    }
                }
            }

            // Link internal block instructions sequentially
            for block in cfg.blocks.values() {
                if block.id.0 == 0 || block.id.0 == u32::MAX {
                    continue;
                }

                for idx in 0..block.instructions.len() {
                    let curr = block.instructions[idx];
                    
                    if idx + 1 < block.instructions.len() {
                        let next = block.instructions[idx + 1];
                        icfg.add_edge(IcfgEdge {
                            from: IcfgNode::Instruction(curr),
                            to: IcfgNode::Instruction(next),
                            kind: IcfgEdgeKind::Normal,
                        });
                    }
                }
            }

            // Link block boundaries using CFG edges
            for edge in &cfg.edges {
                if edge.from.0 == 0 || edge.to.0 == 0 {
                    continue;
                }

                if edge.to.0 == u32::MAX {
                    if let Some(src_block) = cfg.blocks.get(&edge.from) {
                        if let Some(&last_inst) = src_block.instructions.last() {
                            icfg.add_edge(IcfgEdge {
                                from: IcfgNode::Instruction(last_inst),
                                to: IcfgNode::Exit(method_id),
                                kind: IcfgEdgeKind::Normal,
                            });
                        }
                    }
                    continue;
                }

                let from_block = cfg.blocks.get(&edge.from);
                let to_block = cfg.blocks.get(&edge.to);

                if let (Some(fb), Some(tb)) = (from_block, to_block) {
                    if let (Some(&last_inst), Some(&first_inst)) = (fb.instructions.last(), tb.instructions.first()) {
                        icfg.add_edge(IcfgEdge {
                            from: IcfgNode::Instruction(last_inst),
                            to: IcfgNode::Instruction(first_inst),
                            kind: IcfgEdgeKind::Normal,
                        });
                    }
                }
            }

            // 2. Interprocedural Call / Return / CallToReturn connections
            for (idx, &inst_id) in method.body.iter().enumerate() {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    if let InstructionKind::Call { .. } = &inst.kind {
                        let callsite = IcfgNode::Instruction(inst_id);
                        
                        let return_site = if idx + 1 < method.body.len() {
                            IcfgNode::Instruction(method.body[idx + 1])
                        } else {
                            IcfgNode::Exit(method_id)
                        };

                        // Connect Call-to-Return bypass
                        icfg.add_edge(IcfgEdge {
                            from: callsite,
                            to: return_site,
                            kind: IcfgEdgeKind::CallToReturn,
                        });

                        // Resolve callee targets from call graph
                        let callsite_ref = v2_callgraph::CallSiteId(inst_id);
                        if let Some(callees) = self.call_graph.callsite_to_callees.get(&callsite_ref) {
                            for &callee_id in callees {
                                // Call edge: callsite -> callee entry
                                icfg.add_edge(IcfgEdge {
                                    from: callsite,
                                    to: IcfgNode::Entry(callee_id),
                                    kind: IcfgEdgeKind::Call,
                                });

                                // Return edge: callee exit -> caller return-site
                                icfg.add_edge(IcfgEdge {
                                    from: IcfgNode::Exit(callee_id),
                                    to: return_site,
                                    kind: IcfgEdgeKind::Return,
                                });
                            }
                        }
                    }
                }
            }
        }

        icfg
    }
}

// Helper utility for Return edge creation
impl IcfgEdge {
    pub fn new_return(callee: MethodId, return_site: IcfgNode) -> Self {
        Self {
            from: IcfgNode::Exit(callee),
            to: return_site,
            kind: IcfgEdgeKind::Return,
        }
    }
}

// Adjust the Return edge creation in IcfgBuilder::build to use the synthetic exit node
// Wait, in build() above, I wrote:
//   from: callee_id, (which is a MethodId)
//   to: return_site,
// This would fail to compile because callee_id is MethodId and from is IcfgNode.
// We must rewrite the return edge in build() to use IcfgNode::Exit(callee_id)!
// Let's modify the build function or rewrite the file with this fix.

pub fn init() {
    println!("v2-icfg initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_ir::{InstructionKind, Operand, Program};
    use v2_cfg::CfgBuilder;
    use v2_callgraph::{CallGraphBuilder, PythonResolver};
    use v2_semantic::SemanticInfo;

    #[test]
    fn test_icfg_direct_call_return() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());

        // Callee: greet() -> returns "hello"
        let m_greet = program.alloc_method("greet".to_string(), None, Vec::new(), Some(m_id));
        let i_ret = program.alloc_instruction(
            InstructionKind::Return {
                val: Some(Operand::Const(v2_ir::Constant::String("hello".to_string()))),
            },
            None,
        );
        program.methods.get_mut(&m_greet).unwrap().body.push(i_ret);

        // Caller: main() -> call greet()
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));
        let i_call = program.alloc_instruction(
            InstructionKind::Call {
                dest: Some(Operand::Var("x".to_string())),
                callee: "greet".to_string(),
                args: Vec::new(),
            },
            None,
        );
        let i_next = program.alloc_instruction(
            InstructionKind::Return { val: None },
            None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_call, i_next]);

        // Build CFGs
        let mut cfgs = HashMap::new();
        let mut builder_cfg = CfgBuilder::new(&program);
        cfgs.insert(m_greet, builder_cfg.build(&program.methods.get(&m_greet).unwrap().body));
        cfgs.insert(m_main, builder_cfg.build(&program.methods.get(&m_main).unwrap().body));

        // Build Call Graph
        let sem_info = SemanticInfo::new();
        let cg_builder = CallGraphBuilder::new(&program, &sem_info);
        let cg = cg_builder.build(&PythonResolver);

        // Build ICFG
        let icfg_builder = IcfgBuilder::new(&program, &cg, &cfgs);
        let icfg = icfg_builder.build();

        // Check Call-to-Return bypass edge
        let call_node = IcfgNode::Instruction(i_call);
        let next_node = IcfgNode::Instruction(i_next);
        assert!(icfg.edges.iter().any(|e| e.from == call_node && e.to == next_node && e.kind == IcfgEdgeKind::CallToReturn));

        // Check Call edge
        let callee_entry = IcfgNode::Entry(m_greet);
        assert!(icfg.edges.iter().any(|e| e.from == call_node && e.to == callee_entry && e.kind == IcfgEdgeKind::Call));

        // Check Return edge
        let callee_exit = IcfgNode::Exit(m_greet);
        assert!(icfg.edges.iter().any(|e| e.from == callee_exit && e.to == next_node && e.kind == IcfgEdgeKind::Return));
    }
}
