use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use v2_ir::{InstructionId, InstructionKind, Program};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Fallthrough,
    BranchTrue,
    BranchFalse,
    Unconditional,
    LoopBack,
    Exception,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: BlockId,
    pub to: BlockId,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<InstructionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<BlockId, BasicBlock>,
    pub edges: Vec<CfgEdge>,
    pub entry: BlockId,
    pub exit: BlockId,
}

pub struct CfgBuilder<'a> {
    program: &'a Program,
    next_block_id: u32,
}

impl<'a> CfgBuilder<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            next_block_id: 1,
        }
    }

    fn next_block_id(&mut self) -> BlockId {
        let id = self.next_block_id;
        self.next_block_id += 1;
        BlockId(id)
    }

    pub fn build(&mut self, insts: &[InstructionId]) -> ControlFlowGraph {
        let mut blocks = HashMap::new();
        let mut edges = Vec::new();

        // Special Entry and Exit blocks
        let entry_id = BlockId(0);
        let exit_id = BlockId(u32::MAX);

        blocks.insert(
            entry_id,
            BasicBlock {
                id: entry_id,
                instructions: Vec::new(),
            },
        );
        blocks.insert(
            exit_id,
            BasicBlock {
                id: exit_id,
                instructions: Vec::new(),
            },
        );

        if insts.is_empty() {
            // Empty body: connect Entry directly to Exit
            edges.push(CfgEdge {
                from: entry_id,
                to: exit_id,
                kind: EdgeKind::Fallthrough,
            });
            return ControlFlowGraph {
                blocks,
                edges,
                entry: entry_id,
                exit: exit_id,
            };
        }

        // 1. Identify leaders
        let mut leaders = HashSet::new();
        leaders.insert(0); // First instruction is always a leader

        for (idx, &inst_id) in insts.iter().enumerate() {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                match &inst.kind {
                    InstructionKind::Branch { .. } | InstructionKind::Jump { .. } => {
                        // The next instruction is a leader
                        if idx + 1 < insts.len() {
                            leaders.insert(idx + 1);
                        }
                    }
                    InstructionKind::Label(_) => {
                        // Labels start a new basic block
                        leaders.insert(idx);
                    }
                    InstructionKind::Return { .. } => {
                        // Instructions following a return are a leader (dead code starts here)
                        if idx + 1 < insts.len() {
                            leaders.insert(idx + 1);
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut sorted_leaders: Vec<usize> = leaders.into_iter().collect();
        sorted_leaders.sort_unstable();

        // 2. Create basic blocks
        let mut block_list = Vec::new();
        let mut inst_to_block = HashMap::new();
        let mut label_to_block = HashMap::new();

        for i in 0..sorted_leaders.len() {
            let start = sorted_leaders[i];
            let end = if i + 1 < sorted_leaders.len() {
                sorted_leaders[i + 1]
            } else {
                insts.len()
            };

            let block_insts = insts[start..end].to_vec();
            let b_id = self.next_block_id();
            
            // Map the first instruction of the block
            if let Some(&first_inst) = block_insts.first() {
                inst_to_block.insert(first_inst, b_id);
                // If it is a label, map the label to the block ID
                if let Some(inst) = self.program.instructions.get(&first_inst) {
                    if let InstructionKind::Label(lbl) = &inst.kind {
                        label_to_block.insert(*lbl, b_id);
                    }
                }
            }

            let block = BasicBlock {
                id: b_id,
                instructions: block_insts,
            };
            block_list.push(block);
        }

        // Connect entry block to the first basic block
        if let Some(first_block) = block_list.first() {
            edges.push(CfgEdge {
                from: entry_id,
                to: first_block.id,
                kind: EdgeKind::Fallthrough,
            });
        }

        // 3. Resolve edges
        for (i, block) in block_list.iter().enumerate() {
            let last_inst_id = *block.instructions.last().unwrap();
            let last_inst = self.program.instructions.get(&last_inst_id).unwrap();

            match &last_inst.kind {
                InstructionKind::Jump { target } => {
                    if let Some(&target_block) = label_to_block.get(target) {
                        // Check if it goes backwards (simple backedge heuristic)
                        let kind = if target_block.0 <= block.id.0 {
                            EdgeKind::LoopBack
                        } else {
                            EdgeKind::Unconditional
                        };
                        edges.push(CfgEdge {
                            from: block.id,
                            to: target_block,
                            kind,
                        });
                    }
                }
                InstructionKind::Branch { target, .. } => {
                    // Branch true path
                    if let Some(&target_block) = label_to_block.get(target) {
                        edges.push(CfgEdge {
                            from: block.id,
                            to: target_block,
                            kind: EdgeKind::BranchTrue,
                        });
                    }
                    // Branch false path (fallthrough to next block)
                    if i + 1 < block_list.len() {
                        edges.push(CfgEdge {
                            from: block.id,
                            to: block_list[i + 1].id,
                            kind: EdgeKind::BranchFalse,
                        });
                    }
                }
                InstructionKind::Return { .. } => {
                    // Connects to Exit block
                    edges.push(CfgEdge {
                        from: block.id,
                        to: exit_id,
                        kind: EdgeKind::Fallthrough,
                    });
                }
                _ => {
                    // Fallthrough to next block
                    if i + 1 < block_list.len() {
                        edges.push(CfgEdge {
                            from: block.id,
                            to: block_list[i + 1].id,
                            kind: EdgeKind::Fallthrough,
                        });
                    } else {
                        // Connect last block to exit block
                        edges.push(CfgEdge {
                            from: block.id,
                            to: exit_id,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                }
            }

            blocks.insert(block.id, block.clone());
        }

        ControlFlowGraph {
            blocks,
            edges,
            entry: entry_id,
            exit: exit_id,
        }
    }
}

pub fn init() {
    println!("v2-cfg initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_ir::{InstructionKind, Operand, Program, Label};

    #[test]
    fn test_cfg_construction() {
        let mut program = Program::new();
        
        // Build instructions for a simple branch:
        // t1 = true
        // branch t1 goto TrueLabel
        // x = 1
        // jump ExitLabel
        // Label(TrueLabel)
        // x = 2
        // Label(ExitLabel)
        // return x
        
        let t1 = Operand::Temp(1);
        let x = Operand::Var("x".to_string());
        
        let true_lbl = Label(1);
        let exit_lbl = Label(2);

        let i1 = program.alloc_instruction(InstructionKind::Assign { dest: t1.clone(), src: Operand::Var("true".to_string()) }, None);
        let i2 = program.alloc_instruction(InstructionKind::Branch { cond: t1, target: true_lbl }, None);
        let i3 = program.alloc_instruction(InstructionKind::Assign { dest: x.clone(), src: Operand::Const(v2_ir::Constant::Int(1)) }, None);
        let i4 = program.alloc_instruction(InstructionKind::Jump { target: exit_lbl }, None);
        let i5 = program.alloc_instruction(InstructionKind::Label(true_lbl), None);
        let i6 = program.alloc_instruction(InstructionKind::Assign { dest: x.clone(), src: Operand::Const(v2_ir::Constant::Int(2)) }, None);
        let i7 = program.alloc_instruction(InstructionKind::Label(exit_lbl), None);
        let i8 = program.alloc_instruction(InstructionKind::Return { val: Some(x) }, None);

        let body = vec![i1, i2, i3, i4, i5, i6, i7, i8];
        let mut builder = CfgBuilder::new(&program);
        let cfg = builder.build(&body);

        // We expect blocks:
        // 0: Entry
        // 1: i1, i2
        // 2: i3, i4
        // 3: i5, i6
        // 4: i7, i8
        // Exit: u32::MAX
        assert_eq!(cfg.blocks.len(), 6);

        // Check edges
        // Entry -> Block 1
        assert!(cfg.edges.iter().any(|e| e.from == BlockId(0) && e.to == BlockId(1)));
        // Block 1 -> Block 3 (BranchTrue)
        assert!(cfg.edges.iter().any(|e| e.from == BlockId(1) && e.to == BlockId(3) && e.kind == EdgeKind::BranchTrue));
        // Block 1 -> Block 2 (BranchFalse)
        assert!(cfg.edges.iter().any(|e| e.from == BlockId(1) && e.to == BlockId(2) && e.kind == EdgeKind::BranchFalse));
        // Block 2 -> Block 4 (Unconditional jump)
        assert!(cfg.edges.iter().any(|e| e.from == BlockId(2) && e.to == BlockId(4) && e.kind == EdgeKind::Unconditional));
        // Block 3 -> Block 4 (Fallthrough)
        assert!(cfg.edges.iter().any(|e| e.from == BlockId(3) && e.to == BlockId(4) && e.kind == EdgeKind::Fallthrough));
        // Block 4 -> Exit (Return path)
        assert!(cfg.edges.iter().any(|e| e.from == BlockId(4) && e.to == BlockId(u32::MAX) && e.kind == EdgeKind::Fallthrough));
    }
}
