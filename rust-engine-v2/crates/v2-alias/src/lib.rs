use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use v2_ir::{InstructionId, MethodId, Operand, Program, TypeId, InstructionKind};
use v2_icfg::{IcfgNode, IcfgEdgeKind, InterproceduralFlowGraph};
use v2_accesspath::{AccessPath, PathRoot};
use v2_pointsto::{HeapObject, PointsToSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasState {
    pub map: HashMap<AccessPath, PointsToSet>,
}

impl AliasState {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn lookup(&self, ap: &AccessPath) -> PointsToSet {
        self.map.get(ap).cloned().unwrap_or_else(PointsToSet::new)
    }

    pub fn insert(&mut self, ap: AccessPath, pts: PointsToSet) {
        self.map.insert(ap, pts);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AliasStats {
    pub iterations: usize,
    pub worklist_pushes: usize,
    pub worklist_pops: usize,
    pub strong_updates: usize,
    pub weak_updates: usize,
    pub alias_merges: usize,
    pub max_pts_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasResult {
    pub states: HashMap<IcfgNode, AliasState>,
    pub stats: AliasStats,
}

impl AliasResult {
    pub fn lookup(&self, node: &IcfgNode, ap: &AccessPath) -> PointsToSet {
        self.states.get(node)
            .map(|s| s.lookup(ap))
            .unwrap_or_else(PointsToSet::new)
    }

    pub fn may_alias(&self, node: &IcfgNode, ap1: &AccessPath, ap2: &AccessPath) -> bool {
        let pts1 = self.lookup(node, ap1);
        let pts2 = self.lookup(node, ap2);
        let intersection = pts1.intersection(&pts2);
        !intersection.objects.is_empty()
    }

    pub fn must_alias(&self, node: &IcfgNode, ap1: &AccessPath, ap2: &AccessPath) -> bool {
        let pts1 = self.lookup(node, ap1);
        let pts2 = self.lookup(node, ap2);
        
        if pts1.objects.len() == 1 && pts2.objects.len() == 1 {
            pts1 == pts2
        } else {
            false
        }
    }
}

pub fn join(state_a: &AliasState, state_b: &AliasState, stats: Option<&mut AliasStats>) -> AliasState {
    let mut out = state_a.clone();
    let mut merged_count = 0;
    for (ap, b_pts) in &state_b.map {
        if let Some(a_pts) = out.map.get_mut(ap) {
            let union_pts = a_pts.union(b_pts);
            if union_pts.objects.len() > a_pts.objects.len() {
                *a_pts = union_pts;
                merged_count += 1;
            }
        } else {
            out.map.insert(ap.clone(), b_pts.clone());
            merged_count += 1;
        }
    }
    if merged_count > 0 {
        if let Some(s) = stats {
            s.alias_merges += merged_count;
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectContext {
    pub context_id: Option<u32>,
    pub object_context: Option<String>,
    pub heap_clone_id: Option<u32>,
}

pub struct AliasEngine<'a> {
    pub program: &'a Program,
    pub icfg: &'a InterproceduralFlowGraph,
    pub object_context: Option<ObjectContext>,
}

impl<'a> AliasEngine<'a> {
    pub fn new(program: &'a Program, icfg: &'a InterproceduralFlowGraph) -> Self {
        Self {
            program,
            icfg,
            object_context: None,
        }
    }

    pub fn run(&self) -> AliasResult {
        let mut node_entry_states: HashMap<IcfgNode, AliasState> = HashMap::new();
        let mut node_exit_states: HashMap<IcfgNode, AliasState> = HashMap::new();
        let mut stats = AliasStats::default();
        
        let mut worklist = std::collections::VecDeque::new();
        let mut in_worklist = HashSet::new();

        for edge in &self.icfg.edges {
            if let IcfgNode::Entry(_) = edge.from {
                node_entry_states.entry(edge.from).or_insert_with(AliasState::new);
                worklist.push_back(edge.from);
                in_worklist.insert(edge.from);
                stats.worklist_pushes += 1;
            }
        }

        while let Some(curr_node) = worklist.pop_front() {
            stats.worklist_pops += 1;
            stats.iterations += 1;
            in_worklist.remove(&curr_node);

            // 1. Merge exit states of predecessors into current entry state
            let mut entry_state = AliasState::new();
            if let Some(preds) = self.icfg.predecessors.get(&curr_node) {
                for &(pred_node, edge_kind) in preds {
                    if let Some(pred_exit) = node_exit_states.get(&pred_node) {
                        let propagated = self.propagate_edge(pred_node, curr_node, edge_kind, pred_exit);
                        entry_state = join(&entry_state, &propagated, Some(&mut stats));
                    }
                }
            }

            node_entry_states.insert(curr_node, entry_state.clone());

            // 2. Apply transfer function to compute exit state
            let (exit_state, node_stats) = self.apply_transfer(curr_node, &entry_state);
            stats.strong_updates += node_stats.strong_updates;
            stats.weak_updates += node_stats.weak_updates;

            for pts in exit_state.map.values() {
                if pts.objects.len() > stats.max_pts_size {
                    stats.max_pts_size = pts.objects.len();
                }
            }

            // 3. If exit state changed, enqueue successors
            let prev_exit = node_exit_states.get(&curr_node);
            let mut changed = true;
            if let Some(prev) = prev_exit {
                if prev == &exit_state {
                    changed = false;
                }
            }

            if changed {
                node_exit_states.insert(curr_node, exit_state);
                
                if let Some(succs) = self.icfg.successors.get(&curr_node) {
                    for &(succ_node, _) in succs {
                        if !in_worklist.contains(&succ_node) {
                            worklist.push_back(succ_node);
                            in_worklist.insert(succ_node);
                            stats.worklist_pushes += 1;
                        }
                    }
                }
            }
        }

        AliasResult {
            states: node_exit_states,
            stats,
        }
    }

    fn propagate_edge(
        &self,
        from: IcfgNode,
        to: IcfgNode,
        kind: IcfgEdgeKind,
        state: &AliasState,
    ) -> AliasState {
        let mut out = AliasState::new();
        
        match kind {
            IcfgEdgeKind::Call => {
                if let (IcfgNode::Instruction(call_inst_id), IcfgNode::Entry(callee_id)) = (from, to) {
                    if let Some(inst) = self.program.instructions.get(&call_inst_id) {
                        if let InstructionKind::Call { args, .. } = &inst.kind {
                            if let Some(callee) = self.program.methods.get(&callee_id) {
                                let offset = if args.len() > callee.parameters.len() { 1 } else { 0 };
                                for (idx, param_name) in callee.parameters.iter().enumerate() {
                                    if idx + offset < args.len() {
                                        let actual_ap = operand_to_access_path(&args[idx + offset]);
                                        let pts = state.lookup(&actual_ap);
                                        let param_ap = AccessPath::new(PathRoot::Local(param_name.clone()));
                                        out.insert(param_ap, pts);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            IcfgEdgeKind::Return => {
                if let (IcfgNode::Exit(callee_id), IcfgNode::Instruction(ret_inst_id)) = (from, to) {
                    let callsite_id = self.find_callsite_for_return_site(ret_inst_id);
                    if let Some(call_id) = callsite_id {
                        if let Some(inst) = self.program.instructions.get(&call_id) {
                            if let InstructionKind::Call { dest: Some(dest_op), .. } = &inst.kind {
                                if let Some(callee) = self.program.methods.get(&callee_id) {
                                    let mut ret_val_pts = PointsToSet::new();
                                    for &body_inst_id in &callee.body {
                                        if let Some(body_inst) = self.program.instructions.get(&body_inst_id) {
                                            if let InstructionKind::Return { val: Some(ret_op) } = &body_inst.kind {
                                                let ret_ap = operand_to_access_path(ret_op);
                                                ret_val_pts = ret_val_pts.union(&state.lookup(&ret_ap));
                                            }
                                        }
                                    }
                                    let dest_ap = operand_to_access_path(dest_op);
                                    out.insert(dest_ap, ret_val_pts);
                                }
                            }
                        }
                    }
                }
            }
            IcfgEdgeKind::CallToReturn => {
                if let IcfgNode::Instruction(call_inst_id) = from {
                    if let Some(inst) = self.program.instructions.get(&call_inst_id) {
                        for (ap, pts) in &state.map {
                            let mut skip = false;
                            if let InstructionKind::Call { dest: Some(dest_op), .. } = &inst.kind {
                                let dest_ap = operand_to_access_path(dest_op);
                                if ap == &dest_ap {
                                    skip = true;
                                }
                            }
                            if !skip {
                                out.insert(ap.clone(), pts.clone());
                            }
                        }
                    }
                }
            }
            _ => {
                out = state.clone();
            }
        }
        
        out
    }

    fn find_callsite_for_return_site(&self, ret_inst_id: InstructionId) -> Option<InstructionId> {
        let ret_node = IcfgNode::Instruction(ret_inst_id);
        if let Some(preds) = self.icfg.predecessors.get(&ret_node) {
            for &(pred_node, edge_kind) in preds {
                if edge_kind == IcfgEdgeKind::CallToReturn {
                    if let IcfgNode::Instruction(call_id) = pred_node {
                        return Some(call_id);
                    }
                }
            }
        }
        None
    }

    fn apply_transfer(&self, node: IcfgNode, state: &AliasState) -> (AliasState, AliasStats) {
        let mut out = state.clone();
        let mut stats = AliasStats::default();
        
        if let IcfgNode::Instruction(inst_id) = node {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                match &inst.kind {
                    InstructionKind::Alloc { dest, .. } => {
                        let (method_id, type_id) = self.find_enclosing_method_and_type(inst_id)
                            .unwrap_or((MethodId(0), TypeId(0)));
                        
                        let heap_obj = HeapObject::Allocation {
                            site_id: inst_id,
                            method_id,
                            type_id,
                            context: None,
                        };
                        let pts = PointsToSet::singleton(heap_obj);
                        let dest_ap = operand_to_access_path(dest);
                        out.insert(dest_ap, pts);
                        stats.strong_updates += 1;
                    }
                    InstructionKind::Assign { dest, src } => {
                        let src_ap = operand_to_access_path(src);
                        let pts = state.lookup(&src_ap);
                        let dest_ap = operand_to_access_path(dest);
                        out.insert(dest_ap, pts);
                        stats.strong_updates += 1;
                    }
                    InstructionKind::HeapLoad { dest, base, field } => {
                        let base_ap = operand_to_access_path(base);
                        let base_pts = state.lookup(&base_ap);
                        let mut field_pts = PointsToSet::new();
                        for obj in base_pts.objects.iter() {
                            let obj_field_ap = heap_object_field_ap(obj, field);
                            field_pts = field_pts.union(&state.lookup(&obj_field_ap));
                        }
                        let dest_ap = operand_to_access_path(dest);
                        out.insert(dest_ap, field_pts);
                        stats.strong_updates += 1;
                    }
                    InstructionKind::HeapStore { base, field, src } => {
                        let base_ap = operand_to_access_path(base);
                        let base_pts = state.lookup(&base_ap);
                        let src_ap = operand_to_access_path(src);
                        let src_pts = state.lookup(&src_ap);
                        
                        for obj in base_pts.objects.iter() {
                            let obj_field_ap = heap_object_field_ap(obj, field);
                            let current_pts = state.lookup(&obj_field_ap);
                            let new_pts = current_pts.union(&src_pts);
                            out.insert(obj_field_ap, new_pts);
                            stats.weak_updates += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        
        (out, stats)
    }

    fn find_enclosing_method_and_type(&self, inst_id: InstructionId) -> Option<(MethodId, TypeId)> {
        for (&m_id, method) in &self.program.methods {
            if method.body.contains(&inst_id) {
                return Some((m_id, method.parent_type_id.unwrap_or(TypeId(0))));
            }
        }
        None
    }
}

fn operand_to_access_path(op: &Operand) -> AccessPath {
    match op {
        Operand::Var(name) => AccessPath::new(PathRoot::Local(name.clone())),
        Operand::Temp(id) => AccessPath::new(PathRoot::Temp(*id)),
        Operand::Const(constant) => AccessPath::new(PathRoot::Constant(format!("{:?}", constant))),
    }
}

fn heap_object_field_ap(obj: &HeapObject, field: &str) -> AccessPath {
    match obj {
        HeapObject::Allocation { site_id, .. } => {
            AccessPath::new(PathRoot::Alloc(*site_id))
                .append_field(field.to_string())
        }
        HeapObject::Synthetic { name, .. } => {
            AccessPath::new(PathRoot::Local(name.clone()))
                .append_field(field.to_string())
        }
        HeapObject::Unknown => {
            AccessPath::new(PathRoot::Unknown)
                .append_field(field.to_string())
        }
    }
}

pub fn init() {
    println!("v2-alias initialized");
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_ir::InstructionKind;
    use v2_cfg::CfgBuilder;
    use v2_callgraph::{CallGraphBuilder, PythonResolver};
    use v2_icfg::IcfgBuilder;
    use v2_semantic::SemanticInfo;

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_flow_sensitive_local_alias() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_alloc = program.alloc_instruction(
            InstructionKind::Alloc {
                dest: Operand::Var("x".to_string()),
                type_name: "User".to_string(),
            },
            None,
        );
        let i_assign = program.alloc_instruction(
            InstructionKind::Assign {
                dest: Operand::Var("y".to_string()),
                src: Operand::Var("x".to_string()),
            },
            None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_alloc, i_assign]);

        let mut cfgs = HashMap::new();
        let mut cfg_builder = CfgBuilder::new(&program);
        cfgs.insert(m_main, cfg_builder.build(&program.methods.get(&m_main).unwrap().body));

        let sem_info = SemanticInfo::new();
        let cg = CallGraphBuilder::new(&program, &sem_info).build(&PythonResolver);

        let icfg = IcfgBuilder::new(&program, &cg, &cfgs).build();
        let engine = AliasEngine::new(&program, &icfg);
        let result = engine.run();

        let ap_x = AccessPath::new(PathRoot::Local("x".to_string()));
        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));

        let node_assign = IcfgNode::Instruction(i_assign);
        
        assert!(result.may_alias(&node_assign, &ap_x, &ap_y));
        assert!(result.must_alias(&node_assign, &ap_x, &ap_y));
    }

    #[test]
    fn test_diamond_cfg_merge() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        // dummy start: z = 0
        let i_start = program.alloc_instruction(
            InstructionKind::Assign {
                dest: Operand::Var("z".to_string()),
                src: Operand::Const(v2_ir::Constant::Int(0)),
            },
            None,
        );
        // alloc 1: x = Alloc A
        let i_alloc1 = program.alloc_instruction(
            InstructionKind::Alloc {
                dest: Operand::Var("x".to_string()),
                type_name: "A".to_string(),
            },
            None,
        );
        // alloc 2: x = Alloc B
        let i_alloc2 = program.alloc_instruction(
            InstructionKind::Alloc {
                dest: Operand::Var("x".to_string()),
                type_name: "B".to_string(),
            },
            None,
        );
        // assign: y = x
        let i_assign = program.alloc_instruction(
            InstructionKind::Assign {
                dest: Operand::Var("y".to_string()),
                src: Operand::Var("x".to_string()),
            },
            None,
        );
        
        program.methods.get_mut(&m_main).unwrap().body.extend([i_start, i_alloc1, i_alloc2, i_assign]);

        let mut cfgs = HashMap::new();
        let mut cfg = v2_cfg::ControlFlowGraph {
            blocks: HashMap::new(),
            edges: Vec::new(),
            entry: v2_cfg::BlockId(0),
            exit: v2_cfg::BlockId(u32::MAX),
        };
        
        cfg.blocks.insert(v2_cfg::BlockId(0), v2_cfg::BasicBlock {
            id: v2_cfg::BlockId(0),
            instructions: Vec::new(),
        });
        cfg.blocks.insert(v2_cfg::BlockId(1), v2_cfg::BasicBlock {
            id: v2_cfg::BlockId(1),
            instructions: vec![i_start],
        });
        cfg.blocks.insert(v2_cfg::BlockId(2), v2_cfg::BasicBlock {
            id: v2_cfg::BlockId(2),
            instructions: vec![i_alloc1],
        });
        cfg.blocks.insert(v2_cfg::BlockId(3), v2_cfg::BasicBlock {
            id: v2_cfg::BlockId(3),
            instructions: vec![i_alloc2],
        });
        cfg.blocks.insert(v2_cfg::BlockId(4), v2_cfg::BasicBlock {
            id: v2_cfg::BlockId(4),
            instructions: vec![i_assign],
        });
        cfg.blocks.insert(v2_cfg::BlockId(u32::MAX), v2_cfg::BasicBlock {
            id: v2_cfg::BlockId(u32::MAX),
            instructions: Vec::new(),
        });
        
        cfg.edges.push(v2_cfg::CfgEdge {
            from: v2_cfg::BlockId(0),
            to: v2_cfg::BlockId(1),
            kind: v2_cfg::EdgeKind::Fallthrough,
        });
        cfg.edges.push(v2_cfg::CfgEdge {
            from: v2_cfg::BlockId(1),
            to: v2_cfg::BlockId(2),
            kind: v2_cfg::EdgeKind::Fallthrough,
        });
        cfg.edges.push(v2_cfg::CfgEdge {
            from: v2_cfg::BlockId(1),
            to: v2_cfg::BlockId(3),
            kind: v2_cfg::EdgeKind::Fallthrough,
        });
        cfg.edges.push(v2_cfg::CfgEdge {
            from: v2_cfg::BlockId(2),
            to: v2_cfg::BlockId(4),
            kind: v2_cfg::EdgeKind::Fallthrough,
        });
        cfg.edges.push(v2_cfg::CfgEdge {
            from: v2_cfg::BlockId(3),
            to: v2_cfg::BlockId(4),
            kind: v2_cfg::EdgeKind::Fallthrough,
        });
        cfg.edges.push(v2_cfg::CfgEdge {
            from: v2_cfg::BlockId(4),
            to: v2_cfg::BlockId(u32::MAX),
            kind: v2_cfg::EdgeKind::Fallthrough,
        });
        
        cfgs.insert(m_main, cfg);

        let sem_info = SemanticInfo::new();
        let cg = CallGraphBuilder::new(&program, &sem_info).build(&PythonResolver);

        let icfg = IcfgBuilder::new(&program, &cg, &cfgs).build();
        let engine = AliasEngine::new(&program, &icfg);
        let result = engine.run();

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_assign = IcfgNode::Instruction(i_assign);
        
        let pts = result.lookup(&node_assign, &ap_y);
        // points-to set must contain both allocation points
        assert_eq!(pts.objects.len(), 2);
    }
}
