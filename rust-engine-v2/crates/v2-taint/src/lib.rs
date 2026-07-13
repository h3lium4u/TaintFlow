use std::collections::{HashMap, HashSet};
use v2_ir::{InstructionId, MethodId, Operand, Program, InstructionKind};
use v2_icfg::{IcfgNode, IcfgEdgeKind, InterproceduralFlowGraph};
use v2_accesspath::{AccessPath, PathRoot};
use v2_solver::{TabulationProblem, DataFlowFact};
use v2_rules::{RuleRegistry, Finding, Confidence};

use std::sync::atomic::AtomicUsize;
pub static PROPAGATOR_TRANSFERS: AtomicUsize = AtomicUsize::new(0);
pub static ASSIGNMENT_PROPAGATIONS: AtomicUsize = AtomicUsize::new(0);
pub static LOOP_PROPAGATIONS: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn paths_may_alias(
    alias_result: &v2_alias::AliasResult,
    node: &IcfgNode,
    ap1: &AccessPath,
    ap2: &AccessPath,
) -> bool {
    if ap1 == ap2 {
        return true;
    }
    if ap1.segments != ap2.segments {
        return false;
    }
    let base1 = AccessPath::new(ap1.root.clone());
    let base2 = AccessPath::new(ap2.root.clone());
    alias_result.may_alias(node, &base1, &base2)
}

fn operand_to_access_path(op: &Operand) -> AccessPath {
    match op {
        Operand::Var(name) => AccessPath::new(PathRoot::Local(name.clone())),
        Operand::Temp(id) => AccessPath::new(PathRoot::Temp(*id)),
        Operand::Const(constant) => AccessPath::new(PathRoot::Constant(format!("{:?}", constant))),
    }
}

// ---------------------------------------------------------------------------
// Normal Flow Function
// ---------------------------------------------------------------------------

struct TaintNormalFlow {
    curr: IcfgNode,
    _succ: IcfgNode,
    program: &'static Program,
    alias_result: &'static v2_alias::AliasResult,
    rules: &'static RuleRegistry,
}

impl v2_solver::NormalFlowFunction<AccessPath> for TaintNormalFlow {
    fn compute(&self, fact: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        let mut targets = HashSet::new();

        if let IcfgNode::Instruction(inst_id) = self.curr {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                match &inst.kind {
                    InstructionKind::Call { dest, callee, args } => {
                        let is_source = self.rules.is_source(callee);
                        let is_sanitizer = self.rules.is_sanitizer(callee);
                        let is_propagator = self.rules.is_propagator(callee);

                        match fact {
                            DataFlowFact::Zero => {
                                targets.insert(DataFlowFact::Zero);
                                if is_source {
                                    if let Some(dest_op) = dest {
                                        let dest_ap = operand_to_access_path(dest_op);
                                        targets.insert(DataFlowFact::Fact(dest_ap));
                                    }
                                }
                            }
                            DataFlowFact::Fact(ap) => {
                                if is_sanitizer {
                                    // Sanitizer: kill taint on dest, preserve all others.
                                    if let Some(dest_op) = dest {
                                        let dest_ap = operand_to_access_path(dest_op);
                                        if ap != &dest_ap {
                                            targets.insert(DataFlowFact::Fact(ap.clone()));
                                        }
                                        // dest is killed — do not propagate.
                                    } else {
                                        targets.insert(DataFlowFact::Fact(ap.clone()));
                                    }
                                } else {
                                    if is_propagator {
                                        let mut tainted_any = false;
                                        for arg_op in args {
                                            let arg_ap = operand_to_access_path(arg_op);
                                            if ap == &arg_ap {
                                                tainted_any = true;
                                            }
                                        }
                                        if tainted_any {
                                            if let Some(dest_op) = dest {
                                                let dest_ap = operand_to_access_path(dest_op);
                                                targets.insert(DataFlowFact::Fact(dest_ap.clone()));
                                            } else if args.len() >= 1 {
                                                let rec_ap = operand_to_access_path(&args[0]);
                                                targets.insert(DataFlowFact::Fact(rec_ap));
                                            }
                                        }
                                    }
                                    targets.insert(DataFlowFact::Fact(ap.clone()));
                                }
                            }
                        }
                    }
                    InstructionKind::Assign { dest, src } => {
                        let dest_ap = operand_to_access_path(dest);
                        let src_ap = operand_to_access_path(src);
                        match fact {
                            DataFlowFact::Zero => {
                                targets.insert(DataFlowFact::Zero);
                            }
                            DataFlowFact::Fact(ap) => {
                                if ap == &src_ap {
                                    targets.insert(DataFlowFact::Fact(ap.clone()));
                                    targets.insert(DataFlowFact::Fact(dest_ap.clone()));
                                } else if ap == &dest_ap {
                                    // Kill destination — strong update.
                                } else {
                                    targets.insert(DataFlowFact::Fact(ap.clone()));
                                }
                            }
                        }
                    }
                    InstructionKind::Alloc { dest, .. } => {
                        let dest_ap = operand_to_access_path(dest);
                        match fact {
                            DataFlowFact::Zero => {
                                targets.insert(DataFlowFact::Zero);
                            }
                            DataFlowFact::Fact(ap) => {
                                if ap == &dest_ap {
                                    // Kill destination — strong update.
                                } else {
                                    targets.insert(DataFlowFact::Fact(ap.clone()));
                                }
                            }
                        }
                    }
                    InstructionKind::HeapLoad { dest, base, field } => {
                        let dest_ap = operand_to_access_path(dest);
                        let base_ap = operand_to_access_path(base);
                        let base_field_ap = base_ap.append_field(field.clone());

                        match fact {
                            DataFlowFact::Zero => {
                                targets.insert(DataFlowFact::Zero);
                            }
                            DataFlowFact::Fact(ap) => {
                                if ap == &dest_ap {
                                    // Kill destination.
                                } else {
                                    targets.insert(DataFlowFact::Fact(ap.clone()));
                                    let is_base_tainted = ap == &base_ap;
                                    let is_field_tainted = ap == &base_field_ap
                                        || paths_may_alias(self.alias_result, &self.curr, ap, &base_field_ap);
                                    if is_base_tainted || is_field_tainted {
                                        targets.insert(DataFlowFact::Fact(dest_ap.clone()));
                                    }
                                }
                            }
                        }
                    }
                    InstructionKind::HeapStore { base, field, src } => {
                        let base_ap = operand_to_access_path(base);
                        let src_ap = operand_to_access_path(src);
                        let base_field_ap = base_ap.append_field(field.clone());

                        match fact {
                            DataFlowFact::Zero => {
                                targets.insert(DataFlowFact::Zero);
                            }
                            DataFlowFact::Fact(ap) => {
                                targets.insert(DataFlowFact::Fact(ap.clone()));
                                if ap == &src_ap {
                                    targets.insert(DataFlowFact::Fact(base_field_ap.clone()));
                                }
                            }
                        }
                    }
                    _ => {
                        targets.insert(fact.clone());
                    }
                }
            } else {
                targets.insert(fact.clone());
            }
        } else {
            targets.insert(fact.clone());
        }

        targets
    }
}

// ---------------------------------------------------------------------------
// Call Flow Function
// ---------------------------------------------------------------------------

struct TaintCallFlow {
    call_inst_id: InstructionId,
    callee_id: MethodId,
    program: &'static Program,
}

impl v2_solver::CallFlowFunction<AccessPath> for TaintCallFlow {
    fn compute(&self, fact: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        let mut targets = HashSet::new();

        match fact {
            DataFlowFact::Zero => {
                targets.insert(DataFlowFact::Zero);
            }
            DataFlowFact::Fact(ap) => {
                if let Some(inst) = self.program.instructions.get(&self.call_inst_id) {
                    if let InstructionKind::Call { args, .. } = &inst.kind {
                        if let Some(callee) = self.program.methods.get(&self.callee_id) {
                            let offset = if args.len() > callee.parameters.len() { 1 } else { 0 };
                            for (idx, param_name) in callee.parameters.iter().enumerate() {
                                if idx + offset < args.len() {
                                    let actual_ap = operand_to_access_path(&args[idx + offset]);
                                    if ap == &actual_ap {
                                        let param_ap = AccessPath::new(PathRoot::Local(param_name.clone()));
                                        targets.insert(DataFlowFact::Fact(param_ap));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        targets
    }
}

// ---------------------------------------------------------------------------
// Return Flow Function
// ---------------------------------------------------------------------------

struct TaintReturnFlow {
    call_inst_id: InstructionId,
    callee_id: MethodId,
    program: &'static Program,
}

impl v2_solver::ReturnFlowFunction<AccessPath> for TaintReturnFlow {
    fn compute(&self, _call_site_fact: &DataFlowFact<AccessPath>, exit_fact: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        let mut targets = HashSet::new();

        match exit_fact {
            DataFlowFact::Zero => {}
            DataFlowFact::Fact(ap) => {
                if let Some(inst) = self.program.instructions.get(&self.call_inst_id) {
                    if let InstructionKind::Call { dest: Some(dest_op), .. } = &inst.kind {
                        if let Some(callee) = self.program.methods.get(&self.callee_id) {
                            for &body_inst_id in &callee.body {
                                if let Some(body_inst) = self.program.instructions.get(&body_inst_id) {
                                    if let InstructionKind::Return { val: Some(ret_op) } = &body_inst.kind {
                                        let ret_ap = operand_to_access_path(ret_op);
                                        if ap == &ret_ap {
                                            let dest_ap = operand_to_access_path(dest_op);
                                            targets.insert(DataFlowFact::Fact(dest_ap));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        targets
    }
}

// ---------------------------------------------------------------------------
// Call-to-Return Flow Function
// ---------------------------------------------------------------------------

struct TaintCallToReturnFlow {
    call_inst_id: InstructionId,
    program: &'static Program,
    rules: &'static RuleRegistry,
}

impl v2_solver::CallToReturnFlowFunction<AccessPath> for TaintCallToReturnFlow {
    fn compute(&self, fact: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        let mut targets = HashSet::new();

        match fact {
            DataFlowFact::Zero => {
                targets.insert(DataFlowFact::Zero);
                // Sources: generate taint out of Zero on the bypass edge.
                if let Some(inst) = self.program.instructions.get(&self.call_inst_id) {
                    if let InstructionKind::Call { dest, callee, .. } = &inst.kind {
                        if self.rules.is_source(callee) {
                            if let Some(dest_op) = dest {
                                let dest_ap = operand_to_access_path(dest_op);
                                targets.insert(DataFlowFact::Fact(dest_ap));
                            }
                        }
                    }
                }
            }
            DataFlowFact::Fact(ap) => {
                let mut skip = false;
                if let Some(inst) = self.program.instructions.get(&self.call_inst_id) {
                    if let InstructionKind::Call { dest, callee, args } = &inst.kind {
                        let is_san = self.rules.is_sanitizer(callee);
                        let is_prop = self.rules.is_propagator(callee);

                        if is_san {
                            if let Some(dest_op) = dest {
                                let dest_ap = operand_to_access_path(dest_op);
                                if ap == &dest_ap {
                                    skip = true;
                                }
                            }
                        }

                        if is_prop {
                            let mut tainted_any = false;
                            for arg_op in args {
                                let arg_ap = operand_to_access_path(arg_op);
                                if ap == &arg_ap {
                                    tainted_any = true;
                                }
                            }
                            if tainted_any {
                                if let Some(dest_op) = dest {
                                    let dest_ap = operand_to_access_path(dest_op);
                                    targets.insert(DataFlowFact::Fact(dest_ap.clone()));
                                } else if args.len() >= 1 {
                                    let rec_ap = operand_to_access_path(&args[0]);
                                    targets.insert(DataFlowFact::Fact(rec_ap));
                                }
                            }
                        }
                    }
                }
                if !skip {
                    targets.insert(DataFlowFact::Fact(ap.clone()));
                }
            }
        }

        targets
    }
}

// ---------------------------------------------------------------------------
// Identity flows (for nodes without specific handling)
// ---------------------------------------------------------------------------

struct IdentityCallFlow;
impl v2_solver::CallFlowFunction<AccessPath> for IdentityCallFlow {
    fn compute(&self, fact: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        let mut s = HashSet::new();
        s.insert(fact.clone());
        s
    }
}

struct IdentityReturnFlow;
impl v2_solver::ReturnFlowFunction<AccessPath> for IdentityReturnFlow {
    fn compute(&self, _: &DataFlowFact<AccessPath>, _: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        HashSet::new()
    }
}

struct IdentityCallToReturnFlow;
impl v2_solver::CallToReturnFlowFunction<AccessPath> for IdentityCallToReturnFlow {
    fn compute(&self, fact: &DataFlowFact<AccessPath>) -> HashSet<DataFlowFact<AccessPath>> {
        let mut s = HashSet::new();
        s.insert(fact.clone());
        s
    }
}

// ---------------------------------------------------------------------------
// TaintProblem — implements TabulationProblem
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TaintProblem {
    pub program: &'static Program,
    pub icfg: &'static InterproceduralFlowGraph,
    pub alias_result: &'static v2_alias::AliasResult,
    pub rules: &'static RuleRegistry,
    pub entry_methods: Vec<MethodId>,
}

impl TabulationProblem for TaintProblem {
    type Node = IcfgNode;
    type Fact = AccessPath;

    fn initial_seeds(&self) -> HashMap<Self::Node, HashSet<DataFlowFact<Self::Fact>>> {
        let mut seeds = HashMap::new();
        for &m_id in &self.entry_methods {
            let mut facts = HashSet::new();
            facts.insert(DataFlowFact::Zero);
            seeds.insert(IcfgNode::Entry(m_id), facts);
        }
        seeds
    }

    fn zero_value(&self) -> DataFlowFact<Self::Fact> {
        DataFlowFact::Zero
    }

    fn successors(&self, node: &Self::Node) -> Vec<Self::Node> {
        self.icfg.successors.get(node)
            .map(|succs| succs.iter().map(|&(s, _)| s).collect())
            .unwrap_or_default()
    }

    fn predecessors(&self, node: &Self::Node) -> Vec<Self::Node> {
        self.icfg.predecessors.get(node)
            .map(|preds| preds.iter().map(|&(p, _)| p).collect())
            .unwrap_or_default()
    }

    fn is_call_site(&self, node: &Self::Node) -> bool {
        if let Some(succs) = self.icfg.successors.get(node) {
            succs.iter().any(|&(_, kind)| kind == IcfgEdgeKind::Call)
        } else {
            false
        }
    }

    fn is_exit_node(&self, node: &Self::Node) -> bool {
        matches!(node, IcfgNode::Exit(_))
    }

    fn get_normal_flow(&self, curr: &Self::Node, succ: &Self::Node) -> Box<dyn v2_solver::NormalFlowFunction<Self::Fact>> {
        Box::new(TaintNormalFlow {
            curr: curr.clone(),
            _succ: succ.clone(),
            program: self.program,
            alias_result: self.alias_result,
            rules: self.rules,
        })
    }

    fn get_call_flow(&self, call: &Self::Node, entry: &Self::Node) -> Box<dyn v2_solver::CallFlowFunction<Self::Fact>> {
        if let (IcfgNode::Instruction(call_inst_id), IcfgNode::Entry(callee_id)) = (call.clone(), entry.clone()) {
            Box::new(TaintCallFlow {
                call_inst_id,
                callee_id,
                program: self.program,
            })
        } else {
            Box::new(IdentityCallFlow)
        }
    }

    fn get_return_flow(&self, exit: &Self::Node, ret: &Self::Node) -> Box<dyn v2_solver::ReturnFlowFunction<Self::Fact>> {
        if let Some(call_inst_id) = self.find_callsite_for_return_site(ret.clone()) {
            if let IcfgNode::Exit(callee_id) = exit.clone() {
                return Box::new(TaintReturnFlow {
                    call_inst_id,
                    callee_id,
                    program: self.program,
                });
            }
        }
        Box::new(IdentityReturnFlow)
    }

    fn get_call_to_return_flow(&self, call: &Self::Node, _ret: &Self::Node) -> Box<dyn v2_solver::CallToReturnFlowFunction<Self::Fact>> {
        if let IcfgNode::Instruction(call_inst_id) = call.clone() {
            Box::new(TaintCallToReturnFlow {
                call_inst_id,
                program: self.program,
                rules: self.rules,
            })
        } else {
            Box::new(IdentityCallToReturnFlow)
        }
    }
}

impl TaintProblem {
    fn find_callsite_for_return_site(&self, ret_node: IcfgNode) -> Option<InstructionId> {
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
}

// ---------------------------------------------------------------------------
// TaintAnalysis — public entry point
// ---------------------------------------------------------------------------

pub struct TaintAnalysis<'a> {
    pub problem: TaintProblem,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> TaintAnalysis<'a> {
    pub fn new(
        program: &'a Program,
        icfg: &'a InterproceduralFlowGraph,
        alias_result: &'a v2_alias::AliasResult,
        rules: &'a RuleRegistry,
        entry_methods: Vec<MethodId>,
    ) -> Self {
        unsafe {
            let static_program: &'static Program = std::mem::transmute(program);
            let static_icfg: &'static InterproceduralFlowGraph = std::mem::transmute(icfg);
            let static_alias: &'static v2_alias::AliasResult = std::mem::transmute(alias_result);
            let static_rules: &'static RuleRegistry = std::mem::transmute(rules);

            Self {
                problem: TaintProblem {
                    program: static_program,
                    icfg: static_icfg,
                    alias_result: static_alias,
                    rules: static_rules,
                    entry_methods,
                },
                _marker: std::marker::PhantomData,
            }
        }
    }

    /// Run the IFDS solver and return the per-node active fact sets.
    pub fn run(&self) -> HashMap<IcfgNode, HashSet<DataFlowFact<AccessPath>>> {
        let mut solver = v2_solver::IfdsSolver::new(self.problem.clone());
        solver.solve();

        let mut results = HashMap::new();
        for edge in solver.path_edges {
            results.entry(edge.node)
                .or_insert_with(HashSet::new)
                .insert(edge.target_fact);
        }
        results
    }

    /// Run the analysis and collect Findings at sink call sites.
    pub fn run_with_findings(&self) -> (HashMap<IcfgNode, HashSet<DataFlowFact<AccessPath>>>, Vec<Finding>) {
        let results = self.run();
        let mut findings = Vec::new();

        for (_method_id, method) in &self.problem.program.methods {
            for &inst_id in &method.body {
                if let Some(inst) = self.problem.program.instructions.get(&inst_id) {
                    if let InstructionKind::Call { callee, args, .. } = &inst.kind {
                        if self.problem.rules.is_sink(callee) {
                            let node = IcfgNode::Instruction(inst_id);
                            if let Some(facts) = results.get(&node) {
                                for fact in facts {
                                    if let DataFlowFact::Fact(ap) = fact {
                                        // Only report finding if the tainted access path matches one of the call arguments
                                        let matches_arg = args.iter().any(|arg| {
                                            match (&ap.root, arg) {
                                                (PathRoot::Local(name1), Operand::Var(name2)) => name1 == name2,
                                                (PathRoot::Temp(id1), Operand::Temp(id2)) => id1 == id2,
                                                _ => false,
                                            }
                                        });
                                        if !matches_arg {
                                            continue;
                                        }

                                        let sink_rules = self.problem.rules.sink_rules(callee);
                                        for rule in sink_rules {
                                            findings.push(Finding {
                                                rule_id: rule.id.clone(),
                                                rule_name: rule.name.clone(),
                                                cwe: rule.cwe,
                                                severity: rule.severity.clone(),
                                                source_location: None,
                                                sink_location: Some(format!("inst:{}", inst_id.0)),
                                                access_path: format!("{:?}", ap.root),
                                                call_trace: Vec::new(),
                                                confidence: Confidence::High,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        (results, findings)
    }
}

pub fn init() {
    println!("v2-taint initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use v2_cfg::CfgBuilder;
    use v2_callgraph::{CallGraphBuilder, PythonResolver};
    use v2_icfg::IcfgBuilder;
    use v2_semantic::SemanticInfo;
    use v2_rules::{default_registry, Severity};

    fn build_analysis<'a>(
        program: &'a Program,
        icfg: &'a InterproceduralFlowGraph,
        alias_result: &'a v2_alias::AliasResult,
        rules: &'a RuleRegistry,
        entry: MethodId,
    ) -> HashMap<IcfgNode, HashSet<DataFlowFact<AccessPath>>> {
        TaintAnalysis::new(program, icfg, alias_result, rules, vec![entry]).run()
    }

    fn setup(program: &Program, _m_main: MethodId, cfgs: &HashMap<MethodId, v2_cfg::ControlFlowGraph>)
        -> (InterproceduralFlowGraph, v2_alias::AliasResult)
    {
        let sem_info = SemanticInfo::new();
        let cg = CallGraphBuilder::new(program, &sem_info).build(&PythonResolver);
        let icfg = IcfgBuilder::new(program, &cg, cfgs).build();
        let alias_result = v2_alias::AliasEngine::new(program, &icfg).run();
        (icfg, alias_result)
    }

    // Convenience: build CFGs for all declared methods in program.
    fn build_cfgs(program: &Program) -> HashMap<MethodId, v2_cfg::ControlFlowGraph> {
        let mut cfgs = HashMap::new();
        let mut cfg_builder = CfgBuilder::new(program);
        for (&m_id, method) in &program.methods {
            cfgs.insert(m_id, cfg_builder.build(&method.body));
        }
        cfgs
    }

    // ------------------------------------------------------------------
    // Source recognition via rule registry
    // ------------------------------------------------------------------

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_source_recognition_via_rules() {
        // Uses "input" which is in the default Python rule pack.
        let rules = default_registry();
        assert!(rules.is_source("input"));
        assert!(!rules.is_source("eval"));
    }

    #[test]
    fn test_sink_recognition_via_rules() {
        let rules = default_registry();
        assert!(rules.is_sink("eval"));
        assert!(!rules.is_sink("input"));
    }

    #[test]
    fn test_sanitizer_recognition_via_rules() {
        let rules = default_registry();
        assert!(rules.is_sanitizer("html.escape"));
        assert!(!rules.is_sanitizer("eval"));
    }

    // ------------------------------------------------------------------
    // A. Source → Assignment → Sink
    // ------------------------------------------------------------------

    #[test]
    fn test_simple_assignment_taint() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call {
                dest: Some(Operand::Var("x".to_string())),
                callee: "source".to_string(),
                args: Vec::new(),
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
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_assign]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(),
            name: "source".to_string(),
            kind: v2_rules::RuleKind::Source,
            language: None,
            cwe: None,
            severity: Severity::High,
            category: None,
            description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        let active_facts = results.get(&node_exit).unwrap();
        assert!(active_facts.contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // B. Heap Store
    // ------------------------------------------------------------------

    #[test]
    fn test_heap_store() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call {
                dest: Some(Operand::Var("x".to_string())),
                callee: "source".to_string(),
                args: Vec::new(),
            },
            None,
        );
        let i_store = program.alloc_instruction(
            InstructionKind::HeapStore {
                base: Operand::Var("obj".to_string()),
                field: "f".to_string(),
                src: Operand::Var("x".to_string()),
            },
            None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_store]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_obj_f = AccessPath::new(PathRoot::Local("obj".to_string())).append_field("f".to_string());
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_obj_f)));
    }

    // ------------------------------------------------------------------
    // C. Heap Load
    // ------------------------------------------------------------------

    #[test]
    fn test_heap_load() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() },
            None,
        );
        let i_store = program.alloc_instruction(
            InstructionKind::HeapStore { base: Operand::Var("obj".to_string()), field: "f".to_string(), src: Operand::Var("x".to_string()) },
            None,
        );
        let i_load = program.alloc_instruction(
            InstructionKind::HeapLoad { dest: Operand::Var("y".to_string()), base: Operand::Var("obj".to_string()), field: "f".to_string() },
            None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_store, i_load]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // D. Alias Propagation
    // ------------------------------------------------------------------

    #[test]
    fn test_alias_propagation() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_alloc = program.alloc_instruction(
            InstructionKind::Alloc { dest: Operand::Var("a".to_string()), type_name: "Obj".to_string() },
            None,
        );
        let i_assign_b = program.alloc_instruction(
            InstructionKind::Assign { dest: Operand::Var("b".to_string()), src: Operand::Var("a".to_string()) },
            None,
        );
        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() },
            None,
        );
        let i_store = program.alloc_instruction(
            InstructionKind::HeapStore { base: Operand::Var("a".to_string()), field: "f".to_string(), src: Operand::Var("x".to_string()) },
            None,
        );
        let i_load = program.alloc_instruction(
            InstructionKind::HeapLoad { dest: Operand::Var("y".to_string()), base: Operand::Var("b".to_string()), field: "f".to_string() },
            None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_alloc, i_assign_b, i_source, i_store, i_load]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // E+F. Call & Return Flow
    // ------------------------------------------------------------------

    #[test]
    fn test_call_return_flow() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());

        let m_identity = program.alloc_method("identity".to_string(), None, vec!["p".to_string()], Some(m_id));
        let i_ret = program.alloc_instruction(
            InstructionKind::Return { val: Some(Operand::Var("p".to_string())) }, None,
        );
        program.methods.get_mut(&m_identity).unwrap().body.push(i_ret);

        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));
        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_call = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("y".to_string())), callee: "identity".to_string(), args: vec![Operand::Var("x".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_call]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // G. Call-to-Return Bypass
    // ------------------------------------------------------------------

    #[test]
    fn test_call_to_return_bypass() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());

        let m_identity = program.alloc_method("identity".to_string(), None, vec!["p".to_string()], Some(m_id));
        let i_ret = program.alloc_instruction(
            InstructionKind::Return { val: Some(Operand::Var("p".to_string())) }, None,
        );
        program.methods.get_mut(&m_identity).unwrap().body.push(i_ret);

        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));
        let i_source_x = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_source_z = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("z".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_call = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("y".to_string())), callee: "identity".to_string(), args: vec![Operand::Var("x".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source_x, i_source_z, i_call]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_z = AccessPath::new(PathRoot::Local("z".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_z)));
    }

    // ------------------------------------------------------------------
    // H. Recursive Functions
    // ------------------------------------------------------------------

    #[test]
    fn test_recursive_functions() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());

        let m_rec = program.alloc_method("rec".to_string(), None, vec!["p".to_string()], Some(m_id));
        let i_call_rec = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "rec".to_string(), args: vec![Operand::Var("p".to_string())] }, None,
        );
        let i_ret = program.alloc_instruction(
            InstructionKind::Return { val: Some(Operand::Var("p".to_string())) }, None,
        );
        program.methods.get_mut(&m_rec).unwrap().body.extend([i_call_rec, i_ret]);

        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));
        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_call = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("y".to_string())), callee: "rec".to_string(), args: vec![Operand::Var("x".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_call]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // I. Arrays
    // ------------------------------------------------------------------

    #[test]
    fn test_arrays() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_store = program.alloc_instruction(
            InstructionKind::HeapStore { base: Operand::Var("arr".to_string()), field: "[*]".to_string(), src: Operand::Var("x".to_string()) }, None,
        );
        let i_load = program.alloc_instruction(
            InstructionKind::HeapLoad { dest: Operand::Var("y".to_string()), base: Operand::Var("arr".to_string()), field: "[*]".to_string() }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_store, i_load]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // J. Sanitizer (K in spec)
    // ------------------------------------------------------------------

    #[test]
    fn test_sanitizer() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_sanitize = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("y".to_string())), callee: "sanitize".to_string(), args: vec![Operand::Var("x".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_sanitize]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-san-001".to_string(), name: "sanitize".to_string(),
            kind: v2_rules::RuleKind::Sanitizer, language: None, cwe: None,
            severity: Severity::Info, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("sanitize".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);
        let results = build_analysis(&program, &icfg, &alias_result, &rules, m_main);

        let ap_y = AccessPath::new(PathRoot::Local("y".to_string()));
        let node_exit = IcfgNode::Exit(m_main);
        assert!(!results.get(&node_exit).unwrap().contains(&DataFlowFact::Fact(ap_y)));
    }

    // ------------------------------------------------------------------
    // Rule-driven sink reporting (Finding generation)
    // ------------------------------------------------------------------

    #[test]
    fn test_rule_driven_sink_reporting() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("x".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_sink = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "eval".to_string(), args: vec![Operand::Var("x".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_sink]);

        let mut rules = RuleRegistry::new();
        let pack = v2_rules::default_rule_pack();
        rules.load(&pack);
        // also add bare "source" rule
        let mut pack2 = v2_rules::RulePack::new("test-extra");
        pack2.add_rule(v2_rules::Rule {
            id: "t-src-001".to_string(), name: "source".to_string(),
            kind: v2_rules::RuleKind::Source, language: None, cwe: None,
            severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        rules.load(&pack2);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);

        let analysis = TaintAnalysis::new(&program, &icfg, &alias_result, &rules, vec![m_main]);
        let (_results, findings) = analysis.run_with_findings();
        assert!(!findings.is_empty(), "expected at least one finding at eval()");
        assert_eq!(findings[0].rule_id, "py-sink-001");
    }

    // ------------------------------------------------------------------
    // Default rule pack integration
    // ------------------------------------------------------------------

    #[test]
    fn test_default_rules_source_is_input() {
        let rules = default_registry();
        assert!(rules.is_source("input"));
    }

    #[test]
    fn test_default_rules_sink_is_eval() {
        let rules = default_registry();
        assert!(rules.is_sink("eval"));
    }

    #[test]
    fn test_default_rules_sanitizer_is_html_escape() {
        let rules = default_registry();
        assert!(rules.is_sanitizer("html.escape"));
    }

    #[test]
    fn test_receiver_mutating_propagation_list() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("userInput".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_add = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "add".to_string(), args: vec![Operand::Var("list".to_string()), Operand::Var("userInput".to_string())] }, None,
        );
        let i_sink = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "eval".to_string(), args: vec![Operand::Var("list".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_add, i_sink]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src".to_string(), name: "source".to_string(), kind: v2_rules::RuleKind::Source,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-prop".to_string(), name: "add".to_string(), kind: v2_rules::RuleKind::Propagator,
            language: None, cwe: None, severity: Severity::Info, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("add".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-sink".to_string(), name: "eval".to_string(), kind: v2_rules::RuleKind::Sink,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("eval".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);

        let analysis = TaintAnalysis::new(&program, &icfg, &alias_result, &rules, vec![m_main]);
        let (_results, findings) = analysis.run_with_findings();
        assert!(!findings.is_empty(), "Expected list.add() to propagate taint to list and trigger eval(list)");
    }

    #[test]
    fn test_receiver_mutating_propagation_map() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("userInput".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_put = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "put".to_string(), args: vec![Operand::Var("map".to_string()), Operand::Var("key".to_string()), Operand::Var("userInput".to_string())] }, None,
        );
        let i_sink = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "eval".to_string(), args: vec![Operand::Var("map".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_put, i_sink]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src".to_string(), name: "source".to_string(), kind: v2_rules::RuleKind::Source,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-prop".to_string(), name: "put".to_string(), kind: v2_rules::RuleKind::Propagator,
            language: None, cwe: None, severity: Severity::Info, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("put".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-sink".to_string(), name: "eval".to_string(), kind: v2_rules::RuleKind::Sink,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("eval".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);

        let analysis = TaintAnalysis::new(&program, &icfg, &alias_result, &rules, vec![m_main]);
        let (_results, findings) = analysis.run_with_findings();
        assert!(!findings.is_empty(), "Expected map.put() to propagate taint to map and trigger eval(map)");
    }

    #[test]
    fn test_receiver_mutating_propagation_stringbuilder() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("userInput".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_append = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "append".to_string(), args: vec![Operand::Var("sb".to_string()), Operand::Var("userInput".to_string())] }, None,
        );
        let i_sink = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "eval".to_string(), args: vec![Operand::Var("sb".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_append, i_sink]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src".to_string(), name: "source".to_string(), kind: v2_rules::RuleKind::Source,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-prop".to_string(), name: "append".to_string(), kind: v2_rules::RuleKind::Propagator,
            language: None, cwe: None, severity: Severity::Info, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("append".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-sink".to_string(), name: "eval".to_string(), kind: v2_rules::RuleKind::Sink,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("eval".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);

        let analysis = TaintAnalysis::new(&program, &icfg, &alias_result, &rules, vec![m_main]);
        let (_results, findings) = analysis.run_with_findings();
        assert!(!findings.is_empty(), "Expected sb.append() to propagate taint to sb and trigger eval(sb)");
    }

    #[test]
    fn test_receiver_mutating_propagation_processbuilder() {
        let mut program = Program::new();
        let m_id = program.alloc_module("main".to_string(), "main.py".to_string());
        let m_main = program.alloc_method("main".to_string(), None, Vec::new(), Some(m_id));

        let i_source = program.alloc_instruction(
            InstructionKind::Call { dest: Some(Operand::Var("userInput".to_string())), callee: "source".to_string(), args: Vec::new() }, None,
        );
        let i_command = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "command".to_string(), args: vec![Operand::Var("pb".to_string()), Operand::Var("userInput".to_string())] }, None,
        );
        let i_sink = program.alloc_instruction(
            InstructionKind::Call { dest: None, callee: "eval".to_string(), args: vec![Operand::Var("pb".to_string())] }, None,
        );
        program.methods.get_mut(&m_main).unwrap().body.extend([i_source, i_command, i_sink]);

        let mut rules = RuleRegistry::new();
        let mut pack = v2_rules::RulePack::new("test");
        pack.add_rule(v2_rules::Rule {
            id: "t-src".to_string(), name: "source".to_string(), kind: v2_rules::RuleKind::Source,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("source".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-prop".to_string(), name: "command".to_string(), kind: v2_rules::RuleKind::Propagator,
            language: None, cwe: None, severity: Severity::Info, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("command".to_string()),
        });
        pack.add_rule(v2_rules::Rule {
            id: "t-sink".to_string(), name: "eval".to_string(), kind: v2_rules::RuleKind::Sink,
            language: None, cwe: None, severity: Severity::High, category: None, description: None,
            matcher: v2_rules::Matcher::FunctionName("eval".to_string()),
        });
        rules.load(&pack);

        let cfgs = build_cfgs(&program);
        let (icfg, alias_result) = setup(&program, m_main, &cfgs);

        let analysis = TaintAnalysis::new(&program, &icfg, &alias_result, &rules, vec![m_main]);
        let (_results, findings) = analysis.run_with_findings();
        assert!(!findings.is_empty(), "Expected pb.command() to propagate taint to pb and trigger eval(pb)");
    }
}
