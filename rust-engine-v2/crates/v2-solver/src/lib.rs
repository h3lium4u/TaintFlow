use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataFlowFact<F> {
    Zero,
    Fact(F),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathEdge<N, F> {
    pub source_fact: DataFlowFact<F>,
    pub node: N,
    pub target_fact: DataFlowFact<F>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SummaryEdge<N, F> {
    pub call_site: N,
    pub entry_fact: DataFlowFact<F>,
    pub exit_fact: DataFlowFact<F>,
}

pub trait NormalFlowFunction<F> {
    fn compute(&self, fact: &DataFlowFact<F>) -> HashSet<DataFlowFact<F>>;
}

pub trait CallFlowFunction<F> {
    fn compute(&self, fact: &DataFlowFact<F>) -> HashSet<DataFlowFact<F>>;
}

pub trait ReturnFlowFunction<F> {
    fn compute(&self, call_site_fact: &DataFlowFact<F>, exit_fact: &DataFlowFact<F>) -> HashSet<DataFlowFact<F>>;
}

pub trait CallToReturnFlowFunction<F> {
    fn compute(&self, fact: &DataFlowFact<F>) -> HashSet<DataFlowFact<F>>;
}

pub trait TabulationProblem {
    type Node: Clone + Eq + std::hash::Hash;
    type Fact: Clone + Eq + std::hash::Hash;

    fn initial_seeds(&self) -> HashMap<Self::Node, HashSet<DataFlowFact<Self::Fact>>>;
    fn zero_value(&self) -> DataFlowFact<Self::Fact>;
    fn successors(&self, node: &Self::Node) -> Vec<Self::Node>;
    fn predecessors(&self, node: &Self::Node) -> Vec<Self::Node>;
    
    fn is_call_site(&self, node: &Self::Node) -> bool;
    fn is_exit_node(&self, node: &Self::Node) -> bool;
    
    fn get_normal_flow(&self, curr: &Self::Node, succ: &Self::Node) -> Box<dyn NormalFlowFunction<Self::Fact>>;
    fn get_call_flow(&self, call: &Self::Node, entry: &Self::Node) -> Box<dyn CallFlowFunction<Self::Fact>>;
    fn get_return_flow(&self, exit: &Self::Node, ret: &Self::Node) -> Box<dyn ReturnFlowFunction<Self::Fact>>;
    fn get_call_to_return_flow(&self, call: &Self::Node, ret: &Self::Node) -> Box<dyn CallToReturnFlowFunction<Self::Fact>>;
}

pub struct Worklist<T> {
    queue: VecDeque<T>,
    visited: HashSet<T>,
}

impl<T: Clone + Eq + std::hash::Hash> Worklist<T> {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            visited: HashSet::new(),
        }
    }

    pub fn push(&mut self, item: T) -> bool {
        if self.visited.insert(item.clone()) {
            self.queue.push_back(item);
            true
        } else {
            false
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

pub struct IfdsSolver<P: TabulationProblem> {
    pub problem: P,
    pub worklist: Worklist<PathEdge<P::Node, P::Fact>>,
    pub path_edges: HashSet<PathEdge<P::Node, P::Fact>>,
    pub summary_edges: HashSet<SummaryEdge<P::Node, P::Fact>>,
    
    // incoming: (callee_entry, callee_entry_fact) -> Set<(call_site, return_site, caller_entry_fact)>
    pub incoming: HashMap<(P::Node, DataFlowFact<P::Fact>), HashSet<(P::Node, P::Node, DataFlowFact<P::Fact>)>>,
}

impl<P: TabulationProblem> IfdsSolver<P>
where
    P::Node: Clone + Eq + std::hash::Hash,
    P::Fact: Clone + Eq + std::hash::Hash,
{
    pub fn new(problem: P) -> Self {
        Self {
            problem,
            worklist: Worklist::new(),
            path_edges: HashSet::new(),
            summary_edges: HashSet::new(),
            incoming: HashMap::new(),
        }
    }

    pub fn solve(&mut self) {
        let seeds = self.problem.initial_seeds();
        for (node, facts) in seeds {
            for fact in facts {
                let edge = PathEdge {
                    source_fact: self.problem.zero_value(),
                    node: node.clone(),
                    target_fact: fact,
                };
                self.propagate(edge);
            }
        }
        
        while let Some(edge) = self.worklist.pop() {
            let u = edge.node.clone();
            let d1 = edge.source_fact.clone();
            let d2 = edge.target_fact.clone();
            
            if self.problem.is_call_site(&u) {
                self.process_call(u, d1, d2);
            } else if self.problem.is_exit_node(&u) {
                self.process_exit(u, d1, d2);
            } else {
                self.process_normal(u, d1, d2);
            }
        }
    }

    fn propagate(&mut self, edge: PathEdge<P::Node, P::Fact>) {
        if self.path_edges.insert(edge.clone()) {
            self.worklist.push(edge);
        }
    }

    fn is_procedure_entry(&self, node: &P::Node) -> bool {
        let preds = self.problem.predecessors(node);
        if preds.is_empty() {
            return true;
        }
        preds.iter().all(|p| self.problem.is_call_site(p))
    }

    fn find_exit_nodes_of_procedure(&self, entry: &P::Node) -> Vec<P::Node> {
        let mut exits = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry.clone());
        visited.insert(entry.clone());

        while let Some(curr) = queue.pop_front() {
            if self.problem.is_exit_node(&curr) {
                exits.push(curr.clone());
                continue;
            }

            for succ in self.problem.successors(&curr) {
                if !self.is_procedure_entry(&succ) && visited.insert(succ.clone()) {
                    queue.push_back(succ);
                }
            }
        }
        exits
    }

    fn find_entry_node_of_procedure(&self, exit: &P::Node) -> P::Node {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(exit.clone());
        visited.insert(exit.clone());

        while let Some(curr) = queue.pop_front() {
            if self.is_procedure_entry(&curr) {
                return curr;
            }

            for pred in self.problem.predecessors(&curr) {
                if visited.insert(pred.clone()) {
                    queue.push_back(pred);
                }
            }
        }
        exit.clone()
    }

    fn process_normal(&mut self, u: P::Node, d1: DataFlowFact<P::Fact>, d2: DataFlowFact<P::Fact>) {
        let successors = self.problem.successors(&u);
        for succ in successors {
            let flow_func = self.problem.get_normal_flow(&u, &succ);
            let target_facts = flow_func.compute(&d2);
            for d3 in target_facts {
                let next_edge = PathEdge {
                    source_fact: d1.clone(),
                    node: succ.clone(),
                    target_fact: d3,
                };
                self.propagate(next_edge);
            }
        }
    }

    fn process_call(&mut self, u: P::Node, d1: DataFlowFact<P::Fact>, d2: DataFlowFact<P::Fact>) {
        let successors = self.problem.successors(&u);
        
        let mut callee_entries = Vec::new();
        let mut return_sites = Vec::new();
        for succ in successors {
            if self.is_procedure_entry(&succ) {
                callee_entries.push(succ);
            } else {
                return_sites.push(succ);
            }
        }

        if let Some(r) = return_sites.first() {
            let flow_func = self.problem.get_call_to_return_flow(&u, r);
            let target_facts = flow_func.compute(&d2);
            for d3 in target_facts {
                let next_edge = PathEdge {
                    source_fact: d1.clone(),
                    node: r.clone(),
                    target_fact: d3,
                };
                self.propagate(next_edge);
            }
        }

        for s_q in callee_entries {
            let flow_func = self.problem.get_call_flow(&u, &s_q);
            let target_facts = flow_func.compute(&d2);
            for d3 in target_facts {
                if let Some(r) = return_sites.first() {
                    self.incoming
                        .entry((s_q.clone(), d3.clone()))
                        .or_default()
                        .insert((u.clone(), r.clone(), d1.clone()));
                }

                let entry_edge = PathEdge {
                    source_fact: d3.clone(),
                    node: s_q.clone(),
                    target_fact: d3.clone(),
                };
                self.propagate(entry_edge);

                let exit_nodes = self.find_exit_nodes_of_procedure(&s_q);
                for e_q in exit_nodes {
                    let matching_summaries: Vec<_> = self.path_edges.iter()
                        .filter(|e| e.source_fact == d3 && e.node == e_q)
                        .map(|e| e.target_fact.clone())
                        .collect();

                    for d4 in matching_summaries {
                        if let Some(r) = return_sites.first() {
                            let return_flow = self.problem.get_return_flow(&e_q, r);
                            let target_facts = return_flow.compute(&d2, &d4);
                            for d5 in target_facts {
                                let next_edge = PathEdge {
                                    source_fact: d1.clone(),
                                    node: r.clone(),
                                    target_fact: d5,
                                };
                                self.propagate(next_edge);
                            }
                        }
                    }
                }
            }
        }
    }

    fn process_exit(&mut self, e_q: P::Node, d1: DataFlowFact<P::Fact>, d2: DataFlowFact<P::Fact>) {
        let summary = SummaryEdge {
            call_site: e_q.clone(),
            entry_fact: d1.clone(),
            exit_fact: d2.clone(),
        };
        self.summary_edges.insert(summary);

        let s_q = self.find_entry_node_of_procedure(&e_q);

        if let Some(callers) = self.incoming.get(&(s_q.clone(), d1.clone())) {
            for (c, r, d3) in callers.clone() {
                let matching_edges: Vec<_> = self.path_edges.iter()
                    .filter(|edge| edge.source_fact == d3 && edge.node == c)
                    .map(|edge| edge.target_fact.clone())
                    .collect();

                for d4 in matching_edges {
                    let call_flow = self.problem.get_call_flow(&c, &s_q);
                    if call_flow.compute(&d4).contains(&d1) {
                        let return_flow = self.problem.get_return_flow(&e_q, &r);
                        let target_facts = return_flow.compute(&d4, &d2);
                        for d5 in target_facts {
                            let next_edge = PathEdge {
                                source_fact: d3.clone(),
                                node: r.clone(),
                                target_fact: d5,
                            };
                            self.propagate(next_edge);
                        }
                    }
                }
            }
        }
    }
}

pub fn init() {
    println!("v2-solver initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }

    // Dummyreachability problem facts
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    enum DummyFact {
        A,
        B,
        C,
    }

    // Flow functions
    struct GenFact(DummyFact);
    impl NormalFlowFunction<DummyFact> for GenFact {
        fn compute(&self, fact: &DataFlowFact<DummyFact>) -> HashSet<DataFlowFact<DummyFact>> {
            let mut s = HashSet::new();
            s.insert(fact.clone());
            if *fact == DataFlowFact::Zero {
                s.insert(DataFlowFact::Fact(self.0));
            }
            s
        }
    }

    struct CallGen;
    impl CallFlowFunction<DummyFact> for CallGen {
        fn compute(&self, fact: &DataFlowFact<DummyFact>) -> HashSet<DataFlowFact<DummyFact>> {
            let mut s = HashSet::new();
            if let DataFlowFact::Fact(DummyFact::A) = fact {
                s.insert(DataFlowFact::Fact(DummyFact::B));
            }
            s
        }
    }

    struct ReturnGen;
    impl ReturnFlowFunction<DummyFact> for ReturnGen {
        fn compute(&self, call: &DataFlowFact<DummyFact>, exit: &DataFlowFact<DummyFact>) -> HashSet<DataFlowFact<DummyFact>> {
            let mut s = HashSet::new();
            if let (DataFlowFact::Fact(DummyFact::A), DataFlowFact::Fact(DummyFact::B)) = (call, exit) {
                s.insert(DataFlowFact::Fact(DummyFact::C));
            }
            s
        }
    }

    struct IdentityBypass;
    impl CallToReturnFlowFunction<DummyFact> for IdentityBypass {
        fn compute(&self, fact: &DataFlowFact<DummyFact>) -> HashSet<DataFlowFact<DummyFact>> {
            let mut s = HashSet::new();
            s.insert(fact.clone());
            s
        }
    }

    struct IdentityNormal;
    impl NormalFlowFunction<DummyFact> for IdentityNormal {
        fn compute(&self, fact: &DataFlowFact<DummyFact>) -> HashSet<DataFlowFact<DummyFact>> {
            let mut s = HashSet::new();
            s.insert(fact.clone());
            s
        }
    }

    // Dummy problem graph:
    // main:
    //   1: entry
    //   2: call greet (target: 4, return site: 3)
    //   3: return site
    //   5: exit main
    // greet:
    //   4: entry/exit greet
    struct DummyProblem;

    impl TabulationProblem for DummyProblem {
        type Node = u32;
        type Fact = DummyFact;

        fn initial_seeds(&self) -> HashMap<Self::Node, HashSet<DataFlowFact<Self::Fact>>> {
            let mut seeds = HashMap::new();
            let mut facts = HashSet::new();
            facts.insert(DataFlowFact::Zero);
            seeds.insert(1, facts);
            seeds
        }

        fn zero_value(&self) -> DataFlowFact<Self::Fact> {
            DataFlowFact::Zero
        }

        fn successors(&self, node: &Self::Node) -> Vec<Self::Node> {
            match node {
                1 => vec![2],
                2 => vec![4, 3], // 4 is callee entry, 3 is return site
                3 => vec![5],
                4 => vec![], // exit
                _ => vec![],
            }
        }

        fn predecessors(&self, node: &Self::Node) -> Vec<Self::Node> {
            match node {
                2 => vec![1],
                3 => vec![2, 4], // callsite 2, callee exit 4
                4 => vec![2],
                5 => vec![3],
                _ => vec![],
            }
        }

        fn is_call_site(&self, node: &Self::Node) -> bool {
            *node == 2
        }

        fn is_exit_node(&self, node: &Self::Node) -> bool {
            *node == 4 || *node == 5
        }

        fn get_normal_flow(&self, curr: &Self::Node, _succ: &Self::Node) -> Box<dyn NormalFlowFunction<Self::Fact>> {
            if *curr == 1 {
                Box::new(GenFact(DummyFact::A))
            } else {
                Box::new(IdentityNormal)
            }
        }

        fn get_call_flow(&self, _call: &Self::Node, _entry: &Self::Node) -> Box<dyn CallFlowFunction<Self::Fact>> {
            Box::new(CallGen)
        }

        fn get_return_flow(&self, _exit: &Self::Node, _ret: &Self::Node) -> Box<dyn ReturnFlowFunction<Self::Fact>> {
            Box::new(ReturnGen)
        }

        fn get_call_to_return_flow(&self, _call: &Self::Node, _ret: &Self::Node) -> Box<dyn CallToReturnFlowFunction<Self::Fact>> {
            Box::new(IdentityBypass)
        }
    }

    #[test]
    fn test_dummy_propagation() {
        let problem = DummyProblem;
        let mut solver = IfdsSolver::new(problem);
        solver.solve();

        // 1. Check that A is generated at node 2 (callsite)
        assert!(solver.path_edges.contains(&PathEdge {
            source_fact: DataFlowFact::Zero,
            node: 2,
            target_fact: DataFlowFact::Fact(DummyFact::A),
        }));

        // 2. Check that B is generated at callee entry/exit node 4
        assert!(solver.path_edges.contains(&PathEdge {
            source_fact: DataFlowFact::Fact(DummyFact::B),
            node: 4,
            target_fact: DataFlowFact::Fact(DummyFact::B),
        }));

        // 3. Check that C is generated at return site node 3
        assert!(solver.path_edges.contains(&PathEdge {
            source_fact: DataFlowFact::Zero,
            node: 3,
            target_fact: DataFlowFact::Fact(DummyFact::C),
        }));

        // 4. Check that A is preserved at return site node 3 (via bypass)
        assert!(solver.path_edges.contains(&PathEdge {
            source_fact: DataFlowFact::Zero,
            node: 3,
            target_fact: DataFlowFact::Fact(DummyFact::A),
        }));
    }

    // Recursion test case:
    // Node 6 calls itself.
    // 6: call self (callee entry: 6, return site: 7)
    // 7: exit node
    struct RecursiveProblem;
    impl TabulationProblem for RecursiveProblem {
        type Node = u32;
        type Fact = DummyFact;

        fn initial_seeds(&self) -> HashMap<Self::Node, HashSet<DataFlowFact<Self::Fact>>> {
            let mut seeds = HashMap::new();
            let mut facts = HashSet::new();
            facts.insert(DataFlowFact::Fact(DummyFact::A));
            seeds.insert(6, facts);
            seeds
        }

        fn zero_value(&self) -> DataFlowFact<Self::Fact> {
            DataFlowFact::Zero
        }

        fn successors(&self, node: &Self::Node) -> Vec<Self::Node> {
            match node {
                6 => vec![6, 7], // 6 is callee entry, 7 is return site
                _ => vec![],
            }
        }

        fn predecessors(&self, node: &Self::Node) -> Vec<Self::Node> {
            match node {
                6 => vec![6],
                7 => vec![6],
                _ => vec![],
            }
        }

        fn is_call_site(&self, node: &Self::Node) -> bool {
            *node == 6
        }

        fn is_exit_node(&self, node: &Self::Node) -> bool {
            *node == 7
        }

        fn get_normal_flow(&self, _curr: &Self::Node, _succ: &Self::Node) -> Box<dyn NormalFlowFunction<Self::Fact>> {
            Box::new(IdentityNormal)
        }

        fn get_call_flow(&self, _call: &Self::Node, _entry: &Self::Node) -> Box<dyn CallFlowFunction<Self::Fact>> {
            Box::new(CallGen)
        }

        fn get_return_flow(&self, _exit: &Self::Node, _ret: &Self::Node) -> Box<dyn ReturnFlowFunction<Self::Fact>> {
            Box::new(ReturnGen)
        }

        fn get_call_to_return_flow(&self, _call: &Self::Node, _ret: &Self::Node) -> Box<dyn CallToReturnFlowFunction<Self::Fact>> {
            Box::new(IdentityBypass)
        }
    }

    #[test]
    fn test_recursive_termination() {
        let problem = RecursiveProblem;
        let mut solver = IfdsSolver::new(problem);
        
        // This must terminate successfully without infinite loops due to the visited worklist guard.
        solver.solve();
        assert!(solver.path_edges.len() > 0);
    }
}
