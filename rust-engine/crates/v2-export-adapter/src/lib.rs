use ir::Program;
use taint::interproc::{InterproceduralTaintEngine, TaintFlow};

#[derive(Debug, Clone)]
pub struct ProgramFacts {
    pub program: Program,
    pub taint_flows: Vec<TaintFlow>,
    pub icfg_to_inst: std::collections::HashMap<u32, ir::InstructionId>,
}

pub struct Exporter;

impl Exporter {
    pub fn export(engine: &InterproceduralTaintEngine) -> ProgramFacts {
        let mut icfg_to_inst = std::collections::HashMap::new();
        for (&node_id, node) in &engine.icfg.nodes {
            if let Some(inst_id) = node.instruction_id {
                icfg_to_inst.insert(node_id, inst_id);
            }
        }
        ProgramFacts {
            program: engine.program.clone(),
            taint_flows: engine.flows.iter().cloned().collect(),
            icfg_to_inst,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg::icfg::InterproceduralCFG;
    use symbols::call_graph::CallGraph;
    use symbols::GlobalSymbolTable;

    #[test]
    fn test_export_facts() {
        // Construct a minimal program and engine setup to test the export
        let program = Program::new();
        let gst = GlobalSymbolTable::new();
        let cg = CallGraph::build(&program, &gst);
        let icfg = InterproceduralCFG::build(&program, &cg);

        let engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);

        // Perform the export
        let facts1 = Exporter::export(&engine);
        let facts2 = Exporter::export(&engine);

        // Verify that exported facts are identical (reproducibility)
        assert_eq!(facts1.taint_flows.len(), facts2.taint_flows.len());

        // Verify we can read fields from the exported facts
        assert_eq!(facts1.program.id.0, 1);
        assert!(facts1.taint_flows.is_empty());
    }
}
