use ir::Program;
use symbols::GlobalSymbolTable;
use symbols::call_graph::CallGraph;
use cfg::icfg::InterproceduralCFG;
use taint::interproc::InterproceduralTaintEngine;
use v2_export_adapter::Exporter;

#[test]
fn test_exporter_does_not_modify_engine() {
    let program = Program::new();
    let gst = GlobalSymbolTable::new();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);


    let engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);

    // Record initial states of the engine
    let initial_flows_len = engine.flows.len();
    let initial_tainted_facts_len = engine.tainted_facts.len();

    // Run export
    let facts = Exporter::export(&engine);

    // Verify engine state is unchanged
    assert_eq!(engine.flows.len(), initial_flows_len);
    assert_eq!(engine.tainted_facts.len(), initial_tainted_facts_len);

    // Verify program has been exported
    assert_eq!(facts.program.id.0, 1);
}
