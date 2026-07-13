use std::fs;

fn main() {
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    let mut code = String::new();
    for line in content.lines() {
        if line.contains("BenchmarkTest01026") {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            break;
        }
    }
    
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "BenchmarkTest01026.java".to_string();
    
    gst.load_file(&mut program, &code, &filename, "java").unwrap();
    gst.resolve_inheritance_hierarchy();
    
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
    
    println!("=== All Instructions ===");
    let mut keys: Vec<&ir::InstructionId> = program.instructions.keys().collect();
    keys.sort_by_key(|id| id.0);
    for id in keys {
        let inst = program.instructions.get(id).unwrap();
        let node_ids: Vec<u32> = icfg.nodes.iter()
            .filter(|(_, n)| n.instruction_id == Some(*id))
            .map(|(&node_id, _)| node_id)
            .collect();
        println!("  {:?} node_ids={:?} | {:?}", id, node_ids, inst.kind);
    }
    
    println!("\n=== Running Taint Engine ===");
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    let mut target_set = std::collections::HashSet::new();
    target_set.insert(filename.clone().to_lowercase());
    engine.target_and_siblings = target_set;
    
    // Seed sources
    engine.seed_sources(None);
    
    println!("Initial tainted facts:");
    for fact in &engine.tainted_facts {
        println!("  Node {}: var={}", fact.node_id, fact.var);
    }
    
    println!("\n=== Running propagation ===");
    engine.run();
    
    println!("\nDetected flows count: {}", engine.flows.len());
    for flow in &engine.flows {
        println!("  Flow: sink_node={}, sink_var={}, cwe={:?}", 
                 flow.sink_node_id, flow.sink_var, flow.cwe);
    }
}
