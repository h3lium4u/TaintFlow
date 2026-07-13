use std::fs;

fn main() {
    let target_test_id = "BenchmarkTest00087";
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    let mut code = String::new();
    for line in content.lines() {
        if line.contains(target_test_id) {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            break;
        }
    }
    
    if code.is_empty() {
        println!("{} not found!", target_test_id);
        return;
    }
    
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    
    let filename = format!("{}.java", target_test_id);
    program.source_files.insert(filename.clone(), code.clone());
    
    gst.load_file(&mut program, &code, &filename, &"java".to_string()).unwrap();
    gst.resolve_inheritance_hierarchy();
    
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
    
    println!("ICFG nodes count: {}, edges: {}", icfg.nodes.len(), icfg.edges.len());
    
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    engine.seed_sources(None);
    
    println!("Seed sources count: {}", engine.tainted_facts.len());
    for fact in &engine.tainted_facts {
        let node = icfg.nodes.get(&fact.node_id).unwrap();
        let inst_str = node.instruction_id.and_then(|inst_id| program.instructions.get(&inst_id)).map_or("".to_string(), |inst| format!("{:?}", inst.kind));
        println!("  Seed: node={}, var={}, inst={}", fact.node_id, fact.var, inst_str);
    }
    
    engine.run();
    
    println!("Flows detected: {}", engine.flows.len());
    for flow in &engine.flows {
        println!("  Flow CWE: {:?}, sink_node: {}, sink_var: {}", flow.cwe, flow.sink_node_id, flow.sink_var);
    }

    println!("All tainted facts at termination:");
    for fact in &engine.tainted_facts {
        let node = icfg.nodes.get(&fact.node_id).unwrap();
        let inst_str = node.instruction_id.and_then(|inst_id| program.instructions.get(&inst_id)).map_or("".to_string(), |inst| format!("{:?}", inst.kind));
        println!("  Fact: node={}, var={}, inst={}, sanitized={:?}, source_domain={:?}", fact.node_id, fact.var, inst_str, fact.sanitized_for, fact.source_domain);
    }
}
