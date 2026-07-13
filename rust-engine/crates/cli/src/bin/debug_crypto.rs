use std::fs;

fn main() {
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    
    // Find BenchmarkTest00169
    let mut code = String::new();
    for line in content.lines() {
        if line.contains("BenchmarkTest00169") {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            break;
        }
    }
    
    if code.is_empty() {
        println!("BenchmarkTest00169 not found!");
        return;
    }
    
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "test.java".to_string();
    program.source_files.insert(filename.clone(), code.clone());
    
    gst.load_file(&mut program, &code, &filename, &"java".to_string()).unwrap();
    gst.resolve_inheritance_hierarchy();
    
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
    
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    engine.seed_sources(None);
    engine.run();
    
    println!("=== Flows found in BenchmarkTest00169 ===");
    for flow in &engine.flows {
        println!("Flow: source_var={}, sink_var={}, cwe={:?}", flow.source_var, flow.sink_var, flow.cwe);
    }
    
    // Print all tainted facts at sink points
    println!("\nTainted facts:");
    for fact in &engine.tainted_facts {
        println!("  Fact: var={}, node_id={:?}, sanitized={:?}", fact.var, fact.node_id, fact.sanitized_for);
    }
}
