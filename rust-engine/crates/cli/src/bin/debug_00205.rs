use std::fs;

fn main() {
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    let mut code = String::new();
    for line in content.lines() {
        if line.contains("BenchmarkTest00205") {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            break;
        }
    }
    
    if code.is_empty() {
        println!("BenchmarkTest00205 not found!");
        return;
    }
    
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    
    let filename = "Test_CWE_22.java".to_string();
    program.source_files.insert(filename.clone(), code.clone());
    
    gst.load_file(&mut program, &code, &filename, &"java".to_string()).unwrap();
    gst.resolve_inheritance_hierarchy();
    
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
    
    println!("ICFG nodes count: {}, edges: {}", icfg.nodes.len(), icfg.edges.len());
    
    // Print all instructions to see what the callee is for File constructor
    for (id, inst) in &program.instructions {
        println!("  Inst {}: {:?}", id.0, inst.kind);
    }
    
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    engine.seed_sources(None);
    engine.run();
    
    println!("Flows detected: {}", engine.flows.len());
    for flow in &engine.flows {
        println!("  Flow CWE: {:?}, sink_node: {}, sink_var: {}", flow.cwe, flow.sink_node_id, flow.sink_var);
    }
}
