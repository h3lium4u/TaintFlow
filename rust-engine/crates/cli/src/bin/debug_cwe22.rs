use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: debug_cwe22 <BenchmarkTestXXXXX>");
        return;
    }
    let target_name = &args[1];
    
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    let mut code = String::new();
    let mut cwe = "CWE-22".to_string();
    for line in content.lines() {
        if line.contains(target_name) {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            if let Some(c) = data.get("cwe").and_then(|v| v.as_str()) {
                cwe = c.to_string();
            }
            break;
        }
    }
    
    if code.is_empty() {
        println!("{} not found!", target_name);
        return;
    }
    
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    
    let filename = format!("Test_{}.java", cwe.replace("-", "_"));
    program.source_files.insert(filename.clone(), code.clone());
    
    gst.load_file(&mut program, &code, &filename, &"java".to_string()).unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
    
    println!("=== {} ICFG nodes ===", target_name);
    for (id, node) in &icfg.nodes {
        if let Some(inst_id) = node.instruction_id {
            let inst = program.instructions.get(&inst_id).unwrap();
            println!("  Node {}: {:?}", id, inst.kind);
        } else {
            println!("  Node {}: Entry/Exit", id);
        }
    }
    
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    engine.seed_sources(None);
    engine.run();
    
    println!("=== Tainted Facts ===");
    for f in &engine.tainted_facts {
        println!("  Node {}: {:?}", f.node_id, f);
    }
    
    println!("Flows detected: {}", engine.flows.len());
    for flow in &engine.flows {
        println!("  Flow CWE: {:?}, sink_node: {}, sink_var: {}", flow.cwe, flow.sink_node_id, flow.sink_var);
    }
}
