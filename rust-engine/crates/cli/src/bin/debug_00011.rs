use std::fs;

fn main() {
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    let mut code = String::new();
    for line in content.lines() {
        if line.contains("BenchmarkTest00011") {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            break;
        }
    }

    if code.is_empty() {
        println!("BenchmarkTest00011 not found!");
        return;
    }

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();

    // Simulate the validation filename "test.py"
    let filename = "CWE22_Test.java".to_string();
    program.source_files.insert(filename.clone(), code.clone());

    gst.load_file(&mut program, &code, &filename, &"java".to_string())
        .unwrap();
    gst.resolve_inheritance_hierarchy();

    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    println!(
        "ICFG nodes count: {}, edges: {}",
        icfg.nodes.len(),
        icfg.edges.len()
    );

    for (id, inst) in &program.instructions {
        println!("  Inst {}: {:?}", id.0, inst.kind);
    }

    println!("ICFG Edges:");
    for edge in &icfg.edges {
        println!("  node {} -> node {} {:?}", edge.from, edge.to, edge.kind);
    }

    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    engine.seed_sources(None);
    engine.run();

    println!("Tainted Facts:");
    for fact in &engine.tainted_facts {
        println!("  node={}, var={}", fact.node_id, fact.var);
    }

    println!("Suppressed Flows:");
    for f in &engine.suppressed_flows {
        println!(
            "  node={}, var={}, reason={}",
            f.sink_node_id, f.sink_var, f.reason
        );
    }

    println!("Flows detected: {}", engine.flows.len());
    for flow in &engine.flows {
        println!(
            "  Flow CWE: {:?}, sink_node: {}, sink_var: {}",
            flow.cwe, flow.sink_node_id, flow.sink_var
        );
    }
}
