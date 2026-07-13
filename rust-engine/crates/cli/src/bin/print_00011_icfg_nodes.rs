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

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "test.py".to_string();
    program.source_files.insert(filename.clone(), code.clone());
    gst.load_file(&mut program, &code, &filename, &"java".to_string())
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    for (id, node) in &icfg.nodes {
        println!(
            "Node {}: inst={:?}",
            id,
            node.instruction_id.map(|inst_id| program
                .instructions
                .get(&inst_id)
                .unwrap()
                .kind
                .clone())
        );
    }
}
