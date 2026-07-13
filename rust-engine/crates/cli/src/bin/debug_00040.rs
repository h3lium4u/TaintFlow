use std::collections::{HashMap, HashSet};
use std::fs;

fn main() {
    let target_test_id = "BenchmarkTest00455";
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

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = format!("{}.java", target_test_id);
    program.source_files.insert(filename.clone(), code.clone());

    gst.load_file(&mut program, &code, &filename, &"java".to_string())
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.clone());
    engine.seed_sources(None);

    println!("=== Seed sources count: {} ===", engine.tainted_facts.len());
    for fact in &engine.tainted_facts {
        println!("  Seed: node={}, var={}", fact.node_id, fact.var);
    }

    engine.run();
    println!("=== All Tainted Facts at End ===");
    for fact in &engine.tainted_facts {
        let node = icfg.nodes.get(&fact.node_id).unwrap();
        let inst = node
            .instruction_id
            .and_then(|id| program.instructions.get(&id));
        println!(
            "  Fact: node={}, var={}, sanitized_for={:?}, inst={:?}",
            fact.node_id,
            fact.var,
            fact.sanitized_for,
            inst.map(|i| &i.kind)
        );
    }
}
