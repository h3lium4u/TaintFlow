use cfg::icfg::InterproceduralCFG;
use std::fs::File;
use std::io::{BufRead, BufReader};
use symbols::call_graph::CallGraph;
use taint::InterproceduralTaintEngine;
use v2_refiner_domain::PathRefiner;

fn main() {
    let dataset_path = std::path::Path::new("d:/V2 Backup/benchmarks/benchmark_java.jsonl");
    let file = File::open(&dataset_path).unwrap();
    let reader = BufReader::new(file);
    let mut code_opt = None;
    for line in reader.lines() {
        let l = line.unwrap();
        if l.contains("BenchmarkTest00602") {
            let entry: serde_json::Value = serde_json::from_str(&l).unwrap();
            code_opt = Some(entry["code"].as_str().unwrap().to_string());
            break;
        }
    }
    let code = code_opt.expect("Expected BenchmarkTest00602 to exist");

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "Test_CWE_89.java".to_string();

    gst.load_file(&mut program, &code, &filename, &"java")
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    let facts = v2_export_adapter::Exporter::export(&engine);
    let refinements = PathRefiner::refine_paths(&facts);

    println!("=== REFINEMENTS FOR 00602 ===");
    for (i, refi) in refinements.iter().enumerate() {
        let flow = &facts.taint_flows[refi.flow_index];
        println!(
            "Refinement {}: flow_index={}, source_var={}, sink_var={}, status={:?}, reason={}",
            i, refi.flow_index, flow.source_var, flow.sink_var, refi.status, refi.reason
        );
    }
}
