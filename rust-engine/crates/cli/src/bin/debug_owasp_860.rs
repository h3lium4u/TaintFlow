use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn main() {
    let dataset_path = Path::new("d:/V2 Backup/benchmarks/benchmark_java.jsonl");
    let file = File::open(&dataset_path).unwrap();
    let reader = BufReader::new(file);
    let mut code_opt = None;
    for line in reader.lines() {
        let l = line.unwrap();
        if l.contains("BenchmarkTest00860") {
            let entry: serde_json::Value = serde_json::from_str(&l).unwrap();
            code_opt = Some(entry["code"].as_str().unwrap().to_string());
            break;
        }
    }

    let code = code_opt.expect("Expected BenchmarkTest00860 to exist");

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "Test_CWE_90.java".to_string();
    let language = "java".to_string();

    gst.load_file(&mut program, &code, &filename, &language)
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    let facts = v2_export_adapter::Exporter::export(&engine);

    // Run SsaBuilder on the doPost method manually
    let method = program
        .methods
        .values()
        .find(|m| m.name == "doPost")
        .unwrap();
    let cfg = v2_refiner_domain::CfgBuilder::build(&program, method);
    let ssa_builder = v2_refiner_domain::SsaBuilder::new(&program, method, &cfg);
    let ssa = ssa_builder.build();

    // Reconstruct collection states just like PathRefiner
    // (Here we manually call the PathRefiner::refine_paths to trigger the evaluation)
    let refinements = v2_refiner_domain::PathRefiner::refine_paths(&facts);
}
