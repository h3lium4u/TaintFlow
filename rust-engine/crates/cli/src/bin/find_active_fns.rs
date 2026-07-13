use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

#[derive(serde::Deserialize)]
struct Sample {
    code: String,
    cwe: String,
    dataset: String,
    language: String,
}

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let baseline_path = base_dir.join("scratch/v2_fns_baseline.json");

    let file = File::open(&baseline_path).unwrap();
    let reader = BufReader::new(file);
    let samples: Vec<Sample> = serde_json::from_reader(reader).unwrap();

    println!("Total baseline samples to check: {}", samples.len());

    let mut active_fns = Vec::new();

    // Setup engine dependencies minimally
    for sample in samples {
        // Extract class name
        let class_name = if let Some(idx) = sample.code.find("public class BenchmarkTest") {
            let start = idx + "public class ".len();
            let end = sample.code[start..].find(" ").unwrap() + start;
            sample.code[start..end].trim().to_string()
        } else {
            continue;
        };

        // We run a fast manual taint evaluation or check if we can call the solver.
        // To be fast, we compile program and gst
        let mut program = ir::Program::new();
        let mut gst = symbols::global::GlobalSymbolTable::new();
        let filename = format!("{}.java", class_name);
        
        if gst.load_file(&mut program, &sample.code, &filename, &sample.language).is_ok() {
            gst.resolve_inheritance_hierarchy();
            let cg = symbols::call_graph::CallGraph::build(&program, &gst);
            let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
            let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
            engine.seed_sources(None);
            engine.run();

            // Check if a flow to target CWE was found
            let target_cwe = match sample.cwe.as_str() {
                "CWE-22" => taint::CWE::CWE22,
                "CWE-78" => taint::CWE::CWE78,
                "CWE-79" => taint::CWE::CWE79,
                "CWE-89" => taint::CWE::CWE89,
                "CWE-90" => taint::CWE::CWE90,
                "CWE-113" => taint::CWE::CWE113,
                "CWE-327" => taint::CWE::CWE327,
                "CWE-328" => taint::CWE::CWE328,
                "CWE-502" => taint::CWE::CWE502,
                "CWE-614" => taint::CWE::CWE614,
                "CWE-918" => taint::CWE::CWE918,
                _ => continue,
            };

            let has_matching_flow = engine.flows.iter().any(|flow| flow.cwe == target_cwe);
            if !has_matching_flow {
                active_fns.push((class_name, sample.cwe));
            }
        }
    }

    println!("=== ACTIVE FNs ({}) ===", active_fns.len());
    for (id, cwe) in active_fns {
        println!("  {} ({})", id, cwe);
    }
}
