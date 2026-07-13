use serde::Deserialize;
use std::collections::HashSet;
use std::fs;

#[derive(Deserialize)]
struct OwaspEntry {
    test_id: String,
    code: String,
    vulnerable: bool,
    cwe: String,
}

fn main() {
    let owasp_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(owasp_path).expect("Could not read benchmark file");

    let mut vuln_samples = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: OwaspEntry = serde_json::from_str(line).expect("JSON parse error");
        if entry.vulnerable {
            vuln_samples.push(entry);
        }
    }

    println!("Total vulnerable: {}", vuln_samples.len());
    let mut fn_count = 0;

    // We will run the taint engine + semantic rule checks on each vulnerable sample.
    // If neither reports correct CWE target, it is an FN!
    for entry in &vuln_samples {
        let mut program = ir::Program::new();
        let mut gst = symbols::global::GlobalSymbolTable::new();
        let filename = format!("{}.java", entry.test_id);
        program
            .source_files
            .insert(filename.clone(), entry.code.clone());

        if let Err(_) = gst.load_file(&mut program, &entry.code, &filename, &"java".to_string()) {
            continue;
        }
        gst.resolve_inheritance_hierarchy();
        let cg = symbols::call_graph::CallGraph::build(&program, &gst);
        let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

        // 1. Check Semantic Rules
        let semantic_violations = semantic_rules::scan_semantic_violations(&program, "java");
        let target_cwe_str = format!("CWE-{}", entry.cwe.replace("CWE-", ""));
        let mut detected = semantic_violations
            .iter()
            .any(|c| c.replace("CWE-", "") == entry.cwe.replace("CWE-", ""));

        // 2. Check Taint Flow
        if !detected {
            let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
            engine.target_file = Some(filename.clone());
            engine.seed_sources(None);
            engine.run();

            for flow in &engine.flows {
                let flow_cwe_str = format!("{:?}", flow.cwe).replace("CWE", "CWE-");
                if flow_cwe_str == target_cwe_str {
                    detected = true;
                    break;
                }
            }
        }

        if !detected {
            fn_count += 1;
            println!(
                "FN {}: test_id={}, expected_cwe={}",
                fn_count, entry.test_id, entry.cwe
            );
        }
    }

    println!("Total FNs identified: {}", fn_count);
}
