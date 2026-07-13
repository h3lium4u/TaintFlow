use std::fs;
use std::collections::HashMap;

fn main() {
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let python_bench_path = "d:/V2 Backup/benchmarks/benchmark_python.jsonl";
    
    // We want to map (cwe, nodes, edges) -> Vec<Class Name/Test ID>
    let mut size_to_bench: HashMap<(String, usize, usize), Vec<String>> = HashMap::new();
    
    for (path, lang) in &[(java_bench_path, "java"), (python_bench_path, "python")] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if line.is_empty() {
                    continue;
                }
                let data: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let code = data.get("code").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let cwe = data.get("cwe").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let vulnerable = data.get("vulnerable").and_then(|v| v.as_bool()).unwrap_or(false);
                
                // Parse benchmark ID from code
                let mut test_id = "unknown".to_string();
                if let Some(pos) = code.find("BenchmarkTest") {
                    let start = pos;
                    let end = code[start..].find(|c: char| !c.is_numeric() && !c.is_alphabetic())
                        .map(|idx| start + idx)
                        .unwrap_or(code.len());
                    // Clean up suffix like _get or _post if any
                    let candidate = code[start..end].to_string();
                    if let Some(pos_under) = candidate.find('_') {
                        test_id = candidate[..pos_under].to_string();
                    } else {
                        test_id = candidate;
                    }
                }
                
                if vulnerable {
                    let mut program = ir::Program::new();
                    let mut gst = symbols::global::GlobalSymbolTable::new();
                    let filename = if *lang == "java" { "Test.java" } else { "test.py" }.to_string();
                    program.source_files.insert(filename.clone(), code.clone());
                    
                    if gst.load_file(&mut program, &code, &filename, &lang.to_string()).is_ok() {
                        gst.resolve_inheritance_hierarchy();
                        let cg = symbols::call_graph::CallGraph::build(&program, &gst);
                        let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
                        
                        size_to_bench.entry((cwe.clone(), icfg.nodes.len(), icfg.edges.len()))
                            .or_insert_with(Vec::new)
                            .push(test_id);
                    }
                }
            }
        }
    }
    
    // Print all non-CWE-22 FNs in the baseline log that we want to map:
    let targets = vec![
        ("CWE-328", 85, 92),
        ("CWE-328", 96, 103),
        ("CWE-327", 67, 73),
        ("CWE-328", 59, 63),
        ("CWE-327", 80, 88),
        ("CWE-328", 90, 98),
        ("CWE-328", 73, 79),
        ("CWE-327", 84, 91),
        ("CWE-328", 65, 71),
        ("CWE-327", 94, 102),
        ("CWE-327", 93, 99),
        ("CWE-327", 69, 75),
        ("CWE-328", 89, 97),
        ("CWE-78", 69, 64),
        ("CWE-78", 77, 73),
        ("CWE-89", 82, 81),
        ("CWE-78", 68, 63),
        ("CWE-78", 76, 73),
    ];
    
    for (cwe, nodes, edges) in targets {
        if let Some(candidates) = size_to_bench.get(&(cwe.to_string(), nodes, edges)) {
            println!("Target ({}, nodes={}, edges={}) -> Candidates: {:?}", cwe, nodes, edges, candidates);
        } else {
            // Try matching with small delta (e.g. edge difference of 1 due to virtual __init__.py or siblings)
            let mut matches = Vec::new();
            for (&(ref k_cwe, k_n, k_e), val) in &size_to_bench {
                if k_cwe == cwe && k_n == nodes && (k_e as isize - edges as isize).abs() <= 2 {
                    matches.extend(val.clone());
                }
            }
            println!("Target ({}, nodes={}, edges={}) -> Near Matches: {:?}", cwe, nodes, edges, matches);
        }
    }
}
