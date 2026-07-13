use symbols::global::GlobalSymbolTable;
use ir::Program;
use symbols::call_graph::CallGraph;
use cfg::icfg::InterproceduralCFG;

fn main() {
    let base_dir = std::path::Path::new("d:/V2 Backup");
    let owasp_py_path = base_dir.join("benchmarks/benchmark_python.jsonl");
    let file = std::fs::File::open(&owasp_py_path).unwrap();
    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;
    
    let mut target_code = String::new();
    for line in reader.lines() {
        if let Ok(line_str) = line {
            if line_str.contains("BenchmarkTest00353") && !line_str.contains("vulnerable\":false") {
                let entry: serde_json::Value = serde_json::from_str(&line_str).unwrap();
                target_code = entry["code"].as_str().unwrap().to_string();
                break;
            }
        }
    }
    
    let mut gst = GlobalSymbolTable::new();
    let mut program = Program::new();
    gst.load_file(&mut program, &target_code, "test.py", "python").unwrap();
    gst.resolve_inheritance_hierarchy();
    
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);
    
    println!("=== ICFG Edges ===");
    for edge in &icfg.edges {
        if edge.from == 61 || edge.to == 61 || edge.from == 60 || edge.to == 60 {
            println!("Edge: {} -> {} ({:?})", edge.from, edge.to, edge.kind);
        }
    }
}
