use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let owasp_path = base_dir.join("benchmarks/benchmark_python.jsonl");

    let file = File::open(&owasp_path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let sample: serde_json::Value = serde_json::from_str(&line).unwrap();
        let code = sample.get("code").and_then(|v| v.as_str()).unwrap_or("");

        if code.contains("BenchmarkTest00168") {
            println!("=== FOUND BenchmarkTest00168 ===");
            let mut program = ir::Program::new();
            let mut gst = symbols::global::GlobalSymbolTable::new();
            
            if gst.load_file(&mut program, code, "BenchmarkTest00168_python.py", "python").is_ok() {
                gst.resolve_inheritance_hierarchy();
                println!("Instructions:");
                for (id, inst) in &program.instructions {
                    println!("  ID: {:?}, Kind: {:?}", id, inst.kind);
                }
            }
            break;
        }
    }
}
