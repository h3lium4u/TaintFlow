use std::fs::File;
use std::io::{BufRead, BufReader};
use symbols::global::GlobalSymbolTable;
use ir::Program;

fn main() {
    let dataset_path = "D:/V2 Backup/benchmarks/benchmark_python.jsonl";
    let file = File::open(dataset_path).unwrap();
    let reader = BufReader::new(file);
    
    let mut code_to_load = String::new();
    for line in reader.lines() {
        if let Ok(line_str) = line {
            if line_str.contains("BenchmarkTest00172") {
                let obj: serde_json::Value = serde_json::from_str(&line_str).unwrap();
                code_to_load = obj["code"].as_str().unwrap().to_string();
                break;
            }
        }
    }
    
    if code_to_load.is_empty() {
        println!("BenchmarkTest00172 code not found!");
        return;
    }
    
    let mut gst = GlobalSymbolTable::new();
    let mut program = Program::new();
    gst.load_file(&mut program, &code_to_load, "test.py", "python").unwrap();
    
    println!("=== Loaded Python Methods ===");
    for (mid, method) in &program.methods {
        println!("MethodId: {:?} | Name: {} | Parameters: {:?}", mid, method.name, method.parameters);
    }
}
