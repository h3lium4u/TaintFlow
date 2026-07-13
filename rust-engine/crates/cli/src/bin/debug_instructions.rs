use std::fs;

fn main() {
    let java_bench_path = "d:/V2 Backup/benchmarks/benchmark_java.jsonl";
    let content = fs::read_to_string(java_bench_path).unwrap();
    let mut code = String::new();
    for line in content.lines() {
        if line.contains("BenchmarkTest01205") {
            let data: serde_json::Value = serde_json::from_str(line).unwrap();
            code = data.get("code").unwrap().as_str().unwrap().to_string();
            break;
        }
    }

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "Test.java".to_string();
    program.source_files.insert(filename.clone(), code.clone());

    gst.load_file(&mut program, &code, &filename, &"java".to_string())
        .unwrap();

    println!("=== Program Instructions ===");
    for (id, inst) in &program.instructions {
        println!("  InstructionId({:?}): {:?}", id.0, inst.kind);
    }
}
