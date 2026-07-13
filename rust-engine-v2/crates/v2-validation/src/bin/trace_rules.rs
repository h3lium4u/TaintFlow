use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use v2_frontend_base::LanguageFrontend;

#[derive(Deserialize, Clone)]
struct OwaspEntry {
    test_id: String,
    code: String,
    vulnerable: bool,
    language: String,
    cwe: String,
}

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let owasp_java_path = base_dir.join("benchmarks/benchmark_java.jsonl");

    let file = File::open(&owasp_java_path).unwrap();
    let reader = BufReader::new(file);

    let mut entries = HashMap::new();
    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
            if entry.language == "java" {
                entries.insert(entry.test_id.clone(), entry);
            }
        }
    }

    let targets = vec![
        ("BenchmarkTest00024", "PreparedStatement.execute()"),
        ("BenchmarkTest00018", "Statement.executeQuery()"),
        ("BenchmarkTest00007", "Runtime.exec()"),
        ("BenchmarkTest00006", "ProcessBuilder.start()"),
    ];

    let registry = v2_rulepacks::full_registry();

    for (test_id, api) in targets {
        let entry = entries.get(test_id).unwrap();
        println!("\n=== Target: {} ({}) ===", test_id, api);
        
        let frontend = v2_frontend_java::JavaFrontend;
        let semantic = v2_semantic::SemanticInfo::new();
        let program = frontend.lower(&entry.code, &semantic, Path::new("App.java")).unwrap();
        
        for method in program.methods.values() {
            if method.name == "doGet" || method.name == "doPost" || method.name == "run" {
                println!("  Method '{}':", method.name);
                for inst_id in &method.body {
                    if let Some(inst) = program.instructions.get(inst_id) {
                        if let v2_ir::InstructionKind::Call { dest, callee, args } = &inst.kind {
                            println!("    Call {{ dest: {:?}, callee: {:?}, args: {:?} }}", dest, callee, args);
                            
                            let is_src = registry.is_source(callee);
                            let is_sink = registry.is_sink(callee);
                            let is_san = registry.is_sanitizer(callee);
                            let is_prop = registry.is_propagator(callee);
                            
                            println!("      Rules check for callee '{}':", callee);
                            println!("        Is Source    : {}", is_src);
                            println!("        Is Sink      : {}", is_sink);
                            println!("        Is Sanitizer : {}", is_san);
                            println!("        Is Propagator: {}", is_prop);
                        }
                    }
                }
            }
        }
    }
}
