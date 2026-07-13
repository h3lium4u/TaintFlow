use serde::Deserialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use v2_engine::{AnalysisConfiguration, RepositoryAnalysisEngine};

#[derive(Deserialize, Clone)]
struct OwaspEntry {
    test_id: String,
    code: String,
    vulnerable: bool,
    language: String,
    cwe: String,
}

fn temp_workspace(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("v2_diag_{}_{}", tag, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let owasp_java_path = base_dir.join("benchmarks/benchmark_java.jsonl");

    if !owasp_java_path.exists() {
        println!("Error: benchmark_java.jsonl not found!");
        return;
    }

    let file = File::open(&owasp_java_path).unwrap();
    let reader = BufReader::new(file);

    let targets = vec![
        "BenchmarkTest00001",
        "BenchmarkTest00002",
        "BenchmarkTest00003",
        "BenchmarkTest00004",
        "BenchmarkTest00005",
        "BenchmarkTest00011",
    ];
    let mut found_targets = std::collections::HashMap::new();

    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
            for target in &targets {
                if entry.code.contains(target) {
                    found_targets.insert(target.to_string(), entry);
                    break;
                }
            }
        }
    }

    for target in targets {
        println!("====================================================");
        println!("Analyzing Target: {}", target);
        println!("====================================================");

        if let Some(entry) = found_targets.get(target) {
            let dir = temp_workspace("diag");
            let file_name = format!("{}.java", target);
            fs::write(dir.join(&file_name), &entry.code).unwrap();

            println!("\n--- [1] Original Source Code ---");
            println!("{}", entry.code.trim());

            println!("\n--- [2] Reconstructed Logical Statements ---");
            // Lower via frontend manually to show logical lines
            use v2_frontend_base::LanguageFrontend;
            use v2_frontend_java::JavaFrontend;
            let frontend = JavaFrontend;
            let program = frontend.lower(&entry.code, &v2_semantic::SemanticInfo::new(), &dir.join(&file_name)).unwrap();

            // We can re-run preprocess_java directly to print them
            // Let's call preprocess_java if we make it public or simulate it here.
            // Actually, we can make preprocess_java public or just call it directly in the test since we are in the same crate, 
            // but run_diagnostics is in v2-validation which depends on v2-frontend-java, but preprocess_java is private.
            // Let's look at the generated program to see if method bodies are complete.
            println!("\n--- [3] Generated Program IR ---");
            for (mid, method) in &program.methods {
                println!("Method: {} (id: {:?})", method.name, mid);
                for inst_id in &method.body {
                    if let Some(inst) = program.instructions.get(inst_id) {
                        println!("  inst {:?}: {:?}", inst_id, inst.kind);
                    }
                }
            }

            println!("\n--- [4] Generated CFG / ICFG Nodes ---");
            let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());
            let res = engine.run(&dir);

            println!("Analysis Success: {}", res.success);
            println!("Findings Count: {}", res.findings.len());

            println!("\n--- [5] Generated Findings ---");
            println!("{}", serde_json::to_string_pretty(&res.findings).unwrap());

            let _ = fs::remove_dir_all(&dir);
        } else {
            println!("Error: Target {} not found!", target);
        }
    }
}
