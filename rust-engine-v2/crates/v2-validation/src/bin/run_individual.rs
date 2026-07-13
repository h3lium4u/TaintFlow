use serde::Deserialize;
use std::collections::HashMap;
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

fn temp_workspace(test_id: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("v2_test_{}_{}", test_id, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
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
        "BenchmarkTest00006",
        "BenchmarkTest00015",
        "BenchmarkTest00024",
        "BenchmarkTest00293",
        "BenchmarkTest00480",
    ];

    let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());

    for test_id in targets {
        println!("\n=== Running Flow Analysis for: {} ===", test_id);
        let entry = entries.get(test_id).unwrap();
        
        let dir = temp_workspace(test_id);
        let file_path = dir.join(format!("{}.java", test_id));
        fs::write(&file_path, &entry.code).unwrap();
        
        let res = engine.run(&dir);
        
        println!("  Vulnerable expected: {}", entry.vulnerable);
        println!("  Findings generated  : {}", res.findings.len());
        for f in &res.findings {
            println!(
                "    Finding: rule={}, cwe={:?}, file={}, line={:?}",
                f.rule.rule_id, f.rule.cwe, f.sink.file, f.sink.line
            );
        }
        
        let _ = fs::remove_dir_all(&dir);
    }
}
