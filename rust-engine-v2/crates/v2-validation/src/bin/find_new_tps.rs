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
    let dir = std::env::temp_dir().join(format!("v2_tp_check_{}_{}", test_id, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let owasp_java_path = base_dir.join("benchmarks/benchmark_java.jsonl");

    let file = File::open(&owasp_java_path).unwrap();
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
            if entry.language == "java" && entry.vulnerable && (entry.cwe == "CWE-89" || entry.cwe == "CWE-78") {
                entries.push(entry);
            }
        }
    }

    let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());

    println!("Scanning {} vulnerable Java SQL/CMD testcases for active findings...", entries.len());
    let mut new_tps = Vec::new();

    for entry in entries {
        let dir = temp_workspace(&entry.test_id);
        let file_name = "App.java";
        fs::write(dir.join(file_name), &entry.code).unwrap();
        
        let res = engine.run(&dir);
        if !res.findings.is_empty() {
            // Find if any of the findings match the SQL/Command injection rules we added
            for f in &res.findings {
                if f.rule.rule_id == "db-sqli-005" || f.rule.rule_id == "db-sqli-006" || f.rule.rule_id == "db-sqli-007" || f.rule.rule_id == "cmd-007" || f.rule.rule_id == "cmd-008" {
                    new_tps.push((entry.test_id.clone(), entry.cwe.clone(), f.rule.rule_id.clone()));
                    break;
                }
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    println!("\n=== New TPs Gained (Total: {}) ===", new_tps.len());
    for (test_id, cwe, rule_id) in &new_tps {
        println!("- ID: {} | CWE: {} | Rule: {}", test_id, cwe, rule_id);
    }
}
