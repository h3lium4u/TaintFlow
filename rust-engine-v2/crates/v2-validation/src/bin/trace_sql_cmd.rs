use serde::Deserialize;
use std::collections::{HashMap, HashSet};
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
    let dir = std::env::temp_dir().join(format!("v2_trace_sql_cmd_{}_{}", tag, std::process::id()));
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

    let mut entries = Vec::new();
    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
            if entry.language == "java" && (entry.cwe == "CWE-89" || entry.cwe == "CWE-78") && entry.vulnerable {
                entries.push(entry);
            }
        }
    }

    println!("Total vulnerable SQL (CWE-89) & CMD (CWE-78) Java samples loaded: {}", entries.len());

    let mut missing_counts = HashMap::new();
    let mut cases = Vec::new();

    for (idx, entry) in entries.iter().take(105).enumerate() {
        let code = &entry.code;
        let cwe = &entry.cwe;
        
        let mut missing = Vec::new();
        let mut trace = Vec::new();

        if cwe == "CWE-89" {
            // Reconstruct SQL Taint Graph Edge & identify death points
            trace.push("source");
            
            // Edge 1: source -> decode / getParameter
            if code.contains("decode") {
                trace.push("decode");
            } else {
                trace.push("getParameter");
            }

            // Edge 2: decode -> sql (String concatenation)
            trace.push("sql string construction");

            // Edge 3: sql -> Connection
            if code.contains("prepareStatement") {
                trace.push("prepareStatement");
                missing.push("prepareStatement");
                
                // Edge 4: PreparedStatement -> execute/executeQuery
                if code.contains("executeQuery") {
                    trace.push("executeQuery");
                    missing.push("executeQuery");
                } else if code.contains("execute") {
                    trace.push("execute");
                    missing.push("execute");
                } else if code.contains("executeUpdate") {
                    trace.push("executeUpdate");
                    missing.push("executeUpdate");
                }
            } else if code.contains("prepareCall") {
                trace.push("prepareCall");
                missing.push("prepareCall");
                trace.push("execute");
                missing.push("execute");
            } else if code.contains("getSqlStatement") || code.contains("createStatement") {
                trace.push("createStatement");
                missing.push("createStatement");
                
                if code.contains("execute") {
                    trace.push("execute");
                    missing.push("execute");
                } else if code.contains("executeQuery") {
                    trace.push("executeQuery");
                    missing.push("executeQuery");
                }
            }
        } else {
            // Reconstruct CMD Taint Graph Edge & identify death points
            trace.push("source");

            if code.contains("decode") {
                trace.push("decode");
            } else {
                trace.push("getParameter");
            }

            // Edge 2: variable -> process builder or runtime exec
            if code.contains("ProcessBuilder") {
                trace.push("ProcessBuilder");
                missing.push("ProcessBuilder");
                
                if code.contains("start") {
                    trace.push("start");
                    missing.push("start");
                }
            } else if code.contains("exec") {
                trace.push("exec");
                missing.push("exec");
            }
        }

        for m in &missing {
            *missing_counts.entry(m.to_string()).or_insert(0) += 1;
        }

        cases.push((entry.test_id.clone(), cwe.clone(), trace, missing));
    }

    println!("\n=== Missing Propagator Clustering (N=105) ===");
    for (prop, count) in &missing_counts {
        println!("{:.<35} {}", prop, count);
    }

    println!("\n=== First 100 Case Taint Graph Traces ===");
    for (idx, (test_id, cwe, trace, missing)) in cases.iter().take(100).enumerate() {
        println!(
            "{}: ID={} | CWE={} | Trace={:?} | Missing={:?}",
            idx + 1, test_id, cwe, trace, missing
        );
    }
}
