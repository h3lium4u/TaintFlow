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
    let dir = std::env::temp_dir().join(format!("v2_fp_analysis_{}_{}", tag, std::process::id()));
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

    let mut non_vulnerable_entries = Vec::new();
    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
            if !entry.vulnerable && entry.language == "java" {
                non_vulnerable_entries.push(entry);
            }
        }
    }

    println!("Total non-vulnerable Java samples loaded: {}", non_vulnerable_entries.len());

    let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());
    let mut fps = Vec::new();

    // Scan for FPs
    for entry in non_vulnerable_entries {
        let dir = temp_workspace("fp_eval");
        let file_name = format!("{}.java", entry.test_id);
        fs::write(dir.join(&file_name), &entry.code).unwrap();

        let res = engine.run(&dir);
        if res.success && !res.findings.is_empty() {
            fps.push((entry.clone(), res.findings));
        }

        let _ = fs::remove_dir_all(&dir);

        // Collect at least 110 cases to ensure we have a statistically robust sample > 100
        if fps.len() >= 110 {
            break;
        }
    }

    println!("Identified {} False Positive cases.", fps.len());

    let mut cause_counts = HashMap::new();
    let mut pattern_counts = HashMap::new();
    let mut detailed_records = Vec::new();

    for (idx, (entry, findings)) in fps.iter().take(105).enumerate() {
        let code = &entry.code;
        let cwe = &entry.cwe;
        
        let mut cause = "K Other"; // default
        let mut pattern = "other";

        // Determine why it's considered vulnerable by inspecting the generated findings
        let first_finding = &findings[0];
        let sink_rule_id = &first_finding.rule.rule_id;
        let sink_name = &first_finding.rule.rule_name;

        // Classify the cause
        if sink_name.contains("println") || sink_name.contains("print") {
            // PrintWriter.println or print used in safe XSS echoing
            cause = "C Overly Generic Sink";
            pattern = "PrintWriter.println XSS";
        } else if code.contains("org.owasp.esapi.ESAPI.encoder().encodeForHTML") 
            || code.contains("org.owasp.benchmark.helpers.Utils.encodeForHTML")
            || code.contains("StringEscapeUtils.escapeHtml") {
            // The code is sanitized but the engine is missing the sanitizer rule
            cause = "A Missing Sanitizer";
            pattern = "Missing HTML/SQL Sanitizer Rule";
        } else if sink_rule_id.contains("cmd-007") || sink_rule_id.contains("core-sink-002") {
            // Command injection sink matched for safe commands
            cause = "C Overly Generic Sink";
            pattern = "Runtime.exec Command Injection";
        } else {
            // Check for path condition / branch sensitivity
            let has_if = code.contains("if (") || code.contains("else if");
            if has_if {
                cause = "D Missing Path Condition";
                pattern = "Missing conditional check / branch sensitivity";
            }
        }

        *cause_counts.entry(cause.to_string()).or_insert(0) += 1;
        *pattern_counts.entry(pattern.to_string()).or_insert(0) += 1;

        detailed_records.push((
            entry.test_id.clone(),
            cwe.clone(),
            cause.to_string(),
            pattern.to_string(),
            sink_name.clone(),
        ));
    }

    println!("\n=== Earliest Cause Distribution (N = 105 analyzed FPs) ===");
    for (cause, count) in &cause_counts {
        println!("{:.<35} {}", cause, count);
    }

    println!("\n=== Code Pattern Clustering ===");
    for (pat, count) in &pattern_counts {
        println!("{:.<35} {}", pat, count);
    }

    println!("\n=== First 100 False Positive Case Details ===");
    for (idx, (test_id, cwe, cause, pattern, sink_name)) in detailed_records.iter().take(100).enumerate() {
        println!(
            "{}: ID={} | CWE={} | Cause={} | Pattern={} | Sink={}",
            idx + 1, test_id, cwe, cause, pattern, sink_name
        );
    }
}
