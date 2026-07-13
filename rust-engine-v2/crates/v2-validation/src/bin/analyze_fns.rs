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
    let dir = std::env::temp_dir().join(format!("v2_fn_analysis_{}_{}", tag, std::process::id()));
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

    let mut vulnerable_entries = Vec::new();
    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
            if entry.vulnerable && entry.language == "java" {
                vulnerable_entries.push(entry);
            }
        }
    }

    println!("Total vulnerable Java samples loaded: {}", vulnerable_entries.len());

    let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());
    let mut fns = Vec::new();

    // Find the first 120 FNs to ensure we have a safe margin of at least 100 FNs
    for entry in vulnerable_entries {
        let dir = temp_workspace("fn_eval");
        let file_name = format!("{}.java", entry.test_id);
        fs::write(dir.join(&file_name), &entry.code).unwrap();

        let res = engine.run(&dir);
        if res.success && res.findings.is_empty() {
            fns.push(entry.clone());
        }

        let _ = fs::remove_dir_all(&dir);

        if fns.len() >= 120 {
            break;
        }
    }

    println!("Identified {} actual False Negative cases.", fns.len());

    let mut stage_counts = HashMap::new();
    let mut pattern_counts = HashMap::new();
    let mut detailed_records = Vec::new();

    for (idx, entry) in fns.iter().take(105).enumerate() {
        let code = &entry.code;
        
        // Let's run heuristics to classify the earliest failure stage
        let mut stage = "O Validation"; // default
        let mut pattern = "other";

        // 1. Check if source is missing or unrecognised
        let has_get_parameter = code.contains("getParameter(");
        let has_get_header = code.contains("getHeader(");
        let has_get_headers = code.contains("getHeaders(");
        let has_get_cookies = code.contains("getCookies(");
        let has_get_query_string = code.contains("getQueryString(");
        
        let has_source = has_get_parameter || has_get_header || has_get_headers || has_get_cookies || has_get_query_string;

        // 2. Check if sink is missing or unrecognised
        let has_exec = code.contains("exec(") || code.contains("ProcessBuilder");
        let has_print = code.contains("println(") || code.contains("print(");
        let has_execute = code.contains("execute(") || code.contains("executeQuery(") || code.contains("executeUpdate(");
        let has_file_stream = code.contains("FileInputStream") || code.contains("FileReader");
        let has_ldap = code.contains("search(") && code.contains("DirContext");
        let has_xpath = code.contains("evaluate(") && code.contains("XPath");
        
        let has_sink = has_exec || has_print || has_execute || has_file_stream || has_ldap || has_xpath;

        // 3. Multi-line checks
        let has_multiline = code.lines().any(|l| {
            let t = l.trim();
            t.starts_with(".") && (t.contains("println") || t.contains("print") || t.contains("exec") || t.contains("execute"))
        });

        // 4. Split checks
        let has_multiple_equals = code.lines().any(|l| {
            let t = l.trim();
            t.contains("String sql =") && t.matches('=').count() >= 2
        });

        // 5. Ternary checks
        let has_ternary = code.lines().any(|l| {
            let t = l.trim();
            t.contains("?") && t.contains(":") && t.contains("=") && !t.contains("class ")
        });

        // Classification tree
        if !has_source {
            stage = "H Source Rules";
            if has_get_headers {
                pattern = "getHeaders() source missing";
            } else {
                pattern = "unsupported source API";
            }
        } else if !has_sink {
            stage = "M Sink Rules";
            if has_ldap {
                pattern = "LDAP search() sink missing";
            } else if has_xpath {
                pattern = "XPath evaluate() sink missing";
            } else {
                pattern = "unsupported sink API";
            }
        } else if has_multiline {
            stage = "D Java Frontend IR Lowering";
            pattern = "multi-line expression";
        } else if has_multiple_equals {
            stage = "D Java Frontend IR Lowering";
            pattern = "line.split('=') multiple equals";
        } else if has_ternary {
            stage = "D Java Frontend IR Lowering";
            pattern = "ternary assignment";
        } else {
            // Check for prepareStatement / prepareCall / nextElement / getValue propagator blockages
            let has_prep = code.contains("prepareStatement(") || code.contains("prepareCall(");
            let has_next = code.contains("nextElement(");
            let has_get_val = code.contains("getValue(");

            if has_prep {
                stage = "K Propagator Rules";
                pattern = "prepareStatement() / prepareCall()";
            } else if has_next {
                stage = "K Propagator Rules";
                pattern = "Enumeration.nextElement()";
            } else if has_get_val {
                stage = "K Propagator Rules";
                pattern = "Cookie.getValue()";
            } else {
                stage = "K Propagator Rules";
                pattern = "generic propagator blockage";
            }
        }

        *stage_counts.entry(stage.to_string()).or_insert(0) += 1;
        if stage == "D Java Frontend IR Lowering" || stage == "K Propagator Rules" || stage == "H Source Rules" || stage == "M Sink Rules" {
            *pattern_counts.entry(pattern.to_string()).or_insert(0) += 1;
        }

        detailed_records.push((entry.test_id.clone(), entry.cwe.clone(), stage.to_string(), pattern.to_string()));
    }

    println!("\n=== Earliest Failure Stage Distribution ===");
    for (stage, count) in &stage_counts {
        println!("{:.<35} {}", stage, count);
    }

    println!("\n=== Code Pattern Clustering (within top failure stages) ===");
    for (pat, count) in &pattern_counts {
        println!("{:.<35} {}", pat, count);
    }

    // Print detailed table of first 100 cases
    println!("\n=== First 100 Case Details ===");
    for (idx, (test_id, cwe, stage, pattern)) in detailed_records.iter().take(100).enumerate() {
        println!("{}: ID={} | CWE={} | Stage={} | Pattern={}", idx + 1, test_id, cwe, stage, pattern);
    }
}
