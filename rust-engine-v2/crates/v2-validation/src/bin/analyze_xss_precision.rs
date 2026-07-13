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

fn temp_workspace(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("v2_xss_precision_{}_{}", tag, std::process::id()));
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
            if entry.language == "java" {
                entries.push(entry);
            }
        }
    }

    println!("Total Java samples loaded: {}", entries.len());

    let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());
    let mut println_findings = Vec::new();

    for entry in entries {
        let dir = temp_workspace("xss_eval");
        let file_name = format!("{}.java", entry.test_id);
        fs::write(dir.join(&file_name), &entry.code).unwrap();

        let res = engine.run(&dir);
        if res.success {
            for finding in res.findings {
                if finding.rule.rule_name.contains("PrintWriter.println") {
                    println_findings.push((entry.clone(), finding));
                }
            }
        }

        let _ = fs::remove_dir_all(&dir);

        if println_findings.len() >= 120 {
            break;
        }
    }

    println!("Collected {} PrintWriter.println findings.", println_findings.len());

    let mut classifications = HashMap::new();
    let mut detailed_list = Vec::new();

    for (idx, (entry, finding)) in println_findings.iter().take(105).enumerate() {
        let code = &entry.code;
        let cwe = &entry.cwe;
        let is_vulnerable = entry.vulnerable;

        // 1. Is the value reaching println tainted? (Always true since engine flagged it)
        let is_tainted = true;

        // 2. Is it written to actual HttpServletResponse writer?
        let is_http_response = code.contains("response.getWriter()");

        // 3. Is the output HTML, plain text, or another context?
        let is_html = code.contains("text/html");
        let context = if is_html { "HTML" } else { "Plain Text/Unknown" };

        // 4. Is any encoding or sanitization applied before the sink?
        let is_sanitized = code.contains("encodeForHTML") || code.contains("escapeHtml") || code.contains("encodeForSQL");

        // 5. Is the benchmark expected to be vulnerable for XSS?
        let is_xss_target = cwe == "CWE-79";

        // Classify each finding
        let category = if is_xss_target && is_vulnerable {
            "A. Genuine XSS"
        } else if is_sanitized {
            "D. Sanitized output"
        } else if is_xss_target && !is_vulnerable {
            "B. Benign echo"
        } else if !is_xss_target && is_vulnerable {
            "E. Benchmark non-target CWE but technically exploitable"
        } else {
            "C. Constant/debug output"
        };

        *classifications.entry(category.to_string()).or_insert(0) += 1;

        detailed_list.push((
            entry.test_id.clone(),
            cwe.clone(),
            is_vulnerable,
            is_tainted,
            is_http_response,
            context.to_string(),
            is_sanitized,
            is_xss_target,
            category.to_string(),
        ));
    }

    println!("\n=== Category Distribution ===");
    for (cat, count) in &classifications {
        let pct = (*count as f64 / 105.0) * 100.0;
        println!("{:.<60} {} ({:.2}%)", cat, count, pct);
    }

    println!("\n=== Detailed Validation Cases ===");
    for (idx, (test_id, cwe, vuln, tainted, response_writer, context, sanitized, xss_tgt, category)) in detailed_list.iter().take(100).enumerate() {
        println!(
            "{}: ID={} | Target_CWE={} | Vuln={} | Tainted={} | HttpResp={} | Context={} | Sanitized={} | XSS_Tgt={} | Classification={}",
            idx + 1, test_id, cwe, vuln, tainted, response_writer, context, sanitized, xss_tgt, category
        );
    }
}
