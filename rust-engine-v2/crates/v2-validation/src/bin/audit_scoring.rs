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
    let dir = std::env::temp_dir().join(format!("v2_audit_scoring_{}_{}", tag, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn map_finding_cwe(cwe_val: Option<u32>) -> String {
    if let Some(val) = cwe_val {
        format!("CWE-{}", val)
    } else {
        "CWE-unknown".to_string()
    }
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

    // We'll run the audit on the first 1000 samples to keep execution time reasonable (~1 minute)
    // while remaining highly representative.
    let total_samples = 1000;
    println!("Auditing first {} samples...", total_samples);

    let mut mat_a = (0, 0, 0, 0); // (tp, fp, tn, fn)
    let mut mat_b = (0, 0, 0, 0); // (tp, fp, tn, fn)
    let mut mat_c = (0, 0, 0, 0); // (tp, fp, tn, fn)

    let mut remaining_fps_c = Vec::new();

    for (idx, entry) in entries.iter().take(total_samples).enumerate() {
        let dir = temp_workspace("audit");
        let file_name = format!("{}.java", entry.test_id);
        fs::write(dir.join(&file_name), &entry.code).unwrap();

        let res = engine.run(&dir);
        let findings = if res.success { res.findings } else { Vec::new() };

        let _ = fs::remove_dir_all(&dir);

        let has_findings_any = !findings.is_empty();

        // 1. Matrix A: Current benchmark scoring (flags any finding as violation on clean cases)
        if has_findings_any {
            if entry.vulnerable {
                mat_a.0 += 1; // TP
            } else {
                mat_a.1 += 1; // FP
            }
        } else {
            if entry.vulnerable {
                mat_a.3 += 1; // FN
            } else {
                mat_a.2 += 1; // TN
            }
        }

        // 2. Matrix B: Filter findings by target CWE
        let mut has_matching_cwe_finding = false;
        for f in &findings {
            let fcwe = map_finding_cwe(f.rule.cwe);
            if fcwe == entry.cwe {
                has_matching_cwe_finding = true;
                break;
            }
        }

        if has_matching_cwe_finding {
            if entry.vulnerable {
                mat_b.0 += 1;
            } else {
                mat_b.1 += 1;
            }
        } else {
            if entry.vulnerable {
                mat_b.3 += 1;
            } else {
                mat_b.2 += 1;
            }
        }

        // 3. Matrix C: Filter by target CWE + apply sanitizers
        let is_sanitized = entry.code.contains("encodeForHTML") 
            || entry.code.contains("escapeHtml") 
            || entry.code.contains("encodeForSQL")
            || entry.code.contains("HTMLEntityEncode");

        let has_matching_unsanitized = has_matching_cwe_finding && !is_sanitized;

        if has_matching_unsanitized {
            if entry.vulnerable {
                mat_c.0 += 1;
            } else {
                mat_c.1 += 1;
                remaining_fps_c.push(entry.clone());
            }
        } else {
            if entry.vulnerable {
                mat_c.3 += 1;
            } else {
                mat_c.2 += 1;
            }
        }
    }

    println!("\n=== Matrix A (Current Baseline on N={}) ===", total_samples);
    println!("TP: {}, FP: {}, TN: {}, FN: {}", mat_a.0, mat_a.1, mat_a.2, mat_a.3);
    let prec_a = mat_a.0 as f64 / (mat_a.0 + mat_a.1) as f64;
    let rec_a = mat_a.0 as f64 / (mat_a.0 + mat_a.3) as f64;
    println!("Precision: {:.2}%, Recall: {:.2}%", prec_a * 100.0, rec_a * 100.0);

    println!("\n=== Matrix B (CWE-filtered on N={}) ===", total_samples);
    println!("TP: {}, FP: {}, TN: {}, FN: {}", mat_b.0, mat_b.1, mat_b.2, mat_b.3);
    let prec_b = mat_b.0 as f64 / (mat_b.0 + mat_b.1) as f64;
    let rec_b = mat_b.0 as f64 / (mat_b.0 + mat_b.3) as f64;
    println!("Precision: {:.2}%, Recall: {:.2}%", prec_b * 100.0, rec_b * 100.0);

    println!("\n=== Matrix C (CWE-filtered + Sanitizer-simulated on N={}) ===", total_samples);
    println!("TP: {}, FP: {}, TN: {}, FN: {}", mat_c.0, mat_c.1, mat_c.2, mat_c.3);
    let prec_c = mat_c.0 as f64 / (mat_c.0 + mat_c.1) as f64;
    let rec_c = mat_c.0 as f64 / (mat_c.0 + mat_c.3) as f64;
    println!("Precision: {:.2}%, Recall: {:.2}%", prec_c * 100.0, rec_c * 100.0);

    println!("\n=== Remaining False Positives under Matrix C ===");
    println!("Total remaining FPs: {}", remaining_fps_c.len());
    for (idx, fp) in remaining_fps_c.iter().take(10).enumerate() {
        println!("{}: ID={} | Target_CWE={}", idx + 1, fp.test_id, fp.cwe);
    }
}
