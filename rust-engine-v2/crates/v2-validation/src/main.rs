use serde::Deserialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use v2_engine::{AnalysisConfiguration, RepositoryAnalysisEngine};

#[derive(Deserialize)]
struct HoldoutEntry {
    before: String,
    after: String,
    language: String,
    repo: Option<String>,
    source: Option<String>,
}

#[derive(Deserialize)]
struct OwaspEntry {
    code: String,
    vulnerable: bool,
    language: String,
}

fn temp_workspace(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("v2_engine_val_{}_{}", tag, std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.contains(&"--repo".to_string()) {
        let repo_idx = args.iter().position(|r| r == "--repo").unwrap();
        let csv_idx = args.iter().position(|r| r == "--csv").unwrap();
        if repo_idx + 1 < args.len() && csv_idx + 1 < args.len() {
            let repo_path = Path::new(&args[repo_idx + 1]);
            let csv_path = Path::new(&args[csv_idx + 1]);
            println!("=== TaintFlow V2 Repository Validation Campaign ===");
            println!("Repository: {:?}", repo_path);
            println!("CSV Ground Truth: {:?}", csv_path);
            match v2_validation::ValidationSuite::validate_owasp_repository(repo_path, csv_path) {
                Ok(summary) => {
                    println!("\n=== Repository Validation Results ===");
                    println!("Repository Name        : {}", summary.repo_name);
                    println!("Analysis Time (ms)     : {}", summary.elapsed_ms);
                    println!("True Positives (TP)    : {}", summary.confusion_matrix.true_positives);
                    println!("False Positives (FP)   : {}", summary.confusion_matrix.false_positives);
                    println!("True Negatives (TN)    : {}", summary.confusion_matrix.true_negatives);
                    println!("False Negatives (FN)   : {}", summary.confusion_matrix.false_negatives);
                    println!("Precision              : {:.2}%", summary.confusion_matrix.precision * 100.0);
                    println!("Recall                 : {:.2}%", summary.confusion_matrix.recall * 100.0);
                    println!("F1 Score               : {:.4}", summary.confusion_matrix.f1_score);
                    // New: report internal propagation statistics
                    use std::sync::atomic::Ordering;
                    use v2_taint::{PROPAGATOR_TRANSFERS, ASSIGNMENT_PROPAGATIONS, LOOP_PROPAGATIONS};
                    let prop_transfers = PROPAGATOR_TRANSFERS.load(Ordering::Relaxed);
                    let assign_propagations = ASSIGNMENT_PROPAGATIONS.load(Ordering::Relaxed);
                    let loop_propagations = LOOP_PROPAGATIONS.load(Ordering::Relaxed);
                    println!("Propagator Transfers   : {}", prop_transfers);
                    println!("Assignment Propagations: {}", assign_propagations);
                    println!("Loop Propagations      : {}", loop_propagations);
                }
                Err(e) => {
                    eprintln!("Error running repository validation: {}", e);
                    std::process::exit(1);
                }
            }
            return;
        } else {
            eprintln!("Usage: v2-validation --repo <repo_path> --csv <csv_path>");
            std::process::exit(1);
        }
    }

    let base_dir = Path::new("d:/V2 Backup");
    let holdout_path = base_dir.join("datasets/processed/external_holdout.jsonl");
    let owasp_java_path = base_dir.join("benchmarks/benchmark_java.jsonl");
    let owasp_python_path = base_dir.join("benchmarks/benchmark_python.jsonl");
    let _vul4j_path = base_dir.join("datasets/processed/v10_raw_acquired.jsonl");

    println!("=== V2 Engine Dataset Validation ===");

    let mut tp = 0;
    let mut fp = 0;
    let mut tn = 0;
    let mut fn_count = 0;

    let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());

    // 1. Process Holdout (Juliet/GitHub)
    if holdout_path.exists() {
        if let Ok(file) = File::open(&holdout_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Ok(entry) = serde_json::from_str::<HoldoutEntry>(&line) {
                    let _is_juliet = entry.repo.as_deref() == Some("Juliet")
                        || entry.source.as_deref() == Some("Juliet");
                    
                    // Create temp workspaces
                    let dir_before = temp_workspace("before");
                    let file_name = if entry.language == "python" { "app.py" } else { "App.java" };
                    fs::write(dir_before.join(file_name), &entry.before).unwrap();

                    let res_before = engine.run(&dir_before);
                    if !res_before.findings.is_empty() {
                        tp += 1;
                    } else {
                        fn_count += 1;
                    }
                    let _ = fs::remove_dir_all(&dir_before);

                    let dir_after = temp_workspace("after");
                    fs::write(dir_after.join(file_name), &entry.after).unwrap();

                    let res_after = engine.run(&dir_after);
                    if res_after.findings.is_empty() {
                        tn += 1;
                    } else {
                        fp += 1;
                    }
                    let _ = fs::remove_dir_all(&dir_after);
                }
            }
        }
    }

    // 2. Process OWASP
    for p in &[&owasp_java_path, &owasp_python_path] {
        if p.exists() {
            if let Ok(file) = File::open(p) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line) {
                        let dir = temp_workspace("owasp");
                        let file_name = if entry.language == "python" { "app.py" } else { "App.java" };
                        fs::write(dir.join(file_name), &entry.code).unwrap();

                        let res = engine.run(&dir);
                        if entry.vulnerable {
                            if !res.findings.is_empty() {
                                tp += 1;
                            } else {
                                fn_count += 1;
                            }
                        } else {
                            if res.findings.is_empty() {
                                tn += 1;
                            } else {
                                fp += 1;
                            }
                        }
                        let _ = fs::remove_dir_all(&dir);
                    }
                }
            }
        }
    }

    // Compute metrics
    let total = tp + fp + tn + fn_count;
    let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };
    let recall = if tp + fn_count > 0 { tp as f64 / (tp + fn_count) as f64 } else { 1.0 };
    let f1_score = if precision + recall > 0.0 {
        2.0 * (precision * recall) / (precision + recall)
    } else {
        1.0
    };

    // MCC = (TP*TN - FP*FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
    let mcc = {
        let num = (tp as f64) * (tn as f64) - (fp as f64) * (fn_count as f64);
        let den = ((tp + fp) as f64 * (tp + fn_count) as f64 * (tn + fp) as f64 * (tn + fn_count) as f64).sqrt();
        if den == 0.0 { 0.0 } else { num / den }
    };

    use std::sync::atomic::Ordering;
    use v2_taint::{PROPAGATOR_TRANSFERS, ASSIGNMENT_PROPAGATIONS, LOOP_PROPAGATIONS};
    let prop_transfers    = PROPAGATOR_TRANSFERS.load(Ordering::Relaxed);
    let assign_prop       = ASSIGNMENT_PROPAGATIONS.load(Ordering::Relaxed);
    let loop_prop         = LOOP_PROPAGATIONS.load(Ordering::Relaxed);

    println!("\n=== Final Validation Results ===");
    println!("Total Samples Evaluated: {}", total);
    println!("True Positives (TP)    : {}", tp);
    println!("False Positives (FP)   : {}", fp);
    println!("True Negatives (TN)    : {}", tn);
    println!("False Negatives (FN)   : {}", fn_count);
    println!("Precision              : {:.2}%", precision * 100.0);
    println!("Recall                 : {:.2}%", recall * 100.0);
    println!("F1 Score               : {:.4}", f1_score);
    println!("MCC                    : {:.4}", mcc);
    println!("\n=== Propagation Statistics ===");
    println!("Propagator Transfers   : {}", prop_transfers);
    println!("Assignment Propagations: {}", assign_prop);
    println!("Loop Propagations      : {}", loop_prop);
}

