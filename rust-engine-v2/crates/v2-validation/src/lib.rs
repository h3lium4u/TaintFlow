use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use v2_engine::{AnalysisConfiguration, RepositoryAnalysisEngine};

// ---------------------------------------------------------------------------
// 1. Validation Models & Confusion Matrix
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

impl ConfusionMatrix {
    pub fn calculate(tp: usize, fp: usize, fn_: usize, tn: usize) -> Self {
        let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { 1.0 };
        let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { 1.0 };
        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            1.0
        };

        Self {
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_,
            true_negatives: tn,
            precision,
            recall,
            f1_score,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Synthetic & Real-world Curated Repositories
// ---------------------------------------------------------------------------

pub struct CuratedRepository {
    pub root: PathBuf,
}

impl CuratedRepository {
    pub fn create_synthetic_xss(root: &Path) -> Self {
        let _ = fs::create_dir_all(root);
        fs::write(
            root.join("app.py"),
            r#"
x = input()
eval(x) # Vulnerable sink
"#,
        )
        .unwrap();
        Self { root: root.to_path_buf() }
    }

    pub fn create_safe_examples(root: &Path) -> Self {
        let _ = fs::create_dir_all(root);
        fs::write(
            root.join("app.py"),
            r#"
x = "safe_string"
print(x) # Safe call
"#,
        )
        .unwrap();
        Self { root: root.to_path_buf() }
    }

    pub fn create_stress_repo(root: &Path, file_count: usize, methods_per_file: usize) -> Self {
        let _ = fs::create_dir_all(root);
        for i in 0..file_count {
            let file_path = root.join(format!("file_{}.py", i));
            let mut content = String::new();
            content.push_str("class LargeInheritedClass:\n");
            for j in 0..methods_per_file {
                content.push_str(&format!(
                    "    def method_{}(self, val):\n        x = val\n        return x\n",
                    j
                ));
            }
            content.push_str("\n# Safe usage of methods\n");
            fs::write(file_path, content).unwrap();
        }
        Self { root: root.to_path_buf() }
    }
}

// ---------------------------------------------------------------------------
// 3. Differential Testing & Determinism Verifier
// ---------------------------------------------------------------------------

pub struct ValidationSuite;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoValidationSummary {
    pub repo_name: String,
    pub confusion_matrix: ConfusionMatrix,
    pub elapsed_ms: u128,
}

impl ValidationSuite {
    pub fn run_determinism_test(project_path: &Path, runs: usize) -> Result<(), String> {
        let mut config = AnalysisConfiguration::default();
        config.incremental_mode = false;
        let engine = RepositoryAnalysisEngine::new(config);
        let initial_res = engine.run(project_path);
        
        let initial_json = serde_json::to_string(&initial_res.findings).unwrap();

        for i in 0..runs {
            let res = engine.run(project_path);
            let current_json = serde_json::to_string(&res.findings).unwrap();

            if current_json != initial_json {
                return Err(format!("Determinism mismatch on run {}: findings JSON differs", i));
            }
            if res.statistics.file_count != initial_res.statistics.file_count
                || res.statistics.method_count != initial_res.statistics.method_count
                || res.statistics.instruction_count != initial_res.statistics.instruction_count
                || res.statistics.findings_count != initial_res.statistics.findings_count
            {
                return Err(format!("Determinism mismatch on run {}: static counts differ", i));
            }
        }

        Ok(())
    }

    pub fn run_differential_test(project_path: &Path) -> Result<(), String> {
        // 1. Single thread
        let mut config_single = AnalysisConfiguration::default();
        config_single.scheduler_threads = 1;
        config_single.incremental_mode = false;
        let engine_single = RepositoryAnalysisEngine::new(config_single);
        let res_single = engine_single.run(project_path);

        // 2. Parallel thread
        let mut config_parallel = AnalysisConfiguration::default();
        config_parallel.scheduler_threads = 4;
        config_parallel.incremental_mode = false;
        let engine_parallel = RepositoryAnalysisEngine::new(config_parallel);
        let res_parallel = engine_parallel.run(project_path);

        // Verify outputs match
        if res_single.findings.len() != res_parallel.findings.len() {
            return Err("Findings count mismatch between single-thread and multi-thread execution.".to_string());
        }

        let set_single: HashSet<String> = res_single.findings.iter().map(|f| f.fingerprint.0.clone()).collect();
        let set_parallel: HashSet<String> = res_parallel.findings.iter().map(|f| f.fingerprint.0.clone()).collect();

        if set_single != set_parallel {
            return Err("Findings fingerprints differ between single-thread and multi-thread execution.".to_string());
        }

        Ok(())
    }

    pub fn validate_owasp_repository(
        repo_path: &Path,
        csv_path: &Path,
    ) -> Result<RepoValidationSummary, String> {
        let start = std::time::Instant::now();
        
        // 1. Read ground truth from CSV
        let content = fs::read_to_string(csv_path)
            .map_err(|e| format!("Failed to read ground truth CSV: {}", e))?;
            
        let mut ground_truth = std::collections::HashMap::new();
        // CSV columns: testKey,testNum,expectedResult,cwe,category
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split(',')
                .map(|s| s.trim_matches('"').trim())
                .collect();
            if parts.len() >= 3 {
                let test_key = parts[0].to_string();
                let is_vulnerable = parts[2].eq_ignore_ascii_case("vulnerable");
                ground_truth.insert(test_key, is_vulnerable);
            }
        }
        
        if ground_truth.is_empty() {
            return Err("Ground truth CSV is empty or invalid.".to_string());
        }

        // 2. Run TaintFlow V2 Engine on the repository
        let mut config = AnalysisConfiguration::default();
        config.incremental_mode = false; // Disable incremental cache for clean validation run
        let engine = RepositoryAnalysisEngine::new(config);
        let res = engine.run(repo_path);

        if !res.success {
            return Err("Engine analysis execution failed.".to_string());
        }

        // 3. Match findings and calculate TP, FP, TN, FN
        let mut reported_keys = HashSet::new();
        for finding in &res.findings {
            // Extract the testKey (file name base) from the source location
            let file_name = Path::new(&finding.source.file)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !file_name.is_empty() {
                reported_keys.insert(file_name.to_string());
            }
        }

        let mut tp = 0;
        let mut fp = 0;
        let mut fn_ = 0;
        let mut tn = 0;

        for (test_key, &is_vulnerable) in &ground_truth {
            let was_reported = reported_keys.contains(test_key);
            if is_vulnerable {
                if was_reported {
                    tp += 1;
                } else {
                    fn_ += 1;
                }
            } else {
                if was_reported {
                    fp += 1;
                } else {
                    tn += 1;
                }
            }
        }

        let confusion_matrix = ConfusionMatrix::calculate(tp, fp, fn_, tn);
        let elapsed_ms = start.elapsed().as_millis();

        Ok(RepoValidationSummary {
            repo_name: repo_path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            confusion_matrix,
            elapsed_ms,
        })
    }

    pub fn validate_juliet_repository(
        repo_path: &Path,
    ) -> Result<RepoValidationSummary, String> {
        let start = std::time::Instant::now();

        // 1. Run TaintFlow V2 Engine on the Juliet repository
        let mut config = AnalysisConfiguration::default();
        config.incremental_mode = false;
        let engine = RepositoryAnalysisEngine::new(config);
        let res = engine.run(repo_path);

        if !res.success {
            return Err("Juliet engine analysis failed.".to_string());
        }

        // 2. Discover all Juliet files to establish the ground truth list of test cases
        // Each Juliet file has 1 'bad' (vulnerable) test case and 1 'good' (safe) test case.
        let mut file_names = HashSet::new();
        for file in &res.analyzed_files {
            let stem = file.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !stem.is_empty() && (stem.starts_with("CWE") || stem.contains("Juliet")) {
                file_names.insert(stem.to_string());
            }
        }

        // Default to file count if empty
        if file_names.is_empty() {
            for (idx, _) in res.analyzed_files.iter().enumerate() {
                file_names.insert(format!("JulietCase_{}", idx));
            }
        }

        // 3. Match findings by method-level trace checking (bad() vs good())
        let mut reported_bads = HashSet::new();
        let mut reported_goods = HashSet::new();

        for finding in &res.findings {
            let file_stem = Path::new(&finding.source.file)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            
            // Check if any location in trace or source/sink points to a good or bad method
            let method_name = &finding.source.method;
            let is_good = method_name.contains("good") || method_name.contains("Good");
            let is_bad = method_name.contains("bad") || method_name.contains("Bad") || (!is_good && method_name == "__module__");

            if is_bad && !file_stem.is_empty() {
                reported_bads.insert(file_stem.to_string());
            }
            if is_good && !file_stem.is_empty() {
                reported_goods.insert(file_stem.to_string());
            }
        }

        let mut tp = 0;
        let mut fp = 0;
        let mut fn_ = 0;
        let mut tn = 0;

        for stem in &file_names {
            // Evaluated vulnerable test case: bad()
            if reported_bads.contains(stem) {
                tp += 1;
            } else {
                fn_ += 1;
            }

            // Evaluated safe test case: good()
            if reported_goods.contains(stem) {
                fp += 1;
            } else {
                tn += 1;
            }
        }

        let confusion_matrix = ConfusionMatrix::calculate(tp, fp, fn_, tn);
        let elapsed_ms = start.elapsed().as_millis();

        Ok(RepoValidationSummary {
            repo_name: repo_path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("juliet_repo")
                .to_string(),
            confusion_matrix,
            elapsed_ms,
        })
    }

    pub fn load_generic_ground_truth(
        path: &Path,
    ) -> Result<Vec<GroundTruthEntry>, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read ground truth file: {}", e))?;
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        if ext.eq_ignore_ascii_case("json") {
            serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse JSON ground truth: {}", e))
        } else if ext.eq_ignore_ascii_case("csv") {
            let mut entries = Vec::new();
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split(',')
                    .map(|s| s.trim_matches('"').trim())
                    .collect();
                if parts.len() >= 2 {
                    entries.push(GroundTruthEntry {
                        test_key: parts[0].to_string(),
                        expected_result: parts[1].to_string(),
                        cwe: parts.get(2).map(|s| s.to_string()),
                    });
                }
            }
            Ok(entries)
        } else {
            Err(format!("Unsupported format: {}", ext))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthEntry {
    pub test_key: String,
    pub expected_result: String,
    pub cwe: Option<String>,
}

pub fn init() {
    println!("v2-validation initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("v2_validation_tests_{}_{}", tag, std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_confusion_matrix_calculation() {
        let cm = ConfusionMatrix::calculate(10, 2, 1, 87);
        assert!((cm.precision - 0.833).abs() < 0.01);
        assert!((cm.recall - 0.909).abs() < 0.01);
        assert!((cm.f1_score - 0.87).abs() < 0.01);
    }

    #[test]
    fn test_determinism() {
        let workspace = temp_workspace("determinism");
        CuratedRepository::create_synthetic_xss(&workspace);

        let res = ValidationSuite::run_determinism_test(&workspace, 5);
        assert!(res.is_ok());

        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn test_differential_testing() {
        let workspace = temp_workspace("differential");
        CuratedRepository::create_synthetic_xss(&workspace);

        let res = ValidationSuite::run_differential_test(&workspace);
        assert!(res.is_ok());

        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn test_stress_test_repo_generation() {
        let workspace = temp_workspace("stress");
        CuratedRepository::create_stress_repo(&workspace, 5, 10);

        let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());
        let res = engine.run(&workspace);
        assert!(res.success);
        assert_eq!(res.statistics.file_count, 5);

        let _ = fs::remove_dir_all(&workspace);
    }
}
