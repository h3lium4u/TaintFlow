use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use v2_engine::{AnalysisConfiguration, RepositoryAnalysisEngine};

// ---------------------------------------------------------------------------
// 1. Benchmark & Ground Truth Models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroundTruth {
    pub entries: Vec<GroundTruthEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthEntry {
    pub file_relative_path: String,
    pub line: usize,
    pub is_vulnerable: bool,
    pub cwe: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    pub name: String,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub files_scanned: usize,
    pub loc_scanned: usize,
    pub scan_time_ms: f64,
    pub findings_per_cwe: HashMap<u32, usize>,
    pub unsupported_constructs: HashMap<String, usize>,
}

// ---------------------------------------------------------------------------
// 2. Repository Adapters & Unsupported Construct Scanners
// ---------------------------------------------------------------------------

pub struct RepositoryAdapter;

impl RepositoryAdapter {
    /// Discovers ground-truth annotations in code comments:
    /// - `# VULNERABLE: CWE-89` or `// VULNERABLE: CWE-78`
    /// - `# SAFE` or `// SAFE`
    pub fn load_ground_truth_from_comments(project_path: &Path) -> Result<GroundTruth, String> {
        let mut entries = Vec::new();
        let walk_dir = |path: &Path| -> Vec<PathBuf> {
            let mut files = Vec::new();
            let mut stack = vec![path.to_path_buf()];
            while let Some(current) = stack.pop() {
                if let Ok(entries) = fs::read_dir(current) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let name = path.file_name().unwrap_or_default().to_string_lossy();
                            if name != ".git" && name != "target" && name != "node_modules" {
                                stack.push(path);
                            }
                        } else if path.is_file() {
                            let ext = path.extension().unwrap_or_default().to_string_lossy();
                            if ext == "py" || ext == "java" {
                                files.push(path);
                            }
                        }
                    }
                }
            }
            files
        };

        for file in walk_dir(project_path) {
            let content = fs::read_to_string(&file)
                .map_err(|e| format!("Failed to read file {:?}: {}", file, e))?;
            
            let rel_path = file.strip_prefix(project_path)
                .map_err(|_| "Failed to strip prefix".to_string())?
                .to_string_lossy()
                .to_string();

            for (idx, line) in content.lines().enumerate() {
                let line_num = idx + 1;
                if line.contains("VULNERABLE") {
                    let cwe = if line.contains("CWE-89") {
                        Some(89)
                    } else if line.contains("CWE-78") {
                        Some(78)
                    } else if line.contains("CWE-22") {
                        Some(22)
                    } else if line.contains("CWE-95") {
                        Some(95)
                    } else {
                        None
                    };
                    entries.push(GroundTruthEntry {
                        file_relative_path: rel_path.clone(),
                        line: line_num,
                        is_vulnerable: true,
                        cwe,
                    });
                } else if line.contains("SAFE") {
                    entries.push(GroundTruthEntry {
                        file_relative_path: rel_path.clone(),
                        line: line_num,
                        is_vulnerable: false,
                        cwe: None,
                    });
                }
            }
        }

        Ok(GroundTruth { entries })
    }

    /// Scans project files for unmodeled language constructs (reflection, eval, native, etc.)
    pub fn scan_unsupported_constructs(project_path: &Path) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        let keywords = vec![
            ("eval", "eval("),
            ("exec", "exec("),
            ("reflection_java", "Class.forName"),
            ("reflection_java_method", "getMethod"),
            ("reflection_java_invoke", ".invoke("),
            ("reflection_py", "getattr("),
            ("reflection_py_set", "setattr("),
            ("dynamic_import", "importlib"),
            ("dynamic_proxy", "Proxy.newProxyInstance"),
            ("native_method", "native "),
            ("lambda_capture", "lambda "),
        ];

        let walk_dir = |path: &Path| -> Vec<PathBuf> {
            let mut files = Vec::new();
            let mut stack = vec![path.to_path_buf()];
            while let Some(current) = stack.pop() {
                if let Ok(entries) = fs::read_dir(current) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let name = path.file_name().unwrap_or_default().to_string_lossy();
                            if name != ".git" && name != "target" && name != "node_modules" {
                                stack.push(path);
                            }
                        } else if path.is_file() {
                            files.push(path);
                        }
                    }
                }
            }
            files
        };

        for file in walk_dir(project_path) {
            if let Ok(content) = fs::read_to_string(file) {
                for (key, val) in &keywords {
                    if content.contains(val) {
                        *counts.entry(key.to_string()).or_insert(0) += 1;
                    }
                }
            }
        }

        counts
    }
}

// ---------------------------------------------------------------------------
// 3. Validation Runner (Real-world metrics calculator)
// ---------------------------------------------------------------------------

pub struct ValidationRunner;

impl ValidationRunner {
    pub fn run_evaluation(
        name: &str,
        project_path: &Path,
        ground_truth: &GroundTruth,
    ) -> Result<BenchmarkMetrics, String> {
        let t_start = std::time::Instant::now();
        let engine = RepositoryAnalysisEngine::new(AnalysisConfiguration::default());
        let res = engine.run(project_path);
        let scan_time_ms = t_start.elapsed().as_millis() as f64;

        if !res.success {
            return Err("Engine scan execution failed.".to_string());
        }

        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut false_negatives = 0;
        let mut true_negatives = 0;

        let mut findings_per_cwe = HashMap::new();

        // Track which vulnerable entries in ground-truth were matched
        let mut matched_entries = HashSet::new();

        for finding in &res.findings {
            let file_rel = finding.source.file.clone();
            let line_num = finding.source.line.unwrap_or(0);

            if let Some(cwe) = finding.rule.cwe {
                *findings_per_cwe.entry(cwe).or_insert(0) += 1;
            }

            // Find matching ground truth entry
            let mut found_match = false;
            for (idx, gt) in ground_truth.entries.iter().enumerate() {
                if file_rel.contains(&gt.file_relative_path) && (gt.line == 0 || gt.line == line_num) {
                    if gt.is_vulnerable {
                        true_positives += 1;
                        matched_entries.insert(idx);
                    } else {
                        false_positives += 1;
                    }
                    found_match = true;
                    break;
                }
            }

            if !found_match {
                // If it is not in our safe/vulnerable list, count as FP to be safe
                false_positives += 1;
            }
        }

        // Count false negatives and true negatives
        for (idx, gt) in ground_truth.entries.iter().enumerate() {
            if gt.is_vulnerable {
                if !matched_entries.contains(&idx) {
                    false_negatives += 1;
                    // Automatically generate regression case
                    let _ = Self::save_regression_case(project_path, &gt.file_relative_path);
                }
            } else {
                let mut triggered_fp = false;
                for finding in &res.findings {
                    if finding.source.file.contains(&gt.file_relative_path) {
                        triggered_fp = true;
                        break;
                    }
                }
                if !triggered_fp {
                    true_negatives += 1;
                } else {
                    let _ = Self::save_regression_case(project_path, &gt.file_relative_path);
                }
            }
        }

        let precision = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            1.0
        };

        let recall = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            1.0
        };

        let f1_score = if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            1.0
        };

        let unsupported = RepositoryAdapter::scan_unsupported_constructs(project_path);

        Ok(BenchmarkMetrics {
            name: name.to_string(),
            true_positives,
            false_positives,
            false_negatives,
            true_negatives,
            precision,
            recall,
            f1_score,
            files_scanned: res.statistics.file_count,
            loc_scanned: res.statistics.instruction_count / 2, // approximation
            scan_time_ms,
            findings_per_cwe,
            unsupported_constructs: unsupported,
        })
    }

    fn save_regression_case(project_path: &Path, rel_path: &str) -> Result<(), String> {
        let src = project_path.join(rel_path);
        if !src.exists() {
            return Ok(());
        }
        let regression_dir = Path::new("crates/v2-benchmarks/regressions");
        let _ = fs::create_dir_all(regression_dir);
        let dest_filename = format!(
            "reg_{}_{}",
            std::process::id(),
            Path::new(rel_path).file_name().unwrap_or_default().to_string_lossy()
        );
        let dest = regression_dir.join(dest_filename);
        fs::copy(src, dest)
            .map_err(|e| format!("Failed to copy regression file: {}", e))?;
        Ok(())
    }
}

pub fn init() {
    println!("v2-benchmarks validation runner initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("v2_val_run_tests_{}_{}", tag, std::process::id()));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_unsupported_constructs_scanner() {
        let workspace = temp_workspace("unsupported");
        fs::write(workspace.join("test.py"), "eval(x)\ngetattr(obj, 'x')\n").unwrap();

        let counts = RepositoryAdapter::scan_unsupported_constructs(&workspace);
        assert_eq!(counts.get("eval").unwrap(), &1);
        assert_eq!(counts.get("reflection_py").unwrap(), &1);

        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn test_comment_annotations_loader() {
        let workspace = temp_workspace("comments");
        fs::write(
            workspace.join("test.py"),
            r#"
# VULNERABLE: CWE-89
eval(x)
# SAFE
x = "safe"
"#,
        )
        .unwrap();

        let gt = RepositoryAdapter::load_ground_truth_from_comments(&workspace).unwrap();
        assert_eq!(gt.entries.len(), 2);
        assert!(gt.entries[0].is_vulnerable);
        assert_eq!(gt.entries[0].cwe, Some(89));
        assert!(!gt.entries[1].is_vulnerable);

        let _ = fs::remove_dir_all(&workspace);
    }
}
