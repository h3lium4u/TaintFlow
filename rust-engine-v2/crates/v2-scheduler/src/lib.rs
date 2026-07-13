use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use v2_common::Diagnostic;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnalysisTask {
    pub priority: u32,
    pub repository: String,
    pub file_path: String,
    pub module_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub task: AnalysisTask,
    pub success: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub elapsed_ms: u64,
    pub metadata: HashMap<String, String>,
}

pub struct AnalysisCache {
    pub parser: RwLock<HashMap<String, Arc<dyn v2_parser::CstNode + Send + Sync>>>,
    pub semantic: RwLock<HashMap<String, Arc<v2_semantic::SemanticInfo>>>,
    pub cfg: RwLock<HashMap<String, Arc<HashMap<v2_ir::MethodId, v2_cfg::ControlFlowGraph>>>>,
    pub call_graph: RwLock<HashMap<String, Arc<v2_callgraph::CallGraph>>>,
}

impl AnalysisCache {
    pub fn new() -> Self {
        Self {
            parser: RwLock::new(HashMap::new()),
            semantic: RwLock::new(HashMap::new()),
            cfg: RwLock::new(HashMap::new()),
            call_graph: RwLock::new(HashMap::new()),
        }
    }

    pub fn clear(&self) {
        self.parser.write().unwrap().clear();
        self.semantic.write().unwrap().clear();
        self.cfg.write().unwrap().clear();
        self.call_graph.write().unwrap().clear();
    }
}

pub struct Scheduler {
    worker_count: usize,
    cache: Arc<AnalysisCache>,
    cancelled: Arc<AtomicBool>,
}

impl Scheduler {
    pub fn new(worker_count: usize) -> Self {
        Self {
            worker_count,
            cache: Arc::new(AnalysisCache::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn get_cache(&self) -> Arc<AnalysisCache> {
        self.cache.clone()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn run(
        &self,
        mut tasks: Vec<AnalysisTask>,
        analysis_fn: impl Fn(&AnalysisTask, &AnalysisCache) -> Result<Vec<Diagnostic>, String> + Send + Sync,
    ) -> Vec<AnalysisResult> {
        // 1. Deterministic sorting: sort by priority, then file_path
        tasks.sort_by(|t1, t2| {
            t1.priority.cmp(&t2.priority)
                .then_with(|| t1.file_path.cmp(&t2.file_path))
        });

        // 2. Build Rayon ThreadPool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.worker_count)
            .build()
            .unwrap();

        let cache = self.cache.clone();
        let cancelled = self.cancelled.clone();
        let analysis_ref = &analysis_fn;

        // 3. Parallel Execution with Panic/Error Isolation
        let mut results: Vec<AnalysisResult> = pool.install(|| {
            use rayon::prelude::*;
            tasks.into_par_iter()
                .map(|task| {
                    let task_start = Instant::now();

                    if cancelled.load(Ordering::SeqCst) {
                        let mut metadata = HashMap::new();
                        metadata.insert("error".to_string(), "Task cancelled".to_string());
                        return AnalysisResult {
                            task,
                            success: false,
                            diagnostics: Vec::new(),
                            elapsed_ms: 0,
                            metadata,
                        };
                    }

                    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        analysis_ref(&task, &cache)
                    }));

                    let (success, diagnostics, mut metadata) = match run_result {
                        Ok(Ok(diags)) => (true, diags, HashMap::new()),
                        Ok(Err(err_msg)) => {
                            let mut meta = HashMap::new();
                            meta.insert("error".to_string(), err_msg);
                            (false, Vec::new(), meta)
                        }
                        Err(_) => {
                            let mut meta = HashMap::new();
                            meta.insert("error".to_string(), "Task panicked during execution".to_string());
                            (false, Vec::new(), meta)
                        }
                    };

                    metadata.insert("thread_id".to_string(), format!("{:?}", std::thread::current().id()));

                    AnalysisResult {
                        task,
                        success,
                        diagnostics,
                        elapsed_ms: task_start.elapsed().as_millis() as u64,
                        metadata,
                    }
                })
                .collect()
        });

        // 4. Deterministic Merge: Sort collected results to ensure stable order
        results.sort_by(|r1, r2| {
            r1.task.priority.cmp(&r2.task.priority)
                .then_with(|| r1.task.file_path.cmp(&r2.task.file_path))
        });

        results
    }
}

pub fn init() {
    println!("v2-scheduler initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_deterministic_scheduling_and_merge() {
        let scheduler = Scheduler::new(4);
        
        let t1 = AnalysisTask {
            priority: 2,
            repository: "repo".to_string(),
            file_path: "b_file.py".to_string(),
            module_name: "b".to_string(),
        };
        let t2 = AnalysisTask {
            priority: 1,
            repository: "repo".to_string(),
            file_path: "a_file.py".to_string(),
            module_name: "a".to_string(),
        };
        let t3 = AnalysisTask {
            priority: 2,
            repository: "repo".to_string(),
            file_path: "c_file.py".to_string(),
            module_name: "c".to_string(),
        };

        let tasks = vec![t1, t2, t3];
        
        let results = scheduler.run(tasks, |_, _| {
            Ok(vec![])
        });

        // Assert deterministic ordering: priority 1 first, then priority 2 sorted alphabetically by file_path
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].task.file_path, "a_file.py"); // priority 1
        assert_eq!(results[1].task.file_path, "b_file.py"); // priority 2, 'b' before 'c'
        assert_eq!(results[2].task.file_path, "c_file.py"); // priority 2
    }

    #[test]
    fn test_cache_reuse() {
        let scheduler = Scheduler::new(2);
        let cache = scheduler.get_cache();

        let task = AnalysisTask {
            priority: 1,
            repository: "repo".to_string(),
            file_path: "test.py".to_string(),
            module_name: "test".to_string(),
        };

        // Cache a dummy semantic info
        let sem_info = Arc::new(v2_semantic::SemanticInfo::new());
        cache.semantic.write().unwrap().insert("test.py".to_string(), sem_info);

        let results = scheduler.run(vec![task], |task, c| {
            // Verify that we can retrieve the cached semantic info
            let cached = c.semantic.read().unwrap();
            if cached.contains_key(&task.file_path) {
                Ok(vec![])
            } else {
                Err("Cache hit missed!".to_string())
            }
        });

        assert!(results[0].success);
    }

    #[test]
    fn test_error_isolation_and_panic() {
        let scheduler = Scheduler::new(2);
        
        let t_panic = AnalysisTask {
            priority: 1,
            repository: "repo".to_string(),
            file_path: "panic.py".to_string(),
            module_name: "panic".to_string(),
        };
        let t_success = AnalysisTask {
            priority: 1,
            repository: "repo".to_string(),
            file_path: "success.py".to_string(),
            module_name: "success".to_string(),
        };

        let results = scheduler.run(vec![t_panic, t_success], |task, _| {
            if task.file_path == "panic.py" {
                panic!("Simulated execution crash!");
            }
            Ok(vec![])
        });

        assert_eq!(results.len(), 2);
        // The panicking task fails
        let res_panic = results.iter().find(|r| r.task.file_path == "panic.py").unwrap();
        assert!(!res_panic.success);
        assert!(res_panic.metadata.get("error").unwrap().contains("panic"));

        // The other task compiles successfully (error isolated!)
        let res_success = results.iter().find(|r| r.task.file_path == "success.py").unwrap();
        assert!(res_success.success);
    }

    #[test]
    fn test_cancellation() {
        let scheduler = Scheduler::new(2);
        scheduler.cancel(); // Cancel immediately

        let task = AnalysisTask {
            priority: 1,
            repository: "repo".to_string(),
            file_path: "test.py".to_string(),
            module_name: "test".to_string(),
        };

        let results = scheduler.run(vec![task], |_, _| {
            Ok(vec![])
        });

        assert!(!results[0].success);
        assert_eq!(results[0].metadata.get("error").unwrap(), "Task cancelled");
    }
}
