use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use v2_scheduler::{AnalysisTask, Scheduler};

use crate::cache::{build_cache_entry, ProjectCache};
use crate::dependency::{
    parse_java_imports, parse_java_package, parse_python_imports, DependencyGraph,
};
use crate::discovery::{DiscoveredFile, Language, RepositoryDiscovery};
use crate::linker::CrossFileLinker;
use crate::metrics::MetricsCollector;

// ---------------------------------------------------------------------------
// RepositoryGraph
// ---------------------------------------------------------------------------

/// The combined view of all discovered files and their dependency edges.
pub struct RepositoryGraph {
    pub root: PathBuf,
    pub files: Vec<DiscoveredFile>,
    pub dependencies: DependencyGraph,
    pub module_map: HashMap<String, PathBuf>,
}

impl RepositoryGraph {
    pub fn new(root: PathBuf, files: Vec<DiscoveredFile>, dependencies: DependencyGraph) -> Self {
        let module_map = CrossFileLinker::build_module_map(&files);
        Self { root, files, dependencies, module_map }
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

// ---------------------------------------------------------------------------
// AnalysisSession
// ---------------------------------------------------------------------------

/// Partitions files into those that need to be rebuilt vs. those that can be
/// served from the cache in a single analysis run.
#[derive(Debug, Default)]
pub struct AnalysisSession {
    pub to_rebuild: Vec<PathBuf>,
    pub to_reuse: Vec<PathBuf>,
}

impl AnalysisSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn needs_rebuild(&self, path: &Path) -> bool {
        self.to_rebuild.contains(&path.to_path_buf())
    }

    pub fn total_files(&self) -> usize {
        self.to_rebuild.len() + self.to_reuse.len()
    }
}

// ---------------------------------------------------------------------------
// AnalysisResult
// ---------------------------------------------------------------------------

/// Outcome of processing one file in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalysisResult {
    /// File was re-analyzed (cache miss or dependency invalidation).
    Rebuilt { path: PathBuf },
    /// File was loaded from cache without re-analysis.
    Cached { path: PathBuf },
    /// File was skipped (unsupported language, I/O error, etc.).
    Skipped { path: PathBuf, reason: String },
}

impl AnalysisResult {
    pub fn path(&self) -> &Path {
        match self {
            Self::Rebuilt { path }
            | Self::Cached { path }
            | Self::Skipped { path, .. } => path.as_path(),
        }
    }

    pub fn is_rebuilt(&self) -> bool {
        matches!(self, Self::Rebuilt { .. })
    }

    pub fn is_cached(&self) -> bool {
        matches!(self, Self::Cached { .. })
    }
}

// ---------------------------------------------------------------------------
// IncrementalAnalyzer
// ---------------------------------------------------------------------------

/// Determines what needs rebuilding, then runs the pipeline in parallel.
pub struct IncrementalAnalyzer {
    pub graph: RepositoryGraph,
    pub cache: ProjectCache,
}

impl IncrementalAnalyzer {
    pub fn new(graph: RepositoryGraph, cache: ProjectCache) -> Self {
        Self { graph, cache }
    }

    /// Compute which files need rebuilding:
    /// 1. Direct stale check (mtime / size changed).
    /// 2. Transitive invalidation: any file that imports a changed file.
    pub fn compute_session(&self) -> AnalysisSession {
        let mut to_rebuild: HashSet<PathBuf> = HashSet::new();

        // Pass 1 — direct stale check.
        for file in &self.graph.files {
            if self.cache.needs_rebuild(&file.path) {
                to_rebuild.insert(file.path.clone());
            }
        }

        // Pass 2 — propagate invalidation through the dependency graph.
        let changed: Vec<PathBuf> = to_rebuild.iter().cloned().collect();
        for changed_file in &changed {
            for dep in self.graph.dependencies.dependents_of(changed_file) {
                to_rebuild.insert(dep.clone());
            }
        }

        // Partition all files and sort for determinism.
        let mut session = AnalysisSession::new();
        for file in &self.graph.files {
            if to_rebuild.contains(&file.path) {
                session.to_rebuild.push(file.path.clone());
            } else {
                session.to_reuse.push(file.path.clone());
            }
        }
        session.to_rebuild.sort();
        session.to_reuse.sort();
        session
    }

    /// Run the incremental session in parallel with Rayon, returning results
    /// in deterministic (path-sorted) order.
    pub fn run_parallel(&self, session: &AnalysisSession) -> (Vec<AnalysisResult>, MetricsCollector) {
        let mut collector = MetricsCollector::new();
        collector.start_session();
        collector.set_threads(rayon::current_num_threads());

        // Rebuild phase — parallel.
        let mut results: Vec<AnalysisResult> = session
            .to_rebuild
            .par_iter()
            .map(|path| AnalysisResult::Rebuilt { path: path.clone() })
            .collect();

        // Update metrics for rebuilt files.
        collector.metrics.files_analyzed = results.len();

        // Cache phase — sequential (cheap).
        for path in &session.to_reuse {
            results.push(AnalysisResult::Cached { path: path.clone() });
        }
        collector.metrics.files_reused = session.to_reuse.len();

        // Deterministic merge.
        results.sort_by(|a, b| a.path().cmp(b.path()));
        collector.end_session();
        (results, collector)
    }

    /// Bridge to `v2-scheduler`: enqueue files-to-rebuild as `AnalysisTask`s,
    /// then drive the existing `Scheduler::run` for full pipeline execution.
    pub fn run_via_scheduler(
        &self,
        session: &AnalysisSession,
        worker_count: usize,
        analysis_fn: impl Fn(&AnalysisTask, &v2_scheduler::AnalysisCache)
            -> Result<Vec<v2_common::Diagnostic>, String>
            + Send
            + Sync,
    ) -> Vec<v2_scheduler::AnalysisResult> {
        let tasks: Vec<AnalysisTask> = session
            .to_rebuild
            .iter()
            .map(|path| AnalysisTask {
                priority: 1,
                repository: self.graph.root.to_string_lossy().to_string(),
                file_path: path.to_string_lossy().to_string(),
                module_name: path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string(),
            })
            .collect();

        let scheduler = Scheduler::new(worker_count);
        scheduler.run(tasks, analysis_fn)
    }

    /// Update the cache for all successfully rebuilt files.
    pub fn update_cache(&mut self, results: &[AnalysisResult]) {
        for result in results {
            if result.is_rebuilt() {
                if let Some(entry) = build_cache_entry(result.path()) {
                    self.cache.update(entry);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WorkspaceBuilder
// ---------------------------------------------------------------------------

/// Fluent builder: discovers files, parses imports, loads the cache, and
/// produces an `IncrementalAnalyzer` ready to run.
pub struct WorkspaceBuilder {
    root: PathBuf,
    cache_path: Option<PathBuf>,
}

impl WorkspaceBuilder {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into(), cache_path: None }
    }

    /// Specify a persistent cache file (JSON).  Created if absent.
    pub fn with_cache(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    /// Execute discovery, dependency parsing, and cache loading, then return
    /// a fully initialised `IncrementalAnalyzer`.
    pub fn build(self) -> IncrementalAnalyzer {
        // 1. Discover files.
        let files = RepositoryDiscovery::discover(&self.root);

        // 2. Build dependency graph from source imports.
        let mut dep_graph = DependencyGraph::new();
        for file in &files {
            let Ok(content) = std::fs::read_to_string(&file.path) else { continue };
            match &file.language {
                Language::Python => {
                    for imp in parse_python_imports(&file.path, &content) {
                        dep_graph.add_import(imp);
                    }
                    if let Some(stem) = file.path.file_stem().and_then(|s| s.to_str()) {
                        dep_graph.add_export(stem.to_string(), file.path.clone());
                    }
                }
                Language::Java => {
                    for imp in parse_java_imports(&file.path, &content) {
                        dep_graph.add_import(imp);
                    }
                    if let Some(pkg) = parse_java_package(&content) {
                        dep_graph.add_export(pkg, file.path.clone());
                    }
                }
                Language::Unknown(_) => {}
            }
        }

        // 3. Load cache.
        let cache = match &self.cache_path {
            Some(p) => ProjectCache::load(p),
            None => ProjectCache::new(),
        };

        // 4. Assemble and return.
        let graph = RepositoryGraph::new(self.root, files, dep_graph);
        IncrementalAnalyzer::new(graph, cache)
    }
}
