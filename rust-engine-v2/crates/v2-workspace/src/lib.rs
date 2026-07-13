pub mod builder;
pub mod cache;
pub mod dependency;
pub mod discovery;
pub mod linker;
pub mod metrics;

// Flat re-exports for convenience.
pub use builder::{AnalysisResult, AnalysisSession, IncrementalAnalyzer, RepositoryGraph, WorkspaceBuilder};
pub use cache::{build_cache_entry, CacheEntry, FileChecksums, ProjectCache};
pub use dependency::{
    parse_java_imports, parse_java_package, parse_python_imports, DependencyGraph, Import,
};
pub use discovery::{DiscoveredFile, Language, RepositoryDiscovery, IGNORED_DIRS};
pub use linker::{CrossFileLinker, ResolvedImport};
pub use metrics::{AnalysisMetrics, MetricsCollector};

pub fn init() {
    println!("v2-workspace initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Create a unique temporary directory for each test.
    fn temp_repo(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "v2_ws_{}_{}_{}",
            tag,
            std::process::id(),
            id
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &PathBuf, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, content).unwrap();
        p
    }

    fn cleanup(dir: &PathBuf) {
        let _ = fs::remove_dir_all(dir);
    }

    // -----------------------------------------------------------------------
    // 1. Repository Discovery
    // -----------------------------------------------------------------------

    #[test]
    fn test_discovery_finds_python_files() {
        let repo = temp_repo("py");
        write(&repo, "main.py", "import os");
        write(&repo, "utils.py", "def foo(): pass");
        let files = RepositoryDiscovery::discover(&repo);
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.language == Language::Python));
        cleanup(&repo);
    }

    #[test]
    fn test_discovery_finds_java_files() {
        let repo = temp_repo("java");
        write(&repo, "Main.java", "package com.example;");
        let files = RepositoryDiscovery::discover(&repo);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, Language::Java);
        cleanup(&repo);
    }

    #[test]
    fn test_discovery_ignores_standard_dirs() {
        let repo = temp_repo("ignore");
        write(&repo, "main.py", "pass");
        for dir_name in IGNORED_DIRS {
            let d = repo.join(dir_name);
            fs::create_dir_all(&d).unwrap();
            write(&d, "hidden.py", "pass");
        }
        let files = RepositoryDiscovery::discover(&repo);
        // Only the root-level main.py should appear.
        assert_eq!(files.len(), 1);
        assert!(files[0].path.file_name().unwrap() == "main.py");
        cleanup(&repo);
    }

    #[test]
    fn test_discovery_stable_ordering() {
        let repo = temp_repo("order");
        write(&repo, "z.py", "pass");
        write(&repo, "a.py", "pass");
        write(&repo, "m.py", "pass");
        let files = RepositoryDiscovery::discover(&repo);
        let names: Vec<_> = files
            .iter()
            .map(|f| f.path.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "discover() must return files in sorted order");
        cleanup(&repo);
    }

    #[test]
    fn test_language_detection() {
        assert_eq!(
            RepositoryDiscovery::detect_language(&PathBuf::from("foo.py")),
            Language::Python
        );
        assert_eq!(
            RepositoryDiscovery::detect_language(&PathBuf::from("Foo.java")),
            Language::Java
        );
        assert!(matches!(
            RepositoryDiscovery::detect_language(&PathBuf::from("foo.rs")),
            Language::Unknown(_)
        ));
        assert!(!Language::Unknown("rs".into()).is_supported());
    }

    #[test]
    fn test_filter_by_language() {
        let repo = temp_repo("filter");
        write(&repo, "a.py", "pass");
        write(&repo, "B.java", "class B {}");
        let files = RepositoryDiscovery::discover(&repo);
        let py = RepositoryDiscovery::filter_by_language(&files, &Language::Python);
        assert_eq!(py.len(), 1);
        let java = RepositoryDiscovery::filter_by_language(&files, &Language::Java);
        assert_eq!(java.len(), 1);
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 2. Incremental Cache
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_miss_on_new_file() {
        let cache = ProjectCache::new();
        assert!(cache.needs_rebuild(&PathBuf::from("/no/such/file.py")));
    }

    #[test]
    fn test_cache_entry_created() {
        let repo = temp_repo("entry");
        let file = write(&repo, "a.py", "x = 1");
        let mut cache = ProjectCache::new();
        if let Some(entry) = build_cache_entry(&file) {
            cache.update(entry);
        }
        assert_eq!(cache.total_entries(), 1);
        cleanup(&repo);
    }

    #[test]
    fn test_cache_invalidation() {
        let repo = temp_repo("inv");
        let file = write(&repo, "a.py", "x = 1");
        let mut cache = ProjectCache::new();
        if let Some(entry) = build_cache_entry(&file) {
            cache.update(entry);
        }
        cache.invalidate(&file);
        assert!(cache.needs_rebuild(&file));
        cleanup(&repo);
    }

    #[test]
    fn test_cache_hit_rate() {
        let repo = temp_repo("rate");
        let f1 = write(&repo, "a.py", "x=1");
        let f2 = write(&repo, "b.py", "y=2");
        let mut cache = ProjectCache::new();
        if let Some(e) = build_cache_entry(&f1) { cache.update(e); }
        if let Some(e) = build_cache_entry(&f2) { cache.update(e); }
        cache.invalidate(&f2);
        assert_eq!(cache.hit_count(), 1);
        assert_eq!(cache.total_entries(), 2);
        assert!((cache.hit_rate() - 0.5).abs() < 0.01);
        cleanup(&repo);
    }

    #[test]
    fn test_cache_reuse_via_workspace_builder() {
        let repo = temp_repo("reuse");
        write(&repo, "a.py", "x = 1");
        let cache_file = repo.join(".v2_cache.json");
        let analyzer = WorkspaceBuilder::new(&repo)
            .with_cache(&cache_file)
            .build();
        let session = analyzer.compute_session();
        // All files are new → rebuild.
        assert_eq!(session.to_rebuild.len(), 1);
        assert_eq!(session.to_reuse.len(), 0);
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 3. Dependency Graph
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_graph_forward() {
        let mut graph = DependencyGraph::new();
        graph.add_import(Import {
            from_file: PathBuf::from("a.py"),
            module_name: "utils".to_string(),
            alias: None,
        });
        graph.add_export("utils".to_string(), PathBuf::from("utils.py"));
        let deps = graph.dependencies_of(&PathBuf::from("a.py"));
        assert_eq!(deps, vec![PathBuf::from("utils.py")]);
    }

    #[test]
    fn test_dependency_graph_reverse() {
        let mut graph = DependencyGraph::new();
        graph.add_import(Import {
            from_file: PathBuf::from("main.py"),
            module_name: "utils".to_string(),
            alias: None,
        });
        graph.add_export("utils".to_string(), PathBuf::from("utils.py"));
        let dependents = graph.dependents_of(&PathBuf::from("utils.py"));
        assert!(dependents.contains(&&PathBuf::from("main.py")));
    }

    // -----------------------------------------------------------------------
    // 4. Dependency Invalidation Propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_invalidation_propagation() {
        let repo = temp_repo("prop");
        write(&repo, "utils.py", "def helper(): pass");
        write(&repo, "main.py", "import utils\nresult = utils.helper()");
        let analyzer = WorkspaceBuilder::new(&repo).build();
        let session = analyzer.compute_session();
        // Both files are new → both must be in to_rebuild.
        assert_eq!(session.to_rebuild.len(), 2);
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 5. Cross-file Imports
    // -----------------------------------------------------------------------

    #[test]
    fn test_python_import_parsing() {
        let src = "import os\nfrom sys import argv\nimport utils";
        let imps = parse_python_imports(&PathBuf::from("main.py"), src);
        let names: Vec<_> = imps.iter().map(|i| i.module_name.as_str()).collect();
        assert!(names.contains(&"os"));
        assert!(names.contains(&"sys"));
        assert!(names.contains(&"utils"));
    }

    #[test]
    fn test_java_import_and_package_parsing() {
        let src = "package com.example;\nimport java.util.List;\nimport java.io.File;";
        let imps = parse_java_imports(&PathBuf::from("Main.java"), src);
        assert_eq!(imps.len(), 2);
        let pkg = parse_java_package(src);
        assert_eq!(pkg, Some("com.example".to_string()));
    }

    #[test]
    fn test_cross_file_linker_module_map() {
        let repo = temp_repo("linker");
        write(&repo, "utils.py", "def foo(): pass");
        write(&repo, "main.py", "import utils");
        let files = RepositoryDiscovery::discover(&repo);
        let map = CrossFileLinker::build_module_map(&files);
        assert!(map.contains_key("utils"));
        assert!(map.contains_key("main"));
        cleanup(&repo);
    }

    #[test]
    fn test_cross_file_linker_resolve() {
        let repo = temp_repo("resolve");
        write(&repo, "utils.py", "pass");
        write(&repo, "main.py", "import utils");
        let files = RepositoryDiscovery::discover(&repo);
        let map = CrossFileLinker::build_module_map(&files);

        let mut graph = DependencyGraph::new();
        let imps = parse_python_imports(&repo.join("main.py"), "import utils");
        for imp in imps { graph.add_import(imp); }

        let resolved = CrossFileLinker::resolve(&graph, &map);
        let hit = resolved.iter().any(|r| {
            r.module_name == "utils" && r.resolved_file.is_some()
        });
        assert!(hit, "utils should resolve to utils.py");
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 6. Parallel Scheduling — deterministic output
    // -----------------------------------------------------------------------

    #[test]
    fn test_parallel_analysis_deterministic_output() {
        let repo = temp_repo("par");
        for i in 0..10 {
            write(&repo, &format!("file{:02}.py", i), &format!("x = {}", i));
        }

        let analyzer1 = WorkspaceBuilder::new(&repo).build();
        let session1 = analyzer1.compute_session();
        let (results1, _) = analyzer1.run_parallel(&session1);

        let analyzer2 = WorkspaceBuilder::new(&repo).build();
        let session2 = analyzer2.compute_session();
        let (results2, _) = analyzer2.run_parallel(&session2);

        let paths1: Vec<_> = results1.iter().map(|r| r.path().to_path_buf()).collect();
        let paths2: Vec<_> = results2.iter().map(|r| r.path().to_path_buf()).collect();
        assert_eq!(paths1, paths2, "Parallel results must be deterministic");
        cleanup(&repo);
    }

    #[test]
    fn test_analysis_results_are_sorted() {
        let repo = temp_repo("sorted");
        write(&repo, "z.py", "pass");
        write(&repo, "a.py", "pass");
        write(&repo, "m.py", "pass");
        let analyzer = WorkspaceBuilder::new(&repo).build();
        let session = analyzer.compute_session();
        let (results, _) = analyzer.run_parallel(&session);
        let paths: Vec<_> = results.iter().map(|r| r.path().to_path_buf()).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "run_parallel() must return results in path-sorted order");
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 7. Large Repository Simulation
    // -----------------------------------------------------------------------

    #[test]
    fn test_large_repository_simulation() {
        let repo = temp_repo("large");
        for i in 0..100 {
            write(&repo, &format!("mod{:03}.py", i), &format!("# module {}", i));
        }
        let analyzer = WorkspaceBuilder::new(&repo).build();
        assert_eq!(analyzer.graph.file_count(), 100);
        let session = analyzer.compute_session();
        assert_eq!(session.to_rebuild.len(), 100);
        assert_eq!(session.to_reuse.len(), 0);
        let (results, collector) = analyzer.run_parallel(&session);
        assert_eq!(results.len(), 100);
        assert!(results.iter().all(|r| r.is_rebuilt()));
        let metrics = collector.finalize();
        assert_eq!(metrics.files_analyzed, 100);
        assert_eq!(metrics.files_reused, 0);
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 8. Metrics
    // -----------------------------------------------------------------------

    #[test]
    fn test_metrics_collection() {
        let mut c = MetricsCollector::new();
        c.start_session();
        c.record_analyzed();
        c.record_analyzed();
        c.record_reused();
        c.end_session();
        let m = c.finalize();
        assert_eq!(m.files_analyzed, 2);
        assert_eq!(m.files_reused, 1);
        assert_eq!(m.files_total(), 3);
        assert!((m.cache_hit_rate - 1.0 / 3.0).abs() < 0.01);
        assert!(!m.summary().is_empty());
    }

    #[test]
    fn test_metrics_phase_timing() {
        let mut c = MetricsCollector::new();
        c.start_phase();
        c.end_phase_parse();
        c.start_phase();
        c.end_phase_semantic();
        c.start_phase();
        c.end_phase_solver();
        c.start_phase();
        c.end_phase_report();
        let m = c.finalize();
        // Timing values should be valid (>= 0, and all fields present).
        let _ = m.parse_time_ms;
        let _ = m.semantic_time_ms;
        let _ = m.solver_time_ms;
        let _ = m.report_time_ms;
    }

    // -----------------------------------------------------------------------
    // 9. AnalysisResult variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_analysis_result_variants() {
        let rebuilt = AnalysisResult::Rebuilt { path: PathBuf::from("a.py") };
        let cached  = AnalysisResult::Cached  { path: PathBuf::from("b.py") };
        let skipped = AnalysisResult::Skipped { path: PathBuf::from("c.py"), reason: "unsupported".into() };

        assert!(rebuilt.is_rebuilt());
        assert!(!rebuilt.is_cached());
        assert!(cached.is_cached());
        assert!(!cached.is_rebuilt());
        assert!(!skipped.is_rebuilt());
        assert!(!skipped.is_cached());
        assert_eq!(rebuilt.path(), PathBuf::from("a.py").as_path());
    }

    // -----------------------------------------------------------------------
    // 10. Scheduler integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_via_scheduler() {
        let repo = temp_repo("sched");
        write(&repo, "a.py", "x = 1");
        write(&repo, "b.py", "y = 2");
        let analyzer = WorkspaceBuilder::new(&repo).build();
        let session = analyzer.compute_session();
        assert_eq!(session.to_rebuild.len(), 2);

        let sched_results = analyzer.run_via_scheduler(&session, 2, |_, _| Ok(vec![]));
        assert_eq!(sched_results.len(), 2);
        assert!(sched_results.iter().all(|r| r.success));
        cleanup(&repo);
    }

    // -----------------------------------------------------------------------
    // 11. init()
    // -----------------------------------------------------------------------

    #[test]
    fn test_init() {
        init();
    }
}
