use serde::{Deserialize, Serialize};
use std::time::Instant;

// ---------------------------------------------------------------------------
// AnalysisMetrics
// ---------------------------------------------------------------------------

/// Performance counters and timing breakdowns for one analysis session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    /// Files that were re-analyzed (cache miss or invalidation).
    pub files_analyzed: usize,
    /// Files that were loaded from cache (no changes detected).
    pub files_reused: usize,
    /// Fraction of total files that were served from cache [0.0, 1.0].
    pub cache_hit_rate: f64,
    /// Wall-clock duration of the entire session.
    pub total_time_ms: u64,
    /// Time spent in parse phases across all files.
    pub parse_time_ms: u64,
    /// Time spent in semantic analysis phases.
    pub semantic_time_ms: u64,
    /// Time spent in IFDS solver phases.
    pub solver_time_ms: u64,
    /// Time spent in report-generation phases.
    pub report_time_ms: u64,
    /// Approximate heap memory used during the session (bytes).
    pub memory_bytes_estimate: usize,
    /// Number of Rayon worker threads employed.
    pub threads_used: usize,
}

impl AnalysisMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn files_total(&self) -> usize {
        self.files_analyzed + self.files_reused
    }

    pub fn cache_hit_rate_pct(&self) -> f64 {
        self.cache_hit_rate * 100.0
    }

    pub fn summary(&self) -> String {
        format!(
            "Files: {} analyzed, {} cached ({:.1}% hit rate) | \
             Time: {}ms total (parse {}ms, semantic {}ms, solver {}ms, report {}ms) | \
             Threads: {}",
            self.files_analyzed,
            self.files_reused,
            self.cache_hit_rate_pct(),
            self.total_time_ms,
            self.parse_time_ms,
            self.semantic_time_ms,
            self.solver_time_ms,
            self.report_time_ms,
            self.threads_used,
        )
    }
}

// ---------------------------------------------------------------------------
// MetricsCollector
// ---------------------------------------------------------------------------

/// Accumulates timing and counter data during an analysis session.
pub struct MetricsCollector {
    pub metrics: AnalysisMetrics,
    session_start: Option<Instant>,
    phase_start: Option<Instant>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: AnalysisMetrics::new(),
            session_start: None,
            phase_start: None,
        }
    }

    // ------ session timing ------

    pub fn start_session(&mut self) {
        self.session_start = Some(Instant::now());
    }

    pub fn end_session(&mut self) {
        if let Some(t) = self.session_start.take() {
            self.metrics.total_time_ms = t.elapsed().as_millis() as u64;
        }
    }

    // ------ phase timing ------

    pub fn start_phase(&mut self) {
        self.phase_start = Some(Instant::now());
    }

    pub fn end_phase_parse(&mut self) {
        if let Some(t) = self.phase_start.take() {
            self.metrics.parse_time_ms += t.elapsed().as_millis() as u64;
        }
    }

    pub fn end_phase_semantic(&mut self) {
        if let Some(t) = self.phase_start.take() {
            self.metrics.semantic_time_ms += t.elapsed().as_millis() as u64;
        }
    }

    pub fn end_phase_solver(&mut self) {
        if let Some(t) = self.phase_start.take() {
            self.metrics.solver_time_ms += t.elapsed().as_millis() as u64;
        }
    }

    pub fn end_phase_report(&mut self) {
        if let Some(t) = self.phase_start.take() {
            self.metrics.report_time_ms += t.elapsed().as_millis() as u64;
        }
    }

    // ------ counters ------

    pub fn record_analyzed(&mut self) {
        self.metrics.files_analyzed += 1;
    }

    pub fn record_reused(&mut self) {
        self.metrics.files_reused += 1;
    }

    pub fn set_threads(&mut self, n: usize) {
        self.metrics.threads_used = n;
    }

    /// Compute derived metrics and return the final `AnalysisMetrics`.
    pub fn finalize(mut self) -> AnalysisMetrics {
        let total = self.metrics.files_total();
        if total > 0 {
            self.metrics.cache_hit_rate =
                self.metrics.files_reused as f64 / total as f64;
        }
        self.metrics
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
