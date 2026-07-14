// taint/src/log_level.rs -- TaintFlow structured logging subsystem
//
// Controlled by the TAINTFLOW_LOG environment variable:
//
//   TAINTFLOW_LOG=off    -> final metrics only (silent analysis)
//   TAINTFLOW_LOG=info   -> progress + warnings + summary (DEFAULT)
//   TAINTFLOW_LOG=debug  -> + per-sample diagnostics
//   TAINTFLOW_LOG=trace  -> + full propagation traces (current behavior)
//
// Trace logging incurs zero formatting cost unless TRACE is enabled.

use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LogLevel {
    Off   = 0,
    Info  = 1,
    Debug = 2,
    Trace = 3,
}

static LEVEL: OnceLock<LogLevel> = OnceLock::new();

/// Returns the global log level, initialised once from TAINTFLOW_LOG.
/// Defaults to Info if the variable is absent or unrecognised.
#[inline]
pub fn get() -> LogLevel {
    *LEVEL.get_or_init(|| {
        match std::env::var("TAINTFLOW_LOG")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "off"   => LogLevel::Off,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _       => LogLevel::Info,
        }
    })
}

/// True when TRACE logging is active.
#[inline]
pub fn is_trace() -> bool { get() >= LogLevel::Trace }

/// True when DEBUG or higher is active.
#[inline]
pub fn is_debug() -> bool { get() >= LogLevel::Debug }

/// True when INFO or higher is active.
#[inline]
pub fn is_info()  -> bool { get() >= LogLevel::Info }
