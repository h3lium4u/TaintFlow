//! # TaintFlow M1 — External Model Registry
//!
//! Provides `ActiveModelRegistry`: a validated, deterministic, transactional
//! loader for external JSON model packs. Loaded packs extend the built-in
//! source/sink/sanitizer knowledge without modifying it.
//!
//! ## Version contract
//! - `ENGINE_VERSION = (1, 0, 0)` — the runtime engine version, matching
//!   `scan_version: "1.0.0"` in CLI JSON output. Do NOT use
//!   `env!("CARGO_PKG_VERSION")` (that returns the Cargo crate version "0.1.0").
//! - Pack field `min_engine_version` must be a plain semver string (no
//!   pre-release suffix). Major must match ENGINE_VERSION exactly; minor must
//!   be <= ENGINE_VERSION minor; patch is ignored.
//!
//! ## Matching policy (M1)
//! Tier 1: exact qualified match — `callee_lower == rule_callee_lower`
//! Tier 2: exact unqualified method match —
//!         `callee.rsplit('.').next().unwrap() == rule_callee_lower`
//! No substring / contains matching is implemented in M1.
//! Within each tier rules are ordered by (pack_file_name_asc, entry_index_asc).
//! First match wins.
//!
//! ## Supported languages
//! "java", "python", "any". "javascript" and "go" are rejected at load time.
//!
//! ## Safety invariant
//! External sanitizer metadata is stored in `TaintState::external_sanitized_for`
//! (a new field). Built-in sink suppression reads ONLY `sanitized_for`.
//! External sinks read ONLY `external_sanitized_for` (and `sanitized_for`).
//! The two fields are never mixed.

use crate::CWE;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ─── Engine version ───────────────────────────────────────────────────────────

/// Runtime engine compatibility version.
/// Must match `scan_version: "1.0.0"` in `crates/cli/src/main.rs`.
/// Do NOT use `env!("CARGO_PKG_VERSION")` — that returns "0.1.0".
pub const ENGINE_VERSION: (u32, u32, u32) = (1, 0, 0);

// ─── Limits ───────────────────────────────────────────────────────────────────

pub const MAX_PACK_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB per file
pub const MAX_ENTRIES_PER_PACK: usize = 500;
pub const MAX_CALLEE_LEN: usize = 512;
pub const MAX_PACK_ID_LEN: usize = 128;

// ─── Deserialisation types ────────────────────────────────────────────────────

/// Raw JSON shape of a model pack file.
#[derive(Debug, Deserialize)]
pub struct RawPack {
    pub schema_version: u32,
    pub pack_id: String,
    pub min_engine_version: String,
    pub entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
pub struct RawEntry {
    pub id: String,
    pub kind: String,
    pub callee: String,
    #[serde(default)]
    pub cwe: String,
    pub languages: Vec<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub arg_indices: Vec<usize>,
    #[serde(default)]
    pub input_args: Vec<usize>,
    #[serde(default)]
    pub propagates_to: Option<String>,
}

// ─── Internal normalised types ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationTarget {
    Return,
    Receiver,
}

/// A compiled, validated model entry ready for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEntry {
    pub id: String,
    pub kind: ModelKind,
    /// Lowercased callee string as written in the pack.
    pub callee_lower: String,
    /// Lowercased unqualified method part (last `.`-segment).
    pub callee_method_lower: String,
    pub cwe: CWE,
    /// Languages this entry applies to.
    pub languages: Vec<String>,
    pub severity: &'static str,
    pub arg_indices: Vec<usize>,
    pub input_args: Vec<usize>,
    pub propagates_to: PropagationTarget,
    /// Origin — used for deterministic tie-breaking.
    pub pack_id: String,
    pub entry_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelKind {
    Source,
    Sink,
    Sanitizer,
    Propagator,
}

/// Return value from a successful external sink match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedSink {
    pub cwe: CWE,
    pub severity: &'static str,
    pub arg_indices: Vec<usize>,
}

/// Return value from a successful external sanitizer match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedSanitizer {
    pub cwes: HashSet<CWE>,
    pub arg_indices: Vec<usize>,
}

/// Return value from a successful external propagator match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedPropagator {
    pub input_args: Vec<usize>,
    pub propagates_to: PropagationTarget,
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// The active external model registry.
///
/// Built transactionally: a pack is either fully loaded or fully rejected.
/// Rules are stored in deterministic order (pack filename ascending, then
/// entry index ascending within a pack).
#[derive(Debug, Clone, Default)]
pub struct ActiveModelRegistry {
    pub entries: Vec<ModelEntry>,
}

impl ActiveModelRegistry {
    /// Create an empty registry (no external models loaded).
    pub fn new() -> Self {
        Self::default()
    }

    /// Load all `.json` files from `dir`, sorted by filename (UTF-8 byte order).
    /// Each file is validated fully before any entry is committed.
    /// Failures are written to stderr; the registry continues with valid packs.
    pub fn load_from_dir(dir: &Path) -> Self {
        let mut registry = Self::new();

        let mut paths: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
                .collect(),
            Err(e) => {
                eprintln!("[taintflow models] Cannot read models dir {:?}: {}", dir, e);
                return registry;
            }
        };
        paths.sort();

        for path in &paths {
            match Self::load_pack(path) {
                Ok(entries) => {
                    let count = entries.len();
                    registry.entries.extend(entries);
                    eprintln!(
                        "[taintflow models] Loaded pack {:?} ({} entries)",
                        path.file_name().unwrap_or_default(),
                        count
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[taintflow models] Rejected pack {:?}: {}",
                        path.file_name().unwrap_or_default(),
                        e
                    );
                }
            }
        }

        eprintln!(
            "[taintflow models] Registry ready: {} external entries from {} pack(s)",
            registry.entries.len(),
            paths.len()
        );
        registry
    }

    /// Load and validate a single pack file. Returns `Err` if anything is invalid.
    /// Does NOT mutate the registry (caller decides whether to commit).
    pub fn load_pack(path: &Path) -> Result<Vec<ModelEntry>, String> {
        let meta = std::fs::metadata(path).map_err(|e| format!("Cannot stat file: {}", e))?;
        if meta.len() > MAX_PACK_FILE_BYTES {
            return Err(format!(
                "File too large ({} bytes; limit {})",
                meta.len(),
                MAX_PACK_FILE_BYTES
            ));
        }

        let text = std::fs::read_to_string(path).map_err(|e| format!("Cannot read file: {}", e))?;

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        Self::load_pack_from_str(&text, &file_name)
    }

    /// Load and validate a pack from JSON string directly.
    /// Transactional: fails atomically if any field or entry is invalid.
    pub fn load_pack_from_str(text: &str, file_name: &str) -> Result<Vec<ModelEntry>, String> {
        if text.len() as u64 > MAX_PACK_FILE_BYTES {
            return Err(format!(
                "Text too large ({} bytes; limit {})",
                text.len(),
                MAX_PACK_FILE_BYTES
            ));
        }

        let raw: RawPack =
            serde_json::from_str(text).map_err(|e| format!("JSON parse error: {}", e))?;

        // schema_version
        if raw.schema_version != 1 {
            return Err(format!(
                "Unsupported schema_version {}; expected 1",
                raw.schema_version
            ));
        }

        // pack_id
        validate_pack_id(&raw.pack_id)?;

        // min_engine_version
        validate_engine_version(&raw.min_engine_version)?;

        // entry count
        if raw.entries.is_empty() {
            return Err("Pack has no entries".to_string());
        }
        if raw.entries.len() > MAX_ENTRIES_PER_PACK {
            return Err(format!(
                "Too many entries ({}/{})",
                raw.entries.len(),
                MAX_ENTRIES_PER_PACK
            ));
        }

        // Duplicate ID check within pack (sort + dedup)
        let mut ids: Vec<&str> = raw.entries.iter().map(|e| e.id.as_str()).collect();
        ids.sort_unstable();
        for w in ids.windows(2) {
            if w[0] == w[1] {
                return Err(format!("Duplicate entry id '{}'", w[0]));
            }
        }

        // Compile entries
        let pack_id = raw.pack_id.clone();
        let mut entries = Vec::with_capacity(raw.entries.len());
        for (idx, raw_entry) in raw.entries.into_iter().enumerate() {
            let entry = compile_entry(raw_entry, &pack_id, file_name, idx)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Returns `true` if the registry has no external entries (empty registry).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Match an external sink by callee string and language.
    /// Returns the first match using 2-tier deterministic precedence.
    ///
    /// Tier 1: exact qualified (`callee_lower == rule.callee_lower`)
    /// Tier 2: exact unqualified method (`callee_method == rule.callee_lower`)
    ///
    /// Within each tier, order is (pack_filename_asc, entry_index_asc).
    pub fn match_sink(&self, callee: &str, language: &str) -> Option<MatchedSink> {
        let callee_clean = callee.replace('"', "").replace('\'', "");
        let callee_lower = callee_clean.to_lowercase();
        let callee_method = callee_lower
            .rsplit('.')
            .next()
            .unwrap_or(&callee_lower)
            .to_string();
        let lang_lower = language.to_lowercase();

        let sinks: Vec<&ModelEntry> = self
            .entries
            .iter()
            .filter(|e| e.kind == ModelKind::Sink && language_matches(&e.languages, &lang_lower))
            .collect();

        // Tier 1 — exact qualified
        for e in &sinks {
            if callee_lower == e.callee_lower {
                return Some(MatchedSink {
                    cwe: e.cwe,
                    severity: e.severity,
                    arg_indices: e.arg_indices.clone(),
                });
            }
        }

        // Tier 2 — exact unqualified method
        for e in &sinks {
            if callee_method == e.callee_lower {
                return Some(MatchedSink {
                    cwe: e.cwe,
                    severity: e.severity,
                    arg_indices: e.arg_indices.clone(),
                });
            }
        }

        None
    }

    /// Match an external sanitizer by callee string and language.
    /// Returns covered CWEs and arg_indices.
    pub fn match_sanitizer(&self, callee: &str, language: &str) -> Option<MatchedSanitizer> {
        let callee_clean = callee.replace('"', "").replace('\'', "");
        let callee_lower = callee_clean.to_lowercase();
        let callee_method = callee_lower
            .rsplit('.')
            .next()
            .unwrap_or(&callee_lower)
            .to_string();
        let lang_lower = language.to_lowercase();

        let sanitizers: Vec<&ModelEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.kind == ModelKind::Sanitizer && language_matches(&e.languages, &lang_lower)
            })
            .collect();

        // Tier 1 — exact qualified
        for e in &sanitizers {
            if callee_lower == e.callee_lower {
                let mut cwes = HashSet::new();
                cwes.insert(e.cwe);
                return Some(MatchedSanitizer {
                    cwes,
                    arg_indices: e.arg_indices.clone(),
                });
            }
        }

        // Tier 2 — exact unqualified method
        for e in &sanitizers {
            if callee_method == e.callee_lower {
                let mut cwes = HashSet::new();
                cwes.insert(e.cwe);
                return Some(MatchedSanitizer {
                    cwes,
                    arg_indices: e.arg_indices.clone(),
                });
            }
        }

        None
    }

    /// Match an external source by raw expression and language.
    pub fn match_source(&self, expression: &str, language: &str) -> bool {
        let expr_clean = expression.replace('"', "").replace('\'', "");
        let expr_no_args = if let Some(idx) = expr_clean.find('(') {
            expr_clean[..idx].trim()
        } else {
            expr_clean.trim()
        };
        let expr_lower = expr_no_args.to_lowercase();
        let expr_method = expr_lower
            .rsplit('.')
            .next()
            .unwrap_or(&expr_lower)
            .to_string();
        let lang_lower = language.to_lowercase();

        let sources: Vec<&ModelEntry> = self
            .entries
            .iter()
            .filter(|e| e.kind == ModelKind::Source && language_matches(&e.languages, &lang_lower))
            .collect();

        // Tier 1 — exact qualified match
        for e in &sources {
            if expr_lower == e.callee_lower {
                return true;
            }
        }
        // Tier 2 — exact unqualified method match
        for e in &sources {
            if expr_method == e.callee_lower || expr_method == e.callee_method_lower {
                return true;
            }
        }

        false
    }

    /// Match an external propagator by callee string and language.
    /// Returns the first matching propagator using 2-tier deterministic precedence.
    ///
    /// Tier 1: exact qualified (`callee_lower == rule.callee_lower`)
    /// Tier 2: exact unqualified method (`callee_method == rule.callee_lower` or `callee_method_lower`)
    pub fn match_propagator(&self, callee: &str, language: &str) -> Option<MatchedPropagator> {
        let callee_clean = callee.replace('"', "").replace('\'', "");
        let callee_lower = callee_clean.to_lowercase();
        let callee_method = callee_lower
            .rsplit('.')
            .next()
            .unwrap_or(&callee_lower)
            .to_string();
        let lang_lower = language.to_lowercase();

        let propagators: Vec<&ModelEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.kind == ModelKind::Propagator && language_matches(&e.languages, &lang_lower)
            })
            .collect();

        // Tier 1 — exact qualified
        for e in &propagators {
            if callee_lower == e.callee_lower {
                return Some(MatchedPropagator {
                    input_args: e.input_args.clone(),
                    propagates_to: e.propagates_to,
                });
            }
        }

        // Tier 2 — exact unqualified method
        for e in &propagators {
            if callee_method == e.callee_lower {
                return Some(MatchedPropagator {
                    input_args: e.input_args.clone(),
                    propagates_to: e.propagates_to,
                });
            }
        }

        None
    }
}

// ─── Validation helpers ───────────────────────────────────────────────────────

pub fn validate_pack_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("pack_id is empty".to_string());
    }
    if id.len() > MAX_PACK_ID_LEN {
        return Err(format!("pack_id too long ({} chars)", id.len()));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(format!("pack_id '{}' contains invalid characters", id));
    }
    Ok(())
}

/// Validate `min_engine_version` and check compatibility with `ENGINE_VERSION`.
pub fn validate_engine_version(version_str: &str) -> Result<(), String> {
    let parts: Vec<&str> = version_str.splitn(4, '.').collect();
    if parts.len() < 3 {
        return Err(format!(
            "Invalid min_engine_version '{}': must be MAJOR.MINOR.PATCH",
            version_str
        ));
    }
    let patch_str = parts[2];
    if patch_str.contains('-') || patch_str.contains('+') {
        return Err(format!(
            "Pre-release versions are not permitted in min_engine_version: '{}'",
            version_str
        ));
    }
    if parts.len() > 3 {
        return Err(format!(
            "Invalid min_engine_version '{}': too many version components",
            version_str
        ));
    }

    let major: u32 = parts[0]
        .parse()
        .map_err(|_| format!("Invalid major in min_engine_version '{}'", version_str))?;
    let minor: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid minor in min_engine_version '{}'", version_str))?;
    let _patch: u32 = parts[2]
        .parse()
        .map_err(|_| format!("Invalid patch in min_engine_version '{}'", version_str))?;

    if major != ENGINE_VERSION.0 {
        return Err(format!(
            "Incompatible major version: pack requires {}, engine is {}.{}.{}",
            major, ENGINE_VERSION.0, ENGINE_VERSION.1, ENGINE_VERSION.2
        ));
    }
    if minor > ENGINE_VERSION.1 {
        return Err(format!(
            "Engine too old: pack requires minor {}, engine has minor {}",
            minor, ENGINE_VERSION.1
        ));
    }

    Ok(())
}

pub fn compile_entry(
    raw: RawEntry,
    pack_id: &str,
    _file_name: &str,
    idx: usize,
) -> Result<ModelEntry, String> {
    if raw.id.is_empty() {
        return Err(format!("Entry {} has empty id", idx));
    }

    let kind = match raw.kind.as_str() {
        "source" => ModelKind::Source,
        "sink" => ModelKind::Sink,
        "sanitizer" => ModelKind::Sanitizer,
        "propagator" => ModelKind::Propagator,
        other => return Err(format!("Entry '{}': unknown kind '{}'", raw.id, other)),
    };

    if raw.callee.is_empty() {
        return Err(format!("Entry '{}': callee is empty", raw.id));
    }
    if raw.callee.len() > MAX_CALLEE_LEN {
        return Err(format!(
            "Entry '{}': callee too long ({} chars)",
            raw.id,
            raw.callee.len()
        ));
    }
    let callee_clean = raw.callee.replace('"', "").replace('\'', "");
    let callee_lower = callee_clean.to_lowercase();
    let callee_method_lower = callee_lower
        .rsplit('.')
        .next()
        .unwrap_or(&callee_lower)
        .to_string();

    let cwe = if kind == ModelKind::Propagator && raw.cwe.is_empty() {
        CWE::CWE89
    } else {
        parse_cwe(&raw.cwe)
            .ok_or_else(|| format!("Entry '{}': unknown CWE '{}'", raw.id, raw.cwe))?
    };

    let mut languages = Vec::new();
    for lang in &raw.languages {
        match lang.to_lowercase().as_str() {
            "java" => languages.push("java".to_string()),
            "python" => languages.push("python".to_string()),
            "any" => languages.push("any".to_string()),
            "javascript" | "go" => {
                return Err(format!(
                    "Entry '{}': language '{}' is not supported in M1 (only java, python, any)",
                    raw.id, lang
                ))
            }
            other => return Err(format!("Entry '{}': unknown language '{}'", raw.id, other)),
        }
    }
    if languages.is_empty() {
        return Err(format!("Entry '{}': languages list is empty", raw.id));
    }

    let severity = if kind == ModelKind::Propagator && raw.severity.is_empty() {
        "MEDIUM"
    } else {
        parse_severity(&raw.severity)
            .ok_or_else(|| format!("Entry '{}': unknown severity '{}'", raw.id, raw.severity))?
    };

    let input_args = if !raw.input_args.is_empty() {
        raw.input_args
    } else {
        raw.arg_indices.clone()
    };

    let propagates_to = match raw.propagates_to.as_deref() {
        Some("receiver") => PropagationTarget::Receiver,
        Some("return") | None => PropagationTarget::Return,
        Some(other) => {
            return Err(format!(
                "Entry '{}': unknown propagates_to '{}' (expected 'return' or 'receiver')",
                raw.id, other
            ))
        }
    };

    Ok(ModelEntry {
        id: raw.id,
        kind,
        callee_lower,
        callee_method_lower,
        cwe,
        languages,
        severity,
        arg_indices: raw.arg_indices,
        input_args,
        propagates_to,
        pack_id: pack_id.to_string(),
        entry_index: idx,
    })
}

pub fn parse_cwe(s: &str) -> Option<CWE> {
    let norm = s.to_uppercase().replace('-', "").replace('_', "");
    match norm.as_str() {
        "CWE22" => Some(CWE::CWE22),
        "CWE78" => Some(CWE::CWE78),
        "CWE79" => Some(CWE::CWE79),
        "CWE89" => Some(CWE::CWE89),
        "CWE90" => Some(CWE::CWE90),
        "CWE113" => Some(CWE::CWE113),
        "CWE327" => Some(CWE::CWE327),
        "CWE328" => Some(CWE::CWE328),
        "CWE330" => Some(CWE::CWE330),
        "CWE338" => Some(CWE::CWE338),
        "CWE400" => Some(CWE::CWE400),
        "CWE501" => Some(CWE::CWE501),
        "CWE502" => Some(CWE::CWE502),
        "CWE601" => Some(CWE::CWE601),
        "CWE614" => Some(CWE::CWE614),
        "CWE643" => Some(CWE::CWE643),
        "CWE798" => Some(CWE::CWE798),
        "CWE918" => Some(CWE::CWE918),
        _ => None,
    }
}

pub fn parse_severity(s: &str) -> Option<&'static str> {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Some("CRITICAL"),
        "HIGH" => Some("HIGH"),
        "MEDIUM" => Some("MEDIUM"),
        "LOW" => Some("LOW"),
        _ => None,
    }
}

pub fn language_matches(languages: &[String], language: &str) -> bool {
    languages.iter().any(|l| l == "any" || l == language)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Version validation ─────────────────────────────────────────────────

    #[test]
    fn test_version_exact_ok() {
        assert!(validate_engine_version("1.0.0").is_ok());
    }

    #[test]
    fn test_version_patch_ignored() {
        assert!(validate_engine_version("1.0.5").is_ok());
    }

    #[test]
    fn test_version_minor_too_new() {
        assert!(validate_engine_version("1.1.0").is_err());
    }

    #[test]
    fn test_version_major_mismatch_higher() {
        assert!(validate_engine_version("2.0.0").is_err());
    }

    #[test]
    fn test_version_major_mismatch_lower() {
        // Cargo version "0.1.0" must not be mistakenly accepted
        assert!(validate_engine_version("0.1.0").is_err());
    }

    #[test]
    fn test_version_prerelease_rejected() {
        assert!(validate_engine_version("1.0.0-alpha").is_err());
        assert!(validate_engine_version("1.0.0+build123").is_err());
    }

    #[test]
    fn test_version_invalid_str() {
        assert!(validate_engine_version("abc").is_err());
        assert!(validate_engine_version("1.0").is_err());
        assert!(validate_engine_version("1.0.0.0").is_err());
    }

    // ── Matching — exact qualified ─────────────────────────────────────────

    #[test]
    fn test_match_sink_exact_qualified() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        let m = reg.match_sink("CustomDb.rawExec", "java");
        assert!(m.is_some(), "Should match exact qualified callee");
        assert_eq!(m.unwrap().cwe, CWE::CWE89);
    }

    #[test]
    fn test_match_sink_case_insensitive() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        let m = reg.match_sink("customdb.rawexec", "java");
        assert!(m.is_some(), "Should match case-insensitively");
    }

    // ── Matching — negative controls ───────────────────────────────────────

    #[test]
    fn test_no_match_different_class() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        let m = reg.match_sink("MyCustomDb.rawExec", "java");
        assert!(
            m.is_none(),
            "Different class should not match qualified rule"
        );
    }

    #[test]
    fn test_no_match_suffix_method() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        let m = reg.match_sink("CustomDb.rawExecFast", "java");
        assert!(m.is_none(), "Suffix method should not match");
    }

    #[test]
    fn test_no_match_wrong_language() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        let m = reg.match_sink("CustomDb.rawExec", "python");
        assert!(m.is_none(), "Wrong language should not match");
    }

    #[test]
    fn test_any_language_matches_java_and_python() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "CustomDb.rawExec",
      "cwe": "CWE89",
      "languages": ["any"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        assert!(reg.match_sink("CustomDb.rawExec", "java").is_some());
        assert!(reg.match_sink("CustomDb.rawExec", "python").is_some());
    }

    // ── Validation — language rejection ───────────────────────────────────

    #[test]
    fn test_javascript_language_rejected() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "eval",
      "cwe": "CWE79",
      "languages": ["javascript"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let result = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json");
        assert!(result.is_err(), "javascript must be rejected in M1");
    }

    #[test]
    fn test_go_language_rejected() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "db.Query",
      "cwe": "CWE89",
      "languages": ["go"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        let result = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json");
        assert!(result.is_err(), "go must be rejected in M1");
    }

    // ── Validation — schema ────────────────────────────────────────────────

    #[test]
    fn test_wrong_schema_version() {
        let pack_json = r#"{
  "schema_version": 2,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "db.query",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        assert!(ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").is_err());
    }

    #[test]
    fn test_duplicate_entry_id_rejected() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "db.query",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    },
    {
      "id": "s1",
      "kind": "sink",
      "callee": "db.execute",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        assert!(ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").is_err());
    }

    #[test]
    fn test_unknown_cwe_rejected() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "db.query",
      "cwe": "CWE9999",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": [0]
    }
  ]
}"#;
        assert!(ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").is_err());
    }

    #[test]
    fn test_empty_registry_is_empty() {
        let reg = ActiveModelRegistry::new();
        assert!(reg.is_empty());
        assert!(reg.match_sink("anything", "java").is_none());
        assert!(reg.match_sanitizer("anything", "java").is_none());
    }

    // ── Severity propagation ───────────────────────────────────────────────

    #[test]
    fn test_severity_propagated() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "s1",
      "kind": "sink",
      "callee": "DangerSink.exec",
      "cwe": "CWE78",
      "languages": ["java"],
      "severity": "CRITICAL",
      "arg_indices": [0]
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;
        let m = reg.match_sink("DangerSink.exec", "java").unwrap();
        assert_eq!(m.severity, "CRITICAL");
    }

    // ── Sanitizer matching ─────────────────────────────────────────────────

    #[test]
    fn test_sanitizer_match() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "san1",
      "kind": "sanitizer",
      "callee": "ExtSan.clean",
      "cwe": "CWE89",
      "languages": ["java"],
      "severity": "HIGH",
      "arg_indices": []
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;
        let m = reg.match_sanitizer("ExtSan.clean", "java");
        assert!(m.is_some());
        assert!(m.unwrap().cwes.contains(&CWE::CWE89));
    }

    // ── Propagator matching (M2) ───────────────────────────────────────────

    #[test]
    fn test_propagator_match_exact_qualified() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop1",
      "kind": "propagator",
      "callee": "StringUtils.join",
      "languages": ["java"],
      "input_args": [0],
      "propagates_to": "return"
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;
        let m = reg.match_propagator("StringUtils.join", "java");
        assert!(m.is_some(), "Should match exact qualified propagator");
        let matched = m.unwrap();
        assert_eq!(matched.input_args, vec![0]);
        assert_eq!(matched.propagates_to, PropagationTarget::Return);
    }

    #[test]
    fn test_propagator_match_unqualified() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop1",
      "kind": "propagator",
      "callee": "custom_transform",
      "languages": ["python"],
      "input_args": [1],
      "propagates_to": "return"
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;
        let m = reg.match_propagator("module.custom_transform", "python");
        assert!(
            m.is_some(),
            "Should match unqualified method part of propagator"
        );
        let matched = m.unwrap();
        assert_eq!(matched.input_args, vec![1]);
    }

    #[test]
    fn test_propagator_receiver_target() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop1",
      "kind": "propagator",
      "callee": "CustomBuilder.appendData",
      "languages": ["java"],
      "input_args": [0],
      "propagates_to": "receiver"
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;
        let m = reg.match_propagator("CustomBuilder.appendData", "java");
        assert!(m.is_some());
        assert_eq!(m.unwrap().propagates_to, PropagationTarget::Receiver);
    }

    #[test]
    fn test_propagator_unknown_target_rejected() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop1",
      "kind": "propagator",
      "callee": "test.foo",
      "languages": ["java"],
      "input_args": [0],
      "propagates_to": "invalid_target"
    }
  ]
}"#;
        assert!(ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").is_err());
    }

    #[test]
    fn test_propagator_no_match_different_class() {
        let pack_json = r#"{
  "schema_version": 1,
  "pack_id": "test-pack",
  "min_engine_version": "1.0.0",
  "entries": [
    {
      "id": "prop1",
      "kind": "propagator",
      "callee": "CustomUtils.transform",
      "languages": ["java"],
      "input_args": [0],
      "propagates_to": "return"
    }
  ]
}"#;
        let entries = ActiveModelRegistry::load_pack_from_str(pack_json, "test.json").unwrap();
        let mut reg = ActiveModelRegistry::new();
        reg.entries = entries;

        // Unrelated class method with same method name must NOT match qualified propagator
        assert!(reg
            .match_propagator("OtherClass.transform", "java")
            .is_none());
        assert!(reg.match_propagator("thread.transform", "java").is_none());

        // Exact qualified call MUST match
        assert!(reg
            .match_propagator("CustomUtils.transform", "java")
            .is_some());
    }
}
