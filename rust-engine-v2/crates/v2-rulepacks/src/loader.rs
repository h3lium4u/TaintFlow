use std::path::Path;
use v2_rules::{RulePack, RuleRegistry};

// ---------------------------------------------------------------------------
// RulePackLoader
// ---------------------------------------------------------------------------

/// Loads rule packs from embedded definitions, JSON strings, or JSON files.
/// YAML and plugin packs are reserved for future language-plugin extensions.
pub struct RulePackLoader;

impl RulePackLoader {
    // ------------------------------------------------------------------
    // Embedded packs
    // ------------------------------------------------------------------

    /// Build a `RuleRegistry` populated with all embedded enterprise packs.
    pub fn all_embedded() -> RuleRegistry {
        let mut registry = RuleRegistry::new();
        for pack in crate::packs::all_packs() {
            registry.load(&pack);
        }
        registry
    }

    /// Build a `RuleRegistry` from a selection of named embedded packs.
    /// Unknown names are silently ignored.
    pub fn embedded_by_names(names: &[&str]) -> RuleRegistry {
        let mut registry = RuleRegistry::new();
        for pack in crate::packs::all_packs() {
            if names.contains(&pack.name.as_str()) {
                registry.load(&pack);
            }
        }
        registry
    }

    // ------------------------------------------------------------------
    // JSON loading
    // ------------------------------------------------------------------

    /// Deserialise a `RulePack` from a JSON string.
    pub fn from_json(json: &str) -> Result<RulePack, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Load a `RulePack` from a JSON file on disk.
    pub fn from_json_file(path: &Path) -> std::io::Result<RulePack> {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Deserialise a `RulePack` from JSON and load it into a fresh registry.
    pub fn registry_from_json(json: &str) -> Result<RuleRegistry, serde_json::Error> {
        let pack = serde_json::from_str::<RulePack>(json)?;
        let mut registry = RuleRegistry::new();
        registry.load(&pack);
        Ok(registry)
    }

    // ------------------------------------------------------------------
    // Language-specific helpers
    // ------------------------------------------------------------------

    /// Registry containing only Python rules.
    pub fn python_only() -> RuleRegistry {
        Self::embedded_by_names(&["python", "core", "web", "database", "filesystem",
                                   "deserialization", "cryptography", "ssrf",
                                   "command-injection", "xxe", "secrets", "authentication"])
    }

    /// Registry containing only Java rules.
    pub fn java_only() -> RuleRegistry {
        Self::embedded_by_names(&["java", "core", "web", "database", "filesystem",
                                   "deserialization", "cryptography", "ssrf",
                                   "command-injection", "xxe", "secrets", "authentication"])
    }
}
