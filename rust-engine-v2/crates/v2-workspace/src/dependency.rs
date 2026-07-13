use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

/// A symbolic import made by one source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub from_file: PathBuf,
    pub module_name: String,
    pub alias: Option<String>,
}

// ---------------------------------------------------------------------------
// DependencyGraph
// ---------------------------------------------------------------------------

/// Repository-level dependency graph.
/// Maps source files to their imports, and module names to the files that
/// export them, enabling reverse-dependency (dependent) lookups.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// file → list of imports that file makes.
    pub imports: HashMap<PathBuf, Vec<Import>>,
    /// module_name → file that declares/exports that module.
    pub exports: HashMap<String, PathBuf>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_import(&mut self, imp: Import) {
        self.imports.entry(imp.from_file.clone()).or_default().push(imp);
    }

    pub fn add_export(&mut self, module_name: String, file: PathBuf) {
        self.exports.insert(module_name, file);
    }

    /// Returns every file that directly imports from `file`.
    pub fn dependents_of(&self, file: &Path) -> Vec<&PathBuf> {
        let exported_names: Vec<&String> = self.exports.iter()
            .filter(|(_, p)| p.as_path() == file)
            .map(|(name, _)| name)
            .collect();

        self.imports.iter()
            .filter(|(_, imps)| {
                imps.iter().any(|imp| exported_names.contains(&&imp.module_name))
            })
            .map(|(f, _)| f)
            .collect()
    }

    /// Returns every file that `file` imports from (resolved to file paths).
    pub fn dependencies_of(&self, file: &Path) -> Vec<PathBuf> {
        self.imports.get(file)
            .map(|imps| {
                imps.iter()
                    .filter_map(|imp| self.exports.get(&imp.module_name))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All files known to have at least one import.
    pub fn all_importing_files(&self) -> impl Iterator<Item = &PathBuf> {
        self.imports.keys()
    }
}

// ---------------------------------------------------------------------------
// Language-specific import parsers
// ---------------------------------------------------------------------------

/// Parse Python `import X` and `from X import Y` statements.
pub fn parse_python_imports(file: &Path, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("import ") {
            // `import foo` or `import foo as bar`
            let module = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(',');
            if !module.is_empty() {
                imports.push(Import {
                    from_file: file.to_path_buf(),
                    module_name: module.to_string(),
                    alias: None,
                });
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            // `from foo import bar`
            let module = rest.split_whitespace().next().unwrap_or("");
            if !module.is_empty() {
                imports.push(Import {
                    from_file: file.to_path_buf(),
                    module_name: module.to_string(),
                    alias: None,
                });
            }
        }
    }
    imports
}

/// Parse Java `package` declaration.
pub fn parse_java_package(source: &str) -> Option<String> {
    for line in source.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("package ") {
            return Some(rest.trim_end_matches(';').trim().to_string());
        }
    }
    None
}

/// Parse Java `import` statements.
pub fn parse_java_imports(file: &Path, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("import ") {
            let module = rest.trim_end_matches(';').trim();
            if !module.is_empty() {
                imports.push(Import {
                    from_file: file.to_path_buf(),
                    module_name: module.to_string(),
                    alias: None,
                });
            }
        }
    }
    imports
}
