use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Directory names that are always excluded from repository discovery.
pub const IGNORED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "venv",
    "__pycache__",
    "dist",
    "build",
];

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// Programming language detected from file extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    Python,
    Java,
    Unknown(String),
}

impl Language {
    /// Future-extension hook: returns true if this language has a registered analyser.
    pub fn is_supported(&self) -> bool {
        matches!(self, Language::Python | Language::Java)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Language::Python => "python",
            Language::Java => "java",
            Language::Unknown(ext) => ext.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// DiscoveredFile
// ---------------------------------------------------------------------------

/// A single source file found during repository discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub language: Language,
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// RepositoryDiscovery
// ---------------------------------------------------------------------------

/// Recursively discovers source files in a repository, honouring ignore rules.
pub struct RepositoryDiscovery;

impl RepositoryDiscovery {
    /// Walk `root` recursively and return all supported source files,
    /// sorted by path for a deterministic result.
    pub fn discover(root: &Path) -> Vec<DiscoveredFile> {
        let mut files = Vec::new();
        Self::walk(root, &mut files);
        files.sort_by(|a, b| a.path.cmp(&b.path));
        files
    }

    /// Detect the language of a file from its extension.
    pub fn detect_language(path: &Path) -> Language {
        match path.extension().and_then(|e| e.to_str()) {
            Some("py") => Language::Python,
            Some("java") => Language::Java,
            Some(ext) => Language::Unknown(ext.to_string()),
            None => Language::Unknown(String::new()),
        }
    }

    /// Filter a file list to only those of a given language.
    pub fn filter_by_language<'a>(files: &'a [DiscoveredFile], lang: &Language) -> Vec<&'a DiscoveredFile> {
        files.iter().filter(|f| &f.language == lang).collect()
    }

    fn walk(dir: &Path, out: &mut Vec<DiscoveredFile>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if path.is_dir() {
                if !IGNORED_DIRS.contains(&name) {
                    Self::walk(&path, out);
                }
            } else if path.is_file() {
                let language = Self::detect_language(&path);
                if language.is_supported() {
                    let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    out.push(DiscoveredFile { path, language, size_bytes });
                }
            }
        }
    }
}
