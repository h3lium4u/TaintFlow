use std::collections::HashMap;
use std::path::{Path, PathBuf};
use crate::dependency::DependencyGraph;
use crate::discovery::{DiscoveredFile, Language};

// ---------------------------------------------------------------------------
// ResolvedImport
// ---------------------------------------------------------------------------

/// An import whose symbolic module name has been resolved to a concrete file.
#[derive(Debug, Clone)]
pub struct ResolvedImport {
    pub from_file: PathBuf,
    pub module_name: String,
    /// `None` if the module was not found in the repository.
    pub resolved_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// CrossFileLinker
// ---------------------------------------------------------------------------

/// Resolves symbolic imports to concrete file paths within the repository.
pub struct CrossFileLinker;

impl CrossFileLinker {
    /// Build a `module_name → file_path` map from all discovered files.
    pub fn build_module_map(files: &[DiscoveredFile]) -> HashMap<String, PathBuf> {
        let mut map = HashMap::new();
        for file in files {
            if let Some(name) = Self::module_name_for(&file.path, &file.language) {
                map.insert(name, file.path.clone());
            }
        }
        map
    }

    /// Derive the module/class name for a file (language-dependent).
    pub fn module_name_for(path: &Path, lang: &Language) -> Option<String> {
        let stem = path.file_stem()?.to_str()?.to_string();
        match lang {
            Language::Python | Language::Java => Some(stem),
            Language::Unknown(_) => None,
        }
    }

    /// Resolve all imports in `graph` against the `module_map`.
    pub fn resolve(
        graph: &DependencyGraph,
        module_map: &HashMap<String, PathBuf>,
    ) -> Vec<ResolvedImport> {
        let mut resolved = Vec::new();
        for imps in graph.imports.values() {
            for imp in imps {
                // Exact key match first; then try the rightmost dotted component.
                let resolved_file = module_map
                    .get(&imp.module_name)
                    .cloned()
                    .or_else(|| {
                        let stem = imp.module_name.rsplit('.').next().unwrap_or(&imp.module_name);
                        module_map.get(stem).cloned()
                    });
                resolved.push(ResolvedImport {
                    from_file: imp.from_file.clone(),
                    module_name: imp.module_name.clone(),
                    resolved_file,
                });
            }
        }
        resolved
    }
}
