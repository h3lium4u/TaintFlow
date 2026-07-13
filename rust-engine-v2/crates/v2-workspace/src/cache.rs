use serde::{Deserialize, Serialize};
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

// ---------------------------------------------------------------------------
// FileChecksums
// ---------------------------------------------------------------------------

/// Per-phase checksums for one source file.  Each phase writes its own
/// checksum so the cache can be selectively invalidated per phase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChecksums {
    pub content_hash: u64,
    pub ast_checksum: Option<u64>,
    pub semantic_checksum: Option<u64>,
    pub ir_checksum: Option<u64>,
    pub cfg_checksum: Option<u64>,
    pub icfg_checksum: Option<u64>,
    pub alias_checksum: Option<u64>,
    pub taint_checksum: Option<u64>,
    pub finding_checksum: Option<u64>,
}

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

/// One cache entry for a single source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub path: PathBuf,
    pub content_hash: u64,
    pub timestamp_secs: u64,
    pub size_bytes: u64,
    pub checksums: FileChecksums,
    pub is_valid: bool,
}

// ---------------------------------------------------------------------------
// ProjectCache
// ---------------------------------------------------------------------------

/// Persistent project-level analysis cache backed by a JSON file on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectCache {
    pub entries: HashMap<PathBuf, CacheEntry>,
    /// Path used for `save()`. Skipped during serialisation.
    #[serde(skip)]
    pub cache_path: Option<PathBuf>,
}

impl ProjectCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load an existing cache from `cache_path`, falling back to an empty cache.
    pub fn load(cache_path: &Path) -> Self {
        let mut cache: ProjectCache =
            std::fs::read_to_string(cache_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
        cache.cache_path = Some(cache_path.to_path_buf());
        cache
    }

    /// Persist the cache to the path supplied at construction / load time.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(path) = &self.cache_path {
            let json = serde_json::to_string_pretty(self)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }

    /// Returns `true` if the file is absent from cache, or if its size/mtime
    /// has changed since the entry was written.
    pub fn needs_rebuild(&self, path: &Path) -> bool {
        match self.entries.get(path) {
            None => true,
            Some(entry) => {
                if !entry.is_valid {
                    return true;
                }
                let Ok(meta) = std::fs::metadata(path) else { return true };
                let current_size = meta.len();
                let current_mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                current_size != entry.size_bytes || current_mtime != entry.timestamp_secs
            }
        }
    }

    /// Insert or replace the cache entry for `entry.path`.
    pub fn update(&mut self, entry: CacheEntry) {
        self.entries.insert(entry.path.clone(), entry);
    }

    /// Mark an entry as invalid, forcing it to be rebuilt on the next session.
    pub fn invalidate(&mut self, path: &Path) {
        if let Some(entry) = self.entries.get_mut(path) {
            entry.is_valid = false;
        }
    }

    /// Count of valid (non-stale) entries.
    pub fn hit_count(&self) -> usize {
        self.entries.values().filter(|e| e.is_valid).count()
    }

    /// Total number of entries, including invalid ones.
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Fraction of entries that are still valid.
    pub fn hit_rate(&self) -> f64 {
        if self.total_entries() == 0 {
            0.0
        } else {
            self.hit_count() as f64 / self.total_entries() as f64
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hash raw file bytes with the standard library hasher.
pub fn hash_content(content: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    content.hash(&mut h);
    h.finish()
}

/// Build a `CacheEntry` by reading `path` from disk.
/// Returns `None` if the file cannot be read or its metadata is unavailable.
pub fn build_cache_entry(path: &Path) -> Option<CacheEntry> {
    let content = std::fs::read(path).ok()?;
    let meta = std::fs::metadata(path).ok()?;
    let content_hash = hash_content(&content);
    let timestamp_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(CacheEntry {
        path: path.to_path_buf(),
        content_hash,
        timestamp_secs,
        size_bytes: meta.len(),
        checksums: FileChecksums { content_hash, ..Default::default() },
        is_valid: true,
    })
}
