use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use v2_ir::InstructionId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathRoot {
    Local(String),
    Temp(u32),
    Static { class_name: String, field_name: String },
    Alloc(InstructionId),
    Constant(String),
    Unknown,
}

impl fmt::Display for PathRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathRoot::Local(name) => write!(f, "{}", name),
            PathRoot::Temp(id) => write!(f, "t{}", id),
            PathRoot::Static { class_name, field_name } => write!(f, "{}.{}", class_name, field_name),
            PathRoot::Alloc(id) => write!(f, "alloc@{}", id.0),
            PathRoot::Constant(val) => write!(f, "const({})", val),
            PathRoot::Unknown => write!(f, "?"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathSegment {
    Field(String),
    ArrayElement,
    Wildcard,
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathSegment::Field(name) => write!(f, ".{}", name),
            PathSegment::ArrayElement => write!(f, "[*]"),
            PathSegment::Wildcard => write!(f, ".*"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtensionHooks {
    pub alias_set_id: Option<u32>,
    pub context_id: Option<u32>,
    pub heap_alloc_id: Option<InstructionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessPath {
    pub root: PathRoot,
    pub segments: Arc<Vec<PathSegment>>,
    pub hooks: Option<ExtensionHooks>,
}

impl AccessPath {
    pub fn new(root: PathRoot) -> Self {
        Self {
            root,
            segments: Arc::new(Vec::new()),
            hooks: None,
        }
    }

    pub fn append_field(&self, field: String) -> Self {
        let mut new_segs = (*self.segments).clone();
        new_segs.push(PathSegment::Field(field));
        Self {
            root: self.root.clone(),
            segments: Arc::new(new_segs),
            hooks: self.hooks.clone(),
        }
    }

    pub fn append_array(&self) -> Self {
        let mut new_segs = (*self.segments).clone();
        new_segs.push(PathSegment::ArrayElement);
        Self {
            root: self.root.clone(),
            segments: Arc::new(new_segs),
            hooks: self.hooks.clone(),
        }
    }

    pub fn append_static(&self, class_name: String, field_name: String) -> Self {
        Self {
            root: PathRoot::Static { class_name, field_name },
            segments: Arc::new(Vec::new()),
            hooks: self.hooks.clone(),
        }
    }

    pub fn truncate(&self, max_depth: usize) -> Self {
        if self.segments.len() <= max_depth {
            return self.clone();
        }
        let mut new_segs = self.segments.iter().take(max_depth).cloned().collect::<Vec<_>>();
        new_segs.push(PathSegment::Wildcard);
        Self {
            root: self.root.clone(),
            segments: Arc::new(new_segs),
            hooks: self.hooks.clone(),
        }
    }

    pub fn normalize(&self) -> Self {
        let norm_root = match &self.root {
            PathRoot::Local(name) => PathRoot::Local(name.trim().to_string()),
            PathRoot::Static { class_name, field_name } => PathRoot::Static {
                class_name: class_name.trim().to_string(),
                field_name: field_name.trim().to_string(),
            },
            PathRoot::Constant(val) => PathRoot::Constant(val.trim().to_string()),
            other => other.clone(),
        };

        let norm_segs = self.segments.iter().map(|seg| match seg {
            PathSegment::Field(name) => PathSegment::Field(name.trim().to_string()),
            other => other.clone(),
        }).collect::<Vec<_>>();

        Self {
            root: norm_root,
            segments: Arc::new(norm_segs),
            hooks: self.hooks.clone(),
        }
    }

    pub fn canonicalize(&self) -> Self {
        self.normalize()
    }
}

impl fmt::Display for AccessPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.root)?;
        for seg in self.segments.iter() {
            write!(f, "{}", seg)?;
        }
        Ok(())
    }
}

pub fn init() {
    println!("v2-accesspath initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_access_path_formatting_and_append() {
        let root = PathRoot::Local("x".to_string());
        let ap = AccessPath::new(root)
            .append_field("a".to_string())
            .append_field("b".to_string());
            
        assert_eq!(format!("{}", ap), "x.a.b");
    }

    #[test]
    fn test_array_paths_and_wildcards() {
        let root = PathRoot::Local("arr".to_string());
        let ap = AccessPath::new(root).append_array().append_field("field".to_string());
        
        assert_eq!(format!("{}", ap), "arr[*].field");
    }

    #[test]
    fn test_canonicalization_and_hashing() {
        let ap1 = AccessPath::new(PathRoot::Local("  val  ".to_string()))
            .append_field("  field  ".to_string());
        let ap2 = AccessPath::new(PathRoot::Local("val".to_string()))
            .append_field("field".to_string());
            
        assert_eq!(ap1.canonicalize(), ap2.canonicalize());
        
        let mut set = std::collections::HashSet::new();
        set.insert(ap1.canonicalize());
        assert!(set.contains(&ap2.canonicalize()));
    }

    #[test]
    fn test_depth_widening_truncation() {
        let ap = AccessPath::new(PathRoot::Local("a".to_string()))
            .append_field("b".to_string())
            .append_field("c".to_string())
            .append_field("d".to_string())
            .append_field("e".to_string());
            
        let truncated = ap.truncate(3);
        assert_eq!(format!("{}", truncated), "a.b.c.d.*");
    }
}
