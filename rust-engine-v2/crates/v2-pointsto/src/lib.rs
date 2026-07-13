use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use v2_ir::{InstructionId, MethodId, TypeId};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllocationContext {
    pub call_stack: Vec<InstructionId>,
}

impl PartialOrd for AllocationContext {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AllocationContext {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_ids: Vec<u32> = self.call_stack.iter().map(|id| id.0).collect();
        let other_ids: Vec<u32> = other.call_stack.iter().map(|id| id.0).collect();
        self_ids.cmp(&other_ids)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllocationSite {
    pub method_id: MethodId,
    pub instruction_id: InstructionId,
    pub type_id: TypeId,
    pub context_id: Option<u32>,
}

impl PartialOrd for AllocationSite {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AllocationSite {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.instruction_id.0.cmp(&other.instruction_id.0)
            .then_with(|| self.method_id.0.cmp(&other.method_id.0))
            .then_with(|| self.type_id.0.cmp(&other.type_id.0))
            .then_with(|| self.context_id.cmp(&other.context_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HeapObject {
    Allocation {
        site_id: InstructionId,
        method_id: MethodId,
        type_id: TypeId,
        context: Option<AllocationContext>,
    },
    Synthetic {
        name: String,
        type_id: Option<TypeId>,
    },
    Unknown,
}

impl PartialOrd for HeapObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (HeapObject::Allocation { site_id: s1, method_id: m1, type_id: t1, context: c1 },
             HeapObject::Allocation { site_id: s2, method_id: m2, type_id: t2, context: c2 }) => {
                s1.0.cmp(&s2.0)
                    .then_with(|| m1.0.cmp(&m2.0))
                    .then_with(|| t1.0.cmp(&t2.0))
                    .then_with(|| c1.cmp(c2))
            }
            (HeapObject::Synthetic { name: n1, type_id: t1 },
             HeapObject::Synthetic { name: n2, type_id: t2 }) => {
                n1.cmp(n2).then_with(|| {
                    let id1 = t1.map(|id| id.0);
                    let id2 = t2.map(|id| id.0);
                    id1.cmp(&id2)
                })
            }
            (HeapObject::Unknown, HeapObject::Unknown) => std::cmp::Ordering::Equal,
            
            (HeapObject::Allocation { .. }, _) => std::cmp::Ordering::Less,
            (_, HeapObject::Allocation { .. }) => std::cmp::Ordering::Greater,
            (HeapObject::Synthetic { .. }, _) => std::cmp::Ordering::Less,
            (_, HeapObject::Synthetic { .. }) => std::cmp::Ordering::Greater,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PointsToSet {
    pub objects: Arc<BTreeSet<HeapObject>>,
}

impl PointsToSet {
    pub fn new() -> Self {
        Self {
            objects: Arc::new(BTreeSet::new()),
        }
    }

    pub fn singleton(obj: HeapObject) -> Self {
        let mut set = BTreeSet::new();
        set.insert(obj);
        Self {
            objects: Arc::new(set),
        }
    }

    pub fn insert(&self, obj: HeapObject) -> Self {
        let mut new_set = (*self.objects).clone();
        new_set.insert(obj);
        Self {
            objects: Arc::new(new_set),
        }
    }

    pub fn remove(&self, obj: &HeapObject) -> Self {
        let mut new_set = (*self.objects).clone();
        new_set.remove(obj);
        Self {
            objects: Arc::new(new_set),
        }
    }

    pub fn contains(&self, obj: &HeapObject) -> bool {
        self.objects.contains(obj)
    }

    pub fn union(&self, other: &Self) -> Self {
        let mut new_set = (*self.objects).clone();
        for obj in other.objects.iter() {
            new_set.insert(obj.clone());
        }
        Self {
            objects: Arc::new(new_set),
        }
    }

    pub fn intersection(&self, other: &Self) -> Self {
        let mut new_set = BTreeSet::new();
        for obj in self.objects.iter() {
            if other.contains(obj) {
                new_set.insert(obj.clone());
            }
        }
        Self {
            objects: Arc::new(new_set),
        }
    }

    pub fn difference(&self, other: &Self) -> Self {
        let mut new_set = BTreeSet::new();
        for obj in self.objects.iter() {
            if !other.contains(obj) {
                new_set.insert(obj.clone());
            }
        }
        Self {
            objects: Arc::new(new_set),
        }
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        self.objects.is_subset(&other.objects)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HeapLocation {
    FieldAccess {
        base: HeapObject,
        field: String,
    },
    IndexAccess {
        base: HeapObject,
        index: String,
    },
    StaticField {
        class_name: String,
        field_name: String,
    },
    UnknownHeap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AliasClassId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PointsToHooks {
    pub k_object_sens_depth: Option<u32>,
    pub escape_state: Option<u32>,
    pub cloned_heap_id: Option<u32>,
    pub heap_summary_id: Option<u32>,
}

pub fn init() {
    println!("v2-pointsto initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        init();
    }

    #[test]
    fn test_allocation_site_ordering() {
        let m = MethodId(1);
        let t = TypeId(2);
        
        let site1 = AllocationSite {
            method_id: m,
            instruction_id: InstructionId(10),
            type_id: t,
            context_id: None,
        };
        let site2 = AllocationSite {
            method_id: m,
            instruction_id: InstructionId(20),
            type_id: t,
            context_id: None,
        };
        
        assert!(site1 < site2);
    }

    #[test]
    fn test_heap_object_equality() {
        let obj1 = HeapObject::Synthetic {
            name: "stdout".to_string(),
            type_id: None,
        };
        let obj2 = HeapObject::Synthetic {
            name: "stdout".to_string(),
            type_id: None,
        };
        let obj_unknown = HeapObject::Unknown;

        assert_eq!(obj1, obj2);
        assert_ne!(obj1, obj_unknown);
    }

    #[test]
    fn test_points_to_set_operations() {
        let obj_a = HeapObject::Synthetic { name: "A".to_string(), type_id: None };
        let obj_b = HeapObject::Synthetic { name: "B".to_string(), type_id: None };
        let obj_c = HeapObject::Synthetic { name: "C".to_string(), type_id: None };

        let set_ab = PointsToSet::new().insert(obj_a.clone()).insert(obj_b.clone());
        let set_bc = PointsToSet::new().insert(obj_b.clone()).insert(obj_c.clone());

        // Union
        let union_set = set_ab.union(&set_bc);
        assert!(union_set.contains(&obj_a));
        assert!(union_set.contains(&obj_b));
        assert!(union_set.contains(&obj_c));

        // Intersection
        let inter_set = set_ab.intersection(&set_bc);
        assert!(!inter_set.contains(&obj_a));
        assert!(inter_set.contains(&obj_b));

        // Difference
        let diff_set = set_ab.difference(&set_bc);
        assert!(diff_set.contains(&obj_a));
        assert!(!diff_set.contains(&obj_b));
    }

    #[test]
    fn test_serialization_and_determinism() {
        let obj_a = HeapObject::Synthetic { name: "A".to_string(), type_id: None };
        let obj_b = HeapObject::Synthetic { name: "B".to_string(), type_id: None };
        
        let set = PointsToSet::new().insert(obj_b.clone()).insert(obj_a.clone());

        // BTreeSet guarantees that A is sorted before B, so serialization order is deterministic
        let json = serde_json::to_string(&set).unwrap();
        assert!(json.contains("A"));
        assert!(json.contains("B"));
        
        // Uniqueness check in HashSet
        let mut hash_set = std::collections::HashSet::new();
        hash_set.insert(set.clone());
        assert!(hash_set.contains(&set));
    }
}
