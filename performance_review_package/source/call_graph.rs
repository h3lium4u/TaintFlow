use crate::global::{GlobalSymbolTable, TypeKind};
use ir::{InstructionId, InstructionKind, MethodId, Program, TypeId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeType {
    DirectCall,
    VirtualCall,
    InterfaceCall,
    FrameworkCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallNode {
    pub method_id: MethodId,
    pub fqn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct CallEdge {
    pub caller: MethodId,
    pub callee: MethodId,
    pub edge_type: EdgeType,
    pub instruction_id: Option<InstructionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: HashMap<MethodId, CallNode>,
    pub edges: Vec<CallEdge>,
    pub caller_to_edges: HashMap<MethodId, Vec<CallEdge>>,
    pub callee_to_edges: HashMap<MethodId, Vec<CallEdge>>,
}

impl CallGraph {
    pub fn build(program: &Program, gst: &GlobalSymbolTable) -> Self {
        let mut nodes = HashMap::new();
        let mut edges = Vec::new();

        // 1. Populate nodes from the symbol table methods
        for (&method_id, method_info) in &gst.program_index.methods {
            nodes.insert(
                method_id,
                CallNode {
                    method_id,
                    fqn: method_info.fqn.clone(),
                },
            );
        }

        // 2. Identify all instantiated types for RTA (preserved for legacy tracking/RTA queries)
        let mut instantiated_types = HashSet::new();

        // A. Identify from new expressions in IR instructions
        for inst in program.instructions.values() {
            if let InstructionKind::Call { callee, .. } = &inst.kind {
                if callee.starts_with("new ") {
                    let type_name = callee["new ".len()..].trim().to_string();
                    instantiated_types.insert(type_name.clone());
                } else if callee.contains('(')
                    || callee.chars().next().map_or(false, |c| c.is_uppercase())
                {
                    // Python class instantiation or Python/Java constructor call style
                    let stem = callee
                        .split('(')
                        .next()
                        .unwrap_or(callee)
                        .trim()
                        .to_string();
                    let parts: Vec<&str> = stem.split('.').collect();
                    if let Some(&last) = parts.last() {
                        instantiated_types.insert(last.to_string());
                    }
                    instantiated_types.insert(stem);
                }
            }
        }

        // B. Identify from framework annotations/decorators (e.g. implicit framework instantiation)
        for type_info in gst.program_index.types.values() {
            for ann in &type_info.annotations {
                let clean_ann = ann.to_lowercase();
                if clean_ann.contains("service")
                    || clean_ann.contains("component")
                    || clean_ann.contains("repository")
                    || clean_ann.contains("controller")
                    || clean_ann.contains("restcontroller")
                    || clean_ann.contains("bean")
                    || clean_ann.contains("route")
                {
                    instantiated_types.insert(type_info.fqn.clone());
                    instantiated_types.insert(type_info.name.clone());
                }
            }
        }

        // 3. Traversal and Call Resolution
        for (&caller_id, method) in &program.methods {
            let (module_id, caller_class_id) =
                if let Some(m_info) = gst.program_index.methods.get(&caller_id) {
                    (m_info.module_id, m_info.parent_type_id)
                } else {
                    continue;
                };

            // Local variable type estimation inside the method body
            let mut local_types = HashMap::new();

            // Populate parameter types
            if let Some(method_info) = gst.program_index.methods.get(&caller_id) {
                for param_str in &method_info.parameters {
                    let clean_param = param_str.trim();
                    if clean_param.contains(':') {
                        // Python style type hints: param_name: TypeName
                        let parts: Vec<&str> = clean_param.split(':').collect();
                        if parts.len() == 2 {
                            let var_name = parts[0].trim();
                            let type_name = parts[1].trim().split('=').next().unwrap_or(parts[1]).trim();
                            local_types.insert(var_name.to_string(), type_name.to_string());
                        }
                    } else {
                        // Java style parameter declarations: TypeName var_name (or Annotation TypeName var_name)
                        let parts: Vec<&str> = clean_param.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let var_name = parts.last().unwrap().trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                            let mut type_name = "";
                            for word in parts.iter().rev().skip(1) {
                                let clean_word = word.trim();
                                if !clean_word.starts_with('@') {
                                    type_name = clean_word;
                                    break;
                                }
                            }
                            if !type_name.is_empty() && !var_name.is_empty() {
                                let clean_type = type_name.split('<').next().unwrap_or(type_name).to_string();
                                local_types.insert(var_name.to_string(), clean_type);
                            }
                        }
                    }
                }
            }

            let mut all_insts = Vec::new();
            let mut visited = std::collections::HashSet::new();
            fn collect_insts(
                ids: &[ir::InstructionId],
                program: &ir::Program,
                out: &mut Vec<ir::InstructionId>,
                visited: &mut std::collections::HashSet<ir::InstructionId>,
            ) {
                for &id in ids {
                    if !visited.insert(id) {
                        continue;
                    }
                    out.push(id);
                    if let Some(inst) = program.instructions.get(&id) {
                        match &inst.kind {
                            InstructionKind::Branch { then_block, else_block, .. } => {
                                collect_insts(then_block, program, out, visited);
                                if let Some(eb) = else_block {
                                    collect_insts(eb, program, out, visited);
                                }
                            }
                            InstructionKind::Loop { body, .. } => {
                                collect_insts(body, program, out, visited);
                            }
                            InstructionKind::Try { body, catches, finally, .. } => {
                                collect_insts(body, program, out, visited);
                                collect_insts(catches, program, out, visited);
                                if let Some(fb) = finally {
                                    collect_insts(fb, program, out, visited);
                                }
                            }
                            InstructionKind::Catch { body, .. } => {
                                collect_insts(body, program, out, visited);
                            }
                            _ => {}
                        }
                    }
                }
            }
            collect_insts(&method.body, program, &mut all_insts, &mut visited);

            for &inst_id in &all_insts {
                if let Some(inst) = program.instructions.get(&inst_id) {
                    match &inst.kind {
                        InstructionKind::Call {
                            dest: Some(d),
                            callee,
                            ..
                        } => {
                            if callee.starts_with("new ") {
                                let type_name = callee["new ".len()..].trim().to_string();
                                local_types.insert(d.clone(), type_name);
                            } else {
                                // Try resolving the callee to find its return type
                                let mut resolved_return_type = None;
                                let parts: Vec<&str> = callee.split('.').collect();
                                if parts.len() == 2 {
                                    let obj = parts[0];
                                    let method_name = parts[1];
                                    if let Some(obj_type) = local_types.get(obj) {
                                        let clean_obj_type = obj_type.split('<').next().unwrap_or(obj_type).trim();
                                        if let Some(type_id) = gst.resolve_type(module_id, clean_obj_type) {
                                            if let Some(m_id) = gst.resolve_method(type_id, method_name) {
                                                if let Some(m_info) = gst.program_index.methods.get(&m_id) {
                                                    if let Some(ref rt) = m_info.return_type {
                                                        resolved_return_type = Some(rt.clone());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if let Some(rt) = resolved_return_type {
                                    let clean_rt = rt.split('<').next().unwrap_or(&rt).trim().to_string();
                                    local_types.insert(d.clone(), clean_rt);
                                } else {
                                    local_types.insert(d.clone(), callee.clone());
                                }
                            }
                        }
                        InstructionKind::Assign { dest, src } => {
                            local_types.insert(dest.clone(), src.clone());
                            // RC97: Tuple-destructuring support.
                            // When dest is "client, uri" from `client, uri = fixture`,
                            // split and insert each component so that `client` can be
                            // resolved individually in subsequent call sites.
                            if dest.contains(',') && !dest.contains('(') && !dest.contains('[') {
                                for part in dest.split(',') {
                                    let clean = part.trim().to_string();
                                    if !clean.is_empty() {
                                        local_types.insert(clean, src.clone());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Resolve calls
            for &inst_id in &all_insts {
                if let Some(inst) = program.instructions.get(&inst_id) {
                    if let InstructionKind::Call { callee, .. } = &inst.kind {
                        let mut resolved_targets = Vec::new();
                        let parts: Vec<&str> = callee.split('.').collect();

                        if parts.len() >= 2 {
                            let method_name = parts.last().unwrap();
                            let receiver_path = parts[..parts.len() - 1].join(".");
                            let obj_name = parts[0];

                            // Determine type of the object
                            let mut obj_type_name = None;

                            // A. Local variable types
                            if let Some(t) = local_types.get(&receiver_path) {
                                obj_type_name = Some(t.clone());
                            } else if let Some(t) = local_types.get(obj_name) {
                                obj_type_name = Some(t.clone());
                            } else if obj_name.starts_with("new ") {
                                let type_part = obj_name["new ".len()..].trim();
                                let clean_type = type_part.split('(').next().unwrap_or(type_part).trim().to_string();
                                obj_type_name = Some(clean_type);
                            }

                            // B. Class fields
                            if obj_type_name.is_none() {
                                if let Some(class_id) = caller_class_id {
                                    if let Some(field) =
                                        gst.program_index.fields.values().find(|f| {
                                            f.parent_type_id == class_id && f.name == obj_name
                                        })
                                    {
                                        if let Some(ref ft) = field.field_type {
                                            obj_type_name = Some(ft.clone());
                                        }
                                    }
                                }
                            }

                            // C. Dependency Injection Autowire Fallback
                            if obj_type_name.is_none() {
                                if let Some(class_id) = caller_class_id {
                                    if let Some(field) =
                                        gst.program_index.fields.values().find(|f| {
                                            f.parent_type_id == class_id && f.name == obj_name
                                        })
                                    {
                                        let has_di = field.annotations.iter().any(|a| {
                                            a.contains("Autowired")
                                                || a.contains("Inject")
                                                || a.contains("Resource")
                                          });
                                          if has_di {
                                              let fallback_type = format!(
                                                  "{}{}",
                                                  obj_name[..1].to_uppercase(),
                                                  &obj_name[1..]
                                              );
                                              obj_type_name = Some(fallback_type);
                                          }
                                      }
                                  }
                              }

                              let mut resolved_type_id = None;
                              if obj_name == "self" || obj_name == "this" {
                                  resolved_type_id = caller_class_id;
                              }

                              if let Some(ref t_name) = obj_type_name {
                                  let clean_t_name = t_name.split('<').next().unwrap_or(t_name).trim();
                                  resolved_type_id = resolved_type_id.or_else(|| gst.resolve_type(module_id, clean_t_name));
                                  if resolved_type_id.is_none() {
                                      if let Some(class_id) = caller_class_id {
                                          if let Some(parent_info) = gst.program_index.types.get(&class_id) {
                                              let candidate = format!("{}.{}", parent_info.fqn, clean_t_name);
                                              if let Some(&id) = gst.type_index.fqn_to_id.get(&candidate) {
                                                  resolved_type_id = Some(id);
                                              }
                                          }
                                      }
                                  }
                              }

                              if let Some(type_id) = resolved_type_id {
                                  let mut candidates = Vec::new();

                                  // Direct method on the type
                                  if let Some(m_id) = gst.resolve_method(type_id, method_name) {
                                      candidates.push((m_id, EdgeType::DirectCall));
                                  }

                                  // Virtual/Interface resolution via CHA
                                  if let Some(type_info) = gst.program_index.types.get(&type_id) {
                                      match type_info.kind {
                                          TypeKind::Interface => {
                                              let mut implementors = HashSet::new();
                                              for key in &[&type_info.fqn, &type_info.name] {
                                                  if let Some(impls) = gst.interface_to_implementors.get(*key) {
                                                      for &impl_type_id in impls {
                                                          implementors.insert(impl_type_id);
                                                          let mut visited = HashSet::new();
                                                          get_all_subclasses(gst, impl_type_id, &mut visited);
                                                          implementors.extend(visited);
                                                      }
                                                  }
                                              }
                                              // RTA Check: only resolve to the implementor method if the implementor is instantiated
                                              let mut instantiated_implementors = Vec::new();
                                              for &impl_id in &implementors {
                                                  if let Some(impl_info) = gst.program_index.types.get(&impl_id) {
                                                      if instantiated_types.contains(&impl_info.name)
                                                          || instantiated_types.contains(&impl_info.fqn)
                                                      {
                                                          instantiated_implementors.push(impl_id);
                                                      }
                                                  }
                                              }

                                              let targets_to_resolve = if !instantiated_implementors.is_empty() {
                                                  instantiated_implementors
                                              } else {
                                                  implementors.into_iter().collect()
                                              };

                                              for impl_type_id in targets_to_resolve {
                                                  if let Some(m_id) = gst.resolve_method(impl_type_id, method_name) {
                                                      candidates.push((m_id, EdgeType::InterfaceCall));
                                                  }
                                              }
                                          }
                                          TypeKind::Class => {
                                              let mut subclasses = HashSet::new();
                                              let mut visited = HashSet::new();
                                              get_all_subclasses(gst, type_id, &mut visited);
                                              subclasses.extend(visited);

                                              // RTA Check: only resolve to the subclass method if the subclass is instantiated
                                              let mut instantiated_subclasses = Vec::new();
                                              for &sub_id in &subclasses {
                                                  if let Some(sub_info) = gst.program_index.types.get(&sub_id) {
                                                      if instantiated_types.contains(&sub_info.name)
                                                          || instantiated_types.contains(&sub_info.fqn)
                                                      {
                                                          instantiated_subclasses.push(sub_id);
                                                      }
                                                  }
                                              }

                                              let targets_to_resolve = if !instantiated_subclasses.is_empty() {
                                                  instantiated_subclasses
                                              } else {
                                                  subclasses.into_iter().collect()
                                              };

                                              for sub_type_id in targets_to_resolve {
                                                  if let Some(m_id) = gst.resolve_method(sub_type_id, method_name) {
                                                      candidates.push((m_id, EdgeType::VirtualCall));
                                                  }
                                              }
                                          }
                                          TypeKind::Enum => {}
                                      }
                                  }

                                  resolved_targets.extend(candidates);
                              } else {
                                  // Module-level function call resolution
                                  let resolved_module_fqn = if let Some(fqn) = gst.resolve_import(module_id, obj_name) {
                                      let mut path_parts = vec![fqn.as_str()];
                                      path_parts.extend(&parts[1..parts.len() - 1]);
                                      path_parts.join(".")
                                  } else {
                                      receiver_path.clone()
                                  };
                                  
                                  let candidate_fqn = format!("{}.{}", resolved_module_fqn, method_name);
                                  if let Some(&m_id) = gst.method_index.fqn_to_id.get(&candidate_fqn) {
                                      resolved_targets.push((m_id, EdgeType::DirectCall));
                                  } else if let Some(&type_id) = gst.type_index.fqn_to_id.get(&candidate_fqn) {
                                      let constructor_name = if gst.resolve_method(type_id, "<init>").is_some() {
                                          "<init>"
                                      } else {
                                          "__init__"
                                      };
                                      if let Some(m_id) = gst.resolve_method(type_id, constructor_name) {
                                          resolved_targets.push((m_id, EdgeType::DirectCall));
                                      }
                                  }

                                  // RC97: Name-based method resolution fallback.
                                  // When the receiver type is unresolved (e.g. from tuple
                                  // unpacking like `client, uri = fixture`), fall back to
                                  // matching any class method in the program by name.
                                  // This is a standard duck-typing heuristic for Python.
                                  if resolved_targets.is_empty() {
                                      let is_external_import = if let Some(fqn) = gst.resolve_import(module_id, obj_name) {
                                          !gst.type_index.fqn_to_id.contains_key(&fqn)
                                      } else {
                                          false
                                      };

                                      if !is_external_import {
                                          for (m_id, m_info) in &gst.program_index.methods {
                                              if m_info.name == *method_name && m_info.parent_type_id.is_some() {
                                                  resolved_targets.push((*m_id, EdgeType::DirectCall));
                                              }
                                          }
                                      }
                                  }
                              }
                          } else if parts.len() == 1 {
                            let method_name = parts[0];
                            let mut resolved = false;

                            // Direct local class method call (this.method())
                            if let Some(class_id) = caller_class_id {
                                if let Some(m_id) = gst.resolve_method(class_id, method_name) {
                                    resolved_targets.push((m_id, EdgeType::DirectCall));
                                    resolved = true;
                                }
                            }

                            // Import / module function lookup
                            if !resolved {
                                if let Some(fqn) = gst.resolve_import(module_id, method_name) {
                                    if let Some(&m_id) = gst.method_index.fqn_to_id.get(&fqn) {
                                        resolved_targets.push((m_id, EdgeType::DirectCall));
                                    } else if let Some(&type_id) = gst.type_index.fqn_to_id.get(&fqn) {
                                        let constructor_name = if gst.resolve_method(type_id, "<init>").is_some() {
                                            "<init>"
                                        } else {
                                            "__init__"
                                        };
                                        if let Some(m_id) = gst.resolve_method(type_id, constructor_name) {
                                            resolved_targets.push((m_id, EdgeType::DirectCall));
                                        }
                                    }
                                } else if let Some(mod_info) =
                                    gst.program_index.modules.get(&module_id)
                                {
                                    let candidate = format!("{}.{}", mod_info.name, method_name);
                                    if let Some(&m_id) = gst.method_index.fqn_to_id.get(&candidate)
                                    {
                                        resolved_targets.push((m_id, EdgeType::DirectCall));
                                    }
                                }
                            }

                            // Python/Java subscript/dynamic calls (e.g. dict[key](args))
                            if method_name.contains('[') {
                                for (&m_id, m_info) in &gst.program_index.methods {
                                    if m_info.module_id == module_id
                                        && m_info.parent_type_id.is_none()
                                        && m_id != caller_id
                                    {
                                        resolved_targets.push((m_id, EdgeType::DirectCall));
                                    }
                                }
                            }
                        }

                        for (callee_id, edge_type) in resolved_targets {
                            edges.push(CallEdge {
                                caller: caller_id,
                                callee: callee_id,
                                edge_type,
                                instruction_id: Some(inst_id),
                            });
                        }
                    }
                }
            }
        }

        // 4. Resolve Framework Routing
        resolve_framework_routing(program, gst, &mut edges);

        // Deduplicate edges to keep it clean
        let unique_edges: HashSet<CallEdge> = edges.into_iter().collect();
        let edges_vec: Vec<CallEdge> = unique_edges.into_iter().collect();

        // 5. Index caller/callee mappings
        let mut caller_to_edges = HashMap::new();
        let mut callee_to_edges = HashMap::new();
        for edge in &edges_vec {
            caller_to_edges
                .entry(edge.caller)
                .or_insert_with(Vec::new)
                .push(edge.clone());
            callee_to_edges
                .entry(edge.callee)
                .or_insert_with(Vec::new)
                .push(edge.clone());
        }

        Self {
            nodes,
            edges: edges_vec,
            caller_to_edges,
            callee_to_edges,
        }
    }
}

fn resolve_framework_routing(
    _program: &Program,
    gst: &GlobalSymbolTable,
    edges: &mut Vec<CallEdge>,
) {
    // Virtual MethodId(0) represents the entrypoint from the web client / framework dispatcher.
    let http_entry_id = MethodId(0);

    for (&method_id, method_info) in &gst.program_index.methods {
        let mut is_route = false;

        // A. Spring Controller mapping check
        if let Some(parent_id) = method_info.parent_type_id {
            if let Some(parent_info) = gst.program_index.types.get(&parent_id) {
                let is_controller = parent_info.annotations.iter().any(|a| {
                    let clean = a.to_lowercase();
                    clean.contains("controller") || clean.contains("restcontroller")
                });
                if is_controller {
                    let has_mapping = method_info.annotations.iter().any(|a| {
                        let clean = a.to_lowercase();
                        clean.contains("mapping")
                    });
                    if has_mapping {
                        is_route = true;
                    }
                }
            }
        }

        // B. Python decorators check
        let has_py_decorator = method_info.annotations.iter().any(|a| {
            let clean = a.to_lowercase();
            clean.contains("route")
                || clean.contains("get")
                || clean.contains("post")
                || clean.contains("put")
                || clean.contains("delete")
        });
        if has_py_decorator {
            is_route = true;
        }

        if is_route {
            edges.push(CallEdge {
                caller: http_entry_id,
                callee: method_id,
                edge_type: EdgeType::FrameworkCall,
                instruction_id: None,
            });
        }
    }
}

fn get_all_subclasses(
    gst: &GlobalSymbolTable,
    parent_id: TypeId,
    visited: &mut HashSet<TypeId>,
) {
    if let Some(subs) = gst.parent_to_children.get(&parent_id) {
        for &sub_id in subs {
            if visited.insert(sub_id) {
                get_all_subclasses(gst, sub_id, visited);
            }
        }
    }
}
