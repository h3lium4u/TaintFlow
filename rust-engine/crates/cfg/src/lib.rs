use normalizer::{NormalizedKind, NormalizedNode};
use serde::{Deserialize, Serialize};

pub mod evaluator;
pub mod icfg;
pub use icfg::{IcfgEdge, IcfgEdgeKind, IcfgNode, IcfgNodeKind, InterproceduralCFG};

pub type NodeId = u32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CfgNodeKind {
    Entry,
    Exit,
    Statement,
    Branch,
    Loop,
    Try,
    Catch,
    Finally,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode {
    pub id: NodeId,
    pub kind: CfgNodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: NodeId,
    pub to: NodeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

pub struct CfgBuilder {
    nodes: Vec<CfgNode>,
    edges: Vec<CfgEdge>,
    next_id: u32,
    max_nodes: usize,
    warning_emitted: bool,
}

impl CfgBuilder {
    pub fn new(max_nodes: usize) -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            next_id: 0,
            max_nodes,
            warning_emitted: false,
        }
    }

    fn next_node_id(&mut self) -> Option<NodeId> {
        if self.nodes.len() >= self.max_nodes {
            if !self.warning_emitted {
                eprintln!(
                    "[WARNING] Control Flow Graph node limit ({}) exceeded.",
                    self.max_nodes
                );
                self.warning_emitted = true;
            }
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        Some(id)
    }

    pub fn build(&mut self, root: &NormalizedNode) -> ControlFlowGraph {
        // Create Entry and Exit
        let entry_id = self.next_node_id().unwrap();
        self.nodes.push(CfgNode {
            id: entry_id,
            kind: CfgNodeKind::Entry,
        });

        let exit_id = self.next_node_id().unwrap();
        self.nodes.push(CfgNode {
            id: exit_id,
            kind: CfgNodeKind::Exit,
        });

        let body_entry = self.build_recursive(root, entry_id, exit_id, None);
        if let Some(be) = body_entry {
            self.edges.push(CfgEdge {
                from: entry_id,
                to: be,
            });
        }

        ControlFlowGraph {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
        }
    }
    fn build_recursive(
        &mut self,
        node: &NormalizedNode,
        parent_entry: NodeId,
        target_exit: NodeId,
        break_target: Option<NodeId>,
    ) -> Option<NodeId> {
        if self.nodes.len() >= self.max_nodes {
            return None;
        }

        match &node.kind {
            NormalizedKind::Assignment { .. } | NormalizedKind::Call { .. } => {
                let node_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: node_id,
                    kind: CfgNodeKind::Statement,
                });
                self.edges.push(CfgEdge {
                    from: node_id,
                    to: target_exit,
                });
                Some(node_id)
            }
            NormalizedKind::If {
                condition: _condition,
                consequent,
                alternate,
            } => {
                let branch_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: branch_id,
                    kind: CfgNodeKind::Branch,
                });

                let cons_entry =
                    self.build_recursive(consequent, branch_id, target_exit, break_target);
                if let Some(ce) = cons_entry {
                    self.edges.push(CfgEdge {
                        from: branch_id,
                        to: ce,
                    });
                }

                if let Some(alt) = alternate {
                    let alt_entry = self.build_recursive(alt, branch_id, target_exit, break_target);
                    if let Some(ae) = alt_entry {
                        self.edges.push(CfgEdge {
                            from: branch_id,
                            to: ae,
                        });
                    }
                } else {
                    self.edges.push(CfgEdge {
                        from: branch_id,
                        to: target_exit,
                    });
                }

                Some(branch_id)
            }
            NormalizedKind::Block(children) => {
                let mut current_exit = target_exit;
                let mut last_entry = None;

                let is_switch = node.raw.trim().starts_with("switch");
                let child_break_target = if is_switch {
                    Some(target_exit)
                } else {
                    break_target
                };

                // Build backwards to link correctly
                for child in children.iter().rev() {
                    if let Some(entry) =
                        self.build_recursive(child, parent_entry, current_exit, child_break_target)
                    {
                        last_entry = Some(entry);
                        current_exit = entry;
                    }
                }
                last_entry
            }
            NormalizedKind::While { condition: _, body } => {
                let loop_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: loop_id,
                    kind: CfgNodeKind::Loop,
                });
                self.edges.push(CfgEdge {
                    from: loop_id,
                    to: target_exit,
                });

                let body_entry = self.build_recursive(body, loop_id, loop_id, Some(target_exit));
                if let Some(be) = body_entry {
                    self.edges.push(CfgEdge {
                        from: loop_id,
                        to: be,
                    });
                }
                Some(loop_id)
            }
            NormalizedKind::For { body, .. } => {
                let loop_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: loop_id,
                    kind: CfgNodeKind::Loop,
                });
                self.edges.push(CfgEdge {
                    from: loop_id,
                    to: target_exit,
                });

                let body_entry = self.build_recursive(body, loop_id, loop_id, Some(target_exit));
                if let Some(be) = body_entry {
                    self.edges.push(CfgEdge {
                        from: loop_id,
                        to: be,
                    });
                }
                Some(loop_id)
            }
            NormalizedKind::DoWhile { body, condition: _ } => {
                let loop_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: loop_id,
                    kind: CfgNodeKind::Loop,
                });
                self.edges.push(CfgEdge {
                    from: loop_id,
                    to: target_exit,
                });

                let body_entry = self.build_recursive(body, loop_id, loop_id, Some(target_exit));
                if let Some(be) = body_entry {
                    self.edges.push(CfgEdge {
                        from: loop_id,
                        to: be,
                    });
                }
                Some(loop_id)
            }
            NormalizedKind::Try {
                body,
                catch_clauses,
                finally_clause,
            } => {
                let try_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: try_id,
                    kind: CfgNodeKind::Try,
                });

                let finally_exit = if let Some(finally) = finally_clause {
                    let fid = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: fid,
                        kind: CfgNodeKind::Finally,
                    });
                    let f_entry = self.build_recursive(finally, fid, target_exit, break_target);
                    if let Some(fe) = f_entry {
                        self.edges.push(CfgEdge { from: fid, to: fe });
                    } else {
                        self.edges.push(CfgEdge {
                            from: fid,
                            to: target_exit,
                        });
                    }
                    fid
                } else {
                    target_exit
                };

                let try_exit = finally_exit;

                let body_entry = self.build_recursive(body, try_id, try_exit, break_target);
                if let Some(be) = body_entry {
                    self.edges.push(CfgEdge {
                        from: try_id,
                        to: be,
                    });
                }

                for catch in catch_clauses {
                    let catch_entry = self.build_recursive(catch, try_id, try_exit, break_target);
                    if let Some(ce) = catch_entry {
                        self.edges.push(CfgEdge {
                            from: try_id,
                            to: ce,
                        });
                    }
                }

                Some(try_id)
            }
            NormalizedKind::Catch { body, .. } => {
                let catch_id = self.next_node_id()?;
                self.nodes.push(CfgNode {
                    id: catch_id,
                    kind: CfgNodeKind::Catch,
                });
                let body_entry = self.build_recursive(body, catch_id, target_exit, break_target);
                if let Some(be) = body_entry {
                    self.edges.push(CfgEdge {
                        from: catch_id,
                        to: be,
                    });
                }
                Some(catch_id)
            }
            // For other control flow nodes not explicitly defined in NormalizedKind (like Try/Catch/Finally/Loops),
            // we check the raw representation or layout to model them correctly.
            _ => {
                let raw_lower = node.raw.to_lowercase();
                if raw_lower.starts_with("while") || raw_lower.starts_with("for") {
                    // Loop node
                    let loop_id = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: loop_id,
                        kind: CfgNodeKind::Loop,
                    });

                    // Connect loop to loop exit
                    self.edges.push(CfgEdge {
                        from: loop_id,
                        to: target_exit,
                    });

                    // Loop body
                    let body_entry = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: body_entry,
                        kind: CfgNodeKind::Statement,
                    });
                    self.edges.push(CfgEdge {
                        from: loop_id,
                        to: body_entry,
                    });

                    // Back edge to loop header
                    self.edges.push(CfgEdge {
                        from: body_entry,
                        to: loop_id,
                    });

                    Some(loop_id)
                } else if raw_lower.starts_with("try") {
                    // Try node
                    let try_id = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: try_id,
                        kind: CfgNodeKind::Try,
                    });

                    // Catch node
                    let catch_id = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: catch_id,
                        kind: CfgNodeKind::Catch,
                    });

                    // Finally node
                    let finally_id = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: finally_id,
                        kind: CfgNodeKind::Finally,
                    });

                    // Create exception edges
                    self.edges.push(CfgEdge {
                        from: try_id,
                        to: catch_id,
                    });
                    self.edges.push(CfgEdge {
                        from: try_id,
                        to: finally_id,
                    });
                    self.edges.push(CfgEdge {
                        from: catch_id,
                        to: finally_id,
                    });
                    self.edges.push(CfgEdge {
                        from: finally_id,
                        to: target_exit,
                    });

                    Some(try_id)
                } else if raw_lower.contains("return ") || raw_lower.starts_with("return") {
                    // Return node (Connects to exit node)
                    let return_id = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: return_id,
                        kind: CfgNodeKind::Return,
                    });
                    // Exit node is at index 1 in self.nodes (id: 1)
                    self.edges.push(CfgEdge {
                        from: return_id,
                        to: 1,
                    });
                    Some(return_id)
                } else {
                    let node_id = self.next_node_id()?;
                    self.nodes.push(CfgNode {
                        id: node_id,
                        kind: CfgNodeKind::Statement,
                    });

                    let raw_trimmed = node.raw.trim();
                    let to_target = if raw_trimmed.starts_with("break") {
                        break_target.unwrap_or(target_exit)
                    } else {
                        target_exit
                    };

                    self.edges.push(CfgEdge {
                        from: node_id,
                        to: to_target,
                    });
                    Some(node_id)
                }
            }
        }
    }
}
