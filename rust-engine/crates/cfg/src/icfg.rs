use crate::evaluator::{ConstantValue, Evaluator};
use ir::{InstructionId, InstructionKind, MethodId, Program};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use symbols::call_graph::CallGraph;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IcfgNodeKind {
    Entry,
    Exit,
    Statement,
    Call,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IcfgNode {
    pub id: u32,
    pub method_id: MethodId,
    pub instruction_id: Option<InstructionId>,
    pub kind: IcfgNodeKind,
    pub label: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IcfgEdgeKind {
    CFG,
    Call,
    Return,
    Exception,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct IcfgEdge {
    pub from: u32,
    pub to: u32,
    pub kind: IcfgEdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterproceduralCFG {
    pub nodes: HashMap<u32, IcfgNode>,
    pub edges: Vec<IcfgEdge>,

    pub method_to_nodes: HashMap<MethodId, Vec<u32>>,
    pub method_entry_node: HashMap<MethodId, u32>,
    pub method_exit_node: HashMap<MethodId, u32>,
    pub instruction_to_nodes: HashMap<InstructionId, Vec<u32>>,
}

fn clean_var(var: &str) -> String {
    let mut v = var.trim();
    if v.starts_with("final ") {
        v = &v["final ".len()..];
    }
    if v.starts_with("const ") {
        v = &v["const ".len()..];
    }
    let v = v.trim();
    let base = if let Some(idx) = v.find(':').or_else(|| v.find('=')) {
        &v[..idx]
    } else {
        v
    };
    let last = base.split_whitespace().last().unwrap_or(base);
    last.replace("[]", "")
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_string()
}

fn parse_literal_val(src: &str) -> Option<ConstantValue> {
    let s = src.trim();
    if s.to_lowercase() == "true" {
        return Some(ConstantValue::Bool(true));
    }
    if s.to_lowercase() == "false" {
        return Some(ConstantValue::Bool(false));
    }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return Some(ConstantValue::Str(s[1..s.len() - 1].to_string()));
    }
    if s.starts_with('\'') && s.ends_with('\'') && s.len() == 3 {
        return Some(ConstantValue::Char(s.chars().nth(1).unwrap()));
    }
    if let Ok(val) = s.parse::<i64>() {
        return Some(ConstantValue::Int(val));
    }
    None
}

fn walk_instructions(
    insts: &[InstructionId],
    program: &Program,
    in_conditional: bool,
    assign_counts: &mut HashMap<String, usize>,
    conditional_vars: &mut HashSet<String>,
) {
    for &inst_id in insts {
        if let Some(inst) = program.instructions.get(&inst_id) {
            match &inst.kind {
                InstructionKind::Assign { dest, .. } => {
                    let clean_dest = clean_var(dest);
                    *assign_counts.entry(clean_dest.clone()).or_insert(0) += 1;
                    if in_conditional {
                        conditional_vars.insert(clean_dest);
                    }
                }
                InstructionKind::Call {
                    dest: Some(dest), ..
                } => {
                    let clean_dest = clean_var(dest);
                    *assign_counts.entry(clean_dest.clone()).or_insert(0) += 1;
                    if in_conditional {
                        conditional_vars.insert(clean_dest);
                    }
                }
                InstructionKind::Branch {
                    then_block,
                    else_block,
                    ..
                } => {
                    walk_instructions(then_block, program, true, assign_counts, conditional_vars);
                    if let Some(else_b) = else_block {
                        walk_instructions(else_b, program, true, assign_counts, conditional_vars);
                    }
                }
                InstructionKind::Loop { body, .. } => {
                    walk_instructions(body, program, true, assign_counts, conditional_vars);
                }
                InstructionKind::Try {
                    body,
                    catches,
                    finally,
                } => {
                    walk_instructions(body, program, true, assign_counts, conditional_vars);
                    for catch in catches {
                        if let Some(catch_inst) = program.instructions.get(catch) {
                            if let InstructionKind::Catch {
                                body: catch_body, ..
                            } = &catch_inst.kind
                            {
                                walk_instructions(
                                    catch_body,
                                    program,
                                    true,
                                    assign_counts,
                                    conditional_vars,
                                );
                            }
                        }
                    }
                    if let Some(fin) = finally {
                        walk_instructions(fin, program, true, assign_counts, conditional_vars);
                    }
                }
                _ => {}
            }
        }
    }
}

fn analyze_local_constants(
    program: &Program,
    body: &[InstructionId],
) -> HashMap<String, ConstantValue> {
    let mut assign_counts = HashMap::new();
    let mut conditional_vars = HashSet::new();
    walk_instructions(
        body,
        program,
        false,
        &mut assign_counts,
        &mut conditional_vars,
    );

    let mut constants = HashMap::new();
    for &inst_id in body {
        if let Some(inst) = program.instructions.get(&inst_id) {
            match &inst.kind {
                InstructionKind::Assign { dest, src } => {
                    let clean_dest = clean_var(dest);
                    if assign_counts.get(&clean_dest).cloned().unwrap_or(0) > 1
                        || conditional_vars.contains(&clean_dest)
                    {
                        continue;
                    }
                    let clean_src = src.trim();
                    if let Some(val) = parse_literal_val(clean_src) {
                        constants.insert(clean_dest, val);
                    } else {
                        let clean_src_var = clean_var(src);
                        if let Some(val) = constants.get(&clean_src_var).cloned() {
                            constants.insert(clean_dest, val);
                        }
                    }
                }
                InstructionKind::Call {
                    dest: Some(dest),
                    callee,
                    args,
                } => {
                    let clean_dest = clean_var(dest);
                    if assign_counts.get(&clean_dest).cloned().unwrap_or(0) > 1
                        || conditional_vars.contains(&clean_dest)
                    {
                        continue;
                    }
                    if (callee.contains(".charAt") || callee.ends_with(".charAt"))
                        && args.len() == 1
                    {
                        if let Some(dot_idx) = callee.find('.') {
                            let receiver = clean_var(&callee[..dot_idx]);
                            if let Some(ConstantValue::Str(s)) = constants.get(&receiver) {
                                let arg_clean = clean_var(&args[0]);
                                let idx_opt = if let Some(ConstantValue::Int(idx)) =
                                    constants.get(&arg_clean)
                                {
                                    Some(*idx as usize)
                                } else if let Ok(idx) = arg_clean.parse::<usize>() {
                                    Some(idx)
                                } else {
                                    None
                                };
                                if let Some(idx) = idx_opt {
                                    if let Some(c) = s.chars().nth(idx) {
                                        constants.insert(clean_dest, ConstantValue::Char(c));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    constants
}

impl InterproceduralCFG {
    pub fn build(program: &Program, call_graph: &CallGraph) -> Self {
        let mut nodes = HashMap::new();
        let mut edges = Vec::new();
        let mut method_to_nodes: HashMap<MethodId, Vec<u32>> = HashMap::new();
        let mut method_entry_node = HashMap::new();
        let mut method_exit_node = HashMap::new();
        let mut instruction_to_nodes: HashMap<InstructionId, Vec<u32>> = HashMap::new();

        let mut next_node_id = 1;

        // 1. Build local CFG for each method in the program
        for (&method_id, method) in &program.methods {
            let constants = analyze_local_constants(program, &method.body);
            let mut builder = MethodCfgBuilder {
                program,
                method_id,
                nodes: &mut nodes,
                edges: &mut edges,
                next_node_id: &mut next_node_id,
                instruction_to_nodes: &mut instruction_to_nodes,
                method_exit_node_id: 0,
                constants,
            };

            // Allocate entry and exit nodes
            let entry_id =
                builder.alloc_node(IcfgNodeKind::Entry, None, format!("Entry: {}", method.name));
            let exit_id =
                builder.alloc_node(IcfgNodeKind::Exit, None, format!("Exit: {}", method.name));

            method_entry_node.insert(method_id, entry_id);
            method_exit_node.insert(method_id, exit_id);
            builder.method_exit_node_id = exit_id;

            // Build method body backwards from exit
            let body_entry = builder.build_backwards(&method.body, exit_id);

            // Connect entry to body entry
            builder.add_edge(entry_id, body_entry, IcfgEdgeKind::CFG);
        }

        // 2. Add interprocedural Call and Return edges using the CallGraph
        for edge in &call_graph.edges {
            if let Some(inst_id) = edge.instruction_id {
                let caller_nodes = instruction_to_nodes.get(&inst_id);
                let callee_entry = method_entry_node.get(&edge.callee);
                let callee_exit = method_exit_node.get(&edge.callee);

                if let (Some(c_nodes), Some(&entry_id), Some(&exit_id)) =
                    (caller_nodes, callee_entry, callee_exit)
                {
                    // Find Call and Return nodes at caller instruction
                    let caller_call_node = c_nodes.iter().find(|&&n| {
                        nodes
                            .get(&n)
                            .map(|x| x.kind == IcfgNodeKind::Call)
                            .unwrap_or(false)
                    });
                    let caller_return_node = c_nodes.iter().find(|&&n| {
                        nodes
                            .get(&n)
                            .map(|x| x.kind == IcfgNodeKind::Return)
                            .unwrap_or(false)
                    });

                    if let (Some(&call_node_id), Some(&return_node_id)) =
                        (caller_call_node, caller_return_node)
                    {
                        // Caller Call -> Callee Entry
                        edges.push(IcfgEdge {
                            from: call_node_id,
                            to: entry_id,
                            kind: IcfgEdgeKind::Call,
                        });

                        // Callee Exit -> Caller Return Site
                        edges.push(IcfgEdge {
                            from: exit_id,
                            to: return_node_id,
                            kind: IcfgEdgeKind::Return,
                        });
                    }
                }
            }
        }

        // Populate method_to_nodes helper index
        for (&node_id, node) in &nodes {
            method_to_nodes
                .entry(node.method_id)
                .or_default()
                .push(node_id);
        }

        Self {
            nodes,
            edges,
            method_to_nodes,
            method_entry_node,
            method_exit_node,
            instruction_to_nodes,
        }
    }
}

struct MethodCfgBuilder<'a> {
    program: &'a Program,
    method_id: MethodId,
    nodes: &'a mut HashMap<u32, IcfgNode>,
    edges: &'a mut Vec<IcfgEdge>,
    next_node_id: &'a mut u32,
    instruction_to_nodes: &'a mut HashMap<InstructionId, Vec<u32>>,
    method_exit_node_id: u32,
    constants: HashMap<String, ConstantValue>,
}

impl<'a> MethodCfgBuilder<'a> {
    fn alloc_node(
        &mut self,
        kind: IcfgNodeKind,
        instruction_id: Option<InstructionId>,
        label: String,
    ) -> u32 {
        let id = *self.next_node_id;
        *self.next_node_id += 1;
        let node = IcfgNode {
            id,
            method_id: self.method_id,
            instruction_id,
            kind,
            label,
        };
        self.nodes.insert(id, node);
        if let Some(inst_id) = instruction_id {
            self.instruction_to_nodes
                .entry(inst_id)
                .or_default()
                .push(id);
        }
        id
    }

    fn add_edge(&mut self, from: u32, to: u32, kind: IcfgEdgeKind) {
        self.edges.push(IcfgEdge { from, to, kind });
    }

    fn build_backwards(&mut self, insts: &[InstructionId], target_exit: u32) -> u32 {
        let mut current_exit = target_exit;
        for &inst_id in insts.iter().rev() {
            current_exit = self.build_instruction(inst_id, current_exit);
        }
        current_exit
    }

    fn build_instruction(&mut self, inst_id: InstructionId, target_exit: u32) -> u32 {
        let inst = match self.program.instructions.get(&inst_id) {
            Some(i) => i,
            None => return target_exit,
        };

        match &inst.kind {
            InstructionKind::Assign { dest, src } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("{} = {}", dest, src),
                );
                self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);
                stmt_id
            }
            InstructionKind::Call { dest, callee, args } => {
                let return_label = if let Some(d) = dest {
                    format!("return_site: {} = {}", d, callee)
                } else {
                    format!("return_site: {}", callee)
                };
                let return_id = self.alloc_node(IcfgNodeKind::Return, Some(inst_id), return_label);
                self.add_edge(return_id, target_exit, IcfgEdgeKind::CFG);

                let call_label = format!("call: {}({})", callee, args.join(", "));
                let call_id = self.alloc_node(IcfgNodeKind::Call, Some(inst_id), call_label);

                self.add_edge(call_id, return_id, IcfgEdgeKind::CFG);
                call_id
            }
            InstructionKind::Return { val } => {
                let label = if let Some(v) = val {
                    format!("return {}", v)
                } else {
                    "return".to_string()
                };
                let stmt_id = self.alloc_node(IcfgNodeKind::Statement, Some(inst_id), label);
                self.add_edge(stmt_id, self.method_exit_node_id, IcfgEdgeKind::CFG);
                stmt_id
            }
            InstructionKind::Branch {
                cond,
                then_block,
                else_block,
            } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("if {}", cond),
                );

                let mut evaluator = Evaluator::new(&self.constants);
                match evaluator.evaluate(cond) {
                    Some(ConstantValue::Bool(true)) if !then_block.is_empty() => {
                        let then_entry = self.build_backwards(then_block, target_exit);
                        self.add_edge(stmt_id, then_entry, IcfgEdgeKind::CFG);
                    }
                    Some(ConstantValue::Bool(false)) => {
                        if let Some(else_b) = else_block {
                            let else_entry = self.build_backwards(else_b, target_exit);
                            self.add_edge(stmt_id, else_entry, IcfgEdgeKind::CFG);
                        } else {
                            self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);
                        }
                    }
                    _ => {
                        let then_entry = self.build_backwards(then_block, target_exit);
                        self.add_edge(stmt_id, then_entry, IcfgEdgeKind::CFG);

                        if let Some(else_b) = else_block {
                            let else_entry = self.build_backwards(else_b, target_exit);
                            self.add_edge(stmt_id, else_entry, IcfgEdgeKind::CFG);
                        } else {
                            self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);
                        }
                    }
                }
                stmt_id
            }
            InstructionKind::Loop { cond, body } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("while {}", cond),
                );
                self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);

                let body_entry = self.build_backwards(body, stmt_id);
                self.add_edge(stmt_id, body_entry, IcfgEdgeKind::CFG);
                stmt_id
            }
            InstructionKind::Try {
                body,
                catches,
                finally,
            } => {
                let try_exit = if let Some(fin) = finally {
                    self.build_backwards(fin, target_exit)
                } else {
                    target_exit
                };

                let stmt_id =
                    self.alloc_node(IcfgNodeKind::Statement, Some(inst_id), "try".to_string());

                let body_entry = self.build_backwards(body, try_exit);
                self.add_edge(stmt_id, body_entry, IcfgEdgeKind::CFG);

                for &catch_id in catches {
                    let catch_entry = self.build_instruction(catch_id, try_exit);
                    self.add_edge(stmt_id, catch_entry, IcfgEdgeKind::Exception);
                }

                stmt_id
            }
            InstructionKind::Catch {
                exception_var,
                body,
            } => {
                let label = if let Some(v) = exception_var {
                    format!("catch {}", v)
                } else {
                    "catch".to_string()
                };
                let stmt_id = self.alloc_node(IcfgNodeKind::Statement, Some(inst_id), label);
                let body_entry = self.build_backwards(body, target_exit);
                self.add_edge(stmt_id, body_entry, IcfgEdgeKind::CFG);
                stmt_id
            }
            InstructionKind::Throw { val } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("throw {}", val),
                );
                self.add_edge(stmt_id, self.method_exit_node_id, IcfgEdgeKind::Exception);
                stmt_id
            }
            InstructionKind::Source { name } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("source: {}", name),
                );
                self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);
                stmt_id
            }
            InstructionKind::Sink { name } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("sink: {}", name),
                );
                self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);
                stmt_id
            }
            InstructionKind::Sanitizer { name } => {
                let stmt_id = self.alloc_node(
                    IcfgNodeKind::Statement,
                    Some(inst_id),
                    format!("sanitizer: {}", name),
                );
                self.add_edge(stmt_id, target_exit, IcfgEdgeKind::CFG);
                stmt_id
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::Program;
    use symbols::global::GlobalSymbolTable;

    #[test]
    fn test_branch_pruning() {
        let mut program = Program::new();
        let mut gst = GlobalSymbolTable::new();

        let code = r#"
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/trustbound-00/BenchmarkTest00323")
public class BenchmarkTest00323 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00323");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String bar;

        // Simple if statement that assigns constant to bar on true condition
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;

        // javax.servlet.http.HttpSession.putValue(java.lang.String,java.lang.Object^)
        request.getSession().putValue("userid", bar);

        response.getWriter()
                .println(
                        "Item: 'userid' with value: '"
                                + org.owasp.benchmark.helpers.Utils.encodeForHTML(bar)
                                + "' saved in session.");
    }
}
        "#;

        gst.load_file(&mut program, code, "Test.java", "java")
            .unwrap();
        gst.resolve_inheritance_hierarchy();
        let cg = symbols::call_graph::CallGraph::build(&program, &gst);
        let icfg = InterproceduralCFG::build(&program, &cg);

        println!("Nodes:");
        for (id, node) in &icfg.nodes {
            println!("  Node {}: {:?} (label: '{}')", id, node.kind, node.label);
        }
        println!("Edges:");
        for edge in &icfg.edges {
            println!("  Edge: {} -> {}", edge.from, edge.to);
        }

        for (&method_id, method) in &program.methods {
            let constants = analyze_local_constants(&program, &method.body);
            println!("Method: {}, Constants: {:?}", method.name, constants);
        }
    }
}
