use std::fs;
use ir::InstructionKind;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Num(i32),
    Str(String),
    Ident(String),
    Op(String),
    In,
    NotIn,
    OpenParen,
    CloseParen,
}

#[derive(Debug, Clone)]
enum Val {
    Num(i32),
    Str(String),
    Bool(bool),
}

fn tokenize(expr: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' {
            tokens.push(Token::OpenParen);
            i += 1;
            continue;
        }
        if c == ')' {
            tokens.push(Token::CloseParen);
            i += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            let quote = c;
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != quote {
                s.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return None;
            }
            i += 1;
            tokens.push(Token::Str(s));
            continue;
        }
        if c.is_digit(10) {
            let mut num_str = String::new();
            while i < chars.len() && chars[i].is_digit(10) {
                num_str.push(chars[i]);
                i += 1;
            }
            let val = num_str.parse::<i32>().ok()?;
            tokens.push(Token::Num(val));
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut word = String::new();
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                word.push(chars[i]);
                i += 1;
            }
            if word == "in" {
                tokens.push(Token::In);
            } else if word == "not" {
                let mut temp_i = i;
                while temp_i < chars.len() && chars[temp_i].is_whitespace() {
                    temp_i += 1;
                }
                let mut next_word = String::new();
                while temp_i < chars.len() && chars[temp_i].is_alphabetic() {
                    next_word.push(chars[temp_i]);
                    temp_i += 1;
                }
                if next_word == "in" {
                    tokens.push(Token::NotIn);
                    i = temp_i;
                } else {
                    tokens.push(Token::Ident(word));
                }
            } else {
                tokens.push(Token::Ident(word));
            }
            continue;
        }
        let op_chars = ['+', '-', '*', '/', '>', '<', '=', '!', '&', '|', '%', '?', ':'];
        if op_chars.contains(&c) {
            let mut op_str = String::new();
            while i < chars.len() && op_chars.contains(&chars[i]) {
                op_str.push(chars[i]);
                i += 1;
            }
            tokens.push(Token::Op(op_str));
            continue;
        }
        i += 1;
    }
    Some(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let t = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(t)
        } else {
            None
        }
    }

    fn factor(&mut self) -> Option<Val> {
        let t = self.next()?;
        match t {
            Token::Num(val) => Some(Val::Num(val)),
            Token::Str(val) => Some(Val::Str(val)),
            Token::OpenParen => {
                let val = self.expr()?;
                if matches!(self.next(), Some(Token::CloseParen)) {
                    Some(val)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn term(&mut self) -> Option<Val> {
        let mut left = self.factor()?;
        while let Some(t) = self.peek() {
            match t {
                Token::Op(op) if op == "*" || op == "/" || op == "%" => {
                    let op = match self.next()? {
                        Token::Op(o) => o,
                        _ => unreachable!(),
                    };
                    let right = self.factor()?;
                    left = match (left, right) {
                        (Val::Num(l), Val::Num(r)) => {
                            if op == "*" {
                                Val::Num(l * r)
                            } else if op == "/" {
                                Val::Num(l / r)
                            } else {
                                Val::Num(l % r)
                            }
                        }
                        _ => return None,
                    };
                }
                _ => break,
            }
        }
        Some(left)
    }

    fn arith_expr(&mut self) -> Option<Val> {
        let mut left = self.term()?;
        while let Some(t) = self.peek() {
            match t {
                Token::Op(op) if op == "+" || op == "-" => {
                    let op = match self.next()? {
                        Token::Op(o) => o,
                        _ => unreachable!(),
                    };
                    let right = self.term()?;
                    left = match (left, right) {
                        (Val::Num(l), Val::Num(r)) => {
                            if op == "+" {
                                Val::Num(l + r)
                            } else {
                                Val::Num(l - r)
                            }
                        }
                        (Val::Str(l), Val::Str(r)) => {
                            if op == "+" {
                                Val::Str(format!("{}{}", l, r))
                            } else {
                                return None;
                            }
                        }
                        _ => return None,
                    };
                }
                _ => break,
            }
        }
        Some(left)
    }

    fn comp_expr(&mut self) -> Option<Val> {
        let left = self.arith_expr()?;
        if let Some(t) = self.peek() {
            match t {
                Token::Op(op) if op == "==" || op == "!=" || op == ">" || op == "<" || op == ">=" || op == "<=" => {
                    let op = match self.next()? {
                        Token::Op(o) => o,
                        _ => unreachable!(),
                    };
                    let right = self.arith_expr()?;
                    match (left, right) {
                        (Val::Num(l), Val::Num(r)) => {
                            if op == "==" { Some(Val::Bool(l == r)) }
                            else if op == "!=" { Some(Val::Bool(l != r)) }
                            else if op == ">" { Some(Val::Bool(l > r)) }
                            else if op == "<" { Some(Val::Bool(l < r)) }
                            else if op == ">=" { Some(Val::Bool(l >= r)) }
                            else { Some(Val::Bool(l <= r)) }
                        }
                        (Val::Str(l), Val::Str(r)) => {
                            if op == "==" { Some(Val::Bool(l == r)) }
                            else if op == "!=" { Some(Val::Bool(l != r)) }
                            else { None }
                        }
                        _ => None,
                    }
                }
                Token::In => {
                    self.next();
                    let right = self.arith_expr()?;
                    match (left, right) {
                        (Val::Str(l), Val::Str(r)) => Some(Val::Bool(r.contains(&l))),
                        _ => None,
                    }
                }
                Token::NotIn => {
                    self.next();
                    let right = self.arith_expr()?;
                    match (left, right) {
                        (Val::Str(l), Val::Str(r)) => Some(Val::Bool(!r.contains(&l))),
                        _ => None,
                    }
                }
                _ => Some(left),
            }
        } else {
            Some(left)
        }
    }

    fn logic_and(&mut self) -> Option<Val> {
        let mut left = self.comp_expr()?;
        while let Some(Token::Op(op)) = self.peek() {
            if op == "&&" {
                self.next();
                let right = self.comp_expr()?;
                left = match (left, right) {
                    (Val::Bool(l), Val::Bool(r)) => Val::Bool(l && r),
                    _ => return None,
                };
            } else {
                break;
            }
        }
        Some(left)
    }

    fn logic_or(&mut self) -> Option<Val> {
        let mut left = self.logic_and()?;
        while let Some(Token::Op(op)) = self.peek() {
            if op == "||" {
                self.next();
                let right = self.logic_and()?;
                left = match (left, right) {
                    (Val::Bool(l), Val::Bool(r)) => Val::Bool(l || r),
                    _ => return None,
                };
            } else {
                break;
            }
        }
        Some(left)
    }

    fn expr(&mut self) -> Option<Val> {
        let first = self.logic_or()?;
        if let Some(Token::Op(op)) = self.peek() {
            if op == "?" {
                self.next(); // consume "?"
                let then_val = self.expr()?;
                if let Some(Token::Op(colon)) = self.peek() {
                    if colon == ":" {
                        self.next(); // consume ":"
                        let else_val = self.expr()?;
                        return match first {
                            Val::Bool(b) => {
                                if b { Some(then_val) } else { Some(else_val) }
                            }
                            _ => None,
                        };
                    }
                }
                return None;
            }
        }
        Some(first)
    }
}

fn get_renamed_var(var: &str, defs: &std::collections::HashSet<usize>) -> String {
    if defs.is_empty() {
        return format!("{}_0", var);
    }
    if defs.len() == 1 {
        let d = defs.iter().next().unwrap();
        return format!("{}_{}", var, d);
    }
    let mut sorted_defs: Vec<usize> = defs.iter().cloned().collect();
    sorted_defs.sort();
    let defs_str: Vec<String> = sorted_defs.iter().map(|d| d.to_string()).collect();
    format!("{}_phi_{}", var, defs_str.join("_"))
}

fn rename_expression(
    expr: &str,
    incoming_defs: &std::collections::HashMap<String, std::collections::HashSet<usize>>,
) -> String {
    let mut result = String::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            let quote = c;
            result.push(quote);
            i += 1;
            while i < chars.len() && chars[i] != quote {
                result.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                result.push(quote);
                i += 1;
            }
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut word = String::new();
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                word.push(chars[i]);
                i += 1;
            }
            if let Some(defs) = incoming_defs.get(&word) {
                result.push_str(&get_renamed_var(&word, defs));
            } else {
                let empty_set = std::collections::HashSet::new();
                result.push_str(&get_renamed_var(&word, &empty_set));
            }
        } else {
            result.push(c);
            i += 1;
        }
    }
    result
}

fn resolve_constant(
    var: &str,
    assignments: &[(String, String)],
    visited: &mut std::collections::HashSet<String>,
) -> Option<String> {
    if visited.contains(var) {
        return None;
    }
    visited.insert(var.to_string());
    
    for (dest, src) in assignments {
        if dest == var {
            let is_const = src.starts_with('"') || src.parse::<f64>().is_ok() || src == "true" || src == "false" || src == "None" || src == "null";
            if is_const {
                visited.remove(var);
                return Some(src.clone());
            }
            // If it's another variable, try to resolve it recursively
            if src.chars().all(|c| c.is_alphanumeric() || c == '_') {
                if let Some(val) = resolve_constant(src, assignments, visited) {
                    visited.remove(var);
                    return Some(val);
                }
            }
        }
    }
    visited.remove(var);
    None
}

fn collect_instructions(block: &[ir::InstructionId], program: &ir::Program, out: &mut Vec<ir::InstructionId>) {
    for &id in block {
        out.push(id);
        if let Some(inst) = program.instructions.get(&id) {
            match &inst.kind {
                InstructionKind::Branch { then_block, else_block, .. } => {
                    collect_instructions(then_block, program, out);
                    if let Some(eb) = else_block {
                        collect_instructions(eb, program, out);
                    }
                }
                InstructionKind::Loop { body, .. } => {
                    collect_instructions(body, program, out);
                }
                InstructionKind::Try { body, catches, finally, .. } => {
                    collect_instructions(body, program, out);
                    collect_instructions(catches, program, out);
                    if let Some(fb) = finally {
                        collect_instructions(fb, program, out);
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_in_block(target: ir::InstructionId, block: &[ir::InstructionId], program: &ir::Program) -> bool {
    for &id in block {
        if id == target {
            return true;
        }
        if let Some(inst) = program.instructions.get(&id) {
            match &inst.kind {
                InstructionKind::Branch { then_block, else_block, .. } => {
                    if is_in_block(target, then_block, program) {
                        return true;
                    }
                    if let Some(eb) = else_block {
                        if is_in_block(target, eb, program) {
                            return true;
                        }
                    }
                }
                InstructionKind::Loop { body, .. } => {
                    if is_in_block(target, body, program) {
                        return true;
                    }
                }
                InstructionKind::Try { body, catches, finally, .. } => {
                    if is_in_block(target, body, program) {
                        return true;
                    }
                    if is_in_block(target, catches, program) {
                        return true;
                    }
                    if let Some(fb) = finally {
                        if is_in_block(target, fb, program) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn find_instruction_for_ssa_var(ssa_var: &str) -> Option<ir::InstructionId> {
    if ssa_var.contains("_phi_") {
        return None;
    }
    let parts: Vec<&str> = ssa_var.split('_').collect();
    if let Some(last) = parts.last() {
        if let Ok(inst_id_val) = last.parse::<u32>() {
            if inst_id_val > 0 {
                return Some(ir::InstructionId(inst_id_val));
            }
        }
    }
    None
}

fn find_ssa_paths_trace(
    curr: &str,
    target: &str,
    target_is_any: bool,
    assignments: &[(String, String)],
    collection_lookups: &std::collections::HashMap<String, std::collections::HashSet<String>>,
    program: &ir::Program,
    method: &ir::Method,
    visited: &mut std::collections::HashSet<String>,
    current_path: &mut Vec<String>,
    all_paths: &mut Vec<Vec<String>>,
    depth: usize,
) {
    let indent = "  ".repeat(depth);
    println!("{}-> find_ssa_paths(curr='{}', target='{}', target_is_any={})", indent, curr, target, target_is_any);
    println!("{}   current_path={:?}, visited={:?}", indent, current_path, visited);

    if !target_is_any && curr == target {
        println!("{}   [MATCH] curr == target -> Path inserted into all_paths!", indent);
        all_paths.push(current_path.clone());
        return;
    }
    
    if target_is_any {
        let is_constant = curr.starts_with('"') || curr.parse::<f64>().is_ok() || curr == "true" || curr == "false" || curr == "None" || curr == "null";
        let is_sentinel = curr.starts_with("unknown") || curr.contains("unknown");
        if is_constant || is_sentinel {
            println!("{}   [DISCARD] Constant/Sentinel: is_constant={}, is_sentinel={}", indent, is_constant, is_sentinel);
            return;
        }
        let has_def = assignments.iter().any(|(dest, _)| dest == curr) || collection_lookups.contains_key(curr);
        if !has_def {
            println!("{}   [MATCH] Wildcard leaf node (no def) -> Path inserted into all_paths!", indent);
            all_paths.push(current_path.clone());
            return;
        }
    }

    if visited.contains(curr) {
        println!("{}   [DISCARD] Visited cycle: {}", indent, curr);
        return;
    }
    visited.insert(curr.to_string());
    
    if let Some(src_vars) = collection_lookups.get(curr) {
        println!("{}   [RECURSE] Collection lookups for '{}': {:?}", indent, curr, src_vars);
        for src_var in src_vars {
            current_path.push(curr.to_string());
            find_ssa_paths_trace(src_var, target, target_is_any, assignments, collection_lookups, program, method, visited, current_path, all_paths, depth + 1);
            current_path.pop();
        }
    } else {
        let mut found_any_assign = false;
        for (dest, src) in assignments {
            if dest == curr {
                found_any_assign = true;
                if target_is_any && src == "unknown_call" {
                    println!("{}   [MATCH] unknown_call in target_is_any mode", indent);
                    current_path.push(dest.clone());
                    all_paths.push(current_path.clone());
                    current_path.pop();
                    continue;
                }
                
                // Extract variables from src expression
                let mut src_vars = Vec::new();
                let chars: Vec<char> = src.chars().collect();
                let mut idx = 0;
                while idx < chars.len() {
                    let c = chars[idx];
                    if c == '\'' || c == '"' {
                        let quote = c;
                        idx += 1;
                        while idx < chars.len() && chars[idx] != quote {
                            idx += 1;
                        }
                        if idx < chars.len() {
                            idx += 1;
                        }
                        continue;
                    }
                    if c.is_alphabetic() || c == '_' {
                        let mut word = String::new();
                        while idx < chars.len() && (chars[idx].is_alphanumeric() || chars[idx] == '_') {
                            word.push(chars[idx]);
                            idx += 1;
                        }
                        src_vars.push(word);
                    } else {
                        idx += 1;
                    }
                }

                if target_is_any && src_vars.is_empty() {
                    println!("{}   [DISCARD] src is constant/sentinel with no variables", indent);
                    continue;
                }

                println!("{}   [RECURSE] Definition {} = {}, recursing on: {:?}", indent, dest, src, src_vars);
                for src_var in src_vars {
                    current_path.push(dest.clone());
                    find_ssa_paths_trace(&src_var, target, target_is_any, assignments, collection_lookups, program, method, visited, current_path, all_paths, depth + 1);
                    current_path.pop();
                }
            }
        }
        if !found_any_assign {
            println!("{}   [DISCARD] No assignments found for '{}'", indent, curr);
        }
    }
    visited.remove(curr);
    println!("{}<- find_ssa_paths(curr='{}') returning", indent, curr);
}

fn main() {
    let targets = vec![
        ("BenchmarkTest00030", "Test_CWE_79.java", "java", "d:/V2 Backup/benchmarks/benchmark_java.jsonl"),
        ("BenchmarkTest00031", "Test_CWE_501.java", "java", "d:/V2 Backup/benchmarks/benchmark_java.jsonl"),
        ("BenchmarkTest00475", "Test_CWE_79.java", "java", "d:/V2 Backup/benchmarks/benchmark_java.jsonl"),
    ];

    for (target_name, filename, lang, dataset_path) in targets {
        println!("\n========================================================");
        println!("FORENSIC TRACE FOR {}", target_name);
        println!("========================================================");

        let content = fs::read_to_string(dataset_path).unwrap();
        let mut code = String::new();
        for line in content.lines() {
            if line.contains(target_name) {
                let data: serde_json::Value = serde_json::from_str(line).unwrap();
                code = data.get("code").unwrap().as_str().unwrap().to_string();
                break;
            }
        }

        let mut program = ir::Program::new();
        let mut gst = symbols::global::GlobalSymbolTable::new();

        program.source_files.insert(filename.to_string(), code.clone());
        if gst.load_file(&mut program, &code, filename, &lang.to_string()).is_ok() {
            gst.resolve_inheritance_hierarchy();
            let cg = symbols::call_graph::CallGraph::build(&program, &gst);
            let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
            let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
            engine.target_file = Some(filename.to_string());
            engine.seed_sources(None);
            engine.run();

            let facts = v2_export_adapter::Exporter::export(&engine);

            for (flow_idx, flow) in facts.taint_flows.iter().enumerate() {
                println!("\n--- FLOW INDEX {} ---", flow_idx);
                let sink_id = facts.icfg_to_inst.get(&flow.sink_node_id).copied().unwrap_or(ir::InstructionId(flow.sink_node_id));
                let method = program.methods.values().find(|m| m.name == "doPost").unwrap();
                let cfg = v2_refiner_domain::CfgBuilder::build(&program, method);
                let ssa = v2_refiner_domain::SsaBuilder::new(&program, method, &cfg).build();

                let sink_var_map = ssa.instruction_incoming_versions.get(&sink_id);
                let sink_var_defs = sink_var_map.and_then(|m| m.get(&flow.sink_var)).cloned().unwrap_or_default();
                let sink_var_ssa = get_renamed_var(&flow.sink_var, &sink_var_defs);

                let mut source_defs = std::collections::HashSet::new();
                let is_param = method.parameters.iter().any(|p| {
                    let clean_p = p.split(' ').last().unwrap_or(p);
                    clean_p == &flow.source_var
                });
                if is_param || flow.source_node_id == 0 {
                    source_defs.insert(0);
                } else {
                    let source_inst_id = facts.icfg_to_inst.get(&flow.source_node_id).map(|id| id.0 as usize).unwrap_or(flow.source_node_id as usize);
                    source_defs.insert(source_inst_id);
                }
                let source_var_ssa = get_renamed_var(&flow.source_var, &source_defs);
                let target_is_any = flow.source_var.is_empty();

                // CollectionState Reconstruction Simulation (Mimics logic in v2-refiner-domain)
                let mut collection_lookups = std::collections::HashMap::new();
                let mut collection_states: std::collections::HashMap<String, Vec<(String, String)>> = std::collections::HashMap::new();

                let mut insts_sorted = program.instructions.keys().cloned().collect::<Vec<_>>();
                insts_sorted.sort_by_key(|id| id.0);
                for inst_id in insts_sorted {
                    if let Some(inst) = program.instructions.get(&inst_id) {
                        if let ir::InstructionKind::Call { dest, callee, args } = &inst.kind {
                            if callee.contains(".get") || callee.contains(".getitem") {
                                if !args.is_empty() {
                                    if let Some(dest_var) = dest {
                                        let renamed_dest = get_renamed_var(dest_var, &std::collections::HashSet::from([inst_id.0 as usize]));
                                        let receiver = callee.split('.').next().unwrap().to_string();
                                        
                                        // Simulation of collection lookup population:
                                        let mut lookups = std::collections::HashSet::new();
                                        let key_arg = &args[0];
                                        let key_stripped = key_arg.trim_matches('"');
                                        
                                        // Check if key is index or string
                                        let key = if let Ok(idx) = key_stripped.parse::<usize>() {
                                            Some(idx.to_string())
                                        } else if key_arg.starts_with('"') {
                                            Some(key_stripped.to_string())
                                        } else {
                                            None
                                        };

                                        if let Some(k) = key {
                                            if let Some(state) = collection_states.get(&receiver) {
                                                for (sk, sv) in state {
                                                    if sk == &k {
                                                        lookups.insert(sv.clone());
                                                    }
                                                }
                                            }
                                        }
                                        if lookups.is_empty() {
                                            lookups.insert("unknown_collection_val".to_string());
                                        }
                                        collection_lookups.insert(renamed_dest, lookups);
                                    }
                                }
                            }
                        }
                    }
                }

                println!("Collection Lookups Map: {:?}", collection_lookups);

                let mut visited = std::collections::HashSet::new();
                let mut current_path = Vec::new();
                let mut all_paths = Vec::new();
                
                find_ssa_paths_trace(
                    &sink_var_ssa,
                    &source_var_ssa,
                    target_is_any,
                    &ssa.ssa_assignments,
                    &collection_lookups,
                    &program,
                    method,
                    &mut visited,
                    &mut current_path,
                    &mut all_paths,
                    0,
                );

                println!("\nAll Paths Results for Flow:");
                for (p_idx, path) in all_paths.iter().enumerate() {
                    println!("  Path {}: {:?}", p_idx, path);
                    let mut path_is_dead = false;
                    for var in path {
                        if let Some(inst_id) = find_instruction_for_ssa_var(var) {
                            println!("    Evaluating var: {} (inst_{})", var, inst_id.0);
                            
                            let mut all_body_insts = Vec::new();
                            collect_instructions(&method.body, &program, &mut all_body_insts);
                            for other_id in &all_body_insts {
                                if let Some(other_inst) = program.instructions.get(other_id) {
                                    if let InstructionKind::Branch { cond, then_block, else_block } = &other_inst.kind {
                                        if let Some(var_map) = ssa.instruction_incoming_versions.get(other_id) {
                                            let substituted = rename_expression(cond, var_map);
                                            println!("      Branch inst_{} cond: {}, substituted: {}", other_id.0, cond, substituted);
                                            
                                            // Solve substitutions
                                            let chars: Vec<char> = substituted.chars().collect();
                                            let mut resolved_expr = String::new();
                                            let mut i = 0;
                                            while i < chars.len() {
                                                let c = chars[i];
                                                if c.is_alphabetic() || c == '_' {
                                                    let mut word = String::new();
                                                    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                                                        word.push(chars[i]);
                                                        i += 1;
                                                    }
                                                    let mut vis = std::collections::HashSet::new();
                                                    if let Some(val) = resolve_constant(&word, &ssa.ssa_assignments, &mut vis) {
                                                        resolved_expr.push_str(&val);
                                                    } else {
                                                        resolved_expr.push_str(&word);
                                                    }
                                                } else {
                                                    resolved_expr.push(c);
                                                    i += 1;
                                                }
                                            }
                                            println!("        constant substitutions resolved_expr: {}", resolved_expr);
                                            
                                            if let Some(tokens) = tokenize(&resolved_expr) {
                                                let mut parser = Parser { tokens, pos: 0 };
                                                if let Some(Val::Bool(cond_val)) = parser.expr() {
                                                    println!("        parser result: Val::Bool({})", cond_val);
                                                    let in_then = is_in_block(inst_id, then_block, &program);
                                                    let in_else = else_block.as_ref().map(|eb| is_in_block(inst_id, eb, &program)).unwrap_or(false);
                                                    println!("        is_in_then_block: {}, is_in_else_block: {}", in_then, in_else);
                                                    
                                                    if cond_val {
                                                        if in_else {
                                                            println!("        [DEAD] Instruction is inside dead ELSE block!");
                                                            path_is_dead = true;
                                                        }
                                                    } else {
                                                        if in_then {
                                                            println!("        [DEAD] Instruction is inside dead THEN block!");
                                                            path_is_dead = true;
                                                        }
                                                    }
                                                } else {
                                                    println!("        parser result: None (not constant boolean)");
                                                }
                                            } else {
                                                println!("        tokenizer failed on expression");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    println!("  Path feasible: {}", !path_is_dead);
                }
            }
        }
    }
}
