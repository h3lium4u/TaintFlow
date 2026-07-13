use v2_frontend_base::LanguageFrontend;
use v2_ir::{InstructionKind, MethodId, Operand, Program, TypeId};
use v2_semantic::SemanticInfo;
use v2_common::Span;

pub struct JavaFrontend;

struct LogicalLine {
    text: String,
    span: Span,
}

fn preprocess_java(code: &str) -> Vec<LogicalLine> {
    let mut logical_lines = Vec::new();
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0;
    
    let mut current_line = 1;
    let mut current_col = 1;
    
    let mut stmt_accum = String::new();
    let mut stmt_start_line = 1;
    let mut stmt_start_col = 1;
    
    let mut in_string = false;
    let mut in_char = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut paren_nesting = 0;
    let mut bracket_nesting = 0;
    
    while i < chars.len() {
        let c = chars[i];
        let next_c = if i + 1 < chars.len() { Some(chars[i + 1]) } else { None };
        
        let is_newline = c == '\n' || (c == '\r' && next_c != Some('\n'));
        let is_crlf = c == '\r' && next_c == Some('\n');
        
        if in_line_comment {
            if is_newline || is_crlf {
                in_line_comment = false;
            }
        } else if in_block_comment {
            if c == '*' && next_c == Some('/') {
                in_block_comment = false;
                i += 1;
                current_col += 1;
            }
        } else if in_string {
            if c == '\\' {
                stmt_accum.push(c);
                if let Some(nc) = next_c {
                    stmt_accum.push(nc);
                    i += 1;
                    current_col += 1;
                }
            } else if c == '"' {
                in_string = false;
                stmt_accum.push(c);
            } else {
                stmt_accum.push(c);
            }
        } else if in_char {
            if c == '\\' {
                stmt_accum.push(c);
                if let Some(nc) = next_c {
                    stmt_accum.push(nc);
                    i += 1;
                    current_col += 1;
                }
            } else if c == '\'' {
                in_char = false;
                stmt_accum.push(c);
            } else {
                stmt_accum.push(c);
            }
        } else {
            if c == '/' && next_c == Some('/') {
                in_line_comment = true;
                i += 1;
                current_col += 1;
            } else if c == '/' && next_c == Some('*') {
                in_block_comment = true;
                i += 1;
                current_col += 1;
            } else if c == '"' {
                in_string = true;
                stmt_accum.push(c);
            } else if c == '\'' {
                in_char = true;
                stmt_accum.push(c);
            } else if c == '(' {
                paren_nesting += 1;
                stmt_accum.push(c);
            } else if c == ')' {
                if paren_nesting > 0 {
                    paren_nesting -= 1;
                }
                stmt_accum.push(c);
            } else if c == '[' {
                bracket_nesting += 1;
                stmt_accum.push(c);
            } else if c == ']' {
                if bracket_nesting > 0 {
                    bracket_nesting -= 1;
                }
                stmt_accum.push(c);
            } else if c == ';' || c == '{' || c == '}' {
                stmt_accum.push(c);
                let trimmed = stmt_accum.trim().to_string();
                if !trimmed.is_empty() {
                    logical_lines.push(LogicalLine {
                        text: trimmed,
                        span: Span {
                            start_line: stmt_start_line,
                            start_col: stmt_start_col,
                            end_line: current_line,
                            end_col: current_col,
                        },
                    });
                }
                stmt_accum.clear();
                stmt_start_line = 0;
            } else if is_newline || is_crlf {
                if paren_nesting > 0 || bracket_nesting > 0 {
                    stmt_accum.push(' ');
                } else {
                    let trimmed = stmt_accum.trim();
                    if !trimmed.is_empty() {
                        stmt_accum.push(' ');
                    }
                }
            } else if !c.is_whitespace() {
                if stmt_start_line == 0 {
                    stmt_start_line = current_line;
                    stmt_start_col = current_col;
                }
                stmt_accum.push(c);
            } else {
                if !stmt_accum.is_empty() {
                    stmt_accum.push(c);
                }
            }
        }
        
        if is_crlf {
            i += 2;
            current_line += 1;
            current_col = 1;
        } else if is_newline {
            i += 1;
            current_line += 1;
            current_col = 1;
        } else {
            i += 1;
            current_col += 1;
        }
    }
    
    let trimmed = stmt_accum.trim().to_string();
    if !trimmed.is_empty() {
        logical_lines.push(LogicalLine {
            text: trimmed,
            span: Span {
                start_line: stmt_start_line,
                start_col: stmt_start_col,
                end_line: current_line,
                end_col: current_col,
            },
        });
    }
    
    logical_lines
}

impl LanguageFrontend for JavaFrontend {
    fn lower(
        &self,
        code: &str,
        _semantic_info: &SemanticInfo,
        file_path: &std::path::Path,
    ) -> Result<Program, String> {
        let mut program = Program::new();
        let name = file_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("main")
            .to_string();
        let module_id = program.alloc_module(name, file_path.to_string_lossy().to_string());
        
        let mut current_class: Option<TypeId> = None;
        let mut current_method: Option<MethodId> = None;
        
        let logical_lines = preprocess_java(code);
        
        for logical_line in logical_lines {
            let line = &logical_line.text;
            let span = Some(logical_line.span);
            
            // 1. Detect Class / Interface
            if line.contains("class ") || line.contains("interface ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx) = parts.iter().position(|&x| x == "class" || x == "interface") {
                    if idx + 1 < parts.len() {
                        let name = parts[idx + 1].trim_end_matches('{').to_string();
                        current_class = Some(program.alloc_type(name, None, module_id));
                    }
                }
            }
            
            // 2. Detect Method
            if (line.contains("public ") || line.contains("private ") || line.contains("void ") || line.contains("String "))
                && line.contains('(') && line.contains(')') && !line.contains(';') {
                let parts: Vec<&str> = line.split('(').collect();
                if let Some(header) = parts.first() {
                    let header_parts: Vec<&str> = header.split_whitespace().collect();
                    if let Some(&name) = header_parts.last() {
                        let method_name = name.trim().to_string();
                        let mut params = Vec::new();
                        if parts.len() > 1 {
                            let param_str = parts[1].split(')').next().unwrap_or("");
                            for p in param_str.split(',') {
                                let p_parts: Vec<&str> = p.split_whitespace().collect();
                                if let Some(&p_name) = p_parts.last() {
                                    params.push(p_name.trim().to_string());
                                }
                            }
                        }
                        current_method = Some(program.alloc_method(method_name, current_class, params, Some(module_id)));
                    }
                }
            }
            
            // 3. Process Statements inside Method
            if let Some(method_id) = current_method {
                if line.contains("for") && line.contains(':') && line.contains('(') && line.contains(')') {
                    if let Some(start_idx) = line.find('(') {
                        if let Some(end_idx) = line.rfind(')') {
                            if start_idx < end_idx {
                                let inside = &line[start_idx + 1..end_idx];
                                let parts: Vec<&str> = inside.split(':').collect();
                                if parts.len() == 2 {
                                    let lhs = parts[0].trim();
                                    let rhs = parts[1].trim();
                                    let lhs_tokens: Vec<&str> = lhs.split_whitespace().collect();
                                    if let Some(&item_var) = lhs_tokens.last() {
                                        let item_var = item_var.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                                        let collection_var = rhs.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                                        if !item_var.is_empty() && !collection_var.is_empty() {
                                            let inst_id = program.alloc_instruction(
                                                InstructionKind::Assign {
                                                    dest: Operand::Var(item_var.to_string()),
                                                    src: Operand::Var(collection_var.to_string()),
                                                },
                                                span.clone(),
                                            );
                                            program.methods.get_mut(&method_id).unwrap().body.push(inst_id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if line.contains('(') && line.contains(')') {
                    let callees = extract_callees_with_receiver(line);
                    let dest = if let Some((lhs, _)) = line.split_once('=') {
                        let lhs_parts: Vec<&str> = lhs.split_whitespace().collect();
                        lhs_parts.last().map(|&var| Operand::Var(var.to_string()))
                    } else {
                        None
                    };
                    
                    for (callee, receiver) in callees {
                        let mut args = extract_args(line);
                        if let Some(rec_var) = receiver {
                            args.insert(0, Operand::Var(rec_var));
                        }
                        
                        let inst_id = program.alloc_instruction(
                            InstructionKind::Call {
                                dest: dest.clone(),
                                callee,
                                args,
                            },
                            span.clone(),
                        );
                        program.methods.get_mut(&method_id).unwrap().body.push(inst_id);
                    }
                } else if line.contains('=') {
                    if let Some((lhs, rhs)) = line.split_once('=') {
                        let lhs = lhs.trim();
                        let rhs = rhs.trim();
                        let lhs_tokens: Vec<&str> = lhs.split_whitespace().collect();
                        if let Some(&dest_var) = lhs_tokens.last() {
                            let dest_var = dest_var.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                            if !dest_var.is_empty() {
                                let srcs = extract_rhs_vars(rhs);
                                for src_var in srcs {
                                    let inst_id = program.alloc_instruction(
                                        InstructionKind::Assign {
                                            dest: Operand::Var(dest_var.to_string()),
                                            src: Operand::Var(src_var),
                                        },
                                        span.clone(),
                                    );
                                    program.methods.get_mut(&method_id).unwrap().body.push(inst_id);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(program)
    }
}

fn extract_rhs_vars(rhs: &str) -> Vec<String> {
    let mut vars = Vec::new();
    for part in rhs.split('+') {
        let trimmed = part.trim().trim_end_matches(';');
        if trimmed.starts_with('"') || trimmed.starts_with('\'') || trimmed == "null" || trimmed.parse::<i64>().is_ok() {
            continue;
        }
        let base_part = if trimmed.contains('[') {
            trimmed.split('[').next().unwrap_or(trimmed).trim()
        } else {
            trimmed
        };
        // Extract identifier
        let tokens: Vec<&str> = base_part.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(&var) = tokens.last() {
            let var = var.trim();
            if !var.is_empty() && var != "null" && !var.chars().next().unwrap().is_numeric() {
                if var == "param" || var == "bar" || var == "sql" || var == "fileName" || var.chars().next().unwrap().is_lowercase() {
                    vars.push(var.to_string());
                }
            }
        }
    }
    vars
}


fn extract_callees_with_receiver(line: &str) -> Vec<(String, Option<String>)> {
    let mut results = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '(' {
            let mut j = i;
            while j > 0 && chars[j - 1].is_whitespace() {
                j -= 1;
            }
            let mut start = j;
            while start > 0 {
                let c = chars[start - 1];
                if c.is_alphanumeric() || c == '.' || c == '_' {
                    start -= 1;
                } else {
                    break;
                }
            }
            if start < j {
                let mut full_name: String = chars[start..j].iter().collect();
                if full_name.starts_with("new") {
                    full_name = full_name.strip_prefix("new").unwrap().trim().to_string();
                }
                
                let receiver = if full_name.contains('.') {
                    let first_part = full_name.split('.').next().unwrap_or("").trim();
                    if let Some(first_char) = first_part.chars().next() {
                        if first_char.is_lowercase() && first_part != "this" && !first_part.is_empty() {
                            Some(first_part.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut name = full_name.trim_start_matches('.').to_string();
                if !name.is_empty() && name != "if" && name != "for" && name != "while" && name != "catch" {
                    if name.contains('.') {
                        if let Some(first_char) = name.chars().next() {
                            if first_char.is_lowercase() {
                                if let Some(last_part) = name.split('.').last() {
                                    name = last_part.to_string();
                                }
                            }
                        }
                    }
                    results.push((name, receiver));
                }
            }
        }
        i += 1;
    }
    results
}

fn extract_args(line: &str) -> Vec<Operand> {
    let mut args = Vec::new();
    if let Some(start_idx) = line.find('(') {
        if let Some(end_idx) = line.rfind(')') {
            if start_idx < end_idx {
                let inside = &line[start_idx + 1..end_idx];
                for token in inside.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '_') {
                    let mut t = token.trim();
                    if t.contains('.') {
                        if let Some(base) = t.split('.').next() {
                            t = base.trim();
                        }
                    }
                    if !t.is_empty() && t != "new" && t != "null" && t != "true" && t != "false" && !t.chars().next().unwrap().is_numeric() {
                        args.push(Operand::Var(t.to_string()));
                    }
                }
            }
        }
    }
    args
}

pub fn init() {
    println!("v2-frontend-java initialized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_line_assignment_and_call() {
        let code = "
        class App {
            void run() {
                String param = request.getParameter(\"q\");
                execute(param);
            }
        }
        ";
        let logical = preprocess_java(code);
        assert!(!logical.is_empty());
        assert!(logical.iter().any(|l| l.text.contains("getParameter")));
    }

    #[test]
    fn test_multi_line_chained_call() {
        let code = "
        class App {
            void run() {
                response.getWriter()
                    .println(x);
            }
        }
        ";
        let logical = preprocess_java(code);
        // Should join the getWriter and println lines
        let target = logical.iter().find(|l| l.text.contains("getWriter"));
        assert!(target.is_some());
        let joined = &target.unwrap().text;
        assert!(joined.contains("println"));
        assert_eq!(target.unwrap().span.start_line, 4);
        assert_eq!(target.unwrap().span.end_line, 5);
    }

    #[test]
    fn test_multi_line_sql_construction() {
        let code = "
        class App {
            void run() {
                String sql = \"SELECT * \"
                    + \"FROM users \"
                    + \"WHERE id = \" + id;
            }
        }
        ";
        let logical = preprocess_java(code);
        let target = logical.iter().find(|l| l.text.contains("SELECT"));
        assert!(target.is_some());
        let joined = &target.unwrap().text;
        assert!(joined.contains("FROM"));
        assert!(joined.contains("WHERE"));
        assert_eq!(target.unwrap().span.start_line, 4);
        assert_eq!(target.unwrap().span.end_line, 6);
    }

    #[test]
    fn test_nested_method_invocation() {
        let code = "
        class App {
            void run() {
                bar = new String(
                    Base64.decodeBase64(
                        Base64.encodeBase64(param.getBytes())
                    )
                );
            }
        }
        ";
        let logical = preprocess_java(code);
        let target = logical.iter().find(|l| l.text.contains("new String"));
        assert!(target.is_some());
        let joined = &target.unwrap().text;
        assert!(joined.contains("decodeBase64"));
        assert!(joined.contains("encodeBase64"));
        assert_eq!(target.unwrap().span.start_line, 4);
        assert_eq!(target.unwrap().span.end_line, 8);
    }

    #[test]
    fn test_receiver_normalization_static_and_instance() {
        let code = "
        class App {
            void run() {
                String val = URLDecoder.decode(param, \"UTF-8\");
                response.setContentType(\"text/html\");
                ps.execute();
                pb.start();
                Runtime.getRuntime().exec(cmd);
            }
        }
        ";
        let frontend = JavaFrontend;
        let program = frontend.lower(code, &v2_semantic::SemanticInfo::new(), std::path::Path::new("App.java")).unwrap();
        
        let run_method = program.methods.values().find(|m| m.name == "run").unwrap();
        
        let mut insts = Vec::new();
        for inst_id in &run_method.body {
            if let Some(inst) = program.instructions.get(inst_id) {
                insts.push(inst.clone());
            }
        }
        // 1. Static call: URLDecoder.decode
        let decode_call = insts.iter().find(|i| {
            if let InstructionKind::Call { callee, .. } = &i.kind {
                callee == "URLDecoder.decode"
            } else {
                false
            }
        }).unwrap();
        if let InstructionKind::Call { args, .. } = &decode_call.kind {
            assert_eq!(args.len(), 2);
            assert_eq!(args[0], Operand::Var("param".to_string()));
            assert_eq!(args[1], Operand::Var("UTF".to_string()));
        }
        
        // 2. Instance call: response.setContentType
        let ctype_call = insts.iter().find(|i| {
            if let InstructionKind::Call { callee, .. } = &i.kind {
                callee == "setContentType"
            } else {
                false
            }
        }).unwrap();
        if let InstructionKind::Call { args, .. } = &ctype_call.kind {
            assert_eq!(args.len(), 3);
            assert_eq!(args[0], Operand::Var("response".to_string()));
            assert_eq!(args[1], Operand::Var("text".to_string()));
            assert_eq!(args[2], Operand::Var("html".to_string()));
        }

        // 3. PreparedStatement.execute()
        let exec_call = insts.iter().find(|i| {
            if let InstructionKind::Call { callee, .. } = &i.kind {
                callee == "execute"
            } else {
                false
            }
        }).unwrap();
        if let InstructionKind::Call { args, .. } = &exec_call.kind {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Operand::Var("ps".to_string()));
        }

        // 4. ProcessBuilder.start()
        let start_call = insts.iter().find(|i| {
            if let InstructionKind::Call { callee, .. } = &i.kind {
                callee == "start"
            } else {
                false
            }
        }).unwrap();
        if let InstructionKind::Call { args, .. } = &start_call.kind {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Operand::Var("pb".to_string()));
        }

        // 5. Runtime.getRuntime().exec(cmd)
        let exec_proc_call = insts.iter().find(|i| {
            if let InstructionKind::Call { callee, .. } = &i.kind {
                callee == "exec"
            } else {
                false
            }
        }).unwrap();
        if let InstructionKind::Call { args, .. } = &exec_proc_call.kind {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Operand::Var("cmd".to_string()));
        }
    }
}
