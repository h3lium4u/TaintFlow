use cfg::CfgBuilder;
use features::FeatureExtractor;
use normalizer::{NormalizedKind, NormalizedNode, Normalizer};
use parser::UnifiedParser;
use rules::{Finding, PathEntry, RuleEngine, SuppressionInfo};
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use symbols::SymbolTable;
use taint::TaintEngine;

// ─── Output format enum ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

// ─── Legacy extract mode output ───────────────────────────────────────────────

#[derive(Serialize)]
struct ExtractOutput {
    features: Vec<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings: Option<Vec<Finding>>,
}

// ─── Scanner output structs ────────────────────────────────────────────────────

#[derive(Serialize)]
struct ScanReport {
    scan_version: &'static str,
    scanned_files: usize,
    total_findings: usize,
    supported_cwes: Vec<&'static str>,
    findings: Vec<Finding>,
}

// SARIF 2.1 structs
#[derive(Serialize)]
struct SarifReport {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "helpUri")]
    help_uri: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressions: Option<Vec<SarifSuppression>>,
    #[serde(rename = "codeFlows", skip_serializing_if = "Option::is_none")]
    code_flows: Option<Vec<SarifCodeFlow>>,
}

#[derive(Serialize)]
struct SarifSuppression {
    kind: &'static str,
    status: &'static str,
    justification: String,
}

#[derive(Serialize)]
struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Serialize)]
struct SarifThreadFlow {
    locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Serialize)]
struct SarifThreadFlowLocation {
    location: SarifLocation,
    importance: &'static str,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<SarifMessage>,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

// ─── Core analysis ─────────────────────────────────────────────────────────────

fn detect_language(code: &str, ext: &str) -> &'static str {
    if ext == "java" {
        return "java";
    }
    if ext == "py" {
        return "python";
    }
    // Fallback to content heuristics
    if code.contains("public class ")
        || code.contains("import java.")
        || code.contains("package ")
        || (code.contains(";\n") || code.contains(";\r\n"))
    {
        "java"
    } else {
        "python"
    }
}

fn check_suppression(lines: &[&str], line_num: usize, cwe: &str) -> Option<String> {
    if line_num == 0 || line_num > lines.len() {
        return None;
    }

    let normalized_cwe = cwe.to_uppercase().replace('-', "").replace(' ', "");

    // Check same line and preceding line (line_num is 1-indexed)
    let lines_to_check = if line_num > 1 {
        vec![
            (line_num, lines[line_num - 1]),
            (line_num - 1, lines[line_num - 2]),
        ]
    } else {
        vec![(line_num, lines[line_num - 1])]
    };

    for (_, line) in lines_to_check {
        let trimmed = line.trim();
        if let Some(comment_idx) = trimmed.find("//").or_else(|| trimmed.find('#')) {
            let comment_text = &trimmed[comment_idx..];
            if comment_text.contains("taintflow-ignore") {
                let comment_upper = comment_text
                    .to_uppercase()
                    .replace('-', "")
                    .replace(' ', "");
                // If comment doesn't contain "CWE" at all, ignore globally
                if !comment_upper.contains("CWE") {
                    return Some(comment_text.trim().to_string());
                }
                // Check if comment contains specific normalized CWE
                if comment_upper.contains(&normalized_cwe) {
                    return Some(comment_text.trim().to_string());
                }
            }
        }
    }
    None
}

fn is_source_expression(node: &NormalizedNode) -> bool {
    let raw_lower = node.raw.to_lowercase();
    let sources = [
        "getparameter",
        "getheader",
        "getcookies",
        "getquerystring",
        "getinputstream",
        "getreader",
        "readline",
        "nextline",
        "request.args",
        "request.form",
        "request.json",
        "request.cookies",
        "request.headers",
        "request.files",
        "request.data",
        "request.values",
        "input(",
    ];
    sources.iter().any(|&s| raw_lower.contains(s))
}

fn collect_identifiers(node: &NormalizedNode, vars: &mut Vec<String>) {
    match &node.kind {
        NormalizedKind::Identifier(name) => {
            if !vars.contains(name) {
                vars.push(name.clone());
            }
        }
        NormalizedKind::Block(children)
        | NormalizedKind::Concat { parts: children }
        | NormalizedKind::FunctionDefinition { body: children, .. } => {
            for child in children {
                collect_identifiers(child, vars);
            }
        }
        NormalizedKind::Assignment { lhs, rhs } => {
            collect_identifiers(lhs, vars);
            collect_identifiers(rhs, vars);
        }
        NormalizedKind::Call {
            callee, arguments, ..
        } => {
            if let Some(base) = callee.split('.').next() {
                if !vars.contains(&base.to_string()) {
                    vars.push(base.to_string());
                }
            }
            for arg in arguments {
                collect_identifiers(arg, vars);
            }
        }
        NormalizedKind::If {
            condition,
            consequent,
            alternate,
        } => {
            collect_identifiers(condition, vars);
            collect_identifiers(consequent, vars);
            if let Some(alt) = alternate {
                collect_identifiers(alt, vars);
            }
        }
        NormalizedKind::Return(expr) => {
            collect_identifiers(expr, vars);
        }
        NormalizedKind::For {
            init,
            condition,
            update,
            body,
        } => {
            if let Some(i) = init {
                collect_identifiers(i, vars);
            }
            if let Some(c) = condition {
                collect_identifiers(c, vars);
            }
            if let Some(u) = update {
                collect_identifiers(u, vars);
            }
            collect_identifiers(body, vars);
        }
        NormalizedKind::While { condition, body } => {
            collect_identifiers(condition, vars);
            collect_identifiers(body, vars);
        }
        NormalizedKind::DoWhile { body, condition } => {
            collect_identifiers(body, vars);
            collect_identifiers(condition, vars);
        }
        NormalizedKind::Try {
            body,
            catch_clauses,
            finally_clause,
        } => {
            collect_identifiers(body, vars);
            for catch in catch_clauses {
                collect_identifiers(catch, vars);
            }
            if let Some(finally) = finally_clause {
                collect_identifiers(finally, vars);
            }
        }
        _ => {}
    }
}

fn collect_assignments_before<'a>(
    node: &'a NormalizedNode,
    target_var: &str,
    before_line: usize,
    assignments: &mut Vec<&'a NormalizedNode>,
) {
    if node.span.start_line >= before_line {
        return;
    }

    match &node.kind {
        NormalizedKind::Assignment { lhs, .. } => {
            let lhs_name = match &lhs.kind {
                NormalizedKind::Identifier(name) => name.clone(),
                _ => lhs.raw.clone(),
            };
            if lhs_name == target_var || lhs_name.contains(target_var) {
                assignments.push(node);
            }
        }
        NormalizedKind::Block(children)
        | NormalizedKind::Concat { parts: children }
        | NormalizedKind::FunctionDefinition { body: children, .. } => {
            for child in children {
                collect_assignments_before(child, target_var, before_line, assignments);
            }
        }
        NormalizedKind::If {
            condition,
            consequent,
            alternate,
        } => {
            collect_assignments_before(condition, target_var, before_line, assignments);
            collect_assignments_before(consequent, target_var, before_line, assignments);
            if let Some(alt) = alternate {
                collect_assignments_before(alt, target_var, before_line, assignments);
            }
        }
        NormalizedKind::For {
            init,
            condition,
            update,
            body,
        } => {
            if let Some(i) = init {
                collect_assignments_before(i, target_var, before_line, assignments);
            }
            if let Some(c) = condition {
                collect_assignments_before(c, target_var, before_line, assignments);
            }
            if let Some(u) = update {
                collect_assignments_before(u, target_var, before_line, assignments);
            }
            collect_assignments_before(body, target_var, before_line, assignments);
        }
        NormalizedKind::While { condition, body } => {
            collect_assignments_before(condition, target_var, before_line, assignments);
            collect_assignments_before(body, target_var, before_line, assignments);
        }
        NormalizedKind::DoWhile { body, condition } => {
            collect_assignments_before(body, target_var, before_line, assignments);
            collect_assignments_before(condition, target_var, before_line, assignments);
        }
        NormalizedKind::Try {
            body,
            catch_clauses,
            finally_clause,
        } => {
            collect_assignments_before(body, target_var, before_line, assignments);
            for catch in catch_clauses {
                collect_assignments_before(catch, target_var, before_line, assignments);
            }
            if let Some(finally) = finally_clause {
                collect_assignments_before(finally, target_var, before_line, assignments);
            }
        }
        _ => {}
    }
}

fn collect_function_params<'a>(
    node: &'a NormalizedNode,
    target_var: &str,
    before_line: usize,
    params: &mut Vec<&'a NormalizedNode>,
) {
    if node.span.start_line >= before_line {
        return;
    }
    match &node.kind {
        NormalizedKind::FunctionDefinition {
            params: param_names,
            ..
        } => {
            if param_names
                .iter()
                .any(|p| p == target_var || p.to_lowercase().contains(target_var))
            {
                params.push(node);
            }
        }
        NormalizedKind::Block(children) | NormalizedKind::Concat { parts: children } => {
            for child in children {
                collect_function_params(child, target_var, before_line, params);
            }
        }
        _ => {}
    }
}

fn trace_backwards(
    node: &NormalizedNode,
    target_var: &str,
    before_line: usize,
    visited: &mut HashSet<String>,
    path: &mut Vec<(String, usize, String)>,
    file_path: &str,
) -> bool {
    if visited.contains(target_var) {
        return false;
    }
    visited.insert(target_var.to_string());

    let mut assignments = Vec::new();
    collect_assignments_before(node, target_var, before_line, &mut assignments);
    assignments.sort_by(|a, b| b.span.start_line.cmp(&a.span.start_line));

    if let Some(assign) = assignments.first() {
        if let NormalizedKind::Assignment { lhs, rhs } = &assign.kind {
            let line = assign.span.start_line;
            if is_source_expression(rhs) {
                path.push((
                    file_path.to_string(),
                    line,
                    format!("Source: Taint enters via '{}'", rhs.raw),
                ));
                return true;
            }

            let mut rhs_vars = Vec::new();
            collect_identifiers(rhs, &mut rhs_vars);

            for var in rhs_vars {
                let mut sub_path = Vec::new();
                if trace_backwards(node, &var, line, visited, &mut sub_path, file_path) {
                    path.extend(sub_path);
                    path.push((
                        file_path.to_string(),
                        line,
                        format!("Propagated taint from '{}' to '{}'", rhs.raw, lhs.raw),
                    ));
                    return true;
                }
            }
        }
    }

    let mut params = Vec::new();
    collect_function_params(node, target_var, before_line, &mut params);
    if let Some(param_node) = params.first() {
        path.push((
            file_path.to_string(),
            param_node.span.start_line,
            format!(
                "Source: Taint enters via function parameter '{}'",
                target_var
            ),
        ));
        return true;
    }

    false
}

fn analyse_code(code: &str, file_path: &str, language: &str) -> Vec<Finding> {
    let parsed = UnifiedParser::parse(code, language);
    match parsed {
        Ok(ast) => {
            let mut norm = Normalizer::new();
            let normalized = norm.normalize(&ast, language);
            // 1. Taint analysis
            let mut taint_engine = TaintEngine::new(10, 5, 200);
            // Build CHA table from source text before propagation
            taint_engine.build_cha_from_code(code);
            taint_engine.propagate_node(&normalized);

            // 2. Rule evaluation
            let mut rule_engine = RuleEngine::new();
            evaluate_rules_recursive(&mut rule_engine, file_path, &normalized, &taint_engine);
            let mut findings = rule_engine.get_findings();

            // 3. Post-process to resolve propagation paths and check suppressions
            let lines: Vec<&str> = code.lines().collect();
            for f in &mut findings {
                // Try to parse out the tainted variable/expression name from the finding description
                let mut target_var = String::new();
                if let Some(start_quote) = f.description.find('\'') {
                    if let Some(end_quote) = f.description[start_quote + 1..].find('\'') {
                        target_var =
                            f.description[start_quote + 1..start_quote + 1 + end_quote].to_string();
                    }
                }

                let mut path = Vec::new();
                let mut visited = HashSet::new();
                if !target_var.is_empty()
                    && trace_backwards(
                        &normalized,
                        &target_var,
                        f.line_number,
                        &mut visited,
                        &mut path,
                        file_path,
                    )
                {
                    path.push((
                        file_path.to_string(),
                        f.line_number,
                        format!("Sink: Tainted value reaches sink: {}", f.description),
                    ));
                    f.code_flow_path = Some(
                        path.into_iter()
                            .map(|(fp, ln, msg)| PathEntry {
                                file_path: fp,
                                line_number: ln,
                                message: msg,
                            })
                            .collect(),
                    );
                } else {
                    // Fallback to simple path: source = line 1 or first source line, sink = f.line_number
                    let mut src_line = 1;
                    for (idx, line) in lines.iter().enumerate() {
                        let l_low = line.to_lowercase();
                        if l_low.contains("request")
                            || l_low.contains("getparameter")
                            || l_low.contains("input")
                        {
                            src_line = idx + 1;
                            break;
                        }
                    }
                    f.code_flow_path = Some(vec![
                        PathEntry {
                            file_path: file_path.to_string(),
                            line_number: src_line,
                            message: "Source: Taint input entrypoint".to_string(),
                        },
                        PathEntry {
                            file_path: file_path.to_string(),
                            line_number: f.line_number,
                            message: format!("Sink: Tainted value reaches sink: {}", f.description),
                        },
                    ]);
                }

                // Check for inline suppression on this finding
                if let Some(justification) = check_suppression(&lines, f.line_number, &f.cwe) {
                    f.suppression = Some(SuppressionInfo {
                        kind: "inSource".to_string(),
                        status: "accepted".to_string(),
                        justification,
                    });
                }
            }

            findings
        }
        Err(_) => Vec::new(),
    }
}

fn evaluate_rules_recursive(
    rule_engine: &mut RuleEngine,
    file_path: &str,
    node: &NormalizedNode,
    taint_engine: &TaintEngine,
) {
    rule_engine.evaluate_flow_rules(file_path, node, taint_engine);
    rule_engine.evaluate_pattern_rules(file_path, node);
    rule_engine.evaluate_call_pattern_rules(file_path, node);
    match &node.kind {
        NormalizedKind::Block(children)
        | NormalizedKind::Concat { parts: children }
        | NormalizedKind::FunctionDefinition { body: children, .. } => {
            for child in children {
                evaluate_rules_recursive(rule_engine, file_path, child, taint_engine);
            }
        }
        NormalizedKind::Assignment { lhs, rhs } => {
            evaluate_rules_recursive(rule_engine, file_path, lhs, taint_engine);
            evaluate_rules_recursive(rule_engine, file_path, rhs, taint_engine);
        }
        NormalizedKind::If {
            condition,
            consequent,
            alternate,
        } => {
            evaluate_rules_recursive(rule_engine, file_path, condition, taint_engine);
            evaluate_rules_recursive(rule_engine, file_path, consequent, taint_engine);
            if let Some(alt) = alternate {
                evaluate_rules_recursive(rule_engine, file_path, alt, taint_engine);
            }
        }
        NormalizedKind::Call { arguments, .. } => {
            for arg in arguments {
                evaluate_rules_recursive(rule_engine, file_path, arg, taint_engine);
            }
        }
        NormalizedKind::Return(expr) => {
            evaluate_rules_recursive(rule_engine, file_path, expr, taint_engine);
        }
        NormalizedKind::For {
            init,
            condition,
            update,
            body,
        } => {
            if let Some(i) = init {
                evaluate_rules_recursive(rule_engine, file_path, i, taint_engine);
            }
            if let Some(c) = condition {
                evaluate_rules_recursive(rule_engine, file_path, c, taint_engine);
            }
            if let Some(u) = update {
                evaluate_rules_recursive(rule_engine, file_path, u, taint_engine);
            }
            evaluate_rules_recursive(rule_engine, file_path, body, taint_engine);
        }
        NormalizedKind::While { condition, body } => {
            evaluate_rules_recursive(rule_engine, file_path, condition, taint_engine);
            evaluate_rules_recursive(rule_engine, file_path, body, taint_engine);
        }
        NormalizedKind::DoWhile { body, condition } => {
            evaluate_rules_recursive(rule_engine, file_path, body, taint_engine);
            evaluate_rules_recursive(rule_engine, file_path, condition, taint_engine);
        }
        NormalizedKind::Try {
            body,
            catch_clauses,
            finally_clause,
        } => {
            evaluate_rules_recursive(rule_engine, file_path, body, taint_engine);
            for catch in catch_clauses {
                evaluate_rules_recursive(rule_engine, file_path, catch, taint_engine);
            }
            if let Some(finally) = finally_clause {
                evaluate_rules_recursive(rule_engine, file_path, finally, taint_engine);
            }
        }
        NormalizedKind::Catch { body, .. } => {
            evaluate_rules_recursive(rule_engine, file_path, body, taint_engine);
        }
        _ => {}
    }
}

fn populate_symbols(table: &mut SymbolTable, node: &NormalizedNode) {
    match &node.kind {
        NormalizedKind::Assignment { lhs, rhs } => {
            let name = &lhs.raw;
            let kind = if name.contains("self.") || name.contains("this.") {
                symbols::SymbolKind::Field
            } else {
                symbols::SymbolKind::Variable
            };
            table.insert(name, kind, None);
            populate_symbols(table, rhs);
        }
        NormalizedKind::TypeDeclaration {
            name,
            declared_type,
        } => {
            table.insert(
                name,
                symbols::SymbolKind::Variable,
                Some(declared_type.clone()),
            );
        }
        NormalizedKind::Import {
            class_name,
            full_path,
        } => {
            table.insert_import(class_name, full_path);
        }
        NormalizedKind::Call { arguments, .. } => {
            for arg in arguments {
                populate_symbols(table, arg);
            }
        }
        NormalizedKind::If {
            condition,
            consequent,
            alternate,
        } => {
            populate_symbols(table, condition);
            populate_symbols(table, consequent);
            if let Some(alt) = alternate {
                populate_symbols(table, alt);
            }
        }
        NormalizedKind::Concat { parts } => {
            for part in parts {
                populate_symbols(table, part);
            }
        }
        NormalizedKind::Block(children) => {
            table.enter_scope(symbols::ScopeKind::Block);
            for child in children {
                populate_symbols(table, child);
            }
            let _ = table.exit_scope();
        }
        NormalizedKind::FunctionDefinition { body, .. } => {
            table.enter_scope(symbols::ScopeKind::Block);
            for child in body {
                populate_symbols(table, child);
            }
            let _ = table.exit_scope();
        }
        NormalizedKind::Return(expr) => {
            populate_symbols(table, expr);
        }
        NormalizedKind::For {
            init,
            condition,
            update,
            body,
        } => {
            table.enter_scope(symbols::ScopeKind::Block);
            if let Some(i) = init {
                populate_symbols(table, i);
            }
            if let Some(c) = condition {
                populate_symbols(table, c);
            }
            if let Some(u) = update {
                populate_symbols(table, u);
            }
            populate_symbols(table, body);
            let _ = table.exit_scope();
        }
        NormalizedKind::While { condition, body } => {
            table.enter_scope(symbols::ScopeKind::Block);
            populate_symbols(table, condition);
            populate_symbols(table, body);
            let _ = table.exit_scope();
        }
        NormalizedKind::DoWhile { body, condition } => {
            table.enter_scope(symbols::ScopeKind::Block);
            populate_symbols(table, body);
            populate_symbols(table, condition);
            let _ = table.exit_scope();
        }
        NormalizedKind::Try {
            body,
            catch_clauses,
            finally_clause,
        } => {
            table.enter_scope(symbols::ScopeKind::Block);
            populate_symbols(table, body);
            let _ = table.exit_scope();
            for catch in catch_clauses {
                populate_symbols(table, catch);
            }
            if let Some(finally) = finally_clause {
                table.enter_scope(symbols::ScopeKind::Block);
                populate_symbols(table, finally);
                let _ = table.exit_scope();
            }
        }
        NormalizedKind::Catch { parameter, body } => {
            table.enter_scope(symbols::ScopeKind::Block);
            if let Some(p) = parameter {
                table.insert(p, symbols::SymbolKind::Variable, None);
            }
            populate_symbols(table, body);
            let _ = table.exit_scope();
        }
        _ => {}
    }
}

// ─── File walker ──────────────────────────────────────────────────────────────

fn collect_files(path: &Path, ignore_dirs: &HashSet<String>) -> Vec<PathBuf> {
    let mut result = Vec::new();
    if path.is_file() {
        if is_supported_file(path) {
            result.push(path.to_path_buf());
        }
        return result;
    }
    if path.is_dir() {
        let dir_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if ignore_dirs.contains(&dir_name) || dir_name.starts_with('.') {
            return result;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let child = entry.path();
                let mut sub = collect_files(&child, ignore_dirs);
                result.append(&mut sub);
            }
        }
    }
    result
}

fn is_supported_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("py") | Some("java")
    )
}

fn check_taintignore(base: &Path) -> HashSet<String> {
    let mut ignored = HashSet::new();
    // Default ignore dirs
    for d in &[
        "target",
        "node_modules",
        ".git",
        "__pycache__",
        "venv",
        ".venv",
        "dist",
        "build",
    ] {
        ignored.insert(d.to_string());
    }
    let ignore_file = base.join(".taintignore");
    if let Ok(content) = fs::read_to_string(&ignore_file) {
        for line in content.lines() {
            let l = line.trim();
            if !l.is_empty() && !l.starts_with('#') {
                ignored.insert(l.to_string());
            }
        }
    }
    ignored
}

// ─── Severity filter ──────────────────────────────────────────────────────────

fn severity_level(s: &str) -> u8 {
    match s.to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

// ─── Reporting ────────────────────────────────────────────────────────────────

fn print_text_report(findings: &[Finding], scanned: usize) {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║              TaintFlow V1.0 Scan Report               ║");
    println!("╚═══════════════════════════════════════════════════════╝");
    println!();

    let active_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.suppression.is_none())
        .collect();
    let suppressed_count = findings.len() - active_findings.len();

    println!("  Files scanned : {}", scanned);
    println!("  Active findings: {}", active_findings.len());
    if suppressed_count > 0 {
        println!("  Suppressed findings (ignored): {}", suppressed_count);
    }
    println!();

    if active_findings.is_empty() {
        println!("  ✅  No active findings detected.");
        return;
    }
    for (i, f) in active_findings.iter().enumerate() {
        let sev_icon = match f.severity.as_str() {
            "CRITICAL" => "🔴",
            "HIGH" => "🟠",
            "MEDIUM" => "🟡",
            _ => "🔵",
        };
        println!(
            "  [{:>3}] {} [{:<8}] {} - {}:{}",
            i + 1,
            sev_icon,
            f.cwe,
            f.title,
            f.file_path,
            f.line_number
        );
        println!("         {}", f.description);

        // Print the code flow path if present
        if let Some(path) = &f.code_flow_path {
            println!("         Trace Path:");
            for (step, entry) in path.iter().enumerate() {
                println!(
                    "           {:>2}. {}:{} - {}",
                    step + 1,
                    entry.file_path,
                    entry.line_number,
                    entry.message
                );
            }
        }
        println!();
    }
}

fn build_sarif(findings: &[Finding]) -> SarifReport {
    let mut seen_rules: Vec<SarifRule> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut results: Vec<SarifResult> = Vec::new();

    for f in findings {
        let rule_id = format!("TF-{}", f.cwe);
        if seen_ids.insert(rule_id.clone()) {
            seen_rules.push(SarifRule {
                id: rule_id.clone(),
                name: f.title.clone(),
                help_uri: format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    f.cwe.replace("CWE", "")
                ),
            });
        }
        let level = match f.severity.as_str() {
            "CRITICAL" | "HIGH" => "error",
            "MEDIUM" => "warning",
            _ => "note",
        };

        let mut suppressions = None;
        if let Some(supp) = &f.suppression {
            suppressions = Some(vec![SarifSuppression {
                kind: "inSource",
                status: "accepted",
                justification: supp.justification.clone(),
            }]);
        }

        let mut code_flows = None;
        if let Some(path) = &f.code_flow_path {
            let mut thread_locations = Vec::new();
            for entry in path {
                thread_locations.push(SarifThreadFlowLocation {
                    location: SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: entry.file_path.replace('\\', "/"),
                            },
                            region: SarifRegion {
                                start_line: entry.line_number,
                            },
                        },
                        message: Some(SarifMessage {
                            text: entry.message.clone(),
                        }),
                    },
                    importance: "important",
                });
            }
            code_flows = Some(vec![SarifCodeFlow {
                thread_flows: vec![SarifThreadFlow {
                    locations: thread_locations,
                }],
            }]);
        }

        results.push(SarifResult {
            rule_id,
            level,
            message: SarifMessage {
                text: f.description.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file_path.replace('\\', "/"),
                    },
                    region: SarifRegion {
                        start_line: f.line_number,
                    },
                },
                message: None,
            }],
            suppressions,
            code_flows,
        });
    }

    SarifReport {
        version: "2.1.0",
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "TaintFlow",
                    version: "1.0.0",
                    rules: seen_rules,
                },
            },
            results,
        }],
    }
}

// ─── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Legacy extract mode (stdin → JSON features) — keeps existing Python integration working
    if args.len() >= 2 && args[1] == "--extract" {
        run_extract_mode();
        return;
    }

    // Scanner mode: taintflow-cli scan <path> [--format text|json|sarif] [--severity HIGH] [--output file]
    if args.len() >= 3 && args[1] == "scan" {
        let scan_path = PathBuf::from(&args[2]);
        let mut format = OutputFormat::Text;
        let mut min_severity: u8 = 0;
        let mut output_file: Option<String> = None;

        let mut i = 3;
        while i < args.len() {
            match args[i].as_str() {
                "--format" => {
                    if let Some(f) = args.get(i + 1) {
                        format = match f.as_str() {
                            "json" => OutputFormat::Json,
                            "sarif" => OutputFormat::Sarif,
                            _ => OutputFormat::Text,
                        };
                        i += 1;
                    }
                }
                "--severity" => {
                    if let Some(s) = args.get(i + 1) {
                        min_severity = severity_level(s);
                        i += 1;
                    }
                }
                "--output" => {
                    output_file = args.get(i + 1).cloned();
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }

        // Collect files
        let base = if scan_path.is_dir() {
            scan_path.clone()
        } else {
            scan_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."))
        };
        let ignore_dirs = check_taintignore(&base);
        let files = collect_files(&scan_path, &ignore_dirs);
        let scanned = files.len();

        // Analyse each file
        let mut all_findings: Vec<Finding> = Vec::new();
        for file in &files {
            let ext = file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();
            if let Ok(code) = fs::read_to_string(file) {
                let lang = detect_language(&code, &ext);
                let path_str = file.to_string_lossy().to_string();
                let mut findings = analyse_code(&code, &path_str, lang);
                // Apply severity filter
                findings.retain(|f| severity_level(&f.severity) >= min_severity);
                all_findings.append(&mut findings);
            }
        }

        // Render output
        let output_str = match format {
            OutputFormat::Text => {
                print_text_report(&all_findings, scanned);
                return;
            }
            OutputFormat::Json => {
                let report = ScanReport {
                    scan_version: "1.0.0",
                    scanned_files: scanned,
                    total_findings: all_findings.len(),
                    supported_cwes: vec![
                        "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-113", "CWE-327", "CWE-502",
                        "CWE-798", "CWE-918",
                    ],
                    findings: all_findings,
                };
                serde_json::to_string_pretty(&report).unwrap_or_default()
            }
            OutputFormat::Sarif => {
                let sarif = build_sarif(&all_findings);
                serde_json::to_string_pretty(&sarif).unwrap_or_default()
            }
        };

        match output_file {
            Some(path) => {
                fs::write(&path, &output_str).expect("Failed to write output file");
                eprintln!("Report written to: {}", path);
            }
            None => println!("{}", output_str),
        }
        return;
    }

    eprintln!("TaintFlow V1.0 Scanner");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  taintflow-cli scan <path>                         # scan file or directory (text output)");
    eprintln!("  taintflow-cli scan <path> --format json           # JSON report");
    eprintln!("  taintflow-cli scan <path> --format sarif          # SARIF 2.1 report");
    eprintln!("  taintflow-cli scan <path> --severity HIGH         # filter by minimum severity");
    eprintln!("  taintflow-cli scan <path> --output report.json --format json");
    eprintln!("  taintflow-cli --extract                           # legacy feature extraction mode (stdin)");
    std::process::exit(1);
}

// ─── Legacy extract mode ───────────────────────────────────────────────────────

fn run_extract_mode() {
    let mut code = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut code) {
        let err_out = ExtractOutput {
            features: vec![0.0; 55],
            error: Some(format!("Failed to read stdin: {}", e)),
            findings: None,
        };
        println!("{}", serde_json::to_string(&err_out).unwrap());
        return;
    }

    let language = detect_language(&code, "");

    let parsed = UnifiedParser::parse(&code, language).map(|ast| (ast, language));

    match parsed {
        Ok((ast, lang)) => {
            let mut norm = Normalizer::new();
            let normalized = norm.normalize(&ast, lang);

            let mut taint_engine = TaintEngine::new(10, 5, 200);
            taint_engine.build_cha_from_code(&code);
            taint_engine.propagate_node(&normalized);

            let mut rule_engine = RuleEngine::new();
            evaluate_rules_recursive(&mut rule_engine, "sample.code", &normalized, &taint_engine);
            let findings = rule_engine.get_findings();

            let mut cfg_builder = CfgBuilder::new(1000);
            let cfg = cfg_builder.build(&normalized);

            let mut symbols = SymbolTable::new();
            populate_symbols(&mut symbols, &normalized);

            let feat_vec =
                FeatureExtractor::extract(&code, &findings, &cfg, &symbols, &taint_engine);

            let out = ExtractOutput {
                features: feat_vec.0.to_vec(),
                error: None,
                findings: Some(findings),
            };
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        Err(e) => {
            let err_out = ExtractOutput {
                features: vec![0.0; 55],
                error: Some(format!("Parse failed: {:?}", e)),
                findings: None,
            };
            println!("{}", serde_json::to_string(&err_out).unwrap());
            std::process::exit(1);
        }
    }
}
