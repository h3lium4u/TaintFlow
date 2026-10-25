//! # TaintFlow — Semantic Inference & Interprocedural Function Summaries
//!
//! Provides automated, deterministic extraction of interprocedural summaries
//! from function definitions across project files without relying on external
//! rule configurations or cloud LLMs.
//!
//! ## Summary Capabilities:
//! 1. Parameter-to-Return propagation (`param_to_return`):
//!    Infers which parameter indices flow into the returned expression.
//! 2. Parameter-to-Receiver mutation (`param_to_receiver`):
//!    Infers which parameter indices mutate object state (fields, container contents).
//! 3. Reachable Sink Invocations (`sink_invocations`):
//!    Discovers internal sinks reached by function parameters (e.g., query execution, command execution).
//! 4. Multi-Hop Transitive Call Chains (`resolve_inter_summary_dependencies`):
//!    Composes caller-to-callee dependencies across multiple hops until fixpoint.
//! 5. Branch-Aware Sanitizer Tracking (`sanitizes_for` vs `conditional_sanitizes_for`):
//!    Distinguishes unconditional sanitization from branch-dependent validation.
//! 6. Import & Namespace Resolution:
//!    Resolves callees through file-level imports and qualified package paths.

use crate::models::ActiveModelRegistry;
use crate::{get_word_tokens, map_sink_to_cwe_heuristic, CWE};
use normalizer::{NormalizedKind, NormalizedNode, Normalizer};
use parser::UnifiedParser;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Details of an internal sink invocation reachable via a function parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkInvocation {
    /// Zero-based index of the function parameter flowing into this sink.
    pub param_idx: usize,
    /// Callee expression of the sink (e.g., "stmt.executeQuery").
    pub sink_callee: String,
    /// CWE category detected.
    pub cwe: CWE,
    /// Severity rating.
    pub severity: String,
    /// Line number inside the source file where the sink call occurs.
    pub call_line: usize,
    /// Argument index of the sink call that receives the parameter data.
    pub arg_index: usize,
}

/// An internal call site within a function body, used for multi-hop fixpoint resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalCallSummary {
    /// Target callee expression.
    pub callee: String,
    /// For each argument passed to callee, the set of caller parameter indices influencing it.
    pub args_influenced: Vec<HashSet<usize>>,
    /// Line number of the call site.
    pub call_line: usize,
}

/// An inferred summary capturing the interprocedural security semantics of a function.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionSummary {
    /// Lowercased function name (or method name).
    pub name: String,
    /// Exact function name as declared.
    pub original_name: String,
    /// Enclosing class or module name, if known.
    pub enclosing_type: Option<String>,
    /// Source file path where this function is defined.
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
    /// Formal parameter names in order.
    pub param_names: Vec<String>,
    /// Indices of parameters whose data influences the return value.
    pub param_to_return: HashSet<usize>,
    /// Indices of parameters that mutate the receiver (`this`/`self`) or container.
    pub param_to_receiver: HashSet<usize>,
    /// Sinks reachable from function parameters within this function's body (direct + transitive).
    pub sink_invocations: Vec<SinkInvocation>,
    /// Internal function calls invoked within the body (used for multi-hop propagation).
    pub internal_calls: Vec<InternalCallSummary>,
    /// Parameters that are unconditionally sanitized/validated for specific CWEs across all paths.
    pub sanitizes_for: HashMap<usize, HashSet<CWE>>,
    /// Parameters sanitized only in some execution branches (e.g., inside `if` blocks).
    pub conditional_sanitizes_for: HashMap<usize, HashSet<CWE>>,
    /// Whether this function is a pure boolean predicate (returns boolean comparison, no data).
    pub is_pure_predicate: bool,
}

impl FunctionSummary {
    /// Returns true if parameter at `param_idx` propagates to return value.
    pub fn propagates_param_to_return(&self, param_idx: usize) -> bool {
        self.param_to_return.contains(&param_idx)
    }

    /// Returns true if parameter at `param_idx` mutates receiver.
    pub fn propagates_param_to_receiver(&self, param_idx: usize) -> bool {
        self.param_to_receiver.contains(&param_idx)
    }

    /// Returns all sink invocations reached by parameter at `param_idx`.
    pub fn sinks_for_param(&self, param_idx: usize) -> Vec<&SinkInvocation> {
        self.sink_invocations
            .iter()
            .filter(|s| s.param_idx == param_idx)
            .collect()
    }
}

// ─── Summary Inference Engine ──────────────────────────────────────────────────

/// Analyzes normalized function ASTs and infers function summaries deterministically.
pub struct SummaryInferer;

impl SummaryInferer {
    /// Infer a `FunctionSummary` from a function definition node.
    pub fn infer_from_definition(
        name: &str,
        params: &[String],
        body: &[NormalizedNode],
        file_path: &str,
        start_line: usize,
        end_line: usize,
        language: &str,
        model_registry: Option<&ActiveModelRegistry>,
        existing_registry: Option<&ProjectSummaryRegistry>,
    ) -> FunctionSummary {
        let clean_name = name.replace('"', "").replace('\'', "");
        let lower_name = clean_name.to_lowercase();
        let (enclosing, method_name) = if let Some(idx) = lower_name.rfind('.') {
            (
                Some(clean_name[..idx].to_string()),
                clean_name[idx + 1..].to_string(),
            )
        } else {
            (None, clean_name.clone())
        };

        let mut summary = FunctionSummary {
            name: method_name.to_lowercase(),
            original_name: clean_name,
            enclosing_type: enclosing,
            file_path: file_path.to_string(),
            start_line,
            end_line,
            param_names: params
                .iter()
                .map(|p| crate::clean_parameter_name(p))
                .collect(),
            param_to_return: HashSet::new(),
            param_to_receiver: HashSet::new(),
            sink_invocations: Vec::new(),
            internal_calls: Vec::new(),
            sanitizes_for: HashMap::new(),
            conditional_sanitizes_for: HashMap::new(),
            is_pure_predicate: false,
        };

        // Symbol map: variable name -> set of parameter indices that influence it
        let mut var_influences: HashMap<String, HashSet<usize>> = HashMap::new();
        for (idx, param) in params.iter().enumerate() {
            let clean = crate::clean_parameter_name(param);
            let mut set = HashSet::new();
            set.insert(idx);
            var_influences.insert(clean.clone(), set.clone());
            var_influences.insert(clean.to_lowercase(), set.clone());
            var_influences.insert(param.clone(), set.clone());
            var_influences.insert(param.to_lowercase(), set);
        }

        Self::analyze_statements(
            body,
            &mut var_influences,
            &mut summary,
            file_path,
            language,
            model_registry,
            existing_registry,
            false,
            0,
        );

        summary
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_statements(
        stmts: &[NormalizedNode],
        var_influences: &mut HashMap<String, HashSet<usize>>,
        summary: &mut FunctionSummary,
        file_path: &str,
        language: &str,
        model_registry: Option<&ActiveModelRegistry>,
        existing_registry: Option<&ProjectSummaryRegistry>,
        is_inside_branch: bool,
        depth: usize,
    ) {
        if depth > 10 {
            return;
        }

        for node in stmts {
            match &node.kind {
                NormalizedKind::Assignment { lhs, rhs } => {
                    let influenced = Self::eval_expr_influences(
                        rhs,
                        var_influences,
                        summary,
                        existing_registry,
                        depth + 1,
                    );

                    // Check for sanitization casts / methods on RHS
                    Self::check_sanitization_assignment(
                        lhs,
                        rhs,
                        &influenced,
                        summary,
                        is_inside_branch,
                    );

                    // Target variable name
                    let dest = match &lhs.kind {
                        NormalizedKind::Identifier(n) => n.clone(),
                        _ => lhs.raw.clone(),
                    };

                    // Receiver mutation detection: e.g. this.field = param, self.x = param
                    let dest_lower = dest.to_lowercase();
                    if dest_lower.starts_with("this.")
                        || dest_lower.starts_with("self.")
                        || dest_lower.starts_with("self[")
                    {
                        summary.param_to_receiver.extend(influenced.iter().cloned());
                    }

                    if !influenced.is_empty() {
                        var_influences.insert(dest.clone(), influenced.clone());
                        var_influences.insert(dest.to_lowercase(), influenced);
                    } else {
                        var_influences.remove(&dest);
                        var_influences.remove(&dest.to_lowercase());
                    }
                }

                NormalizedKind::Call {
                    callee, arguments, ..
                } => {
                    let callee_lower = callee.to_lowercase();
                    let method = callee_lower.rsplit('.').next().unwrap_or(&callee_lower);

                    // Collect parameter influences for each argument
                    let mut args_influenced = Vec::new();
                    for arg in arguments {
                        let inf = Self::eval_expr_influences(
                            arg,
                            var_influences,
                            summary,
                            existing_registry,
                            depth + 1,
                        );
                        args_influenced.push(inf);
                    }

                    // Record internal call for multi-hop analysis
                    summary.internal_calls.push(InternalCallSummary {
                        callee: callee.clone(),
                        args_influenced: args_influenced.clone(),
                        call_line: node.span.start_line,
                    });

                    // 1. Receiver mutation calls: e.g. list.add(x), dict.put(k, v), receiver.append(x)
                    let is_mutation_method = method == "add"
                        || method == "append"
                        || method == "extend"
                        || method == "put"
                        || method == "push"
                        || method == "insert"
                        || method == "set"
                        || method == "update"
                        || method == "write";

                    if is_mutation_method {
                        if let Some((receiver, _)) = callee_lower.rsplit_once('.') {
                            let r = receiver.trim();
                            if r == "this"
                                || r == "self"
                                || r.starts_with("this.")
                                || r.starts_with("self.")
                            {
                                for inf in &args_influenced {
                                    summary.param_to_receiver.extend(inf.iter().cloned());
                                }
                            }
                        }
                    }

                    // 2. Direct Sink check
                    let cwe_opt =
                        map_sink_to_cwe_heuristic(callee, Some(file_path)).or_else(|| {
                            model_registry
                                .and_then(|reg| reg.match_sink(callee, language).map(|m| m.cwe))
                        });

                    if let Some(cwe) = cwe_opt {
                        let severity = match cwe {
                            CWE::CWE78 => "CRITICAL",
                            CWE::CWE89 => "HIGH",
                            CWE::CWE22 => "HIGH",
                            CWE::CWE918 => "HIGH",
                            CWE::CWE502 => "HIGH",
                            _ => "HIGH",
                        };

                        for (arg_idx, inf) in args_influenced.iter().enumerate() {
                            for &param_idx in inf {
                                summary.sink_invocations.push(SinkInvocation {
                                    param_idx,
                                    sink_callee: callee.clone(),
                                    cwe,
                                    severity: severity.to_string(),
                                    call_line: node.span.start_line,
                                    arg_index: arg_idx,
                                });
                            }
                        }
                    }

                    // 3. Existing project call resolution (if available during first pass)
                    if let Some(reg) = existing_registry {
                        if let Some(called_summary) =
                            reg.find_summary_for_caller(callee, arguments.len(), file_path)
                        {
                            for sink_inv in &called_summary.sink_invocations {
                                if let Some(inf) = args_influenced.get(sink_inv.param_idx) {
                                    for &caller_param in inf {
                                        summary.sink_invocations.push(SinkInvocation {
                                            param_idx: caller_param,
                                            sink_callee: sink_inv.sink_callee.clone(),
                                            cwe: sink_inv.cwe,
                                            severity: sink_inv.severity.clone(),
                                            call_line: node.span.start_line,
                                            arg_index: sink_inv.arg_index,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                NormalizedKind::Return(expr) => {
                    let is_bool = Self::is_boolean_expr(expr);
                    if is_bool {
                        summary.is_pure_predicate = true;
                    } else {
                        let inf = Self::eval_expr_influences(
                            expr,
                            var_influences,
                            summary,
                            existing_registry,
                            depth + 1,
                        );
                        summary.param_to_return.extend(inf);
                    }
                }

                NormalizedKind::Block(children) | NormalizedKind::Concat { parts: children } => {
                    Self::analyze_statements(
                        children,
                        var_influences,
                        summary,
                        file_path,
                        language,
                        model_registry,
                        existing_registry,
                        is_inside_branch,
                        depth + 1,
                    );
                }

                // ── Branch-Aware Conditional Analysis ─────────────────────────
                NormalizedKind::If {
                    consequent,
                    alternate,
                    ..
                } => {
                    let pre_branch = var_influences.clone();

                    let mut cons_influences = pre_branch.clone();
                    Self::analyze_statements(
                        std::slice::from_ref(consequent),
                        &mut cons_influences,
                        summary,
                        file_path,
                        language,
                        model_registry,
                        existing_registry,
                        true,
                        depth + 1,
                    );

                    let mut alt_influences = pre_branch.clone();
                    if let Some(alt) = alternate {
                        Self::analyze_statements(
                            std::slice::from_ref(alt),
                            &mut alt_influences,
                            summary,
                            file_path,
                            language,
                            model_registry,
                            existing_registry,
                            true,
                            depth + 1,
                        );
                    }

                    // Branch join point: union of parameter influences across both paths
                    for (k, v) in cons_influences {
                        var_influences.entry(k).or_default().extend(v);
                    }
                    if alternate.is_some() {
                        for (k, v) in alt_influences {
                            var_influences.entry(k).or_default().extend(v);
                        }
                    }
                }

                NormalizedKind::Try {
                    body,
                    catch_clauses,
                    finally_clause,
                } => {
                    Self::analyze_statements(
                        std::slice::from_ref(body),
                        var_influences,
                        summary,
                        file_path,
                        language,
                        model_registry,
                        existing_registry,
                        is_inside_branch,
                        depth + 1,
                    );
                    for c in catch_clauses {
                        Self::analyze_statements(
                            std::slice::from_ref(c),
                            var_influences,
                            summary,
                            file_path,
                            language,
                            model_registry,
                            existing_registry,
                            true,
                            depth + 1,
                        );
                    }
                    if let Some(f) = finally_clause {
                        Self::analyze_statements(
                            std::slice::from_ref(f),
                            var_influences,
                            summary,
                            file_path,
                            language,
                            model_registry,
                            existing_registry,
                            is_inside_branch,
                            depth + 1,
                        );
                    }
                }

                NormalizedKind::For { body, .. }
                | NormalizedKind::While { body, .. }
                | NormalizedKind::DoWhile { body, .. }
                | NormalizedKind::Catch { body, .. } => {
                    Self::analyze_statements(
                        std::slice::from_ref(body),
                        var_influences,
                        summary,
                        file_path,
                        language,
                        model_registry,
                        existing_registry,
                        true,
                        depth + 1,
                    );
                }

                _ => {}
            }
        }
    }

    fn eval_expr_influences(
        node: &NormalizedNode,
        var_influences: &HashMap<String, HashSet<usize>>,
        summary: &FunctionSummary,
        existing_registry: Option<&ProjectSummaryRegistry>,
        depth: usize,
    ) -> HashSet<usize> {
        let mut result = HashSet::new();
        if depth > 10 {
            return result;
        }

        match &node.kind {
            NormalizedKind::Identifier(name) => {
                if let Some(set) = var_influences.get(name) {
                    result.extend(set.iter().cloned());
                } else if let Some(set) = var_influences.get(&name.to_lowercase()) {
                    result.extend(set.iter().cloned());
                } else if let Some(idx) = summary
                    .param_names
                    .iter()
                    .position(|p| p.eq_ignore_ascii_case(name))
                {
                    result.insert(idx);
                }
            }

            NormalizedKind::Concat { parts } => {
                for part in parts {
                    let inf = Self::eval_expr_influences(
                        part,
                        var_influences,
                        summary,
                        existing_registry,
                        depth + 1,
                    );
                    result.extend(inf);
                }
            }

            NormalizedKind::Call {
                callee, arguments, ..
            } => {
                // If calling a project summary with known param_to_return
                if let Some(reg) = existing_registry {
                    if let Some(called_summary) =
                        reg.find_summary_for_caller(callee, arguments.len(), &summary.file_path)
                    {
                        for &p_idx in &called_summary.param_to_return {
                            if let Some(arg) = arguments.get(p_idx) {
                                let inf = Self::eval_expr_influences(
                                    arg,
                                    var_influences,
                                    summary,
                                    existing_registry,
                                    depth + 1,
                                );
                                result.extend(inf);
                            }
                        }
                        return result;
                    }
                }

                // Boolean predicates return comparison results, not data values
                if Self::is_boolean_callee(callee) {
                    return result;
                }

                // General propagation: inspect receiver and arguments
                if let Some(receiver_str) = callee.rsplit('.').nth(1) {
                    let r = receiver_str.trim();
                    if let Some(set) = var_influences.get(r) {
                        result.extend(set.iter().cloned());
                    }
                }

                for arg in arguments {
                    let inf = Self::eval_expr_influences(
                        arg,
                        var_influences,
                        summary,
                        existing_registry,
                        depth + 1,
                    );
                    result.extend(inf);
                }
            }

            NormalizedKind::Block(children) => {
                for child in children {
                    let inf = Self::eval_expr_influences(
                        child,
                        var_influences,
                        summary,
                        existing_registry,
                        depth + 1,
                    );
                    result.extend(inf);
                }
            }

            NormalizedKind::Return(expr) => {
                return Self::eval_expr_influences(
                    expr,
                    var_influences,
                    summary,
                    existing_registry,
                    depth + 1,
                );
            }

            _ => {
                // Sound token-boundary matching: tokenize raw text, avoiding substring false positives
                let tokens = get_word_tokens(&node.raw);
                for (idx, param) in summary.param_names.iter().enumerate() {
                    if tokens.iter().any(|t| t.eq_ignore_ascii_case(param)) {
                        result.insert(idx);
                    }
                }
                for (var, indices) in var_influences {
                    if tokens.iter().any(|t| t.eq_ignore_ascii_case(var)) {
                        result.extend(indices.iter().cloned());
                    }
                }
            }
        }

        result
    }

    fn check_sanitization_assignment(
        _lhs: &NormalizedNode,
        rhs: &NormalizedNode,
        influenced: &HashSet<usize>,
        summary: &mut FunctionSummary,
        is_inside_branch: bool,
    ) {
        if influenced.is_empty() {
            return;
        }

        let raw_lower = rhs.raw.to_lowercase();

        // Integer / numerical parsing: strictly neutralizes injection CWEs
        let is_numeric_cast = raw_lower.contains("parseint")
            || raw_lower.contains("parselong")
            || raw_lower.contains("parsefloat")
            || raw_lower.contains("parsedouble")
            || raw_lower.contains("int(")
            || raw_lower.contains("float(")
            || raw_lower.contains("math.abs");

        if is_numeric_cast {
            for &idx in influenced {
                let target_map = if is_inside_branch {
                    &mut summary.conditional_sanitizes_for
                } else {
                    &mut summary.sanitizes_for
                };
                let entry = target_map.entry(idx).or_default();
                entry.insert(CWE::CWE89);
                entry.insert(CWE::CWE78);
                entry.insert(CWE::CWE22);
                entry.insert(CWE::CWE918);
            }
        }

        // HTML escaping: neutralizes CWE-79 only
        let is_html_escape = raw_lower.contains("htmlescape")
            || raw_lower.contains("escapehtml")
            || raw_lower.contains("html.escape")
            || raw_lower.contains("escape_html");

        if is_html_escape {
            for &idx in influenced {
                let target_map = if is_inside_branch {
                    &mut summary.conditional_sanitizes_for
                } else {
                    &mut summary.sanitizes_for
                };
                let entry = target_map.entry(idx).or_default();
                entry.insert(CWE::CWE79);
            }
        }

        // URL encoding: neutralizes CWE-79 and CWE-113
        let is_url_encode = raw_lower.contains("urlencoder.encode")
            || raw_lower.contains("urllib.parse.quote")
            || raw_lower.contains("quote_plus");

        if is_url_encode {
            for &idx in influenced {
                let target_map = if is_inside_branch {
                    &mut summary.conditional_sanitizes_for
                } else {
                    &mut summary.sanitizes_for
                };
                let entry = target_map.entry(idx).or_default();
                entry.insert(CWE::CWE79);
                entry.insert(CWE::CWE113);
            }
        }
    }

    fn is_boolean_callee(callee: &str) -> bool {
        let c_lower = callee.to_lowercase();
        let method = c_lower.rsplit('.').next().unwrap_or(&c_lower);
        method == "equals"
            || method == "equalsignorecase"
            || method == "startswith"
            || method == "endswith"
            || method == "contains"
            || method == "containskey"
            || method == "containsvalue"
            || method == "isempty"
            || method == "isblank"
            || method == "exists"
            || method == "isfile"
            || method == "isdir"
    }

    fn is_boolean_expr(node: &NormalizedNode) -> bool {
        let r = node.raw.trim().to_lowercase();
        r == "true"
            || r == "false"
            || r.contains("==")
            || r.contains("!=")
            || r.contains("<=")
            || r.contains(">=")
            || (r.contains('<') && !r.contains("<<"))
            || (r.contains('>') && !r.contains(">>"))
            || r.starts_with('!')
            || r.contains("&&")
            || r.contains("||")
            || r.contains(" is ")
            || r.contains(" in ")
            || r.contains(" and ")
            || r.contains(" or ")
            || r.starts_with("not ")
    }
}

// ─── Project-Wide Summary Registry ─────────────────────────────────────────────

/// High-performance repository storing inferred function summaries across an entire project.
#[derive(Debug, Default, Clone)]
pub struct ProjectSummaryRegistry {
    /// Qualified or exact name -> summary
    pub by_qualified: HashMap<String, FunctionSummary>,
    /// Unqualified method name -> list of summaries
    pub by_method: HashMap<String, Vec<FunctionSummary>>,
    /// File path -> list of summaries defined within that file
    pub by_file: HashMap<String, Vec<FunctionSummary>>,
    /// File path -> map of imported names (e.g. `DBHelper` -> `com.example.db.DBHelper`)
    pub file_imports: HashMap<String, HashMap<String, String>>,
    /// File path -> declared package (e.g. `com.example.db`)
    pub file_packages: HashMap<String, String>,
    /// File path -> enclosing class name (e.g. `SqlHelper`)
    pub file_classes: HashMap<String, String>,
}

impl ProjectSummaryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an import statement found within a file.
    pub fn record_import(&mut self, file_path: &str, short_name: &str, full_path: &str) {
        self.file_imports
            .entry(file_path.to_string())
            .or_default()
            .insert(short_name.to_lowercase(), full_path.to_lowercase());
    }

    /// Register a newly inferred summary into the lookup indices.
    pub fn register(&mut self, summary: FunctionSummary) {
        let method_lower = summary.name.to_lowercase();
        let orig_lower = summary.original_name.to_lowercase();

        self.by_qualified
            .insert(orig_lower.clone(), summary.clone());
        self.by_qualified.insert(
            format!("{}.{}", summary.file_path.to_lowercase(), method_lower),
            summary.clone(),
        );
        if let Some(ref enc) = summary.enclosing_type {
            let enc_lower = enc.to_lowercase();
            self.by_qualified
                .insert(format!("{}.{}", enc_lower, method_lower), summary.clone());
            if let Some(short_class) = enc_lower.rsplit('.').next() {
                self.by_qualified
                    .insert(format!("{}.{}", short_class, method_lower), summary.clone());
            }
        }

        self.by_method
            .entry(method_lower)
            .or_default()
            .push(summary.clone());

        self.by_file
            .entry(summary.file_path.clone())
            .or_default()
            .push(summary);
    }

    /// Look up a summary taking caller file imports and context into account.
    pub fn find_summary_for_caller(
        &self,
        callee: &str,
        arg_count: usize,
        caller_file: &str,
    ) -> Option<&FunctionSummary> {
        let clean = callee.replace('"', "").replace('\'', "").to_lowercase();

        // 1. Check if caller imported the callee or its enclosing receiver
        if let Some(imports) = self.file_imports.get(caller_file) {
            if let Some(imported_full) = imports.get(&clean) {
                if let Some(s) = self.by_qualified.get(imported_full) {
                    return Some(s);
                }
            }
            if let Some(receiver) = clean.rsplit('.').nth(1) {
                if let Some(imported_class) = imports.get(receiver) {
                    let method = clean.rsplit('.').next().unwrap_or(&clean);
                    let resolved = format!("{}.{}", imported_class, method);
                    if let Some(s) = self.by_qualified.get(&resolved) {
                        return Some(s);
                    }
                }
            }
        }

        // 2. Exact match on qualified callee
        if let Some(s) = self.by_qualified.get(&clean) {
            return Some(s);
        }

        // 3. Same-file match priority
        let method = clean.rsplit('.').next().unwrap_or(&clean);
        if let Some(file_list) = self.by_file.get(caller_file) {
            for s in file_list {
                if s.name == method && s.param_names.len() == arg_count {
                    return Some(s);
                }
            }
        }

        // 4. Method match with matching parameter count and optional receiver check
        let (receiver_opt, method) = if let Some((r, m)) = clean.rsplit_once('.') {
            (Some(r), m)
        } else {
            (None, clean.as_str())
        };

        if let Some(list) = self.by_method.get(method) {
            if let Some(r) = receiver_opt {
                for s in list {
                    if s.param_names.len() == arg_count {
                        if let Some(ref enc) = s.enclosing_type {
                            let enc_lower = enc.to_lowercase();
                            if enc_lower == r
                                || enc_lower.ends_with(&format!(".{}", r))
                                || r.ends_with(&format!(".{}", enc_lower))
                            {
                                return Some(s);
                            }
                        }
                        let fp_lower = s.file_path.to_lowercase();
                        if fp_lower.starts_with(r) || fp_lower.contains(r) {
                            return Some(s);
                        }
                    }
                }
            }
            for s in list {
                if s.param_names.len() == arg_count {
                    return Some(s);
                }
            }
            // 5. Fallback first method match
            if let Some(first) = list.first() {
                return Some(first);
            }
        }

        None
    }

    /// Direct lookup by callee string and argument count.
    pub fn find_summary(&self, callee: &str, arg_count: usize) -> Option<&FunctionSummary> {
        self.find_summary_for_caller(callee, arg_count, "")
    }

    /// Multi-hop fixpoint propagation: resolves multi-hop call chains
    /// (e.g. Controller -> Service -> DAO -> Sink) until all transitive
    /// sink invocations and propagations converge.
    pub fn resolve_inter_summary_dependencies(&mut self) {
        let max_iterations = 5;
        for _iter in 0..max_iterations {
            let mut new_sinks: Vec<(String, SinkInvocation)> = Vec::new();
            let mut new_returns: Vec<(String, usize)> = Vec::new();
            let mut new_receivers: Vec<(String, usize)> = Vec::new();

            for (func_key, summary) in &self.by_qualified {
                for call in &summary.internal_calls {
                    let target_summary = self.find_summary_for_caller(
                        &call.callee,
                        call.args_influenced.len(),
                        &summary.file_path,
                    );
                    if let Some(target) = target_summary {
                        // Propagate transitive sink invocations
                        for target_sink in &target.sink_invocations {
                            if let Some(influencing_params) =
                                call.args_influenced.get(target_sink.param_idx)
                            {
                                for &caller_p in influencing_params {
                                    let already_has = summary.sink_invocations.iter().any(|s| {
                                        s.param_idx == caller_p
                                            && s.sink_callee == target_sink.sink_callee
                                            && s.cwe == target_sink.cwe
                                    });
                                    if !already_has {
                                        new_sinks.push((
                                            func_key.clone(),
                                            SinkInvocation {
                                                param_idx: caller_p,
                                                sink_callee: target_sink.sink_callee.clone(),
                                                cwe: target_sink.cwe,
                                                severity: target_sink.severity.clone(),
                                                call_line: call.call_line,
                                                arg_index: target_sink.arg_index,
                                            },
                                        ));
                                    }
                                }
                            }
                        }

                        // Propagate return dataflow
                        for &ret_p in &target.param_to_return {
                            if let Some(influencing_params) = call.args_influenced.get(ret_p) {
                                for &caller_p in influencing_params {
                                    if !summary.param_to_return.contains(&caller_p) {
                                        new_returns.push((func_key.clone(), caller_p));
                                    }
                                }
                            }
                        }

                        // Propagate receiver mutation
                        for &rec_p in &target.param_to_receiver {
                            if let Some(influencing_params) = call.args_influenced.get(rec_p) {
                                for &caller_p in influencing_params {
                                    if !summary.param_to_receiver.contains(&caller_p) {
                                        new_receivers.push((func_key.clone(), caller_p));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if new_sinks.is_empty() && new_returns.is_empty() && new_receivers.is_empty() {
                break;
            }

            // Apply discovered transitive properties
            for (key, sink) in new_sinks {
                if let Some(s) = self.by_qualified.get_mut(&key) {
                    s.sink_invocations.push(sink);
                }
            }
            for (key, ret_p) in new_returns {
                if let Some(s) = self.by_qualified.get_mut(&key) {
                    s.param_to_return.insert(ret_p);
                }
            }
            for (key, rec_p) in new_receivers {
                if let Some(s) = self.by_qualified.get_mut(&key) {
                    s.param_to_receiver.insert(rec_p);
                }
            }
        }
    }

    /// Index all functions defined in raw source code text.
    pub fn index_code(
        &mut self,
        file_path: &str,
        code: &str,
        language: &str,
        model_registry: Option<&ActiveModelRegistry>,
    ) {
        // Extract package declaration if present in source text
        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("package ") && trimmed.ends_with(';') {
                let pkg = trimmed["package ".len()..trimmed.len() - 1].trim();
                if !pkg.is_empty() {
                    self.file_packages
                        .insert(file_path.to_string(), pkg.to_lowercase());
                }
                break;
            }
        }

        let stem = std::path::Path::new(file_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !stem.is_empty() {
            self.file_classes
                .insert(file_path.to_string(), stem.to_string());
        }

        if let Ok(ast) = UnifiedParser::parse(code, language) {
            let mut norm = Normalizer::new();
            let normalized = norm.normalize(&ast, language);
            self.index_node(file_path, &normalized, language, model_registry);
        }
    }

    /// Recursively search an AST node and index every function definition and import found.
    pub fn index_node(
        &mut self,
        file_path: &str,
        node: &NormalizedNode,
        language: &str,
        model_registry: Option<&ActiveModelRegistry>,
    ) {
        if !self.file_packages.contains_key(file_path) {
            for line in node.raw.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("package ") && trimmed.ends_with(';') {
                    let pkg = trimmed["package ".len()..trimmed.len() - 1].trim();
                    if !pkg.is_empty() {
                        self.file_packages
                            .insert(file_path.to_string(), pkg.to_lowercase());
                    }
                    break;
                }
            }
        }
        if !self.file_classes.contains_key(file_path) {
            let stem = std::path::Path::new(file_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if !stem.is_empty() {
                self.file_classes
                    .insert(file_path.to_string(), stem.to_string());
            }
        }

        match &node.kind {
            NormalizedKind::Import {
                class_name,
                full_path,
            } => {
                self.record_import(file_path, class_name, full_path);
            }

            NormalizedKind::FunctionDefinition {
                name, params, body, ..
            } => {
                let mut summary = SummaryInferer::infer_from_definition(
                    name,
                    params,
                    body,
                    file_path,
                    node.span.start_line,
                    node.span.end_line,
                    language,
                    model_registry,
                    Some(self),
                );

                if summary.enclosing_type.is_none() {
                    let pkg = self.file_packages.get(file_path);
                    let cls = self.file_classes.get(file_path);
                    match (pkg, cls) {
                        (Some(p), Some(c)) => {
                            summary.enclosing_type = Some(format!("{}.{}", p, c));
                        }
                        (None, Some(c)) => {
                            summary.enclosing_type = Some(c.clone());
                        }
                        _ => {}
                    }
                }

                self.register(summary);

                // Recurse into body to index any nested functions
                for child in body {
                    self.index_node(file_path, child, language, model_registry);
                }
            }

            NormalizedKind::Block(children) | NormalizedKind::Concat { parts: children } => {
                for child in children {
                    self.index_node(file_path, child, language, model_registry);
                }
            }

            NormalizedKind::If {
                condition,
                consequent,
                alternate,
            } => {
                self.index_node(file_path, condition, language, model_registry);
                self.index_node(file_path, consequent, language, model_registry);
                if let Some(alt) = alternate {
                    self.index_node(file_path, alt, language, model_registry);
                }
            }

            NormalizedKind::Try {
                body,
                catch_clauses,
                finally_clause,
            } => {
                self.index_node(file_path, body, language, model_registry);
                for c in catch_clauses {
                    self.index_node(file_path, c, language, model_registry);
                }
                if let Some(f) = finally_clause {
                    self.index_node(file_path, f, language, model_registry);
                }
            }

            NormalizedKind::For { body, .. }
            | NormalizedKind::While { body, .. }
            | NormalizedKind::DoWhile { body, .. }
            | NormalizedKind::Catch { body, .. } => {
                self.index_node(file_path, body, language, model_registry);
            }

            _ => {}
        }
    }

    /// Total number of distinct function summaries recorded.
    pub fn len(&self) -> usize {
        self.by_qualified.len()
    }

    /// True if registry contains no summaries.
    pub fn is_empty(&self) -> bool {
        self.by_qualified.is_empty()
    }

    /// Total count of internal sink invocations discovered across all project functions.
    pub fn total_sinks_discovered(&self) -> usize {
        self.by_qualified
            .values()
            .map(|s| s.sink_invocations.len())
            .sum()
    }

    /// Total count of parameter-to-return propagators discovered.
    pub fn total_propagators_discovered(&self) -> usize {
        self.by_qualified
            .values()
            .map(|s| s.param_to_return.len())
            .sum()
    }
}
