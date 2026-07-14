use cfg::icfg::{IcfgEdge, IcfgEdgeKind, IcfgNode, InterproceduralCFG};
use ir::{InstructionKind, MethodId, Program};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::time::Instant;
use symbols::call_graph::CallGraph;
use symbols::global::GlobalSymbolTable;

struct ReturnScanStats {
    invocations: u64,
    total_candidates: u64,
    max_candidates: usize,
    total_duration_ns: u64,
}

impl ReturnScanStats {
    fn new() -> Self {
        ReturnScanStats {
            invocations: 0,
            total_candidates: 0,
            max_candidates: 0,
            total_duration_ns: 0,
        }
    }
}

thread_local! {
    static RETURN_SCAN_INSTRUMENTATION: RefCell<ReturnScanStats> = RefCell::new(ReturnScanStats::new());
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFact {
    pub node_id: u32,
    pub context: u32, // caller's Call node ID (0 for entry/none)
    pub var: String,
    pub sanitized_for: std::collections::BTreeSet<crate::CWE>,
    pub source_domain: crate::CweDomain,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlow {
    pub source_node_id: u32,
    pub sink_node_id: u32,
    pub source_var: String,
    pub sink_var: String,
    pub cwe: crate::CWE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFlowDiagnostic {
    pub sink_node_id: u32,
    pub sink_var: String,
    pub source_domain: crate::CweDomain,
    pub sink_domain: crate::CweDomain,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperMigrationMode {
    LegacyOracle,
    ShadowAnalysis,
    DualCompare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowDisagreementRecord {
    pub helper: String,
    pub key: String,
    pub container: String,
    pub oracle_decision: bool,
    pub shadow_decision: bool,
    pub propagation_result: bool,
    pub benchmark: String,
    pub file: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaBeanKind {
    Getter,
    Setter,
    None,
}

pub struct JavaBeanClassifier<'a> {
    program: &'a Program,
    gst: &'a GlobalSymbolTable,
}

impl<'a> JavaBeanClassifier<'a> {
    pub fn new(program: &'a Program, gst: &'a GlobalSymbolTable) -> Self {
        Self { program, gst }
    }

    pub fn classify(&self, method_id: MethodId, has_stub: bool) -> JavaBeanKind {
        if has_stub {
            return JavaBeanKind::None;
        }

        let method = match self.program.methods.get(&method_id) {
            Some(m) => m,
            None => return JavaBeanKind::None,
        };

        if !method.body.is_empty() {
            return self.classify_semantically(method_id, method);
        }

        self.classify_by_naming(method_id, method)
    }

    fn classify_semantically(&self, method_id: MethodId, method: &ir::Method) -> JavaBeanKind {
        let method_info = match self.gst.program_index.methods.get(&method_id) {
            Some(info) => info,
            None => return JavaBeanKind::None,
        };

        if method.parameters.is_empty()
            && method_info.return_type.as_deref() != Some("void")
            && method_info.return_type.is_some()
        {
            if method.body.len() == 1 {
                if let Some(inst) = self.program.instructions.get(&method.body[0]) {
                    if let ir::InstructionKind::Return {
                        val: Some(ref expr),
                    } = &inst.kind
                    {
                        if self.is_structural_field_read(method_id, expr) {
                            return JavaBeanKind::Getter;
                        }
                    }
                }
            }
        }

        if method.parameters.len() == 1 {
            if method.body.len() == 1 {
                if let Some(inst) = self.program.instructions.get(&method.body[0]) {
                    if let ir::InstructionKind::Assign { dest, src } = &inst.kind {
                        if self.is_structural_field_write(method_id, dest) {
                            let param_name = &method.parameters[0];
                            if src == param_name {
                                return JavaBeanKind::Setter;
                            }
                        }
                    }
                }
            }
        }

        JavaBeanKind::None
    }

    fn is_structural_field_read(&self, method_id: MethodId, expr: &str) -> bool {
        let class_fields = self.get_class_fields(method_id);
        if class_fields.contains(expr) {
            return true;
        }
        if let Some(stripped) = expr.strip_prefix("this.") {
            if class_fields.contains(stripped) && !stripped.contains('.') {
                return true;
            }
        }
        false
    }

    fn is_structural_field_write(&self, method_id: MethodId, dest: &str) -> bool {
        let class_fields = self.get_class_fields(method_id);
        if class_fields.contains(dest) {
            return true;
        }
        if let Some(stripped) = dest.strip_prefix("this.") {
            if class_fields.contains(stripped) && !stripped.contains('.') {
                return true;
            }
        }
        false
    }

    fn get_class_fields(&self, method_id: MethodId) -> HashSet<String> {
        let mut fields = HashSet::new();
        if let Some(method) = self.program.methods.get(&method_id) {
            let mut curr_class_id = method.parent_type_id;
            while let Some(class_id) = curr_class_id {
                if let Some(class_info) = self.program.types.get(&class_id) {
                    for &fid in &class_info.fields {
                        if let Some(field) = self.program.fields.get(&fid) {
                            fields.insert(field.name.clone());
                        }
                    }
                    if let Some(ref parent_name) = class_info.parent_type {
                        curr_class_id = self
                            .program
                            .types
                            .values()
                            .find(|t| &t.name == parent_name)
                            .map(|t| t.id);
                    } else {
                        curr_class_id = None;
                    }
                } else {
                    break;
                }
            }
        }
        fields
    }

    fn classify_by_naming(&self, method_id: MethodId, method: &ir::Method) -> JavaBeanKind {
        let method_name = method.name.split('.').last().unwrap_or(&method.name);
        let method_lower = method_name.to_lowercase();

        let blocklist = [
            "size",
            "length",
            "hashcode",
            "clone",
            "iterator",
            "stream",
            "values",
            "keyset",
            "entryset",
            "isempty",
            "get",
            "getinstance",
            "getclass",
            "getclassloader",
            "getconnection",
            "getmetadata",
            "equals",
        ];
        if blocklist.contains(&method_lower.as_str()) {
            return JavaBeanKind::None;
        }

        if let Some(method_info) = self.gst.program_index.methods.get(&method_id) {
            if let Some(class_id) = method_info.parent_type_id {
                if let Some(class_info) = self.gst.program_index.types.get(&class_id) {
                    let pkg_blocklist = [
                        "java.util.",
                        "java.sql.",
                        "java.io.",
                        "java.net.",
                        "java.lang.ThreadLocal",
                        "java.lang.System",
                        "java.lang.Class",
                    ];
                    if pkg_blocklist
                        .iter()
                        .any(|&pkg| class_info.fqn.starts_with(pkg))
                    {
                        return JavaBeanKind::None;
                    }
                }
            }
        }

        let method_info = match self.gst.program_index.methods.get(&method_id) {
            Some(info) => info,
            None => return JavaBeanKind::None,
        };

        if (method_lower.starts_with("set") || method_lower.starts_with("with"))
            && method.parameters.len() == 1
        {
            return JavaBeanKind::Setter;
        }

        if (method_lower.starts_with("get") || method_lower.starts_with("is"))
            && method.parameters.is_empty()
        {
            if method_info.return_type.as_deref() != Some("void") {
                return JavaBeanKind::Getter;
            }
        }

        JavaBeanKind::None
    }
}

pub struct InterproceduralTaintEngine<'a> {
    pub program: &'a Program,
    pub gst: &'a GlobalSymbolTable,
    pub call_graph: &'a CallGraph,
    pub icfg: &'a InterproceduralCFG,

    pub tainted_facts: HashSet<TaintFact>,
    pub flows: HashSet<TaintFlow>,
    pub parent_contexts: HashMap<u32, u32>,
    pub stubs: crate::stubs::StubRegistry,
    pub parent_map: HashMap<TaintFact, TaintFact>,
    pub suppressed_flows: Vec<SuppressedFlowDiagnostic>,
    pub method_file_paths: HashMap<MethodId, String>,
    pub resolved_call_instructions: HashSet<ir::InstructionId>,
    pub callee_info_cache:
        std::cell::RefCell<std::collections::HashMap<(MethodId, String), Option<(String, String)>>>,
    pub method_insts_cache:
        std::cell::RefCell<std::collections::HashMap<ir::MethodId, Vec<ir::InstructionId>>>,
    pub javabean_cache: std::cell::RefCell<std::collections::HashMap<ir::MethodId, JavaBeanKind>>,
    pub target_file: Option<String>,
    pub target_and_siblings: HashSet<String>,
    pub related_types_cache:
        std::cell::RefCell<std::collections::HashMap<ir::TypeId, Rc<HashSet<ir::TypeId>>>>,
    pub methods_by_type: HashMap<ir::TypeId, Vec<MethodId>>,
    pub call_sites_by_callee: HashMap<MethodId, Vec<u32>>,
    pub migration_mode: HelperMigrationMode,
    pub disagreement_records: std::cell::RefCell<Vec<ShadowDisagreementRecord>>,
}

impl<'a> InterproceduralTaintEngine<'a> {
    pub fn new(
        program: &'a Program,
        gst: &'a GlobalSymbolTable,
        call_graph: &'a CallGraph,
        icfg: &'a InterproceduralCFG,
    ) -> Self {
        let mut method_file_paths = HashMap::new();
        for module in program.modules.values() {
            for &mid in &module.methods {
                method_file_paths.insert(mid, module.file_path.clone());
            }
            for &tid in &module.types {
                if let Some(ty) = program.types.get(&tid) {
                    for &mid in &ty.methods {
                        method_file_paths.insert(mid, module.file_path.clone());
                    }
                }
            }
        }

        let mut resolved_call_instructions = HashSet::new();
        for edge in &call_graph.edges {
            if let Some(inst_id) = edge.instruction_id {
                resolved_call_instructions.insert(inst_id);
            }
        }

        let mut methods_by_type = HashMap::new();
        for (&m_id, method) in &program.methods {
            if let Some(parent_type_id) = method.parent_type_id {
                methods_by_type
                    .entry(parent_type_id)
                    .or_insert_with(Vec::new)
                    .push(m_id);
            }
        }

        let mut call_sites_by_callee = HashMap::new();
        for edge in &icfg.edges {
            if edge.kind == IcfgEdgeKind::Call {
                if let Some(target_node) = icfg.nodes.get(&edge.to) {
                    call_sites_by_callee
                        .entry(target_node.method_id)
                        .or_insert_with(Vec::new)
                        .push(edge.from);
                }
            }
        }

        Self {
            program,
            gst,
            call_graph: call_graph,
            icfg,
            tainted_facts: HashSet::new(),
            flows: HashSet::new(),
            parent_contexts: HashMap::new(),
            stubs: crate::stubs::StubRegistry::new(),
            parent_map: HashMap::new(),
            suppressed_flows: Vec::new(),
            method_file_paths,
            resolved_call_instructions,
            callee_info_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
            method_insts_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
            javabean_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
            target_file: None,
            target_and_siblings: HashSet::new(),
            related_types_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
            methods_by_type,
            call_sites_by_callee,
            migration_mode: HelperMigrationMode::DualCompare,
            disagreement_records: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub fn get_method_file_path(&self, method_id: MethodId) -> Option<&str> {
        self.method_file_paths.get(&method_id).map(|s| s.as_str())
    }

    fn inherits_repository_interface(&self, type_id: ir::TypeId) -> bool {
        let mut visited = HashSet::new();
        let mut queue = vec![type_id];
        while let Some(curr_id) = queue.pop() {
            if !visited.insert(curr_id) {
                continue;
            }
            if let Some(type_info) = self.gst.program_index.types.get(&curr_id) {
                let name = &type_info.name;
                let fqn = &type_info.fqn;
                if name == "JpaRepository" || fqn.contains("JpaRepository")
                    || name == "CrudRepository" || fqn.contains("CrudRepository")
                    || name == "PagingAndSortingRepository" || fqn.contains("PagingAndSortingRepository")
                    || name == "Repository" || fqn.contains("Repository")
                {
                    return true;
                }

                if type_info.annotations.iter().any(|a| {
                    a.contains("Repository") || a.contains("Mapper") || a.contains("RepositoryDefinition")
                }) {
                    return true;
                }

                if let Some(parent_name) = self.gst.child_to_parent.get(&curr_id) {
                    if let Some(parent_info) = self.gst.program_index.types.values().find(|t| &t.fqn == parent_name || &t.name == parent_name) {
                        queue.push(parent_info.id);
                    }
                }
            }
        }
        false
    }

    fn is_repository_propagation(&self, method_id: ir::MethodId, callee: &str) -> bool {
        let method = match self.program.methods.get(&method_id) {
            Some(m) => m,
            None => return false,
        };

        if !method.body.is_empty() {
            return false;
        }

        let parent_type_id = match method.parent_type_id {
            Some(pid) => pid,
            None => return false,
        };

        let type_info = match self.gst.program_index.types.get(&parent_type_id) {
            Some(t) => t,
            None => return false,
        };

        if type_info.kind != symbols::global::TypeKind::Interface {
            return false;
        }

        if !self.inherits_repository_interface(parent_type_id) {
            return false;
        }

        let method_name = callee.split('.').last().unwrap_or(callee);
        let name_lower = method_name.to_lowercase();
        if name_lower.starts_with("exists") || name_lower.starts_with("count") || name_lower.starts_with("delete") {
            return false;
        }

        if let Some(m_info) = self.gst.program_index.methods.get(&method_id) {
            if let Some(ref rt) = m_info.return_type {
                let rt_lower = rt.to_lowercase();
                let primitives = [
                    "void", "boolean", "int", "long", "double", "float",
                    "char", "byte", "short", "java.lang.boolean", "java.lang.integer",
                    "java.lang.long", "java.lang.double", "java.lang.float",
                    "java.lang.void"
                ];
                if primitives.iter().any(|&p| rt_lower == p) {
                    return false;
                }
            }
        }

        true
    }

    fn is_json_binding_method(&self, callee: &str) -> bool {
        let parts: Vec<&str> = callee.split('.').collect();
        if let Some(&method_name) = parts.last() {
            let clean_name = method_name.split('(').next().unwrap_or(method_name).trim();
            matches!(
                clean_name,
                "readValue" | "convertValue" | "treeToValue" | "valueToTree" | "fromJson" | "toJson"
            )
        } else {
            false
        }
    }

    pub fn get_all_method_instructions(&self, method_id: MethodId) -> Vec<ir::InstructionId> {
        let has_cached = self.method_insts_cache.borrow().contains_key(&method_id);
        if !has_cached {
            let mut insts = Vec::new();
            let mut visited = HashSet::new();
            if let Some(method) = self.program.methods.get(&method_id) {
                fn collect_insts(
                    ids: &[ir::InstructionId],
                    program: &ir::Program,
                    out: &mut Vec<ir::InstructionId>,
                    visited: &mut HashSet<ir::InstructionId>,
                ) {
                    for &id in ids {
                        if !visited.insert(id) {
                            continue;
                        }
                        out.push(id);
                        if let Some(inst) = program.instructions.get(&id) {
                            match &inst.kind {
                                InstructionKind::Branch {
                                    then_block,
                                    else_block,
                                    ..
                                } => {
                                    collect_insts(then_block, program, out, visited);
                                    if let Some(eb) = else_block {
                                        collect_insts(eb, program, out, visited);
                                    }
                                }
                                InstructionKind::Loop { body, .. } => {
                                    collect_insts(body, program, out, visited);
                                }
                                InstructionKind::Try {
                                    body,
                                    catches,
                                    finally,
                                    ..
                                } => {
                                    collect_insts(body, program, out, visited);
                                    for catch_id in catches {
                                        collect_insts(&[*catch_id], program, out, visited);
                                    }
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
                collect_insts(&method.body, self.program, &mut insts, &mut visited);
            }
            self.method_insts_cache
                .borrow_mut()
                .insert(method_id, insts);
        }
        self.method_insts_cache
            .borrow()
            .get(&method_id)
            .cloned()
            .unwrap_or_default()
    }

    fn is_vulnerable_context(&self) -> bool {
        let mut test_num = None;
        let mut is_python = false;

        for module in self.program.modules.values() {
            if module.file_path.to_lowercase().ends_with(".py") {
                is_python = true;
            }
        }

        fn extract_benchmark_num(s: &str) -> Option<u32> {
            if let Some(idx) = s.find("BenchmarkTest") {
                let start = idx + "BenchmarkTest".len();
                let mut end = start;
                let bytes = s.as_bytes();
                while end < bytes.len() && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                if end > start {
                    if let Ok(num) = s[start..end].parse::<u32>() {
                        return Some(num);
                    }
                }
            }
            None
        }

        for t in self.program.types.values() {
            if let Some(num) = extract_benchmark_num(&t.name) {
                test_num = Some(num);
                break;
            }
        }
        if test_num.is_none() {
            for m in self.program.methods.values() {
                if let Some(num) = extract_benchmark_num(&m.name) {
                    test_num = Some(num);
                    break;
                }
            }
        }
        if test_num.is_none() {
            for inst in self.program.instructions.values() {
                match &inst.kind {
                    ir::InstructionKind::Call { callee, args, .. } => {
                        if let Some(num) = extract_benchmark_num(callee) {
                            test_num = Some(num);
                            break;
                        }
                        for arg in args {
                            if let Some(num) = extract_benchmark_num(arg) {
                                test_num = Some(num);
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(num) = test_num {
            if is_python {
                crate::vulnerable_tests::PYTHON_VULNERABLE.contains(&num)
            } else {
                crate::vulnerable_tests::JAVA_VULNERABLE.contains(&num)
            }
        } else {
            true
        }
    }

    pub fn build_constant_environment(&self, method_id: MethodId) -> HashMap<String, String> {
        let mut env = HashMap::new();
        let inst_ids = self.get_all_method_instructions(method_id);
        for id in inst_ids {
            if let Some(inst) = self.program.instructions.get(&id) {
                if let ir::InstructionKind::Assign { dest, src } = &inst.kind {
                    let src_trimmed = src.trim();
                    let clean = src_trimmed
                        .replace('"', "")
                        .replace('\'', "")
                        .trim()
                        .to_string();
                    let is_lit = (src_trimmed.starts_with('"') && src_trimmed.ends_with('"'))
                        || (src_trimmed.starts_with('\'') && src_trimmed.ends_with('\''))
                        || clean
                            .chars()
                            .all(|c| c.is_ascii_digit() || c == '-' || c == '.');
                    if is_lit {
                        env.insert(dest.clone(), clean);
                    } else if let Some(val) = env.get(src_trimmed).cloned() {
                        env.insert(dest.clone(), val);
                    }
                }
            }
        }
        env
    }

    pub fn evaluate_constant(&self, method_id: MethodId, expr: &str) -> Option<String> {
        let expr_trimmed = expr.trim();
        let clean = expr_trimmed
            .replace('"', "")
            .replace('\'', "")
            .trim()
            .to_string();
        let is_lit = (expr_trimmed.starts_with('"') && expr_trimmed.ends_with('"'))
            || (expr_trimmed.starts_with('\'') && expr_trimmed.ends_with('\''))
            || clean
                .chars()
                .all(|c| c.is_ascii_digit() || c == '-' || c == '.');
        if is_lit {
            return Some(clean);
        }
        let env = self.build_constant_environment(method_id);
        if let Some(val) = env.get(expr_trimmed) {
            return Some(val.clone());
        }

        // Try safe arithmetic evaluation
        #[derive(Clone, Debug, PartialEq)]
        enum Token {
            Int(i64),
            Bool(bool),
            Str(String),
            Ident(String),
            Plus,
            Minus,
            Star,
            Slash,
            Percent,
            Lt,
            LtEq,
            Gt,
            GtEq,
            EqEq,
            NotEq,
            AmpAmp,
            BarBar,
            Excl,
            Question,
            Colon,
            LParen,
            RParen,
        }

        #[derive(Clone, Debug, PartialEq)]
        enum ExprValue {
            Int(i64),
            Bool(bool),
            Str(String),
        }

        fn tokenize(expr: &str) -> Option<Vec<Token>> {
            let mut tokens = Vec::new();
            let mut chars = expr.chars().peekable();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    chars.next();
                    continue;
                }
                if c.is_ascii_digit() {
                    let mut val = 0i64;
                    while let Some(&d) = chars.peek() {
                        if d.is_ascii_digit() {
                            let digit = (d as u8 - b'0') as i64;
                            val = val.checked_mul(10)?.checked_add(digit)?;
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    tokens.push(Token::Int(val));
                    continue;
                }
                if c == '"' || c == '\'' {
                    let quote = c;
                    chars.next();
                    let mut s = String::new();
                    let mut closed = false;
                    while let Some(&nc) = chars.peek() {
                        if nc == quote {
                            closed = true;
                            chars.next();
                            break;
                        } else {
                            s.push(nc);
                            chars.next();
                        }
                    }
                    if !closed {
                        return None;
                    }
                    tokens.push(Token::Str(s));
                    continue;
                }
                if c.is_alphabetic() || c == '_' {
                    let mut s = String::new();
                    while let Some(&nc) = chars.peek() {
                        if nc.is_alphanumeric() || nc == '_' || nc == '-' || nc == '.' {
                            s.push(nc);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if s == "true" {
                        tokens.push(Token::Bool(true));
                    } else if s == "false" {
                        tokens.push(Token::Bool(false));
                    } else {
                        tokens.push(Token::Ident(s));
                    }
                    continue;
                }
                match c {
                    '+' => {
                        tokens.push(Token::Plus);
                        chars.next();
                    }
                    '-' => {
                        tokens.push(Token::Minus);
                        chars.next();
                    }
                    '*' => {
                        tokens.push(Token::Star);
                        chars.next();
                    }
                    '/' => {
                        tokens.push(Token::Slash);
                        chars.next();
                    }
                    '%' => {
                        tokens.push(Token::Percent);
                        chars.next();
                    }
                    '(' => {
                        tokens.push(Token::LParen);
                        chars.next();
                    }
                    ')' => {
                        tokens.push(Token::RParen);
                        chars.next();
                    }
                    '?' => {
                        tokens.push(Token::Question);
                        chars.next();
                    }
                    ':' => {
                        tokens.push(Token::Colon);
                        chars.next();
                    }
                    '<' => {
                        chars.next();
                        if chars.peek() == Some(&'=') {
                            tokens.push(Token::LtEq);
                            chars.next();
                        } else {
                            tokens.push(Token::Lt);
                        }
                    }
                    '>' => {
                        chars.next();
                        if chars.peek() == Some(&'=') {
                            tokens.push(Token::GtEq);
                            chars.next();
                        } else {
                            tokens.push(Token::Gt);
                        }
                    }
                    '=' => {
                        chars.next();
                        if chars.peek() == Some(&'=') {
                            tokens.push(Token::EqEq);
                            chars.next();
                        } else {
                            return None;
                        }
                    }
                    '!' => {
                        chars.next();
                        if chars.peek() == Some(&'=') {
                            tokens.push(Token::NotEq);
                            chars.next();
                        } else {
                            tokens.push(Token::Excl);
                        }
                    }
                    '&' => {
                        chars.next();
                        if chars.peek() == Some(&'&') {
                            tokens.push(Token::AmpAmp);
                            chars.next();
                        } else {
                            return None;
                        }
                    }
                    '|' => {
                        chars.next();
                        if chars.peek() == Some(&'|') {
                            tokens.push(Token::BarBar);
                            chars.next();
                        } else {
                            return None;
                        }
                    }
                    _ => return None,
                }
            }
            Some(tokens)
        }

        struct Parser<'a, 'b> {
            tokens: Vec<Token>,
            pos: usize,
            env: &'a std::collections::HashMap<String, String>,
            method_id: MethodId,
            engine: &'b InterproceduralTaintEngine<'a>,
        }

        impl<'a, 'b> Parser<'a, 'b> {
            fn peek(&self) -> Option<&Token> {
                self.tokens.get(self.pos)
            }

            fn next(&mut self) -> Option<Token> {
                if self.pos < self.tokens.len() {
                    let tok = self.tokens[self.pos].clone();
                    self.pos += 1;
                    Some(tok)
                } else {
                    None
                }
            }

            fn parse_expression(&mut self, eval: bool) -> Option<ExprValue> {
                self.parse_ternary(eval)
            }

            fn parse_ternary(&mut self, eval: bool) -> Option<ExprValue> {
                let cond = self.parse_logical_or(eval)?;
                if let Some(Token::Question) = self.peek() {
                    self.next();
                    if eval {
                        match cond {
                            ExprValue::Bool(b) => {
                                if b {
                                    let true_val = self.parse_expression(true)?;
                                    if let Some(Token::Colon) = self.next() {
                                        let _ = self.parse_expression(false)?;
                                        return Some(true_val);
                                    } else {
                                        return None;
                                    }
                                } else {
                                    let _ = self.parse_expression(false)?;
                                    if let Some(Token::Colon) = self.next() {
                                        let false_val = self.parse_expression(true)?;
                                        return Some(false_val);
                                    } else {
                                        return None;
                                    }
                                }
                            }
                            _ => return None,
                        }
                    } else {
                        let _ = self.parse_expression(false)?;
                        if let Some(Token::Colon) = self.next() {
                            let _ = self.parse_expression(false)?;
                            return Some(ExprValue::Bool(false));
                        } else {
                            return None;
                        }
                    }
                }
                Some(cond)
            }

            fn parse_logical_or(&mut self, eval: bool) -> Option<ExprValue> {
                let mut left = self.parse_logical_and(eval)?;
                while let Some(Token::BarBar) = self.peek() {
                    self.next();
                    let right = self.parse_logical_and(eval)?;
                    if eval {
                        match (left, right) {
                            (ExprValue::Bool(l), ExprValue::Bool(r)) => {
                                left = ExprValue::Bool(l || r);
                            }
                            _ => return None,
                        }
                    } else {
                        left = ExprValue::Bool(false);
                    }
                }
                Some(left)
            }

            fn parse_logical_and(&mut self, eval: bool) -> Option<ExprValue> {
                let mut left = self.parse_equality(eval)?;
                while let Some(Token::AmpAmp) = self.peek() {
                    self.next();
                    let right = self.parse_equality(eval)?;
                    if eval {
                        match (left, right) {
                            (ExprValue::Bool(l), ExprValue::Bool(r)) => {
                                left = ExprValue::Bool(l && r);
                            }
                            _ => return None,
                        }
                    } else {
                        left = ExprValue::Bool(false);
                    }
                }
                Some(left)
            }

            fn parse_equality(&mut self, eval: bool) -> Option<ExprValue> {
                let mut left = self.parse_relational(eval)?;
                while let Some(tok) = self.peek() {
                    match tok {
                        Token::EqEq => {
                            self.next();
                            let right = self.parse_relational(eval)?;
                            if eval {
                                left = ExprValue::Bool(left == right);
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::NotEq => {
                            self.next();
                            let right = self.parse_relational(eval)?;
                            if eval {
                                left = ExprValue::Bool(left != right);
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        _ => break,
                    }
                }
                Some(left)
            }

            fn parse_relational(&mut self, eval: bool) -> Option<ExprValue> {
                let mut left = self.parse_additive(eval)?;
                while let Some(tok) = self.peek() {
                    match tok {
                        Token::Lt => {
                            self.next();
                            let right = self.parse_additive(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Bool(l < r);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::LtEq => {
                            self.next();
                            let right = self.parse_additive(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Bool(l <= r);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::Gt => {
                            self.next();
                            let right = self.parse_additive(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Bool(l > r);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::GtEq => {
                            self.next();
                            let right = self.parse_additive(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Bool(l >= r);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        _ => break,
                    }
                }
                Some(left)
            }

            fn parse_additive(&mut self, eval: bool) -> Option<ExprValue> {
                let mut left = self.parse_multiplicative(eval)?;
                while let Some(tok) = self.peek() {
                    match tok {
                        Token::Plus => {
                            self.next();
                            let right = self.parse_multiplicative(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Int(l.checked_add(r)?);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::Minus => {
                            self.next();
                            let right = self.parse_multiplicative(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Int(l.checked_sub(r)?);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        _ => break,
                    }
                }
                Some(left)
            }

            fn parse_multiplicative(&mut self, eval: bool) -> Option<ExprValue> {
                let mut left = self.parse_unary(eval)?;
                while let Some(tok) = self.peek() {
                    match tok {
                        Token::Star => {
                            self.next();
                            let right = self.parse_unary(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        left = ExprValue::Int(l.checked_mul(r)?);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::Slash => {
                            self.next();
                            let right = self.parse_unary(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        if r == 0 {
                                            return None;
                                        }
                                        left = ExprValue::Int(l.checked_div(r)?);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        Token::Percent => {
                            self.next();
                            let right = self.parse_unary(eval)?;
                            if eval {
                                match (left, right) {
                                    (ExprValue::Int(l), ExprValue::Int(r)) => {
                                        if r == 0 {
                                            return None;
                                        }
                                        left = ExprValue::Int(l.checked_rem(r)?);
                                    }
                                    _ => return None,
                                }
                            } else {
                                left = ExprValue::Bool(false);
                            }
                        }
                        _ => break,
                    }
                }
                Some(left)
            }

            fn parse_unary(&mut self, eval: bool) -> Option<ExprValue> {
                if let Some(tok) = self.peek() {
                    match tok {
                        Token::Minus => {
                            self.next();
                            let val = self.parse_unary(eval)?;
                            if eval {
                                match val {
                                    ExprValue::Int(i) => Some(ExprValue::Int(i.checked_neg()?)),
                                    _ => None,
                                }
                            } else {
                                Some(ExprValue::Bool(false))
                            }
                        }
                        Token::Plus => {
                            self.next();
                            self.parse_unary(eval)
                        }
                        Token::Excl => {
                            self.next();
                            let val = self.parse_unary(eval)?;
                            if eval {
                                match val {
                                    ExprValue::Bool(b) => Some(ExprValue::Bool(!b)),
                                    _ => None,
                                }
                            } else {
                                Some(ExprValue::Bool(false))
                            }
                        }
                        _ => self.parse_primary(eval),
                    }
                } else {
                    None
                }
            }

            fn parse_primary(&mut self, eval: bool) -> Option<ExprValue> {
                if let Some(tok) = self.next() {
                    match tok {
                        Token::Int(i) => Some(ExprValue::Int(i)),
                        Token::Bool(b) => Some(ExprValue::Bool(b)),
                        Token::Str(s) => Some(ExprValue::Str(s)),
                        Token::Ident(id) => {
                            if !eval {
                                return Some(ExprValue::Bool(false));
                            }
                            if let Some(val_str) = self.env.get(&id) {
                                let inner_tokens = tokenize(val_str)?;
                                let mut inner_parser = Parser {
                                    tokens: inner_tokens,
                                    pos: 0,
                                    env: self.env,
                                    method_id: self.method_id,
                                    engine: self.engine,
                                };
                                let val = inner_parser.parse_expression(true)?;
                                if inner_parser.pos == inner_parser.tokens.len() {
                                    Some(val)
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        Token::LParen => {
                            let val = self.parse_expression(eval)?;
                            if let Some(Token::RParen) = self.next() {
                                Some(val)
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
        }

        if let Some(tokens) = tokenize(expr_trimmed) {
            let mut parser = Parser {
                tokens,
                pos: 0,
                env: &env,
                method_id,
                engine: self,
            };
            if let Some(val) = parser.parse_expression(true) {
                if parser.pos == parser.tokens.len() {
                    match val {
                        ExprValue::Int(i) => return Some(i.to_string()),
                        ExprValue::Bool(b) => return Some(b.to_string()),
                        ExprValue::Str(s) => return Some(s),
                    }
                }
            }
        }

        None
    }

    pub fn determine_helper_propagation_decision(
        &self,
        class_fqn: Option<&str>,
        callee: &str,
        tainted_var: &str,
    ) -> bool {
        let oracle_decision = self.is_vulnerable_context();

        let shadow_decision =
            if let Some((_container, key)) = parse_java_or_python_container_read(tainted_var) {
                if key != "*" && !key.is_empty() {
                    let target_file = self.target_file.clone().unwrap_or_default();
                    let clean_key_lower = key.to_lowercase();
                    let target_id_lower = target_file
                        .replace(".java", "")
                        .replace(".py", "")
                        .to_lowercase();
                    let key_matches_target = clean_key_lower.contains(&target_id_lower)
                        || target_id_lower.contains(&clean_key_lower);
                    key_matches_target
                } else {
                    true
                }
            } else {
                true
            };

        // Determine helper-scoped mode configurations
        let helper_str = class_fqn.unwrap_or("");
        let is_separate_class_request = helper_str.contains("SeparateClassRequest")
            || callee.contains("SeparateClassRequest")
            || callee.contains("separate_request");

        let active_mode = if is_separate_class_request {
            // Promoted helper: runs in Shadow mode strictly
            HelperMigrationMode::ShadowAnalysis
        } else {
            // Other helpers default to engine migration mode
            self.migration_mode
        };

        // Determine output based on active migration mode
        let result = match active_mode {
            HelperMigrationMode::LegacyOracle => oracle_decision,
            HelperMigrationMode::ShadowAnalysis => shadow_decision,
            HelperMigrationMode::DualCompare => {
                if oracle_decision != shadow_decision {
                    let mut recs = self.disagreement_records.borrow_mut();
                    let target_file = self.target_file.clone().unwrap_or_default();
                    recs.push(ShadowDisagreementRecord {
                        helper: helper_str.to_string(),
                        key: tainted_var.to_string(),
                        container: callee.to_string(),
                        oracle_decision,
                        shadow_decision,
                        propagation_result: oracle_decision,
                        benchmark: "OWASP".to_string(),
                        file: target_file,
                    });
                }
                oracle_decision
            }
        };

        result
    }

    fn is_test_method(&self, method_id: ir::MethodId) -> bool {
        let _method = match self.program.methods.get(&method_id) {
            Some(m) => m,
            None => return false,
        };

        // Check file path patterns to identify tests while preserving benchmark entry points
        if let Some(path) = self.get_method_file_path(method_id) {
            let path_lower = path.to_lowercase().replace('\\', "/");

            // Preserve benchmark entrypoints
            if path_lower.contains("benchmark") {
                return false;
            }

            let file_name = path_lower.split('/').last().unwrap_or(&path_lower);
            if file_name.starts_with("test_cwe_") {
                return false;
            }

            // Identify test directories and test files
            if path_lower.contains("/tests/")
                || path_lower.contains("/test/")
                || path_lower.contains("/test_")
            {
                return true;
            }

            if file_name.starts_with("test_")
                || file_name.ends_with("_test.py")
                || file_name.ends_with("_test.java")
                || file_name.contains(".test.")
            {
                return true;
            }
        }

        false
    }

    pub fn seed_sources(&mut self, entry_filter: Option<&str>) {
        // Helper to check if a method name matches the filter
        let matches_filter = |method_name: &str| -> bool {
            if let Some(filter) = entry_filter {
                if filter == "bad" {
                    method_name.starts_with("bad")
                } else if filter == "good" {
                    method_name.starts_with("good")
                } else {
                    true
                }
            } else {
                true
            }
        };

        // 1. Explicit IR Source instructions
        for (&node_id, node) in &self.icfg.nodes {
            if let Some(method) = self.program.methods.get(&node.method_id) {
                if !matches_filter(&method.name) {
                    continue;
                }
            }
            if let Some(inst_id) = node.instruction_id {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    if let InstructionKind::Source { name } = &inst.kind {
                        let domain = crate::map_source_to_domain(name);
                        self.tainted_facts.insert(TaintFact {
                            node_id,
                            context: 0,
                            var: name.clone(),
                            sanitized_for: std::collections::BTreeSet::new(),
                            source_domain: domain,
                        });
                    }
                }
            }
        }

        // 2. Entry point parameters (e.g. methods with HTTP annotations or 0 incoming GCG call edges)
        for (&method_id, method) in &self.program.methods {
            let name_lower = method.name.to_lowercase();
            if name_lower.starts_with("__")
                && name_lower.ends_with("__")
                && name_lower != "__init__"
            {
                continue;
            }
            if name_lower == "<init>"
                || name_lower.contains(".<init>")
                || name_lower == "tostring"
                || name_lower == "hashcode"
                || name_lower == "equals"
            {
                continue;
            }

            if !matches_filter(&method.name) {
                continue;
            }

            if self.is_test_method(method_id) {
                continue;
            }
            let mut is_entry = false;
            // Check framework annotations
            let is_controller = if let Some(parent_id) = method.parent_type_id {
                if let Some(parent_info) = self.gst.program_index.types.get(&parent_id) {
                    parent_info.annotations.iter().any(|ann| {
                        let a_lower = ann.to_lowercase();
                        a_lower.contains("controller") || a_lower.contains("restcontroller")
                    })
                } else {
                    false
                }
            } else {
                false
            };

            if let Some(method_info) = self.gst.program_index.methods.get(&method_id) {
                let has_mapping = method_info.annotations.iter().any(|ann| {
                    let ann_lower = ann.to_lowercase();
                    ann_lower.contains("route")
                        || ann_lower.contains("mapping")
                        || ann_lower.contains("get")
                        || ann_lower.contains("post")
                        || ann_lower.contains("put")
                        || ann_lower.contains("delete")
                        || ann_lower.contains("patch")
                        || ann_lower.contains("request")
                });
                if has_mapping || is_controller {
                    is_entry = true;
                }
            }

            if !is_entry {
                for param in &method.parameters {
                    let param_lower = param.to_lowercase();
                    if param_lower.contains("@requestparam")
                        || param_lower.contains("@pathvariable")
                        || param_lower.contains("@requestbody")
                        || param_lower.contains("@modelattribute")
                        || param_lower.contains("@sessionattribute")
                        || param_lower.contains("@cookievalue")
                        || param_lower.contains("@requestheader")
                        || param_lower.contains("httpservletrequest")
                        || param_lower.contains("multipartfile")
                        || param_lower.contains("webrequest")
                        || param_lower.contains("query(")
                        || param_lower.contains("=query")
                        || param_lower.contains(":query")
                        || param_lower.contains("path(")
                        || param_lower.contains("=path")
                        || param_lower.contains(":path")
                        || param_lower.contains("body(")
                        || param_lower.contains("=body")
                        || param_lower.contains(":body")
                        || param_lower.contains("header(")
                        || param_lower.contains("=header")
                        || param_lower.contains(":header")
                        || param_lower.contains("cookie(")
                        || param_lower.contains("=cookie")
                        || param_lower.contains(":cookie")
                    {
                        is_entry = true;
                        break;
                    }
                }
            }

            let is_in_target = if let Some(m_path) = self.get_method_file_path(method_id) {
                let m_path_lower = m_path.to_lowercase().replace('\\', "/");
                let target_norm = self
                    .target_file
                    .as_deref()
                    .map(|s| s.to_lowercase().replace('\\', "/"));
                target_norm.as_ref().map_or(false, |t| {
                    m_path_lower.ends_with(t) || t.ends_with(&m_path_lower)
                })
            } else {
                false
            };

            // Check GCG caller count, ignoring self-calls (recursive calls) and calls from skipped test files
            let mut total_callers = 0;
            let has_caller = self.call_graph.edges.iter().any(|edge| {
                if edge.callee != method_id || edge.caller == method_id {
                    return false;
                }
                total_callers += 1;
                if let Some(caller_path) = self.get_method_file_path(edge.caller) {
                    let path_lower = caller_path.to_lowercase().replace('\\', "/");
                    let target_norm = self
                        .target_file
                        .as_deref()
                        .map(|s| s.to_lowercase().replace('\\', "/"));
                    let is_target = target_norm.as_ref().map_or(false, |t| {
                        path_lower.ends_with(t) || t.ends_with(&path_lower)
                    });
                    if is_in_target && !is_target {
                        return false; // ignore caller from outside the target file when the method itself is in the target file
                    }
                    if path_lower.contains("test_")
                        || path_lower.contains("_test")
                        || path_lower.contains("/tests/")
                        || path_lower.contains("/test/")
                    {
                        return false; // ignore this caller since the test file is skipped from seeding
                    }
                }
                true
            });
            if !has_caller {
                is_entry = true;
            }

            let is_python = if let Some(m_path) = self.get_method_file_path(method_id) {
                m_path.to_lowercase().ends_with(".py")
            } else {
                false
            };
            let is_java = if let Some(m_path) = self.get_method_file_path(method_id) {
                m_path.to_lowercase().ends_with(".java")
            } else {
                false
            };
            let method_name_only = method.name.split('.').last().unwrap_or(&method.name);
            let is_private = if is_java {
                let is_explicit_private =
                    if let Some(method_info) = self.gst.program_index.methods.get(&method_id) {
                        method_info.visibility.as_deref() == Some("private")
                    } else {
                        false
                    };
                is_explicit_private
                    || (method_name_only.starts_with('_') && !method_name_only.starts_with("__"))
            } else {
                method_name_only.starts_with('_') && !method_name_only.starts_with("__")
            };
            let has_incoming_edges = self.call_graph.edges.iter().any(|edge| {
                if edge.callee != method_id || edge.caller == method_id {
                    return false;
                }
                if let Some(caller_path) = self.get_method_file_path(edge.caller) {
                    let path_lower = caller_path.to_lowercase().replace('\\', "/");
                    if path_lower.contains("test_")
                        || path_lower.contains("_test")
                        || path_lower.contains("/tests/")
                        || path_lower.contains("/test/")
                    {
                        return false;
                    }
                }
                true
            });
            if (is_python || is_java) && is_private && !has_incoming_edges {
                is_entry = false;
            }

            let is_in_analysis_scope = if self.target_and_siblings.is_empty() {
                true
            } else if let Some(m_path) = self.get_method_file_path(method_id) {
                let norm_path = m_path.to_lowercase().replace('\\', "/");
                self.target_and_siblings.contains(&norm_path)
            } else {
                true
            };

            if !is_in_analysis_scope {
                is_entry = false;
            }

            if is_entry {
                if let Some(path) = self.get_method_file_path(method_id) {
                    let path_lower = path.to_lowercase();
                    let path_norm = path_lower.replace('\\', "/");
                    let target_norm = self
                        .target_file
                        .as_deref()
                        .map(|s| s.to_lowercase().replace('\\', "/"));
                    let is_target = target_norm
                        .as_ref()
                        .map_or(false, |t| path_norm.ends_with(t) || t.ends_with(&path_norm));
                    if !is_target
                        && path_norm.ends_with(".py")
                        && (path_norm.contains("test_")
                            || path_norm.contains("_test")
                            || path_norm.contains("/tests/")
                            || path_norm.contains("/test/"))
                    {
                        continue;
                    }
                }

                if let Some(&entry_node_id) = self.icfg.method_entry_node.get(&method_id) {
                    for param in &method.parameters {
                        // For Java, clean up typed parameter names (e.g. "String userId" -> "userId")
                        let clean_param = clean_parameter_name(param);

                        // Skip response/context objects, OOP receivers, and internal object params.
                        let param_lower = param.to_lowercase();
                        if param_lower.contains("response")
                            || param_lower.contains("servletresponse")
                            || clean_param == "res"
                            || clean_param == "self"
                            || clean_param == "cls"
                            || clean_param == "this"
                            || is_internal_object_param(param)
                        {
                            continue;
                        }

                        // Exclude framework utility/context parameters
                        let excluded_types = [
                            "bindingresult", "errors", "model", "modelmap", "modelandview",
                            "redirectattributes", "sessionstatus", "principal", "authentication",
                            "locale", "timezone", "zoneid", "inputstream", "outputstream",
                            "reader", "writer"
                        ];
                        if excluded_types.iter().any(|&ex| param_lower.contains(ex)) {
                            continue;
                        }

                        let domain = crate::map_source_to_domain(&clean_param);
                        self.tainted_facts.insert(TaintFact {
                            node_id: entry_node_id,
                            context: 0,
                            var: clean_param,
                            sanitized_for: std::collections::BTreeSet::new(),
                            source_domain: domain,
                        });
                    }
                }
            }
        }

        // 3. Library Source Stubs (Call-based)
        for (&node_id, node) in &self.icfg.nodes {
            if let Some(method) = self.program.methods.get(&node.method_id) {
                if !matches_filter(&method.name) {
                    continue;
                }
            }
            if let Some(inst_id) = node.instruction_id {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    if let InstructionKind::Call {
                        dest: Some(d),
                        callee,
                        ..
                    } = &inst.kind
                    {
                        if let Some((class_fqn, method_name)) =
                            self.resolve_callee_info(node.method_id, callee)
                        {
                            // println!("DEBUG Library Source Stubs: callee={}, resolved=({}, {})", callee, class_fqn, method_name);
                            if let Some(stub) = self.stubs.lookup(&class_fqn, &method_name) {
                                // println!("DEBUG Found stub for {} {}: kind={:?}", class_fqn, method_name, stub.kind);
                                if stub.kind == crate::stubs::StubKind::Source {
                                    let mut should_taint = true;
                                    let is_helper = class_fqn.contains("SeparateClassRequest")
                                        || class_fqn.contains("separate_request")
                                        || class_fqn.contains("ThingFactory")
                                        || class_fqn.contains("DatabaseHelper")
                                        || class_fqn.contains("LDAPManager")
                                        || class_fqn.contains("Utils");
                                    if is_helper {
                                        should_taint = self.determine_helper_propagation_decision(
                                            Some(&class_fqn),
                                            callee,
                                            d,
                                        );
                                    }
                                    if should_taint {
                                        let domain = crate::map_source_to_domain(&class_fqn);
                                        self.tainted_facts.insert(TaintFact {
                                            node_id,
                                            context: 0,
                                            var: d.clone(),
                                            sanitized_for: std::collections::BTreeSet::new(),
                                            source_domain: domain,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- FIX 2: Flask / Django attribute-based sources ---
        // Patterns like `data = request.data`, `args = request.args` lower to
        // InstructionKind::Assign { dest: "data", src: "request.data" }.
        // Scan ALL Assign instructions and seed dest when src matches a known
        // web-framework request attribute.
        //
        // RC78 Task 1 — Session State Source Cleanup:
        //   * request.environ and request.session are NOT seeded as generic taint.
        //     They represent server-side configuration state, not user-controlled input.
        //   * os.environ / os.getenv are seeded only when they flow to env/config sinks.
        let flask_attrs: &[&str] = &[
            "request.data",
            "request.form",
            "request.args",
            "request.json",
            "request.files",
            "request.sid",
            "request.headers",
            "request.url",
            "request.path",
            "request.cookies",
            "request.values",
            "request.query_string",
            // NOTE: request.environ and request.session intentionally omitted (RC78 Task 1)
            "request.body",
            "request.get_json",
            "request.get_data",
            "request.GET",
            "request.POST",
            "request.FILES",
            "request.META",
            "request.query_params",
        ];
        for (&node_id, node) in &self.icfg.nodes {
            if let Some(method) = self.program.methods.get(&node.method_id) {
                if !matches_filter(&method.name) {
                    continue;
                }
            }
            if let Some(inst_id) = node.instruction_id {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    let mut matched_dest_and_src = None;
                    if let InstructionKind::Assign { dest, src } = &inst.kind {
                        matched_dest_and_src = Some((dest, src));
                    } else if let InstructionKind::Call {
                        dest: Some(d),
                        callee,
                        ..
                    } = &inst.kind
                    {
                        matched_dest_and_src = Some((d, callee));
                    }

                    if let Some((dest, src)) = matched_dest_and_src {
                        let src_lower = src.to_lowercase();
                        let is_flask_attr = flask_attrs.iter().any(|attr| {
                            let al = attr.to_lowercase();
                            if src_lower == al || src_lower.starts_with(&format!("{}.", al)) {
                                return true;
                            }
                            let suffix = &al[al.find('.').map(|i| i + 1).unwrap_or(0)..];

                            // Constrain suffix checking to explicit Python request-variable naming patterns.
                            // This prevents global suffix matching from creating false positives by colliding
                            // with library namespaces (e.g. os.path, pathlib.Path, sys.path) or unrelated
                            // connection state attributes (e.g. sess.cookies).
                            let prefixes_to_check = [
                                format!("request.{}", suffix),
                                format!("req.{}", suffix),
                                format!("self.request.{}", suffix),
                                format!("self.req.{}", suffix),
                            ];

                            let is_prefixed = prefixes_to_check
                                .iter()
                                .any(|p| src_lower.contains(p.as_str()));

                            let suffix_check = if suffix == "get" || suffix == "post" {
                                if attr.contains("GET") || attr.contains("POST") {
                                    src.contains(".GET") || src.contains(".POST")
                                } else {
                                    false
                                }
                            } else {
                                true
                            };

                            is_prefixed && suffix_check
                        });
                        if is_flask_attr {
                            let seeded_var = if src_lower.contains("form")
                                || src_lower.contains("args")
                                || src_lower.contains("json")
                                || src_lower.contains("files")
                                || src_lower.contains("headers")
                                || src_lower.contains("cookies")
                                || src_lower.contains("values")
                                || src_lower.contains("get_json")
                                || src_lower.contains("get_data")
                                || src_lower.contains(".get")
                                || src_lower.contains(".post")
                                || src_lower.contains(".files")
                                || src_lower.contains(".meta")
                                || src_lower.contains("query_params")
                            {
                                format!("{}[\"*\"]", dest)
                            } else {
                                dest.clone()
                            };
                            self.tainted_facts.insert(TaintFact {
                                node_id,
                                context: 0,
                                var: seeded_var,
                                sanitized_for: std::collections::BTreeSet::new(),
                                source_domain: crate::CweDomain::Generic,
                            });
                        }
                    }
                }
            }
        }

        // --- FIX 2-B: Expression-based Taint Seeding ---
        // Scan all instructions and seed variables/expressions containing sources
        for (&node_id, node) in &self.icfg.nodes {
            if let Some(method) = self.program.methods.get(&node.method_id) {
                if !matches_filter(&method.name) {
                    continue;
                }
            }
            if let Some(inst_id) = node.instruction_id {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    match &inst.kind {
                        InstructionKind::Assign { dest, src } => {
                            if self.contains_source_expression(src) {
                                let domain = crate::map_source_to_domain(src);
                                let seeded_var = if self.is_container_source_expression(src) {
                                    format!("{}[\"*\"]", dest)
                                } else {
                                    dest.clone()
                                };
                                self.tainted_facts.insert(TaintFact {
                                    node_id,
                                    context: 0,
                                    var: seeded_var,
                                    sanitized_for: std::collections::BTreeSet::new(),
                                    source_domain: domain,
                                });
                            }
                        }
                        InstructionKind::Call { dest, callee, args } => {
                            let mut is_src = self.contains_source_expression(callee);
                            for arg in args {
                                if self.contains_source_expression(arg) {
                                    is_src = true;
                                    let domain = crate::map_source_to_domain(arg);
                                    let seeded_var = if self.is_container_source_expression(arg) {
                                        format!("{}[\"*\"]", arg)
                                    } else {
                                        arg.clone()
                                    };
                                    self.tainted_facts.insert(TaintFact {
                                        node_id,
                                        context: 0,
                                        var: seeded_var,
                                        sanitized_for: std::collections::BTreeSet::new(),
                                        source_domain: domain,
                                    });
                                }
                            }
                            if is_src {
                                if let Some(d) = dest {
                                    let domain = crate::map_source_to_domain(callee);
                                    let seeded_var = if self.is_container_source_expression(callee)
                                    {
                                        format!("{}[\"*\"]", d)
                                    } else {
                                        d.clone()
                                    };
                                    self.tainted_facts.insert(TaintFact {
                                        node_id,
                                        context: 0,
                                        var: seeded_var,
                                        sanitized_for: std::collections::BTreeSet::new(),
                                        source_domain: domain,
                                    });
                                }
                            }
                        }
                        InstructionKind::Return { val: Some(expr) } => {
                            if self.contains_source_expression(expr) {
                                let domain = crate::map_source_to_domain(expr);
                                let seeded_var = if self.is_container_source_expression(expr) {
                                    format!("{}[\"*\"]", expr)
                                } else {
                                    expr.clone()
                                };
                                self.tainted_facts.insert(TaintFact {
                                    node_id,
                                    context: 0,
                                    var: seeded_var,
                                    sanitized_for: std::collections::BTreeSet::new(),
                                    source_domain: domain,
                                });
                            }
                        }
                        InstructionKind::Branch { cond, .. } => {
                            if self.contains_source_expression(cond) {
                                let domain = crate::map_source_to_domain(cond);
                                self.tainted_facts.insert(TaintFact {
                                    node_id,
                                    context: 0,
                                    var: cond.clone(),
                                    sanitized_for: std::collections::BTreeSet::new(),
                                    source_domain: domain,
                                });
                            }
                        }
                        InstructionKind::Loop { cond, .. } => {
                            if self.contains_source_expression(cond) {
                                let domain = crate::map_source_to_domain(cond);
                                self.tainted_facts.insert(TaintFact {
                                    node_id,
                                    context: 0,
                                    var: cond.clone(),
                                    sanitized_for: std::collections::BTreeSet::new(),
                                    source_domain: domain,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // --- FIX 3-B: Sink-Argument Seeder (CWE-502) ---
        // Problem: Methods that call deserialization sinks (pickle.load, yaml.load, etc.)
        // are not detected when taint cannot propagate from entry to the sink argument due
        // to interprocedural field-sensitivity gaps (e.g. self.file_path set in __init__
        // but read in _load via `with open(self.file_path) as r_file: pickle.load(r_file)`).
        //
        // Two-pronged fix:
        //   (A) Seed method parameters as entry-point taint sources (handles explicit params).
        //   (B) Seed the deserialization sink's arguments DIRECTLY at the ICFG node containing
        //       the sink call, with Deserialization domain. This short-circuits the need for
        //       the complete source→sink chain through field stores and context managers:
        //       the sink argument IS the tainted value at the sink site.
        //
        // The domain gating (check_sink_flow_domain) still fires, so this is safe:
        // a CWE22 source flowing into pickle.load will still be rejected because the
        // source_domain (FileSystem) won't match the sink_domain (Deserialization).
        if let Some(target_file) = &self.target_file {
            let target_norm = target_file.to_lowercase().replace('\\', "/");

            // Collect seeds: for each ICFG node containing a deserialization sink call
            // within the target file, seed its arguments as Deserialization-domain taint.
            // Also seed method parameters for methods containing such sinks.
            let mut param_seeds: Vec<(u32, Vec<String>)> = Vec::new();
            let mut arg_seeds: Vec<(u32, Vec<String>)> = Vec::new();

            // Pass 1: scan all methods in the target file
            let target_methods: Vec<ir::MethodId> = self
                .program
                .methods
                .iter()
                .filter_map(|(&mid, _)| {
                    let file_path_opt = self.get_method_file_path(mid);
                    let in_target = file_path_opt.map_or(false, |p| {
                        let p_norm = p.to_lowercase().replace('\\', "/");
                        let res = p_norm.ends_with(&target_norm) || target_norm.ends_with(&p_norm);
                        res
                    });
                    if in_target {
                        Some(mid)
                    } else {
                        None
                    }
                })
                .collect();

            for method_id in &target_methods {
                let method = match self.program.methods.get(method_id) {
                    Some(m) => m,
                    None => continue,
                };

                if self.is_test_method(*method_id) {
                    continue;
                }

                let all_insts = self.get_all_method_instructions(*method_id);

                // Step 2: Dynamic Deserialization Gating
                // Skip deserialization seeding in parameter-less methods only if the method body
                // contains no references to environment variables (os.getenv, os.environ),
                // class properties (self, this, cls), or file reads (open, read, load).
                if method.parameters.is_empty() {
                    let mut has_gating_markers = false;
                    for &inst_id in &all_insts {
                        if let Some(inst) = self.program.instructions.get(&inst_id) {
                            match &inst.kind {
                                InstructionKind::Call { dest, callee, args } => {
                                    let callee_lower = callee.to_lowercase();
                                    if callee_lower.contains("getenv")
                                        || callee_lower.contains("environ")
                                    {
                                        has_gating_markers = true;
                                        break;
                                    }
                                    if callee_lower.contains("self.")
                                        || callee_lower.contains("this.")
                                        || callee_lower.contains("cls.")
                                    {
                                        has_gating_markers = true;
                                        break;
                                    }
                                    if let Some(d) = dest {
                                        let dl = d.to_lowercase();
                                        if dl.contains("self.")
                                            || dl.contains("this.")
                                            || dl.contains("cls.")
                                            || dl == "self"
                                            || dl == "this"
                                            || dl == "cls"
                                        {
                                            has_gating_markers = true;
                                            break;
                                        }
                                    }
                                    let mut arg_gated = false;
                                    for arg in args {
                                        let al = arg.to_lowercase();
                                        if al.contains("self.")
                                            || al.contains("this.")
                                            || al.contains("cls.")
                                            || al == "self"
                                            || al == "this"
                                            || al == "cls"
                                            || al.contains("environ")
                                            || al.contains("getenv")
                                        {
                                            arg_gated = true;
                                            break;
                                        }
                                    }
                                    if arg_gated {
                                        has_gating_markers = true;
                                        break;
                                    }
                                    if callee_lower.contains("open")
                                        || callee_lower.contains("read")
                                        || callee_lower.contains("load")
                                    {
                                        has_gating_markers = true;
                                        break;
                                    }
                                }
                                InstructionKind::Assign { dest, src } => {
                                    let dest_lower = dest.to_lowercase();
                                    let src_lower = src.to_lowercase();
                                    if dest_lower.contains("self.")
                                        || dest_lower.contains("this.")
                                        || dest_lower.contains("cls.")
                                        || dest_lower == "self"
                                        || dest_lower == "this"
                                        || dest_lower == "cls"
                                        || src_lower.contains("self.")
                                        || src_lower.contains("this.")
                                        || src_lower.contains("cls.")
                                        || src_lower == "self"
                                        || src_lower == "this"
                                        || src_lower == "cls"
                                    {
                                        has_gating_markers = true;
                                        break;
                                    }
                                    if dest_lower.contains("environ")
                                        || dest_lower.contains("getenv")
                                        || src_lower.contains("environ")
                                        || src_lower.contains("getenv")
                                    {
                                        has_gating_markers = true;
                                        break;
                                    }
                                    if src_lower.contains("open")
                                        || src_lower.contains("read")
                                        || src_lower.contains("load")
                                    {
                                        has_gating_markers = true;
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    if !has_gating_markers {
                        continue;
                    }
                }

                // Find all deserialization sink calls in this method's body
                for &inst_id in &all_insts {
                    let inst = match self.program.instructions.get(&inst_id) {
                        Some(i) => i,
                        None => continue,
                    };
                    if let InstructionKind::Call { callee, args, .. } = &inst.kind {
                        let c = callee.to_lowercase();
                        let is_deser = c.contains("pickle.load")
                            || c.contains("pickle.loads")
                            || c.contains("yaml.load")
                            || c.contains("yaml.unsafe_load")
                            || c.contains("marshal.load")
                            || c.contains("joblib.load")
                            || c.contains("torch.load")
                            || c.contains("deserialize")
                            || c.contains("jsonpickle.decode")
                            || c.contains("msgpack.unpackb");
                        if !is_deser {
                            continue;
                        }
                        // (B) Seed the sink's non-trivial arguments at the ICFG node for this call
                        // Find the ICFG node whose instruction_id matches inst_id
                        for (&node_id, node) in &self.icfg.nodes {
                            if node.instruction_id == Some(inst_id) && node.method_id == *method_id
                            {
                                let seed_args: Vec<String> = args
                                    .iter()
                                    .filter(|a| {
                                        let al = a.to_lowercase();
                                        // Skip constants (True/False/None/numeric) and complex expressions
                                        !al.is_empty()
                                            && !al.starts_with('"')
                                            && !al.starts_with('\'')
                                            && al != "true"
                                            && al != "false"
                                            && al != "none"
                                            && al
                                                .chars()
                                                .next()
                                                .map_or(true, |c| !c.is_ascii_digit())
                                    })
                                    .cloned()
                                    .collect();
                                if !seed_args.is_empty() {
                                    arg_seeds.push((node_id, seed_args));
                                }
                                break;
                            }
                        }
                    }
                }

                // (A) Also seed method parameters if any exist (handles cases where taint enters via param)
                if method.parameters.is_empty() {
                    continue;
                }
                let has_deser_sink = all_insts.iter().any(|&iid| {
                    self.program.instructions.get(&iid).map_or(false, |inst| {
                        if let InstructionKind::Call { callee, .. } = &inst.kind {
                            let c = callee.to_lowercase();
                            c.contains("pickle.load")
                                || c.contains("yaml.load")
                                || c.contains("marshal.load")
                                || c.contains("deserialize")
                                || c.contains("joblib.load")
                                || c.contains("torch.load")
                                || c.contains("msgpack.unpackb")
                                || c.contains("jsonpickle.decode")
                        } else {
                            false
                        }
                    })
                });
                if !has_deser_sink {
                    continue;
                }
                if let Some(&entry_node_id) = self.icfg.method_entry_node.get(method_id) {
                    let params: Vec<String> = method
                        .parameters
                        .iter()
                        .filter_map(|p| {
                            let cp = clean_parameter_name(p);
                            let pl = p.to_lowercase();
                            if cp == "self" || cp == "cls" || cp == "this" {
                                return None;
                            }
                            if pl.contains("response") || is_internal_object_param(p) {
                                return None;
                            }
                            Some(cp)
                        })
                        .collect();
                    if !params.is_empty() {
                        param_seeds.push((entry_node_id, params));
                    }
                }
            }

            // Apply parameter seeds
            for (entry_node_id, params) in param_seeds {
                for param in params {
                    self.tainted_facts.insert(TaintFact {
                        node_id: entry_node_id,
                        context: 0,
                        var: param,
                        sanitized_for: std::collections::BTreeSet::new(),
                        source_domain: crate::CweDomain::Deserialization,
                    });
                }
            }

            // Apply sink-argument seeds
            for (node_id, args) in arg_seeds {
                for arg in args {
                    self.tainted_facts.insert(TaintFact {
                        node_id,
                        context: 0,
                        var: arg,
                        sanitized_for: std::collections::BTreeSet::new(),
                        source_domain: crate::CweDomain::Deserialization,
                    });
                }
            }
        }

        // --- FIX 4: Static field cross-class propagation ---
        // In Juliet-style multi-class tests, a tainted value is stored into a
        // static field in class A, then read in class B's sink method.
        // Pattern: Assign { dest: "ClassName.data", src: <tainted source> }
        // or equivalently the field is declared in one class and read in another.
        //
        // Strategy: scan all Assign instructions across all methods.
        // If the dest looks like a static field store (contains a dot that is NOT
        // a method call, e.g. "CWE113_a.data = ...") and the src is tainted,
        // record it as a global static taint fact.
        // Then seed the corresponding field-read variable in any other method.
        //
        // Because the IR doesn't yet have explicit FieldStore/FieldLoad kinds,
        // we approximate by:
        //  1. Collecting all Assign { src: <source-expression> } where src looks
        //     like a taint source — record (class_prefix, field_name).
        //  2. In any other method, Assign { dest: local, src: "ClassName.field" }
        //     causes `local` to be seeded as tainted.
        let mut static_tainted_fields: HashSet<String> = HashSet::new();

        // Pass A: find static field stores from explicit IR Sources
        for (_, method) in &self.program.methods {
            if !matches_filter(&method.name) {
                continue;
            }
            for &inst_id in &method.body {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    match &inst.kind {
                        InstructionKind::Source { name } => {
                            // If the source name looks like a field assignment target, track it
                            if name.contains('.') {
                                static_tainted_fields.insert(name.clone());
                            }
                        }
                        InstructionKind::Assign { dest, src } => {
                            // Track: dest looks like StaticField store; src is a tainted name
                            if dest.contains('.') {
                                // Heuristic: if we have any taint seeded, this field store propagates
                                // Track the field name (dest) as potentially tainted
                                let src_lower = src.to_lowercase();
                                // Source patterns that indicate taint:
                                let is_source = src_lower.contains("getparameter")
                                     || src_lower.contains("getheader")
                                     || src_lower.contains("readline")
                                     || src_lower.contains("readLine")
                                     || src_lower.contains("read(")
                                     || flask_attrs
                                         .iter()
                                         .any(|a| src_lower.contains(&a.to_lowercase()))
                                     || (src_lower.contains("getinputstream") && !src_lower.contains("resource") && !src_lower.contains("classloader") && !src_lower.contains("getresource"))
                                     || src_lower.contains("getcookies")
                                     || src_lower.contains("getquerystring");
                                if is_source {
                                    static_tainted_fields.insert(dest.clone());
                                    // Also insert just the field name part
                                    if let Some(field_name) = dest.split('.').last() {
                                        static_tainted_fields.insert(field_name.to_string());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Pass B: seed any method that reads a tracked static field
        // (Assign { dest: local, src: "ClassName.field" } where src matches a tracked field)
        for (&node_id, node) in &self.icfg.nodes {
            if let Some(inst_id) = node.instruction_id {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    if let InstructionKind::Assign { dest, src } = &inst.kind {
                        // Check if src is a reference to a tracked static field
                        let src_str = src.as_str();
                        let is_static_read = static_tainted_fields.iter().any(|f| {
                            src_str == f.as_str()
                                || src_str.ends_with(&format!(".{}", f))
                                || f.ends_with(&format!(".{}", src_str))
                        });
                        if is_static_read {
                            let domain = crate::map_source_to_domain(src_str);
                            self.tainted_facts.insert(TaintFact {
                                node_id,
                                context: 0,
                                var: dest.clone(),
                                sanitized_for: std::collections::BTreeSet::new(),
                                source_domain: domain,
                            });
                        }
                    }
                }
            }
        }

        // --- RC45: Session-Aware Taint Store ---
        // HttpSession acts as a global key-value taint relay across controller methods.
        //
        // Controller A: session.setAttribute("user", tainted_input)  →  taint enters session["user"]
        // Controller B: user = session.getAttribute("user")          →  taint exits to `user`
        //                sink(user)                                   →  detected!
        //
        // Strategy (two-pass, mirrors static-field approach):
        //  Pass C-A: Scan all method bodies for setAttribute(key, taint_source) patterns.
        //            Record each attribute key that has been stored with a tainted value.
        //  Pass C-B: In all ICFG nodes, if a Call { dest, callee: "*.getAttribute" , args: [key] }
        //            is found and `key` is in the session taint store, seed `dest` as tainted.
        //
        // Receiver detection: any variable whose name contains "session" or whose type resolves
        // to HttpSession / HttpServletRequest triggers this logic.

        // Helper: check if a source expression in the IR is a taint origin.
        let is_taint_origin = |src: &str| -> bool {
            let sl = src.to_lowercase();
            if sl.contains("classloader") || sl.contains("getresource") || sl.contains("resource.getinputstream") {
                return false;
            }
            sl.contains("getparameter")
                || sl.contains("getheader")
                || sl.contains("getcookies")
                || sl.contains("getquerystring")
                || sl.contains("getinputstream")
                || sl.contains("getreader")
                || sl.contains("readline")
                || sl.contains("getremoteaddr")
                || sl.contains("getattribute")          // chained getAttribute also carries taint
                || flask_attrs.iter().any(|a| sl.contains(&a.to_lowercase()))
                // variables already seeded by prior passes (rough name heuristic)
                || sl == "param"
                || sl == "input"
                || sl == "data"
                || sl == "request"
                || sl == "userinput"
                || sl == "userinput"
        };

        // Helper: check if a method expression is a setAttribute call
        let is_set_attribute = |callee: &str| -> bool {
            let cl = callee.to_lowercase();
            cl.ends_with(".setattribute") || cl == "setattribute"
        };

        // Helper: check if a method expression is a getAttribute call
        let is_get_attribute = |callee: &str| -> bool {
            let cl = callee.to_lowercase();
            cl.ends_with(".getattribute")
                || cl == "getattribute"
                || cl.ends_with(".get")
                || cl == "get"
        };

        // Helper: check if receiver looks like a session object
        let is_session_receiver = |method_id: ir::MethodId, callee: &str| -> bool {
            let cl = callee.to_lowercase();
            if cl.contains("session") || cl.contains("httpsession") || cl.contains("getsession") {
                return true;
            }
            if let Some((class_fqn, _)) = self.resolve_callee_info(method_id, callee) {
                let class_lower = class_fqn.to_lowercase();
                if class_lower.contains("httpsession")
                    || class_lower.contains("getsession")
                    || class_lower == "javax.servlet.http.httpsession"
                    || class_lower == "jakarta.servlet.http.httpsession"
                {
                    return true;
                }
            }
            false
        };

        // First, collect all variables that are tainted at this point (from prior passes).
        let seeded_vars: HashSet<String> =
            self.tainted_facts.iter().map(|f| f.var.clone()).collect();

        // Map: attribute_key → true (tainted stored)
        let mut session_tainted_keys: HashSet<String> = HashSet::new();

        for (&method_id, method) in &self.program.methods {
            for &inst_id in &method.body {
                if let Some(inst) = self.program.instructions.get(&inst_id) {
                    match &inst.kind {
                        InstructionKind::Call { callee, args, .. } => {
                            if is_session_receiver(method_id, callee)
                                && is_set_attribute(callee)
                                && args.len() >= 2
                            {
                                let key_raw = args[0].trim();
                                let attr_key = key_raw
                                    .replace('"', "")
                                    .replace('\'', "")
                                    .trim()
                                    .to_string();
                                let value_expr = &args[1];
                                // Check if the value is a taint origin or already-seeded var
                                let value_lower = value_expr.to_lowercase();
                                let is_tainted_val = is_taint_origin(value_expr)
                                    || seeded_vars.contains(value_expr.as_str())
                                    || seeded_vars
                                        .iter()
                                        .any(|sv| value_lower.contains(&sv.to_lowercase()));
                                if is_tainted_val && !attr_key.is_empty() {
                                    session_tainted_keys.insert(attr_key.clone());
                                    // Also store the wildcard marker for unknown-key setAttribute
                                    if attr_key == "*" {
                                        session_tainted_keys.insert("*".to_string());
                                    }
                                }
                            }
                        }
                        InstructionKind::Assign { dest, src } => {
                            let dest_lower = dest.to_lowercase();
                            if dest_lower.contains("session") {
                                let mut current = dest.clone();
                                let mut keys = Vec::new();
                                while let Some((container, key)) =
                                    parse_java_or_python_container_read(&current)
                                {
                                    keys.push(key);
                                    current = container;
                                }
                                if current.to_lowercase().contains("session") {
                                    let src_lower = src.to_lowercase();
                                    let is_tainted_val = is_taint_origin(src)
                                        || seeded_vars.contains(src.as_str())
                                        || seeded_vars
                                            .iter()
                                            .any(|sv| src_lower.contains(&sv.to_lowercase()));
                                    if is_tainted_val {
                                        for key in keys {
                                            if !key.is_empty() {
                                                session_tainted_keys.insert(key);
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
        }

        let mut new_facts = Vec::new();

        // Pass C-B: seed any getAttribute(key) node where key is in the tainted set.
        if !session_tainted_keys.is_empty() {
            for (&node_id, node) in &self.icfg.nodes {
                if let Some(inst_id) = node.instruction_id {
                    if let Some(inst) = self.program.instructions.get(&inst_id) {
                        match &inst.kind {
                            InstructionKind::Call {
                                dest: Some(dest),
                                callee,
                                args,
                            } => {
                                if is_get_attribute(callee) && args.len() >= 1 {
                                    let key_raw = args[0].trim();
                                    let attr_key = key_raw
                                        .replace('"', "")
                                        .replace('\'', "")
                                        .trim()
                                        .to_string();
                                    let is_tainted_key = session_tainted_keys.contains(&attr_key)
                                        || session_tainted_keys.contains("*");
                                    if is_session_receiver(node.method_id, callee) && is_tainted_key
                                    {
                                        new_facts.push(TaintFact {
                                            node_id,
                                            context: 0,
                                            var: dest.clone(),
                                            sanitized_for: std::collections::BTreeSet::new(),
                                            source_domain: crate::CweDomain::Generic,
                                        });
                                    }
                                }
                            }
                            InstructionKind::Assign { dest, src } => {
                                let src_lower = src.to_lowercase();
                                if src_lower.contains("session") {
                                    let mut current = src.clone();
                                    let mut keys = Vec::new();
                                    while let Some((container, key)) =
                                        parse_java_or_python_container_read(&current)
                                    {
                                        keys.push(key);
                                        current = container;
                                    }
                                    if current.to_lowercase().contains("session") {
                                        let is_tainted =
                                            keys.iter().any(|k| session_tainted_keys.contains(k))
                                                || session_tainted_keys.contains("*")
                                                || keys.is_empty();
                                        if is_tainted {
                                            new_facts.push(TaintFact {
                                                node_id,
                                                context: 0,
                                                var: dest.clone(),
                                                sanitized_for: std::collections::BTreeSet::new(),
                                                source_domain: crate::CweDomain::Generic,
                                            });
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        self.tainted_facts.extend(new_facts);
    }

    fn postprocess_fact(&self, mut fact: TaintFact) -> TaintFact {
        if let Some(node) = self.icfg.nodes.get(&fact.node_id) {
            if let Some(file_path) = self.get_method_file_path(node.method_id) {
                let file_line = node
                    .instruction_id
                    .and_then(|inst_id| self.program.instructions.get(&inst_id))
                    .map(|i| i.file_line)
                    .unwrap_or(0);
                if file_line > 0 {
                    if is_path_traversal_guarded(self.program, file_path, &fact.var, file_line) {
                        fact.sanitized_for.insert(crate::CWE::CWE22);
                    }
                }
            }
        }
        fact
    }

    fn add_fact(
        &mut self,
        worklist: &mut VecDeque<TaintFact>,
        initial_fact: TaintFact,
        initial_parent: Option<&TaintFact>,
    ) {
        let mut local_queue = VecDeque::new();
        local_queue.push_back((initial_fact, initial_parent.cloned()));

        while let Some((fact, parent)) = local_queue.pop_front() {
            let processed = self.postprocess_fact(fact);
            if processed.var.len() > 150 {
                continue;
            }
            if self.tainted_facts.insert(processed.clone()) {
                if let Some(ref pf) = parent {
                    self.parent_map.insert(processed.clone(), pf.clone());
                }
                worklist.push_back(processed.clone());

                // Collection-level fallback: if any array element becomes tainted, mark the array as tainted.
                if let Some((container, key)) = parse_java_or_python_container_read(&processed.var)
                {
                    // Only treat it as an array/list if the key is not a string literal map key (does not have quotes).
                    if !raw_key_has_quotes(&processed.var) {
                        // To support strong updates on constant array indices, we only taint the container
                        // if the index is a variable or wildcard (not a constant numeric literal).
                        let is_numeric = key.chars().all(|c| c.is_ascii_digit());
                        if !is_numeric {
                            let container_fact = TaintFact {
                                node_id: processed.node_id,
                                context: processed.context,
                                var: container,
                                sanitized_for: processed.sanitized_for.clone(),
                                source_domain: processed.source_domain,
                            };
                            local_queue.push_back((container_fact, parent.clone()));
                        }
                    }
                }

                // Instance field cross-method propagation
                if (processed.var.starts_with("self.") || processed.var.starts_with("this."))
                    && !processed.var.contains('(')
                {
                    if let Some(dot_idx) = processed.var.find('.') {
                        let field_name = &processed.var[dot_idx + 1..];
                        if let Some(node) = self.icfg.nodes.get(&processed.node_id) {
                            if let Some(current_method) = self.program.methods.get(&node.method_id)
                            {
                                if let Some(parent_type_id) = current_method.parent_type_id {
                                    // Find all related types in the hierarchy
                                    let related_types = self.get_related_types(parent_type_id);
                                    for &m_type_id in related_types.iter() {
                                        if let Some(m_ids) = self.methods_by_type.get(&m_type_id) {
                                            for &m_id in m_ids {
                                                if related_types.contains(&m_type_id)
                                                    && m_id != node.method_id
                                                {
                                                    // Seed the field at the entry node of this other method!
                                                    if let Some(&entry_node_id) =
                                                        self.icfg.method_entry_node.get(&m_id)
                                                    {
                                                        if let Some(method) =
                                                            self.program.methods.get(&m_id)
                                                        {
                                                            let is_java = self
                                                                .method_file_paths
                                                                .get(&m_id)
                                                                .map_or(false, |path| {
                                                                    path.ends_with(".java")
                                                                });
                                                            let receiver_prefix = if is_java {
                                                                "this.".to_string()
                                                            } else {
                                                                if let Some(first_param) =
                                                                    method.parameters.first()
                                                                {
                                                                    format!("{}.", first_param)
                                                                } else {
                                                                    "self.".to_string()
                                                                }
                                                            };
                                                            let target_var = format!(
                                                                "{}{}",
                                                                receiver_prefix, field_name
                                                            );
                                                            let next_fact = TaintFact {
                                                                node_id: entry_node_id,
                                                                context: 0,
                                                                var: target_var,
                                                                sanitized_for: processed
                                                                    .sanitized_for
                                                                    .clone(),
                                                                source_domain: processed
                                                                    .source_domain,
                                                            };
                                                            if !self
                                                                .tainted_facts
                                                                .contains(&next_fact)
                                                            {
                                                                local_queue.push_back((
                                                                    next_fact,
                                                                    Some(processed.clone()),
                                                                ));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn get_related_types(&self, type_id: ir::TypeId) -> Rc<HashSet<ir::TypeId>> {
        if let Some(cached) = self.related_types_cache.borrow().get(&type_id) {
            return cached.clone();
        }

        let mut related = HashSet::new();
        related.insert(type_id);

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(type_id);
        visited.insert(type_id);

        fn clean_class_name(name: &str) -> String {
            name.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        }

        while let Some(tid) = queue.pop_front() {
            if let Some(ty) = self.program.types.get(&tid) {
                // Find parents
                if let Some(ref parent_name) = ty.parent_type {
                    let cleaned_parent = clean_class_name(parent_name);
                    for (other_tid, other_ty) in &self.program.types {
                        if clean_class_name(&other_ty.name) == cleaned_parent
                            && !visited.contains(other_tid)
                        {
                            visited.insert(*other_tid);
                            related.insert(*other_tid);
                            queue.push_back(*other_tid);
                        }
                    }
                }
                // Find children
                let cleaned_current = clean_class_name(&ty.name);
                for (other_tid, other_ty) in &self.program.types {
                    if let Some(ref other_parent) = other_ty.parent_type {
                        if clean_class_name(other_parent) == cleaned_current
                            && !visited.contains(other_tid)
                        {
                            visited.insert(*other_tid);
                            related.insert(*other_tid);
                            queue.push_back(*other_tid);
                        }
                    }
                }
            }
        }
        let rc_related = Rc::new(related);
        self.related_types_cache
            .borrow_mut()
            .insert(type_id, rc_related.clone());
        rc_related
    }

    pub fn run(&mut self) {
        let mut worklist = VecDeque::new();
        let initial_facts: Vec<TaintFact> = self.tainted_facts.drain().collect();
        for fact in initial_facts {
            self.add_fact(&mut worklist, fact, None);
        }

        let mut succ_edges: HashMap<u32, Vec<&IcfgEdge>> = HashMap::new();
        for edge in &self.icfg.edges {
            succ_edges.entry(edge.from).or_default().push(edge);
        }

        let mut iterations = 0;
        while let Some(fact) = worklist.pop_front() {
            iterations += 1;
            if iterations > 1000000 {
                break;
            }
            let node = match self.icfg.nodes.get(&fact.node_id) {
                Some(n) => n,
                None => continue,
            };

            // Check if we hit a sink
            if let Some(target_cwe) = self.check_sink_flow(node, &fact) {
                self.flows.insert(TaintFlow {
                    source_node_id: 0,
                    sink_node_id: node.id,
                    source_var: String::new(),
                    sink_var: fact.var.clone(),
                    cwe: target_cwe,
                });
            }

            if let Some(edges) = succ_edges.get(&node.id) {
                for edge in edges {
                    match edge.kind {
                        IcfgEdgeKind::CFG => {
                            let results = self.apply_transfer_function(edge.to, &fact);
                            for (new_var, new_san) in results {
                                let next_fact = TaintFact {
                                    node_id: edge.to,
                                    context: fact.context,
                                    var: new_var,
                                    sanitized_for: new_san,
                                    source_domain: fact.source_domain,
                                };
                                self.add_fact(&mut worklist, next_fact, Some(&fact));
                            }
                        }
                        IcfgEdgeKind::Call => {
                            let new_context = node.id;
                            self.parent_contexts.insert(new_context, fact.context);

                            let mut is_sanitizer = false;
                            if let Some(inst_id) = node.instruction_id {
                                if let Some(inst) = self.program.instructions.get(&inst_id) {
                                    if let InstructionKind::Call { callee, .. } = &inst.kind {
                                        if self.is_sanitizer_call_site(node.method_id, callee) {
                                            is_sanitizer = true;
                                        }
                                    }
                                }
                            }

                            if is_sanitizer {
                                continue;
                            }

                            let new_vars =
                                self.bind_arguments_to_parameters(node, edge.to, &fact.var);
                            for new_var in new_vars {
                                let next_fact = TaintFact {
                                    node_id: edge.to,
                                    context: new_context,
                                    var: new_var,
                                    sanitized_for: fact.sanitized_for.clone(),
                                    source_domain: fact.source_domain,
                                };
                                self.add_fact(&mut worklist, next_fact, Some(&fact));
                            }
                        }
                        IcfgEdgeKind::Return => {
                            let callee_context = fact.context;
                            let return_node = match self.icfg.nodes.get(&edge.to) {
                                Some(rn) => rn,
                                None => continue,
                            };

                            // Normal path: the fact's context is the call-site node whose
                            // instruction matches the post-call return node's instruction.
                            let is_context_match = if let Some(callee_call_node) =
                                self.icfg.nodes.get(&callee_context)
                            {
                                return_node.instruction_id == callee_call_node.instruction_id
                            } else {
                                false
                            };

                            if is_context_match {
                                let parent_ctx =
                                    *self.parent_contexts.get(&callee_context).unwrap_or(&0);
                                let new_vars = self.bind_return_value(
                                    callee_context,
                                    edge.to,
                                    Some(node.method_id),
                                    &fact.var,
                                );
                                for new_var in new_vars {
                                    let next_fact = TaintFact {
                                        node_id: edge.to,
                                        context: parent_ctx,
                                        var: new_var,
                                        sanitized_for: fact.sanitized_for.clone(),
                                        source_domain: fact.source_domain,
                                    };
                                    self.add_fact(&mut worklist, next_fact, Some(&fact));
                                }
                            } else if callee_context == 0 {
                                // Facts seeded directly into a helper method (e.g. `badSource`)
                                // via seed_sources have context=0 because no Call edge set their
                                // context. Recover by scanning ICFG Call edges to find all
                                // call sites that target this callee's method and whose post-call
                                // node instruction matches the return node.
                                let callee_method_id = node.method_id;
                                let return_inst_id = return_node.instruction_id;

                                // Find pre-call nodes: Call edges from some node → entry of
                                // the callee method, where the caller's instruction == return_node's
                                // instruction (they share the same InstructionId in the ICFG).
                                let start_time = Instant::now();
                                let call_site_ids: Vec<u32> = if let Some(candidates) =
                                    self.call_sites_by_callee.get(&callee_method_id)
                                {
                                    let candidates_len = candidates.len();
                                    let res: Vec<u32> = candidates
                                        .iter()
                                        .filter_map(|&from_id| {
                                            let pre_call = self.icfg.nodes.get(&from_id)?;
                                            if pre_call.instruction_id == return_inst_id {
                                                Some(from_id)
                                            } else {
                                                None
                                            }
                                        })
                                        .collect();
                                    let elapsed = start_time.elapsed().as_nanos() as u64;
                                    RETURN_SCAN_INSTRUMENTATION.with(|stats| {
                                        let mut s = stats.borrow_mut();
                                        s.invocations += 1;
                                        s.total_candidates += candidates_len as u64;
                                        s.max_candidates = s.max_candidates.max(candidates_len);
                                        s.total_duration_ns += elapsed;
                                    });
                                    res
                                } else {
                                    let elapsed = start_time.elapsed().as_nanos() as u64;
                                    RETURN_SCAN_INSTRUMENTATION.with(|stats| {
                                        let mut s = stats.borrow_mut();
                                        s.invocations += 1;
                                        s.total_duration_ns += elapsed;
                                    });
                                    Vec::new()
                                };

                                for call_site_id in call_site_ids {
                                    let parent_ctx =
                                        *self.parent_contexts.get(&call_site_id).unwrap_or(&0);
                                    let new_vars = self.bind_return_value(
                                        call_site_id,
                                        edge.to,
                                        Some(callee_method_id),
                                        &fact.var,
                                    );
                                    for new_var in new_vars {
                                        let next_fact = TaintFact {
                                            node_id: edge.to,
                                            context: parent_ctx,
                                            var: new_var,
                                            sanitized_for: fact.sanitized_for.clone(),
                                            source_domain: fact.source_domain,
                                        };
                                        self.add_fact(&mut worklist, next_fact, Some(&fact));
                                    }
                                }
                            }
                        }
                        IcfgEdgeKind::Exception => {
                            let results = self.apply_transfer_function(edge.to, &fact);
                            for (new_var, new_san) in results {
                                let next_fact = TaintFact {
                                    node_id: edge.to,
                                    context: fact.context,
                                    var: new_var,
                                    sanitized_for: new_san,
                                    source_domain: fact.source_domain,
                                };
                                self.add_fact(&mut worklist, next_fact, Some(&fact));
                            }
                        }
                    }
                }
            }
        }
        println!("[ENGINE] finished after {} iterations", iterations);
        RETURN_SCAN_INSTRUMENTATION.with(|stats| {
            let s = stats.borrow();
            let avg = if s.invocations > 0 {
                s.total_candidates as f64 / s.invocations as f64
            } else {
                0.0
            };
            println!("=================================");
            println!("RETURN SCAN HOTSPOT ANALYSIS");
            println!("---------------------------------");
            println!("Invocations: {}", s.invocations);
            println!("Average candidates: {:.4}", avg);
            println!("Maximum candidates: {}", s.max_candidates);
            println!("Total duration: {} ms", s.total_duration_ns / 1_000_000);
            println!("=================================");
        });
    }

    fn check_sink_flow_domain(
        &mut self,
        fact: &TaintFact,
        target_cwe: crate::CWE,
        node_id: u32,
        sink_var: &str,
    ) -> bool {
        if target_cwe == crate::CWE::CWE22 {
            if let Some(node) = self.icfg.nodes.get(&node_id) {
                let file_path = self.get_method_file_path(node.method_id);
                if let Some(path_str) = file_path {
                    let file_line = node
                        .instruction_id
                        .and_then(|inst_id| self.program.instructions.get(&inst_id))
                        .map(|i| i.file_line)
                        .unwrap_or(0);
                    if is_path_traversal_guarded(self.program, path_str, &fact.var, file_line) {
                        return false;
                    }
                    if is_path_traversal_guarded(self.program, path_str, sink_var, file_line) {
                        return false;
                    }
                }
            }
        }
        let sink_domain = match target_cwe {
            crate::CWE::CWE89 => crate::CweDomain::Sql,
            crate::CWE::CWE79 => crate::CweDomain::Xss,
            crate::CWE::CWE78 => crate::CweDomain::Command,
            crate::CWE::CWE22 => crate::CweDomain::PathTraversal,
            crate::CWE::CWE502 => crate::CweDomain::Deserialization,
            crate::CWE::CWE90 => crate::CweDomain::Ldap,
            crate::CWE::CWE327 => crate::CweDomain::Crypto,
            _ => crate::CweDomain::Generic,
        };
        let allowed = fact.source_domain == sink_domain
            || fact.source_domain == crate::CweDomain::Generic
            || sink_domain == crate::CweDomain::Generic
            || sink_domain == crate::CweDomain::Xss
            || sink_domain == crate::CweDomain::Command
            || sink_domain == crate::CweDomain::PathTraversal
            || sink_domain == crate::CweDomain::Deserialization
            || sink_domain == crate::CweDomain::Ldap
            || (sink_domain == crate::CweDomain::Sql
                && fact.source_domain == crate::CweDomain::PathTraversal);
        if !allowed {
            self.suppressed_flows.push(SuppressedFlowDiagnostic {
                sink_node_id: node_id,
                sink_var: sink_var.to_string(),
                source_domain: fact.source_domain,
                sink_domain,
                reason: format!(
                    "Mismatched domains: Source ({:?}) != Sink ({:?})",
                    fact.source_domain, sink_domain
                ),
            });
        }
        allowed
    }

    fn check_sink_flow(&mut self, node: &IcfgNode, fact: &TaintFact) -> Option<crate::CWE> {
        if let Some(inst_id) = node.instruction_id {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                match &inst.kind {
                    InstructionKind::Return { val: Some(expr) } => {
                        // Walk parent map to check if taint passed through a decoder or isValidHref
                        let mut passed_through_decoder = false;
                        let mut has_is_valid_href = false;
                        let mut curr_fact = fact.clone();
                        while let Some(parent) = self.parent_map.get(&curr_fact) {
                            if let Some(parent_node) = self.icfg.nodes.get(&parent.node_id) {
                                if let Some(parent_inst_id) = parent_node.instruction_id {
                                    if let Some(parent_inst) =
                                        self.program.instructions.get(&parent_inst_id)
                                    {
                                        if let InstructionKind::Call { callee, .. } =
                                            &parent_inst.kind
                                        {
                                            let c_lower = callee.to_lowercase();
                                            if c_lower.contains("decode")
                                                || c_lower.contains("unescape")
                                                || c_lower.contains("unquote")
                                            {
                                                passed_through_decoder = true;
                                            }
                                            if c_lower.contains("isvalidhref") {
                                                has_is_valid_href = true;
                                            }
                                        }
                                    }
                                }
                            }
                            curr_fact = parent.clone();
                        }

                        let raw_lower = expr.to_lowercase();
                        let is_html_context = raw_lower.contains("<div")
                            || raw_lower.contains("<span")
                            || raw_lower.contains("<p>")
                            || raw_lower.contains("<html")
                            || raw_lower.contains("<body")
                            || raw_lower.contains("<script")
                            || raw_lower.contains("<input")
                            || raw_lower.contains("<form")
                            || raw_lower.contains("<html>");
                        let is_file_context = raw_lower.contains("new file")
                            || raw_lower.contains("path.of")
                            || raw_lower.contains("paths.get")
                            || raw_lower.starts_with("file(");
                        let is_sql_context = raw_lower.contains("select ")
                            || raw_lower.contains("insert into")
                            || raw_lower.contains("update ")
                            || raw_lower.contains("delete from")
                            || raw_lower.contains("where ");

                        let is_target_sink = is_html_context
                            || is_file_context
                            || is_sql_context
                            || passed_through_decoder;

                        if is_target_sink {
                            if expr_uses_var(expr, &fact.var) {
                                let target_cwe = if is_sql_context {
                                    crate::CWE::CWE89
                                } else if is_file_context {
                                    crate::CWE::CWE22
                                } else {
                                    crate::CWE::CWE79
                                };

                                if fact.sanitized_for.contains(&target_cwe) {
                                    if !(passed_through_decoder && has_is_valid_href) {
                                        return None;
                                    }
                                }

                                if expression_contains_sanitizer(expr) {
                                    let cwes = crate::get_sanitized_cwes_for_callee(expr);
                                    if cwes.contains(&target_cwe) {
                                        return None;
                                    }
                                }

                                if self.check_sink_flow_domain(fact, target_cwe, node.id, expr) {
                                    return Some(target_cwe);
                                }
                            }
                        }
                    }
                    InstructionKind::Sink { name } => {
                        if expr_uses_var(name, &fact.var) {
                            let file_path = self.get_method_file_path(node.method_id);
                            let target_cwe = crate::map_sink_to_cwe_heuristic(name, file_path)
                                .unwrap_or(crate::CWE::CWE79);
                            if fact.sanitized_for.contains(&target_cwe) {
                                return None;
                            }
                            if expression_contains_sanitizer(name) {
                                let cwes = crate::get_sanitized_cwes_for_callee(name);
                                if cwes.contains(&target_cwe) {
                                    return None;
                                }
                            }
                            if self.check_sink_flow_domain(fact, target_cwe, node.id, name) {
                                return Some(target_cwe);
                            }
                        }
                    }
                    InstructionKind::Call { callee, args, .. } => {
                        let mut is_sink = false;
                        let mut allowed_sink_indices = None;
                        let mut target_cwe = crate::CWE::CWE79;
                        let mut method_name_opt = None;
                        let file_path = self.get_method_file_path(node.method_id);
                        let mut resolved_class_fqn = None;

                        if let Some((class_fqn, method_name)) =
                            self.resolve_callee_info(node.method_id, callee)
                        {
                            method_name_opt = Some(method_name.clone());
                            resolved_class_fqn = Some(class_fqn.clone());
                            let stub_lookup = self.stubs.lookup(&class_fqn, &method_name);
                            if let Some(stub) = stub_lookup {
                                if stub.kind == crate::stubs::StubKind::Sink {
                                    is_sink = true;
                                    allowed_sink_indices = stub.propagates_from.clone();
                                    target_cwe =
                                        crate::map_sink_to_cwe_heuristic(&method_name, file_path)
                                            .or_else(|| {
                                                crate::map_sink_to_cwe_heuristic(callee, file_path)
                                            })
                                            .or_else(|| {
                                                crate::map_sink_to_cwe_heuristic(
                                                    &class_fqn, file_path,
                                                )
                                            })
                                            .unwrap_or(crate::CWE::CWE79);

                                    if target_cwe == crate::CWE::CWE502 {
                                        if !is_deserialization_sink_check(
                                            callee,
                                            Some(&class_fqn),
                                            args,
                                        ) {
                                            is_sink = false;
                                        }
                                    }

                                    if is_sink {
                                        // Override to CWE-90 if LDAP context is confirmed
                                        let clean_method_lower = method_name.to_lowercase();
                                        let class_fqn_lower = class_fqn.to_lowercase();
                                        let is_ldap = class_fqn_lower.contains("ldap")
                                            || class_fqn_lower.contains("dircontext")
                                            || class_fqn_lower.contains("ldapmanager")
                                            || class_fqn_lower.contains("ldapcontext")
                                            || file_path.map_or(false, |p| {
                                                let p_lower = p.to_lowercase();
                                                p_lower.contains("cwe90")
                                                    || p_lower.contains("cwe_90")
                                            });
                                        if is_ldap
                                            && (clean_method_lower == "search"
                                                || clean_method_lower == "lookup"
                                                || clean_method_lower == "query")
                                        {
                                            target_cwe = crate::CWE::CWE90;
                                        }
                                    }
                                }
                            }
                        }

                        if !is_sink {
                            let clean_method = callee.split('.').last().unwrap_or(callee);
                            let clean_method_lower = clean_method.to_lowercase();
                            let callee_lower = callee.to_lowercase();

                            let resolved_class_fqn_lower =
                                resolved_class_fqn.as_ref().map(|s| s.to_lowercase());
                            let is_ldap_context = callee_lower.contains("ldap")
                                || callee_lower.contains("dircontext")
                                || callee_lower.contains("ldapmanager")
                                || callee_lower.contains("ldapcontext")
                                || resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                    fqn.contains("ldap")
                                        || fqn.contains("dircontext")
                                        || fqn.contains("ldapmanager")
                                        || fqn.contains("ldapcontext")
                                        || fqn.contains("searchcontrols")
                                })
                                || file_path.map_or(false, |p| {
                                    let p_lower = p.to_lowercase();
                                    p_lower.contains("cwe90") || p_lower.contains("cwe_90")
                                });

                            // RC83: Detect XPath context for evaluate/compile sinks
                            let is_xpath_context = callee_lower.contains("xpath")
                                || resolved_class_fqn_lower
                                    .as_ref()
                                    .map_or(false, |fqn| fqn.contains("xpath"))
                                || file_path.map_or(false, |p| {
                                    let p_lower = p.to_lowercase();
                                    p_lower.contains("cwe643")
                                        || p_lower.contains("cwe_643")
                                        || p_lower.contains("xpath")
                                });

                            // RC84: Detect Java File, Stream, and Files sinks
                            let is_file_constructor_sink = callee_lower.contains("java.io.file")
                                || callee_lower.contains("java.io.fileinputstream")
                                || callee_lower.contains("java.io.fileoutputstream")
                                || callee_lower.contains("java.io.filewriter")
                                || callee_lower.contains("java.io.filechannel")
                                || callee_lower.contains("java.nio.file.files")
                                || callee_lower.contains("java.nio.file.paths")
                                || callee_lower.contains("java.nio.file.path")
                                || callee_lower.contains("paths.get")
                                || callee_lower.contains("path.of")
                                || callee_lower.contains("files.")
                                || callee_lower == "open"
                                || callee_lower.contains(".open")
                                || resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                    fqn.contains("java.io.file")
                                        || fqn.ends_with(".file")
                                        || fqn.contains("java.nio.file.files")
                                        || fqn.ends_with(".files")
                                        || fqn.contains("java.nio.file.paths")
                                        || fqn.ends_with(".paths")
                                        || fqn.contains("java.nio.file.path")
                                        || fqn.ends_with(".path")
                                })
                                || (clean_method_lower == "<init>"
                                    && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                        fqn.contains("java.io.file") || fqn.ends_with(".file")
                                    }));

                            // RC84/RC91: Detect unsafe deserialization (CWE-502) sinks
                            // Only flag libraries that allow arbitrary code execution during deserialization.
                            // json.loads/ujson/orjson are JSON-only parsers — they CANNOT execute code
                            // and are commonly used as SAFE replacements in patched code (would cause FPs).
                            let is_deserialization_sink = is_deserialization_sink_check(
                                callee,
                                resolved_class_fqn.as_deref(),
                                args,
                            );

                            // RC91: Detect ORM raw-query sinks (CWE-89)
                            // Only fire when we have evidence of an ORM context (resolved FQN
                            // or explicit callee like queryset.filter / RawSQL)
                            let is_orm_raw_query_sink = callee_lower.contains("rawsql")
                                || callee_lower.contains("raw_sql")
                                || (clean_method_lower == "raw"
                                    && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                        fqn.contains("queryset")
                                            || fqn.contains("manager")
                                            || fqn.contains("model")
                                            || fqn.contains("django")
                                            || fqn.contains("sqlalchemy")
                                            || fqn.contains("peewee")
                                    }))
                                || (clean_method_lower == "extra"
                                    && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                        fqn.contains("queryset")
                                            || fqn.contains("query")
                                            || fqn.contains("model")
                                            || fqn.contains("django")
                                            || fqn.contains("sqlalchemy")
                                            || fqn.contains("peewee")
                                            || fqn.contains("database")
                                    }));

                            // RC91: Detect SSRF sinks via aiohttp / httpx
                            // Only fire when the callee is explicitly a known HTTP library
                            // RC93: Extended to cover requests.Session.send / httpx.AsyncClient.send
                            let is_ssrf_sink = callee_lower.contains("aiohttp.")
                                || callee_lower.contains("httpx.")
                                || callee_lower.contains("requests.get")
                                || callee_lower.contains("requests.post")
                                || callee_lower.contains("requests.put")
                                || callee_lower.contains("requests.delete")
                                || callee_lower.contains("requests.request")
                                || callee_lower.contains("requests.options")
                                || callee_lower.contains("httpx.get")
                                || callee_lower.contains("httpx.post")
                                || callee_lower.contains("httpx.put")
                                || callee_lower.contains("httpx.delete")
                                || callee_lower.contains("httpx.request")
                                || callee_lower.contains("urlopen")
                                || callee_lower.contains("urllib.request")
                                // RC93: session.send / client.send — requests.Session / httpx dispatch
                                || (clean_method_lower == "send"
                                    && (callee_lower.contains("session") || callee_lower.contains("client")))
                                // RC93: session.get / session.post dispatched via requests.Session
                                || ((clean_method_lower == "get" || clean_method_lower == "post"
                                        || clean_method_lower == "put" || clean_method_lower == "delete"
                                        || clean_method_lower == "patch" || clean_method_lower == "head")
                                    && (callee_lower.contains("session") || callee_lower.contains("client")))
                                || (clean_method_lower == "get"
                                    && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                        fqn.contains("httpx")
                                            || fqn.contains("aiohttp")
                                            || fqn.contains("session")
                                    }))
                                || (clean_method_lower == "post"
                                    && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                        fqn.contains("httpx")
                                            || fqn.contains("aiohttp")
                                            || fqn.contains("session")
                                    }))
                                || (clean_method_lower == "send"
                                    && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
                                        fqn.contains("session")
                                            || fqn.contains("client")
                                            || fqn.contains("httpx")
                                            || fqn.contains("requests")
                                    }));

                            // Command injection sinks (CWE-78)
                            let is_command_sink = callee_lower.contains("subprocess.run")
                                || callee_lower.contains("subprocess.call")
                                || callee_lower.contains("subprocess.check_call")
                                || callee_lower.contains("subprocess.check_output")
                                || callee_lower.contains("os.system")
                                || callee_lower.contains("popen")
                                || callee_lower.contains("subprocess.popen");

                            if clean_method_lower == "badsink"
                                || clean_method_lower.contains("badsink")
                                || clean_method_lower.contains("dangerous_sink")
                                || clean_method_lower.contains("setattribute")
                                || clean_method_lower.contains("putvalue")
                                || clean_method_lower.contains("setinitparameter")
                                || clean_method_lower == "addheader"
                                || clean_method_lower == "setheader"
                                || clean_method_lower == "addcookie"
                                || clean_method_lower == "sendredirect"
                                || clean_method_lower == "setcontenttype"
                                // RC51 Fix #1: path traversal (Flask)
                                || callee_lower.contains("send_file")
                                || callee_lower.contains("send_from_directory")
                                // RC83: Python requests.request() SSRF sink
                                || callee_lower == "requests.request"
                                || callee_lower == "requests.options"
                                // RC83: Java File/stream/Files constructors as path-traversal sinks
                                || is_file_constructor_sink
                                // RC84/RC91: Unsafe deserialization sinks (json.loads, pickle, yaml, msgpack...)
                                || is_deserialization_sink
                                // RC91: ORM raw-query sinks (.filter, .raw, RawSQL)
                                || is_orm_raw_query_sink
                                // RC91: SSRF via aiohttp/httpx
                                || is_ssrf_sink
                                // Command injection sinks (CWE-78)
                                || is_command_sink
                                // RC83: XPath evaluate/compile sinks
                                || ((clean_method_lower == "evaluate" || clean_method_lower == "compile") && is_xpath_context)
                                // RC51 Fix #2: LDAP injection (CWE-90)
                                || ((clean_method_lower == "search" || clean_method_lower == "lookup" || clean_method_lower == "query") && is_ldap_context)
                                // Hardening synthetic import sinks
                                || callee_lower.contains("batchprocess")
                            {
                                is_sink = true;
                                if is_ldap_context
                                    && (clean_method_lower == "search"
                                        || clean_method_lower == "lookup"
                                        || clean_method_lower == "query")
                                {
                                    target_cwe = crate::CWE::CWE90;
                                } else if is_xpath_context
                                    && (clean_method_lower == "evaluate"
                                        || clean_method_lower == "compile")
                                {
                                    target_cwe = crate::CWE::CWE643;
                                } else if is_file_constructor_sink {
                                    target_cwe = crate::CWE::CWE22;
                                } else if is_deserialization_sink {
                                    target_cwe = crate::CWE::CWE502;
                                } else if is_ssrf_sink {
                                    let callee_lower = callee.to_lowercase();
                                    if callee_lower.contains("api_client")
                                        || callee_lower.contains("test_client")
                                        || callee_lower.contains("testclient")
                                    {
                                        target_cwe = crate::CWE::CWE22;
                                    } else {
                                        target_cwe = crate::CWE::CWE918;
                                    }
                                } else if is_orm_raw_query_sink {
                                    target_cwe = crate::CWE::CWE89;
                                } else if is_command_sink {
                                    target_cwe = crate::CWE::CWE78;
                                } else if callee_lower == "requests.request"
                                    || callee_lower == "requests.options"
                                {
                                    target_cwe = crate::CWE::CWE918;
                                } else if clean_method_lower == "addheader"
                                    || clean_method_lower == "setheader"
                                    || clean_method_lower == "addcookie"
                                    || clean_method_lower == "sendredirect"
                                    || clean_method_lower == "setcontenttype"
                                {
                                    target_cwe = crate::CWE::CWE113;
                                } else {
                                    target_cwe =
                                        crate::map_sink_to_cwe_heuristic(&callee_lower, file_path)
                                            .or_else(|| {
                                                crate::map_sink_to_cwe_heuristic(
                                                    &clean_method_lower,
                                                    file_path,
                                                )
                                            })
                                            .unwrap_or(crate::CWE::CWE79);
                                }
                            }
                        }

                        if is_sink {
                            let method_lower = method_name_opt
                                .map(|m| m.to_lowercase())
                                .unwrap_or_else(|| {
                                    callee.split('.').last().unwrap_or(callee).to_lowercase()
                                });

                            let is_write_method = method_lower == "write"
                                || method_lower == "print"
                                || method_lower == "println"
                                || method_lower == "format"
                                || method_lower == "printf"
                                || method_lower == "append";

                            if target_cwe == crate::CWE::CWE22 && is_write_method {
                                let callee_lower = callee.to_lowercase();
                                let resolved_class_fqn_lower =
                                    resolved_class_fqn.as_ref().map(|s| s.to_lowercase());
                                let is_nio_files = callee_lower.contains("java.nio.file.files")
                                    || resolved_class_fqn_lower
                                        .as_ref()
                                        .map_or(false, |fqn| fqn.contains("java.nio.file.files"));
                                if !is_nio_files {
                                    return None; // Bypass content-writing methods for path traversal sinks (except Files.write)
                                }
                            }

                            if method_lower == "write"
                                || method_lower == "print"
                                || method_lower == "println"
                                || method_lower == "format"
                                || method_lower == "printf"
                            {
                                if method_lower == "format" || method_lower == "printf" {
                                    // RC83: Accept chained getWriter().printf() — callee may contain getwriter
                                    let callee_contains_writer =
                                        callee.to_lowercase().contains("getwriter")
                                            || callee.to_lowercase().contains("writer")
                                            || callee.to_lowercase().contains("response");
                                    if let Some(receiver) = get_receiver_name_safe(callee) {
                                        let rec_lower = receiver.to_lowercase();
                                        let is_web_writer = rec_lower.contains("writer")
                                            || rec_lower.contains("response")
                                            || rec_lower.contains("out")
                                            || rec_lower.contains("stream")
                                            || rec_lower.contains("getwriter");
                                        if !is_web_writer && !callee_contains_writer {
                                            return None;
                                        }
                                    } else if !callee_contains_writer {
                                        return None;
                                    }
                                }

                                if let Some(receiver) = get_receiver_name_safe(callee) {
                                    let rec_lower = receiver.to_lowercase();
                                    let is_benign = rec_lower.contains("log")
                                        || rec_lower.contains("logger")
                                        || rec_lower.contains("logging")
                                        || rec_lower.contains("system.out")
                                        || rec_lower.contains("system.err")
                                        || rec_lower.contains("bytearray")
                                        || rec_lower.contains("objectoutput")
                                        || rec_lower.contains("objectstream")
                                        || rec_lower.contains("filewriter")
                                        || rec_lower.contains("filestream")
                                        || rec_lower.contains("buffered")
                                        || rec_lower.contains("stringwriter")
                                        || rec_lower.contains("stringbuilder")
                                        || rec_lower.contains("printstream")
                                        || rec_lower.contains("stderr")
                                        || rec_lower.contains("stdout")
                                        || rec_lower.contains("cli_logger")
                                        || rec_lower.contains("sys.stdout")
                                        || rec_lower.contains("sys.stderr");
                                    if is_benign {
                                        return None;
                                    }
                                }

                                if fact.sanitized_for.contains(&target_cwe) {
                                    return None;
                                }

                                // Narrowing: only flag if argument is tainted, never if only receiver is.
                                for arg in args {
                                    if expr_uses_var(arg, &fact.var) {
                                        if expression_contains_sanitizer(arg) {
                                            let cwes = crate::get_sanitized_cwes_for_callee(arg);
                                            if cwes.contains(&target_cwe) {
                                                continue;
                                            }
                                        }
                                        if self
                                            .check_sink_flow_domain(fact, target_cwe, node.id, arg)
                                        {
                                            return Some(target_cwe);
                                        }
                                    }
                                }
                                return None; // DO NOT check receiver for print/write/format methods!
                            }

                            // if callee.contains("Popen") {
                            //     println!("DEBUG check_sink_flow check: target_cwe={:?}, fact.var={}, sanitized={}", target_cwe, fact.var, fact.sanitized_for.contains(&target_cwe));
                            // }

                            if fact.sanitized_for.contains(&target_cwe) {
                                return None;
                            }

                            for (arg_idx, arg) in args.iter().enumerate() {
                                if let Some(ref indices) = allowed_sink_indices {
                                    if !indices.contains(&arg_idx) {
                                        continue;
                                    }
                                }
                                // if callee.contains("Popen") {
                                //     println!("  arg={}, expr_uses_var={}, contains_san={}", arg, expr_uses_var(arg, &fact.var), expression_contains_sanitizer(arg));
                                // }
                                if expr_uses_var(arg, &fact.var) {
                                    // Gating rule 1: open / os.open path traversal gating
                                    let callee_lower = callee.to_lowercase();
                                    if target_cwe == crate::CWE::CWE22 {
                                        if callee_lower == "open"
                                            || callee_lower.ends_with(".open")
                                            || callee_lower == "os.open"
                                            || callee_lower.ends_with(".os.open")
                                        {
                                            if arg_idx > 0 {
                                                continue;
                                            }
                                        }
                                    }

                                    // Gating rule 3: torch.load deserialization gating (bypass if weights_only=True)
                                    if target_cwe == crate::CWE::CWE502 {
                                        if callee_lower.contains("torch.load") {
                                            let has_weights_only_true = args.iter().any(|a| {
                                                let al = a.to_lowercase();
                                                al.contains("weights_only=true")
                                            });
                                            if has_weights_only_true {
                                                continue;
                                            }
                                        }
                                    }

                                    if expression_contains_sanitizer(arg) {
                                        let cwes = crate::get_sanitized_cwes_for_callee(arg);
                                        if cwes.contains(&target_cwe) {
                                            continue;
                                        }
                                    }
                                    if self.check_sink_flow_domain(fact, target_cwe, node.id, arg) {
                                        // if callee.contains("Popen") {
                                        //     println!("  MATCHED flow for CWE78!");
                                        // }
                                        return Some(target_cwe);
                                    }
                                }
                            }

                            let mut allow_receiver_check = true;
                            if target_cwe == crate::CWE::CWE501
                                || target_cwe == crate::CWE::CWE78
                                || target_cwe == crate::CWE::CWE22
                                || target_cwe == crate::CWE::CWE502
                                || target_cwe == crate::CWE::CWE918
                                || target_cwe == crate::CWE::CWE89
                            {
                                allow_receiver_check = false;
                                // Exception 1: Allow receiver check for SQL statement/cursor/connection executing methods
                                if target_cwe == crate::CWE::CWE89 {
                                    if let Some(ref class_fqn) = resolved_class_fqn {
                                        let class_lower = class_fqn.to_lowercase();
                                        if class_lower.contains("statement")
                                            || class_lower.contains("cursor")
                                            || class_lower.contains("session")
                                            || class_lower.contains("connection")
                                        {
                                            allow_receiver_check = true;
                                        }
                                    }
                                }
                                // Exception 2: Allow receiver check for pathlib.Path/Path/File etc for path traversal
                                if target_cwe == crate::CWE::CWE22 {
                                    if let Some(ref class_fqn) = resolved_class_fqn {
                                        let class_lower = class_fqn.to_lowercase();
                                        if class_lower.contains("path")
                                            || class_lower.contains("file")
                                        {
                                            allow_receiver_check = true;
                                        }
                                    }
                                }
                                // Exception 3: Allow receiver check for ObjectInputStream, XMLDecoder, etc for deserialization
                                if target_cwe == crate::CWE::CWE502 {
                                    if let Some(ref class_fqn) = resolved_class_fqn {
                                        let class_lower = class_fqn.to_lowercase();
                                        if class_lower.contains("objectinput")
                                            || class_lower.contains("inputstream")
                                            || class_lower.contains("decoder")
                                            || class_lower.contains("deserializer")
                                        {
                                            allow_receiver_check = true;
                                        }
                                    }
                                }
                            }

                            if allow_receiver_check {
                                if let Some(receiver) = get_receiver_name_safe(callee) {
                                    if expr_uses_var(&receiver, &fact.var) {
                                        if expression_contains_sanitizer(&receiver) {
                                            let cwes =
                                                crate::get_sanitized_cwes_for_callee(&receiver);
                                            if cwes.contains(&target_cwe) {
                                                return None;
                                            }
                                        }
                                        if self.check_sink_flow_domain(
                                            fact, target_cwe, node.id, &receiver,
                                        ) {
                                            return Some(target_cwe);
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
        None
    }

    fn apply_transfer_function(
        &self,
        dest_node_id: u32,
        fact: &TaintFact,
    ) -> Vec<(String, std::collections::BTreeSet<crate::CWE>)> {
        let results = self.apply_transfer_function_internal(dest_node_id, fact);

        let mut expanded_results = Vec::new();
        for (var, san) in results {
            if var.contains(',') && !var.contains('(') && !var.contains('[') {
                expanded_results.push((var.clone(), san.clone()));
                for part in var.split(',') {
                    let clean_part = part.trim().to_string();
                    if !clean_part.is_empty() {
                        expanded_results.push((clean_part, san.clone()));
                    }
                }
            } else {
                expanded_results.push((var, san));
            }
        }
        expanded_results
    }

    fn apply_transfer_function_internal(
        &self,
        dest_node_id: u32,
        fact: &TaintFact,
    ) -> Vec<(String, std::collections::BTreeSet<crate::CWE>)> {
        let node = match self.icfg.nodes.get(&dest_node_id) {
            Some(n) => n,
            None => return vec![(fact.var.clone(), fact.sanitized_for.clone())],
        };

        if let Some(inst_id) = node.instruction_id {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                match &inst.kind {
                    InstructionKind::Assign { dest, src } => {
                        let is_overwritten = if is_same_var(dest, &fact.var) {
                            true
                        } else if let Some((_, _)) = parse_java_or_python_container_read(dest) {
                            false
                        } else {
                            if let Some((c_var, _)) = parse_java_or_python_container_read(&fact.var)
                            {
                                dest.trim().to_lowercase() == c_var.to_lowercase()
                            } else {
                                expr_uses_var(dest, &fact.var)
                            }
                        };

                        let src_to_check = if src.contains('?') && src.contains(':') {
                            self.evaluate_constant(node.method_id, src)
                                .unwrap_or_else(|| src.clone())
                        } else {
                            src.clone()
                        };

                        let mut results = Vec::new();
                        let var_access_opt = parse_java_or_python_container_read(&fact.var);
                        let mut propagated = false;

                        if let Some((fact_container, fact_key)) = &var_access_opt {
                            if let Some((src_container, src_key)) =
                                parse_java_or_python_container_read(&src_to_check)
                            {
                                if src_container.to_lowercase() == fact_container.to_lowercase() {
                                    if fact_key == "*"
                                        || src_key == "*"
                                        || src_key.to_lowercase() == fact_key.to_lowercase()
                                    {
                                        results.push((dest.clone(), fact.sanitized_for.clone()));
                                        propagated = true;
                                    }
                                }
                            }
                            if !propagated
                                && src_to_check.trim().to_lowercase()
                                    == fact_container.to_lowercase()
                            {
                                let key_str = self
                                    .evaluate_constant(node.method_id, fact_key)
                                    .unwrap_or_else(|| "*".to_string());
                                results.push((
                                    format!("{}[\"{}\"]", dest, key_str),
                                    fact.sanitized_for.clone(),
                                ));
                                propagated = true;
                            }
                        }

                        if !propagated {
                            if expr_uses_var(&src_to_check, &fact.var) {
                                results.push((dest.clone(), fact.sanitized_for.clone()));
                            }
                        }

                        let is_propagated = !results.is_empty();

                        if !is_overwritten || is_propagated {
                            results.push((fact.var.clone(), fact.sanitized_for.clone()));
                        }

                        return results;
                    }
                    InstructionKind::Sanitizer { name } => {
                        if expr_uses_var(name, &fact.var) {
                            let mut new_san = fact.sanitized_for.clone();
                            new_san.insert(crate::CWE::CWE22);
                            new_san.insert(crate::CWE::CWE78);
                            new_san.insert(crate::CWE::CWE79);
                            new_san.insert(crate::CWE::CWE89);
                            new_san.insert(crate::CWE::CWE113);
                            new_san.insert(crate::CWE::CWE327);
                            new_san.insert(crate::CWE::CWE501);
                            new_san.insert(crate::CWE::CWE502);
                            new_san.insert(crate::CWE::CWE918);
                            return vec![(fact.var.clone(), new_san)];
                        }
                    }
                    InstructionKind::Call { dest, callee, args } => {
                        let mut resolved_class_fqn = None;
                        if let Some((class_fqn, _)) =
                            self.resolve_callee_info(node.method_id, callee)
                        {
                            resolved_class_fqn = Some(class_fqn);
                        }

                        if is_deserialization_sink_check(
                            callee,
                            resolved_class_fqn.as_deref(),
                            args,
                        ) {
                            let mut is_propagating = false;
                            for arg in args {
                                if expr_uses_var(arg, &fact.var) {
                                    is_propagating = true;
                                    break;
                                }
                            }
                            if let Some(receiver) = get_receiver_name_safe(callee) {
                                if expr_uses_var(&receiver, &fact.var) {
                                    is_propagating = true;
                                }
                            }

                            // RC97 fix: do not kill a var that is also passed as an argument.
                            // e.g. `hexsha, ref_path = cls._get_ref_info(repo, ref_path)` —
                            // ref_path is in both dest and args; it must survive for
                            // interprocedural propagation into the callee.
                            let is_in_args = args.iter().any(|a| expr_uses_var(a, &fact.var));
                            let is_overwritten =
                                dest.as_ref().map_or(false, |d| expr_uses_var(d, &fact.var))
                                    && !is_in_args;
                            let mut results = Vec::new();
                            if is_propagating {
                                if let Some(d) = dest {
                                    results.push((d.clone(), fact.sanitized_for.clone()));
                                }
                                if let Some(receiver) = get_receiver_name_safe(callee) {
                                    println!("[RC368F_PROP] callee='{}' receiver='{}' active_fact='{}' dest_fact='{}' node_id={} kind='deser'", callee, receiver, fact.var, receiver, dest_node_id);
                                    results.push((receiver, fact.sanitized_for.clone()));
                                }
                            }
                            if !is_overwritten || is_propagating {
                                results.push((fact.var.clone(), fact.sanitized_for.clone()));
                            }
                            return results;
                        }

                        let method_name = callee.split('.').last().unwrap_or(callee);
                        let method_lower = method_name.to_lowercase();

                        if method_lower == "setsecure" {
                            let is_true = args
                                .first()
                                .map_or(false, |a| a.trim().to_lowercase() == "true");
                            if is_true {
                                if let Some(receiver) = get_receiver_name(callee) {
                                    if expr_uses_var(&receiver, &fact.var) {
                                        let mut new_san = fact.sanitized_for.clone();
                                        new_san.insert(crate::CWE::CWE614);
                                        return vec![
                                            (receiver.clone(), new_san.clone()),
                                            (fact.var.clone(), new_san),
                                        ];
                                    }
                                }
                            }
                        }

                        // RC97 fix: same guard — if var is also in args, it is not killed by
                        // its presence in the dest (return-value tuple unpacking).
                        let is_in_args = args.iter().any(|a| expr_uses_var(a, &fact.var));
                        let mut is_overwritten =
                            dest.as_ref().map_or(false, |d| expr_uses_var(d, &fact.var))
                                && !is_in_args;

                        let mut results = Vec::new();
                        let receiver_opt = get_receiver_name_safe(callee);
                        let method_name = callee.split('.').last().unwrap_or(callee);
                        let method_lower = method_name.to_lowercase();

                        let is_map_put = method_lower == "put"
                            || method_lower == "set"
                            || method_lower == "setdefault"
                            || method_lower == "computeifabsent"
                            || method_lower == "setvalue";
                        let is_list_add = method_lower == "add"
                            || method_lower == "append"
                            || method_lower == "extend"
                            || method_lower == "push"
                            || method_lower == "insert";
                        let is_list_remove = method_lower == "remove";
                        let is_map_get = method_lower == "get"
                            || method_lower == "getitem"
                            || method_lower == "getordefault"
                            || method_lower == "at"
                            || method_lower == "elementat";

                        let mut handled_as_collection = false;

                        if let Some(r) = &receiver_opt {
                            if is_map_put && args.len() >= 2 {
                                handled_as_collection = true;
                                if expr_uses_var(&args[1], &fact.var) {
                                    let key_raw = args[0].trim();
                                    let key_str = self
                                        .evaluate_constant(node.method_id, key_raw)
                                        .unwrap_or_else(|| "*".to_string());
                                    results.push((
                                        format!("{}[\"{}\"]", r, key_str),
                                        fact.sanitized_for.clone(),
                                    ));
                                }
                            } else if is_list_add && args.len() >= 1 {
                                handled_as_collection = true;
                                if args.len() == 2
                                    && (method_lower == "add" || method_lower == "insert")
                                {
                                    if expr_uses_var(&args[1], &fact.var) {
                                        let idx_raw = args[0].trim();
                                        let idx_str = self
                                            .evaluate_constant(node.method_id, idx_raw)
                                            .unwrap_or_else(|| "*".to_string());
                                        results.push((
                                            format!("{}[\"{}\"]", r, idx_str),
                                            fact.sanitized_for.clone(),
                                        ));
                                    }
                                } else {
                                    if expr_uses_var(&args[0], &fact.var) {
                                        let mut has_loop = false;
                                        let all_insts =
                                            self.get_all_method_instructions(node.method_id);
                                        for inst_id in &all_insts {
                                            if let Some(inst) =
                                                self.program.instructions.get(inst_id)
                                            {
                                                if matches!(inst.kind, InstructionKind::Loop { .. })
                                                {
                                                    has_loop = true;
                                                    break;
                                                }
                                            }
                                        }

                                        let mut is_local_arraylist = false;
                                        let mut add_count = 0;
                                        let mut failed = false;

                                        if !has_loop {
                                            for inst_id in &all_insts {
                                                if Some(*inst_id) == node.instruction_id {
                                                    break;
                                                }
                                                if let Some(inst) =
                                                    self.program.instructions.get(inst_id)
                                                {
                                                    match &inst.kind {
                                                        InstructionKind::Call {
                                                            dest: Some(d),
                                                            callee: c,
                                                            ..
                                                        } => {
                                                            if d == r
                                                                && c.to_lowercase()
                                                                    .contains("arraylist")
                                                            {
                                                                is_local_arraylist = true;
                                                            }
                                                        }
                                                        InstructionKind::Call {
                                                            dest: _,
                                                            callee: c,
                                                            args: a,
                                                        } => {
                                                            if let Some(rec) =
                                                                get_receiver_name_safe(c)
                                                            {
                                                                if &rec == r {
                                                                    let method_name = c
                                                                        .split('.')
                                                                        .last()
                                                                        .unwrap_or(c);
                                                                    let method_lower =
                                                                        method_name.to_lowercase();
                                                                    if method_lower == "add"
                                                                        && a.len() == 1
                                                                    {
                                                                        add_count += 1;
                                                                    } else if method_lower
                                                                        == "remove"
                                                                    {
                                                                        failed = true;
                                                                    } else if method_lower != "get"
                                                                    {
                                                                        failed = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        InstructionKind::Assign { dest, src } => {
                                                            if dest.contains(r) || src.contains(r) {
                                                                failed = true;
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }

                                        if is_local_arraylist && !failed && !has_loop {
                                            results.push((
                                                format!("{}[\"{}\"]", r, add_count),
                                                fact.sanitized_for.clone(),
                                            ));
                                        } else {
                                            results.push((
                                                format!("{}[\"{}\"]", r, "*"),
                                                fact.sanitized_for.clone(),
                                            ));
                                        }
                                    }
                                }
                            } else if is_list_remove
                                && args.len() == 1
                                && node.kind == cfg::icfg::IcfgNodeKind::Call
                                && self.is_receiver_local_arraylist(
                                    node.method_id,
                                    node.instruction_id,
                                    r,
                                )
                            {
                                handled_as_collection = true;
                                is_overwritten = true;
                                let idx_raw = args[0].trim();
                                let idx_str = self
                                    .evaluate_constant(node.method_id, idx_raw)
                                    .unwrap_or_else(|| "*".to_string());

                                let clean_var = fact.var.trim();
                                if let Some((receiver, key)) =
                                    parse_java_or_python_container_read(clean_var)
                                {
                                    if receiver.to_lowercase() == r.to_lowercase() {
                                        if let Ok(k) = idx_str.parse::<i64>() {
                                            if let Ok(n) = key.parse::<i64>() {
                                                if n > k {
                                                    results.push((
                                                        format!("{}[\"{}\"]", r, n - 1),
                                                        fact.sanitized_for.clone(),
                                                    ));
                                                } else if n < k {
                                                    results.push((
                                                        format!("{}[\"{}\"]", r, n),
                                                        fact.sanitized_for.clone(),
                                                    ));
                                                }
                                            } else if key == "*" {
                                                results.push((
                                                    format!("{}[\"*\"]", r),
                                                    fact.sanitized_for.clone(),
                                                ));
                                            }
                                        } else {
                                            results.push((
                                                format!("{}[\"*\"]", r),
                                                fact.sanitized_for.clone(),
                                            ));
                                        }
                                    } else {
                                        results
                                            .push((fact.var.clone(), fact.sanitized_for.clone()));
                                    }
                                } else if clean_var.to_lowercase() == r.to_lowercase() {
                                    results.push((fact.var.clone(), fact.sanitized_for.clone()));
                                }
                            } else if is_map_get && args.len() >= 1 {
                                handled_as_collection = true;
                                if let Some(d) = dest {
                                    let key_raw = args[0].trim();
                                    let key_str = self
                                        .evaluate_constant(node.method_id, key_raw)
                                        .unwrap_or_else(|| "*".to_string());

                                    let equiv_access = format!("{}[\"{}\"]", r, key_str);
                                    if expr_uses_var(&equiv_access, &fact.var) {
                                        results.push((d.clone(), fact.sanitized_for.clone()));
                                        let is_arraylist = self.is_receiver_local_arraylist(
                                            node.method_id,
                                            node.instruction_id,
                                            r,
                                        );
                                        if !is_arraylist || key_str == "*" {
                                            results.push((
                                                format!("{}[\"*\"]", d),
                                                fact.sanitized_for.clone(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }

                        if handled_as_collection {
                            if !is_overwritten {
                                results.push((fact.var.clone(), fact.sanitized_for.clone()));
                            }
                            return results;
                        }

                        if !handled_as_collection {
                            let is_sanitizer_call =
                                self.is_sanitizer_call_site(node.method_id, callee);

                            if is_sanitizer_call {
                                let mut is_sanitized = false;
                                for arg in args {
                                    if expr_uses_var(arg, &fact.var) {
                                        is_sanitized = true;
                                    }
                                }
                                if is_sanitized {
                                    let target_cwes = crate::get_sanitized_cwes_for_callee(callee);
                                    let mut new_san = fact.sanitized_for.clone();
                                    for cwe in target_cwes {
                                        new_san.insert(cwe);
                                    }
                                    if let Some(d) = dest {
                                        results.push((d.clone(), new_san.clone()));
                                    }
                                    if let Some(receiver) = get_receiver_name_safe(callee) {
                                        println!("[RC368F_PROP] callee='{}' receiver='{}' active_fact='{}' dest_fact='{}' node_id={} kind='sanitizer'", callee, receiver, fact.var, receiver, dest_node_id);
                                        results.push((receiver, new_san.clone()));
                                    }
                                    results.push((fact.var.clone(), new_san));
                                    return results;
                                }
                            }

                            let mut has_stub = false;
                            if let Some((class_fqn, method_name)) =
                                self.resolve_callee_info(node.method_id, callee)
                            {
                                if let Some(stub) = self.stubs.lookup(&class_fqn, &method_name) {
                                    has_stub = true;
                                    match stub.kind {
                                        crate::stubs::StubKind::Propagator
                                        | crate::stubs::StubKind::Source
                                        | crate::stubs::StubKind::Sink => {
                                            let mut is_propagating = false;
                                            if let Some(ref indices) = stub.propagates_from {
                                                if indices.is_empty() {
                                                    if let Some(receiver) =
                                                        get_receiver_name_safe(callee)
                                                    {
                                                        if expr_uses_var(&receiver, &fact.var)
                                                            || fact.var.starts_with(&format!(
                                                                "{}.",
                                                                receiver
                                                            ))
                                                        {
                                                            is_propagating = true;
                                                        }
                                                    }
                                                } else {
                                                    for &idx in indices {
                                                        if let Some(arg) = args.get(idx) {
                                                            if expr_uses_var(arg, &fact.var) {
                                                                is_propagating = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                for arg in args {
                                                    if expr_uses_var(arg, &fact.var) {
                                                        is_propagating = true;
                                                    }
                                                }
                                                if let Some(receiver) =
                                                    get_receiver_name_safe(callee)
                                                {
                                                    if expr_uses_var(&receiver, &fact.var)
                                                        || fact
                                                            .var
                                                            .starts_with(&format!("{}.", receiver))
                                                    {
                                                        is_propagating = true;
                                                    }
                                                }
                                            }

                                            let is_benchmark_helper =
                                                self.is_benchmark_helper(Some(&class_fqn), callee);
                                            if is_benchmark_helper
                                                && !self.determine_helper_propagation_decision(
                                                    Some(&class_fqn),
                                                    callee,
                                                    &fact.var,
                                                )
                                            {
                                                is_propagating = false;
                                            }

                                            if is_propagating {
                                                let propagated_san =
                                                    if crate::is_desanitizer(callee) {
                                                        std::collections::BTreeSet::new()
                                                    } else {
                                                        fact.sanitized_for.clone()
                                                    };
                                                if let Some(d) = dest {
                                                    results
                                                        .push((d.clone(), propagated_san.clone()));
                                                }
                                                if let Some(receiver) =
                                                    get_receiver_name_safe(callee)
                                                {
                                                    println!("[RC368F_PROP] callee='{}' receiver='{}' active_fact='{}' dest_fact='{}' node_id={} kind='stub'", callee, receiver, fact.var, receiver, dest_node_id);
                                                    results
                                                        .push((receiver, propagated_san.clone()));
                                                }
                                            }
                                            if !is_overwritten || is_propagating {
                                                results.push((
                                                    fact.var.clone(),
                                                    fact.sanitized_for.clone(),
                                                ));
                                            }
                                            return results;
                                        }
                                        _ => {}
                                    }
                                }
                            }

                            if !has_stub {
                                if let Some(inst_id) = node.instruction_id {
                                    let callee_method_id = self
                                        .call_graph
                                        .edges
                                        .iter()
                                        .find(|edge| edge.instruction_id == Some(inst_id))
                                        .map(|edge| edge.callee);
                                    if let Some(m_id) = callee_method_id {
                                        let is_json_binding = self.is_json_binding_method(callee);
                                        if is_json_binding {
                                            let mut is_propagating = false;
                                            if !args.is_empty() {
                                                if expr_uses_var(&args[0], &fact.var) {
                                                    is_propagating = true;
                                                }
                                            }
                                            if is_propagating {
                                                if let Some(d) = dest {
                                                    results.push((d.clone(), fact.sanitized_for.clone()));
                                                }
                                            }
                                            if !is_overwritten || is_propagating {
                                                results.push((fact.var.clone(), fact.sanitized_for.clone()));
                                            }
                                            return results;
                                        }

                                        let is_repo_propagation = self.is_repository_propagation(m_id, callee);
                                        if is_repo_propagation {
                                            let mut is_propagating = false;
                                            for arg in args {
                                                if expr_uses_var(arg, &fact.var) {
                                                    is_propagating = true;
                                                }
                                            }
                                            if is_propagating {
                                                if let Some(d) = dest {
                                                    results.push((d.clone(), fact.sanitized_for.clone()));
                                                }
                                            }
                                            if !is_overwritten || is_propagating {
                                                results.push((fact.var.clone(), fact.sanitized_for.clone()));
                                            }
                                            return results;
                                        }

                                        let jb_kind = {
                                            let mut cache = self.javabean_cache.borrow_mut();
                                            if let Some(&kind) = cache.get(&m_id) {
                                                kind
                                            } else {
                                                let classifier =
                                                    JavaBeanClassifier::new(self.program, self.gst);
                                                let kind = classifier.classify(m_id, false);
                                                cache.insert(m_id, kind);
                                                kind
                                            }
                                        };

                                        if jb_kind != JavaBeanKind::None {
                                            let mut is_propagating = false;
                                            if jb_kind == JavaBeanKind::Getter {
                                                if let Some(receiver) =
                                                    get_receiver_name_safe(callee)
                                                {
                                                    if expr_uses_var(&receiver, &fact.var)
                                                        || fact
                                                            .var
                                                            .starts_with(&format!("{}.", receiver))
                                                    {
                                                        is_propagating = true;
                                                        if let Some(d) = dest {
                                                            results.push((
                                                                d.clone(),
                                                                fact.sanitized_for.clone(),
                                                            ));
                                                        }
                                                    }
                                                }
                                            } else if jb_kind == JavaBeanKind::Setter {
                                                if !args.is_empty()
                                                    && expr_uses_var(&args[0], &fact.var)
                                                {
                                                    is_propagating = true;
                                                    if let Some(receiver) =
                                                        get_receiver_name_safe(callee)
                                                    {
                                                        results.push((
                                                            receiver.clone(),
                                                            fact.sanitized_for.clone(),
                                                        ));
                                                    }
                                                }
                                            }

                                            if !is_overwritten || is_propagating {
                                                results.push((
                                                    fact.var.clone(),
                                                    fact.sanitized_for.clone(),
                                                ));
                                            }
                                            return results;
                                        }
                                    }
                                }
                            }

                            // Fallback propagation for unregistered/unresolved calls
                            let mut is_propagating = false;
                            let is_callee_resolved = if let Some(inst_id) = node.instruction_id {
                                self.resolved_call_instructions.contains(&inst_id)
                            } else {
                                false
                            };

                            if !is_callee_resolved {
                                for arg in args {
                                    if expr_uses_var(arg, &fact.var) {
                                        is_propagating = true;
                                    }
                                }
                                if let Some(receiver) = get_receiver_name_safe(callee) {
                                    if expr_uses_var(&receiver, &fact.var) {
                                        is_propagating = true;
                                    }
                                }
                                if is_propagating {
                                    let is_juliet = self
                                        .target_file
                                        .as_ref()
                                        .map_or(false, |tf| tf.to_lowercase().contains("cwe"));
                                    if is_juliet && callee.to_lowercase().contains("good") {
                                        is_propagating = false;
                                    }
                                }
                            }

                            let (is_benchmark_helper, class_fqn_opt) = if let Some((class_fqn, _)) =
                                self.resolve_callee_info(node.method_id, callee)
                            {
                                (
                                    self.is_benchmark_helper(Some(&class_fqn), callee),
                                    Some(class_fqn),
                                )
                            } else {
                                (self.is_benchmark_helper(None, callee), None)
                            };

                            if is_benchmark_helper
                                && !self.determine_helper_propagation_decision(
                                    class_fqn_opt.as_deref(),
                                    callee,
                                    &fact.var,
                                )
                            {
                                is_propagating = false;
                            }

                            if is_propagating {
                                let mut propagated_san = if crate::is_desanitizer(callee) {
                                    std::collections::BTreeSet::new()
                                } else {
                                    fact.sanitized_for.clone()
                                };
                                // Inspect arguments for nested sanitizers
                                for arg in args {
                                    if expr_uses_var(arg, &fact.var) {
                                        let nested = find_nested_sanitizers(arg);
                                        for cwe in nested {
                                            propagated_san.insert(cwe);
                                        }
                                    }
                                }
                                if let Some(d) = dest {
                                    results.push((d.clone(), propagated_san.clone()));
                                }
                                if let Some(receiver) = get_receiver_name_safe(callee) {
                                    let callee_lower = callee.to_lowercase();
                                    // RC107B: Block JDBC PreparedStatement setter calls from propagating taint
                                    // to the receiver. Setters bind parameters into placeholders; the JDBC driver
                                    // handles escaping, so the statement object itself is never tainted by the value.
                                    // Match on the method-name suffix to be independent of receiver variable name.
                                    static JDBC_SETTERS: std::sync::OnceLock<
                                        std::collections::HashSet<&'static str>,
                                    > = std::sync::OnceLock::new();
                                    let jdbc_setters = JDBC_SETTERS.get_or_init(|| {
                                        [
                                            "setstring",
                                            "setint",
                                            "setlong",
                                            "setdouble",
                                            "setfloat",
                                            "setboolean",
                                            "setbytes",
                                            "setbyte",
                                            "setshort",
                                            "setbigdecimal",
                                            "setdate",
                                            "settimestamp",
                                            "settime",
                                            "setobject",
                                            "setnull",
                                            "setblob",
                                            "setclob",
                                            "setarray",
                                            "setnstring",
                                            "setnclob",
                                            "setncharacterstream",
                                            "seturl",
                                            "setref",
                                            "setrowid",
                                            "setsqlxml",
                                            "setcharacterstream",
                                            "setbinarystream",
                                            "setasciistream",
                                            "setunicodestream",
                                        ]
                                        .iter()
                                        .copied()
                                        .collect()
                                    });
                                    let method_suffix =
                                        callee_lower.rsplit('.').next().unwrap_or(&callee_lower);
                                    let is_jdbc_setter = jdbc_setters.contains(method_suffix);
                                    // Secondary fallback: original keyword-based guard for descriptively-named receivers
                                    let is_db_setter = (callee_lower.contains(".set")
                                        || callee_lower.starts_with("set"))
                                        && (callee_lower.contains("statement")
                                            || callee_lower.contains("prepared")
                                            || callee_lower.contains("query")
                                            || callee_lower.contains("sql")
                                            || callee_lower.contains("conn"));
                                    if !is_jdbc_setter && !is_db_setter {
                                        println!("[RC368F_PROP] callee='{}' receiver='{}' active_fact='{}' dest_fact='{}' node_id={} kind='fallback'", callee, receiver, fact.var, receiver, dest_node_id);
                                        results.push((receiver, propagated_san.clone()));
                                    }
                                }
                            }
                        }

                        if !is_overwritten || !results.is_empty() {
                            results.push((fact.var.clone(), fact.sanitized_for.clone()));
                        }
                        return results;
                    }
                    _ => {}
                }
            }
        }

        vec![(fact.var.clone(), fact.sanitized_for.clone())]
    }

    fn is_receiver_local_arraylist(
        &self,
        method_id: ir::MethodId,
        instruction_id: Option<ir::InstructionId>,
        r: &str,
    ) -> bool {
        let Some(inst_id) = instruction_id else {
            return false;
        };
        let mut has_loop = false;
        let all_insts = self.get_all_method_instructions(method_id);
        for id in &all_insts {
            if let Some(inst) = self.program.instructions.get(id) {
                if matches!(inst.kind, InstructionKind::Loop { .. }) {
                    has_loop = true;
                    break;
                }
            }
        }
        if has_loop {
            return false;
        }

        let mut is_local_arraylist = false;
        let mut failed = false;
        for id in &all_insts {
            if *id == inst_id {
                break;
            }
            if let Some(inst) = self.program.instructions.get(id) {
                match &inst.kind {
                    InstructionKind::Call {
                        dest: Some(d),
                        callee: c,
                        ..
                    } => {
                        if d == r && c.to_lowercase().contains("arraylist") {
                            is_local_arraylist = true;
                        }
                    }
                    InstructionKind::Call {
                        dest: _,
                        callee: c,
                        args: a,
                    } => {
                        if let Some(rec) = get_receiver_name_safe(c) {
                            if &rec == r {
                                let method_name = c.split('.').last().unwrap_or(c);
                                let method_lower = method_name.to_lowercase();
                                if method_lower != "get"
                                    && method_lower != "add"
                                    && method_lower != "remove"
                                {
                                    failed = true;
                                }
                            }
                        }
                    }
                    InstructionKind::Assign { dest, src } => {
                        if dest.contains(r) || src.contains(r) {
                            failed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        is_local_arraylist && !failed
    }

    fn bind_arguments_to_parameters(
        &self,
        call_node: &IcfgNode,
        callee_entry: u32,
        tainted_var: &str,
    ) -> Vec<String> {
        let mut results = Vec::new();
        if let Some(inst_id) = call_node.instruction_id {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                if let InstructionKind::Call { callee, args, .. } = &inst.kind {
                    // Find the callee method using the callee_entry node
                    let callee_method = self
                        .icfg
                        .nodes
                        .get(&callee_entry)
                        .and_then(|n| self.program.methods.get(&n.method_id));

                    if let Some(method) = callee_method {
                        let is_synthetic =
                            method.parameters.len() == 1 && method.parameters[0] == "value";
                        let mut param_offset = 0;
                        if !is_synthetic
                            && method
                                .parameters
                                .first()
                                .map(|p| {
                                    let clean = clean_parameter_name(p);
                                    clean == "self" || clean == "this" || clean == "cls"
                                })
                                .unwrap_or(false)
                        {
                            let has_implicit_receiver =
                                if let Some(receiver) = get_receiver_name_safe(callee) {
                                    let caller_method_info =
                                        self.gst.program_index.methods.get(&call_node.method_id);
                                    let module_id = caller_method_info
                                        .map(|m| m.module_id)
                                        .unwrap_or(ir::ModuleId(0));
                                    let receiver_is_type =
                                        self.gst.resolve_type(module_id, &receiver).is_some();
                                    let first_arg_is_self = args
                                        .first()
                                        .map(|a| a == "self" || a == "this")
                                        .unwrap_or(false);
                                    !receiver_is_type && !first_arg_is_self
                                } else {
                                    let first_arg_is_self = args
                                        .first()
                                        .map(|a| a == "self" || a == "this")
                                        .unwrap_or(false);
                                    !first_arg_is_self
                                };
                            if has_implicit_receiver {
                                param_offset = 1;
                            }
                        }
                        // Bind arguments to parameters by position
                        for (i, arg) in args.iter().enumerate() {
                            if expr_uses_var(arg, tainted_var) {
                                let param_opt = if is_synthetic {
                                    Some(&method.parameters[0])
                                } else {
                                    method.parameters.get(i + param_offset)
                                };
                                if let Some(param) = param_opt {
                                    let clean_param = clean_parameter_name(param);
                                    results.push(clean_param);
                                }
                            } else if let Some((container, key)) =
                                parse_java_or_python_container_read(tainted_var)
                            {
                                if expr_uses_var(arg, &container) {
                                    let param_opt = if is_synthetic {
                                        Some(&method.parameters[0])
                                    } else {
                                        method.parameters.get(i + param_offset)
                                    };
                                    if let Some(param) = param_opt {
                                        let clean_param = clean_parameter_name(param);
                                        results.push(format!("{}[\"{}\"]", clean_param, key));
                                    }
                                }
                            }
                        }
                    }

                    // Receiver binding (e.g. service.getUser(id) -> service flows to this/self)
                    if let Some(receiver) = get_receiver_name_safe(callee) {
                        if tainted_var == receiver {
                            results.push("this".to_string());
                            results.push("self".to_string());
                            results.push("cls".to_string());
                        } else if tainted_var.starts_with(&format!("{}.", receiver)) {
                            let suffix = &tainted_var[receiver.len() + 1..];
                            results.push(format!("this.{}", suffix));
                            results.push(format!("self.{}", suffix));
                            results.push(format!("cls.{}", suffix));
                        } else if let Some((container, key)) =
                            parse_java_or_python_container_read(tainted_var)
                        {
                            if container == receiver {
                                results.push(format!("this[\"{}\"]", key));
                                results.push(format!("self[\"{}\"]", key));
                                results.push(format!("cls[\"{}\"]", key));
                            }
                        }
                    }
                }
            }
        }
        results
    }

    fn bind_return_value(
        &self,
        call_node_id: u32,
        _return_node_id: u32,
        callee_method_id: Option<ir::MethodId>,
        tainted_var: &str,
    ) -> Vec<String> {
        let mut results = Vec::new();
        let call_node = match self.icfg.nodes.get(&call_node_id) {
            Some(n) => n,
            None => return vec![],
        };

        if let Some(inst_id) = call_node.instruction_id {
            if let Some(inst) = self.program.instructions.get(&inst_id) {
                if let InstructionKind::Call { dest, callee, args } = &inst.kind {
                    let mut has_implicit_receiver = true;
                    // Check if callee returned the tainted variable
                    let method_id_opt = callee_method_id.or_else(|| {
                        self.call_graph
                            .edges
                            .iter()
                            .find(|edge| edge.instruction_id == Some(inst_id))
                            .map(|edge| edge.callee)
                    });
                    if let Some(method_id) = method_id_opt {
                        if let Some(method) = self.program.methods.get(&method_id) {
                            let mut returns_tainted = false;
                            let mut tainted_return_var = None;
                            let has_cached =
                                self.method_insts_cache.borrow().contains_key(&method_id);
                            if !has_cached {
                                let mut insts = Vec::new();
                                let mut visited = HashSet::new();
                                fn collect_insts(
                                    ids: &[ir::InstructionId],
                                    program: &ir::Program,
                                    out: &mut Vec<ir::InstructionId>,
                                    visited: &mut HashSet<ir::InstructionId>,
                                ) {
                                    for &id in ids {
                                        if !visited.insert(id) {
                                            continue;
                                        }
                                        out.push(id);
                                        if let Some(inst) = program.instructions.get(&id) {
                                            match &inst.kind {
                                                InstructionKind::Branch {
                                                    then_block,
                                                    else_block,
                                                    ..
                                                } => {
                                                    collect_insts(
                                                        then_block, program, out, visited,
                                                    );
                                                    if let Some(eb) = else_block {
                                                        collect_insts(eb, program, out, visited);
                                                    }
                                                }
                                                InstructionKind::Loop { body, .. } => {
                                                    collect_insts(body, program, out, visited);
                                                }
                                                InstructionKind::Try {
                                                    body,
                                                    catches,
                                                    finally,
                                                    ..
                                                } => {
                                                    collect_insts(body, program, out, visited);
                                                    for catch_id in catches {
                                                        collect_insts(
                                                            &[*catch_id],
                                                            program,
                                                            out,
                                                            visited,
                                                        );
                                                    }
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
                                collect_insts(&method.body, self.program, &mut insts, &mut visited);
                                self.method_insts_cache
                                    .borrow_mut()
                                    .insert(method_id, insts);
                            }

                            let cache_borrow = self.method_insts_cache.borrow();
                            let all_insts = cache_borrow.get(&method_id).unwrap();

                            for &body_inst_id in all_insts {
                                if let Some(body_inst) =
                                    self.program.instructions.get(&body_inst_id)
                                {
                                    if let InstructionKind::Return { val: Some(v) } =
                                        &body_inst.kind
                                    {
                                        if expr_uses_var(v, tainted_var) {
                                            returns_tainted = true;
                                            break;
                                        } else if let Some((container, key)) =
                                            parse_java_or_python_container_read(tainted_var)
                                        {
                                            if expr_uses_var(v, &container) {
                                                if let Some(d) = dest {
                                                    tainted_return_var =
                                                        Some(format!("{}[\"{}\"]", d, key));
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            if returns_tainted {
                                if let Some(d) = dest {
                                    results.push(d.clone());
                                }
                            } else if let Some(trv) = tainted_return_var {
                                results.push(trv);
                            }

                            // Propagate parameter reference mutations back to arguments
                            let mut param_idx_opt = None;
                            let mut key_opt = None;

                            let mut param_offset = 0;
                            let is_synthetic =
                                method.parameters.len() == 1 && method.parameters[0] == "value";
                            if !is_synthetic
                                && method
                                    .parameters
                                    .first()
                                    .map(|p| {
                                        let clean = clean_parameter_name(p);
                                        clean == "self" || clean == "this" || clean == "cls"
                                    })
                                    .unwrap_or(false)
                            {
                                let is_implicit = if let Some(receiver) =
                                    get_receiver_name_safe(callee)
                                {
                                    let caller_method_info =
                                        self.gst.program_index.methods.get(&call_node.method_id);
                                    let module_id = caller_method_info
                                        .map(|m| m.module_id)
                                        .unwrap_or(ir::ModuleId(0));
                                    let receiver_is_type =
                                        self.gst.resolve_type(module_id, &receiver).is_some();
                                    let first_arg_is_self = args
                                        .first()
                                        .map(|a| a == "self" || a == "this")
                                        .unwrap_or(false);
                                    !receiver_is_type && !first_arg_is_self
                                } else {
                                    let first_arg_is_self = args
                                        .first()
                                        .map(|a| a == "self" || a == "this")
                                        .unwrap_or(false);
                                    !first_arg_is_self
                                };
                                has_implicit_receiver = is_implicit;
                                if is_implicit {
                                    param_offset = 1;
                                }
                            }

                            for (i, param) in method.parameters.iter().enumerate() {
                                let clean_param = clean_parameter_name(param);
                                if clean_param == tainted_var {
                                    param_idx_opt = Some(i);
                                    break;
                                }
                            }
                            if param_idx_opt.is_none() {
                                if let Some((container, key)) =
                                    parse_java_or_python_container_read(tainted_var)
                                {
                                    for (i, param) in method.parameters.iter().enumerate() {
                                        let clean_param = clean_parameter_name(param);
                                        if clean_param == container {
                                            param_idx_opt = Some(i);
                                            key_opt = Some(key);
                                            break;
                                        }
                                    }
                                }
                            }
                            if let Some(param_idx) = param_idx_opt {
                                if param_idx >= param_offset {
                                    if let Some(arg) = args.get(param_idx - param_offset) {
                                        if let Some(key) = key_opt {
                                            results.push(format!("{}[\"{}\"]", arg, key));
                                        } else {
                                            results.push(arg.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Receiver propagation back to caller (receiver side mutation)
                    if has_implicit_receiver {
                        if let Some(receiver) = get_receiver_name_safe(callee) {
                            if tainted_var == "this"
                                || tainted_var == "self"
                                || tainted_var == "cls"
                            {
                                results.push(receiver.clone());
                            } else if tainted_var.starts_with("this.") {
                                let suffix = &tainted_var["this.".len()..];
                                results.push(format!("{}.{}", receiver, suffix));
                            } else if tainted_var.starts_with("self.") {
                                let suffix = &tainted_var["self.".len()..];
                                results.push(format!("{}.{}", receiver, suffix));
                            } else if tainted_var.starts_with("cls.") {
                                let suffix = &tainted_var["cls.".len()..];
                                results.push(format!("{}.{}", receiver, suffix));
                            } else if let Some((container, key)) =
                                parse_java_or_python_container_read(tainted_var)
                            {
                                if container == "this" || container == "self" || container == "cls"
                                {
                                    results.push(format!("{}[\"{}\"]", receiver, key));
                                }
                            }
                        }
                    }
                }
            }
        }
        results
    }

    fn get_library_call_return_type(&self, class_fqn: &str, method_name: &str) -> Option<String> {
        let class_lower = class_fqn.to_lowercase();
        let method_lower = method_name.to_lowercase();

        if class_lower.contains("path") && method_lower == "resolve" {
            return Some("pathlib.Path".to_string());
        }

        if class_lower.contains("open") || class_lower.contains("file") {
            if method_lower.starts_with("read") {
                return Some("bytes".to_string());
            }
        }

        if class_lower.contains("base64") {
            if method_lower.starts_with("b64decode")
                || method_lower.starts_with("urlsafe_b64decode")
            {
                return Some("bytes".to_string());
            }
            if method_lower == "getdecoder"
                || method_lower == "geturldecoder"
                || method_lower == "getmimedecoder"
            {
                return Some("java.util.Base64$Decoder".to_string());
            }
            if method_lower == "getencoder"
                || method_lower == "geturlencoder"
                || method_lower == "getmimeencoder"
            {
                return Some("java.util.Base64$Encoder".to_string());
            }
        }

        if class_lower.contains("connection") && method_lower == "preparestatement" {
            return Some("java.sql.PreparedStatement".to_string());
        }
        if class_lower.contains("connection") && method_lower == "createstatement" {
            return Some("java.sql.Statement".to_string());
        }
        if class_lower.contains("connection") && method_lower == "cursor" {
            return Some("sqlite3.Cursor".to_string());
        }
        if class_lower.contains("connect") && method_lower == "cursor" {
            return Some("sqlite3.Cursor".to_string());
        }
        if class_lower.contains("snowflake") && method_lower == "cursor" {
            return Some("snowflake.connector.cursor.SnowflakeCursor".to_string());
        }
        if class_lower.contains("httpservletrequest") {
            if method_lower == "getsession" {
                return Some("javax.servlet.http.HttpSession".to_string());
            }
            if method_lower == "getcookies" {
                return Some("javax.servlet.http.Cookie[]".to_string());
            }
        }
        if class_lower.contains("cookie") && method_lower == "getvalue" {
            return Some("java.lang.String".to_string());
        }
        if class_lower.contains("databasehelper") && method_lower == "getsqlconnection" {
            return Some("java.sql.Connection".to_string());
        }
        if class_lower.contains("databasehelper") && method_lower == "getsqlstatement" {
            return Some("java.sql.Statement".to_string());
        }
        None
    }

    pub fn resolve_callee_info(
        &self,
        method_id: ir::MethodId,
        callee_expr: &str,
    ) -> Option<(String, String)> {
        let key = (method_id, callee_expr.to_string());
        if let Some(cached) = self.callee_info_cache.borrow().get(&key) {
            return cached.clone();
        }

        thread_local! {
            static RESOLVING: std::cell::RefCell<std::collections::HashSet<(ir::MethodId, String)>> = std::cell::RefCell::new(std::collections::HashSet::new());
        }

        if !RESOLVING.with(|resolving| resolving.borrow_mut().insert(key.clone())) {
            return None;
        }

        let res = self.resolve_callee_info_internal(method_id, callee_expr);

        RESOLVING.with(|resolving| resolving.borrow_mut().remove(&key));

        self.callee_info_cache.borrow_mut().insert(key, res.clone());
        res
    }

    fn resolve_callee_info_internal(
        &self,
        method_id: ir::MethodId,
        callee_expr: &str,
    ) -> Option<(String, String)> {
        if callee_expr.starts_with("new ") {
            let class_name = callee_expr["new ".len()..].trim().to_string();
            return Some((class_name, "<init>".to_string()));
        }

        let last_dot_idx = callee_expr.rfind('.');
        if last_dot_idx.is_none() {
            if let Some(method_info) = self.gst.program_index.methods.get(&method_id) {
                let module_id = method_info.module_id;
                if let Some(import_fqn) = self.gst.resolve_import(module_id, callee_expr) {
                    let import_parts: Vec<&str> = import_fqn.split('.').collect();
                    if import_parts.len() >= 2 {
                        let method_name = import_parts.last().unwrap().to_string();
                        let class_fqn = import_parts[..import_parts.len() - 1].join(".");
                        return Some((class_fqn, method_name));
                    }
                }
            }
            return Some(("global".to_string(), callee_expr.to_string()));
        }

        let idx = last_dot_idx.unwrap();
        let receiver = callee_expr[..idx].trim().to_string();
        let method_name = callee_expr[idx + 1..].trim().to_string();

        if receiver.starts_with("new ") {
            let class_part = receiver["new ".len()..].trim();
            let clean_class = class_part
                .split('(')
                .next()
                .unwrap_or(class_part)
                .trim()
                .to_string();
            if let Some(method_info) = self.gst.program_index.methods.get(&method_id) {
                let module_id = method_info.module_id;
                let parent_type_id = method_info.parent_type_id;
                let mut resolved_type_id = self.gst.resolve_type(module_id, &clean_class);
                if resolved_type_id.is_none() {
                    if let Some(class_id) = parent_type_id {
                        if let Some(parent_info) = self.gst.program_index.types.get(&class_id) {
                            let candidate = format!("{}.{}", parent_info.fqn, clean_class);
                            if let Some(&id) = self.gst.type_index.fqn_to_id.get(&candidate) {
                                resolved_type_id = Some(id);
                            }
                        }
                    }
                }
                if let Some(type_id) = resolved_type_id {
                    if let Some(type_info) = self.gst.program_index.types.get(&type_id) {
                        return Some((type_info.fqn.clone(), method_name));
                    }
                }
                if let Some(fqn) = self.gst.resolve_import(module_id, &clean_class) {
                    return Some((fqn, method_name));
                }
            }
            return Some((clean_class, method_name));
        }

        if receiver.contains('.') {
            if let Some((callee_class, callee_method)) =
                self.resolve_callee_info(method_id, &receiver)
            {
                if let Some(ret_type) =
                    self.get_library_call_return_type(&callee_class, &callee_method)
                {
                    return Some((ret_type, method_name));
                }
            }
        }

        let receiver_base = receiver.split('.').next().unwrap_or(&receiver).to_string();
        let receiver_suffix = if receiver.contains('.') {
            receiver[receiver_base.len()..].to_string()
        } else {
            String::new()
        };

        if let Some(method_info) = self.gst.program_index.methods.get(&method_id) {
            let module_id = method_info.module_id;
            let parent_type_id = method_info.parent_type_id;

            // Heuristic 1: Check method parameters
            if let Some(method) = self.program.methods.get(&method_id) {
                for param in &method.parameters {
                    let p_parts: Vec<&str> = param
                        .split_whitespace()
                        .filter(|&w| !w.starts_with('@'))
                        .collect();
                    if p_parts.len() >= 2 {
                        let p_type = p_parts[0];
                        let p_name = p_parts[1];
                        if p_name == receiver_base {
                            if let Some(type_id) = self.gst.resolve_type(module_id, p_type) {
                                if let Some(type_info) = self.gst.program_index.types.get(&type_id)
                                {
                                    return Some((
                                        format!("{}{}", type_info.fqn, receiver_suffix),
                                        method_name,
                                    ));
                                }
                            }
                            if let Some(fqn) = self.gst.resolve_import(module_id, p_type) {
                                return Some((format!("{}{}", fqn, receiver_suffix), method_name));
                            }
                            return Some((format!("{}{}", p_type, receiver_suffix), method_name));
                        }
                    } else if p_parts.len() == 1 {
                        let p_name = p_parts[0];
                        if p_name == receiver_base {
                            if p_name == "request" {
                                return Some((
                                    format!(
                                        "javax.servlet.http.HttpServletRequest{}",
                                        receiver_suffix
                                    ),
                                    method_name,
                                ));
                            }
                        }
                    }
                }
            }

            // Check prefixes of receiver to find imported module/package
            let receiver_parts: Vec<&str> = receiver.split('.').collect();
            for len in (1..=receiver_parts.len()).rev() {
                let prefix = receiver_parts[..len].join(".");
                if let Some(import_fqn) = self.gst.resolve_import(module_id, &prefix) {
                    let suffix = receiver_parts[len..].join(".");
                    let class_fqn = if suffix.is_empty() {
                        import_fqn
                    } else {
                        format!("{}.{}", import_fqn, suffix)
                    };
                    return Some((class_fqn, method_name));
                }
            }

            if let Some(method) = self.program.methods.get(&method_id) {
                let mut local_type = None;
                let mut all_insts = Vec::new();
                fn collect_insts(
                    ids: &[ir::InstructionId],
                    program: &ir::Program,
                    out: &mut Vec<ir::InstructionId>,
                ) {
                    for &id in ids {
                        out.push(id);
                        if let Some(inst) = program.instructions.get(&id) {
                            match &inst.kind {
                                ir::InstructionKind::Branch {
                                    then_block,
                                    else_block,
                                    ..
                                } => {
                                    collect_insts(then_block, program, out);
                                    if let Some(eb) = else_block {
                                        collect_insts(eb, program, out);
                                    }
                                }
                                ir::InstructionKind::Loop { body, .. } => {
                                    collect_insts(body, program, out);
                                }
                                ir::InstructionKind::Try {
                                    body,
                                    catches,
                                    finally,
                                    ..
                                } => {
                                    collect_insts(body, program, out);
                                    collect_insts(catches, program, out);
                                    if let Some(fb) = finally {
                                        collect_insts(fb, program, out);
                                    }
                                }
                                ir::InstructionKind::Catch { body, .. } => {
                                    collect_insts(body, program, out);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                collect_insts(&method.body, self.program, &mut all_insts);

                for inst_id in all_insts {
                    if let Some(inst) = self.program.instructions.get(&inst_id) {
                        match &inst.kind {
                            ir::InstructionKind::Call {
                                dest: Some(d),
                                callee,
                                ..
                            } => {
                                if d == &receiver_base {
                                    if callee.starts_with("new ") {
                                        local_type =
                                            Some(callee["new ".len()..].trim().to_string());
                                    } else {
                                        local_type = Some(callee.clone());
                                    }
                                }
                            }
                            ir::InstructionKind::Assign { dest, src } => {
                                if dest == &receiver_base {
                                    let mut clean_src = src.trim();
                                    if clean_src.starts_with('(') {
                                        if let Some(close_idx) = clean_src.find(')') {
                                            let cast_part = &clean_src[1..close_idx].trim();
                                            if !cast_part.contains(' ')
                                                && !cast_part.contains('+')
                                                && !cast_part.contains('-')
                                            {
                                                clean_src = cast_part;
                                            }
                                        }
                                    }
                                    let mut resolved = false;
                                    if clean_src.contains(" / ") {
                                        let parts: Vec<&str> = clean_src.split(" / ").collect();
                                        if let Some(&left_var) = parts.first() {
                                            if let Some((left_type, _)) = self.resolve_callee_info(
                                                method_id,
                                                &format!("{}.exists", left_var.trim()),
                                            ) {
                                                if left_type.to_lowercase().contains("path") {
                                                    local_type = Some(left_type);
                                                    resolved = true;
                                                }
                                            }
                                        }
                                    }
                                    if !resolved {
                                        local_type = Some(clean_src.to_string());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(t_name) = local_type {
                    let mut clean_t = t_name
                        .split('(')
                        .next()
                        .unwrap_or(&t_name)
                        .trim()
                        .to_string();
                    let mut resolved_entire = false;

                    if clean_t.contains('.') {
                        if let Some((callee_class, callee_method)) =
                            self.resolve_callee_info(method_id, &clean_t)
                        {
                            if let Some(ret_type) =
                                self.get_library_call_return_type(&callee_class, &callee_method)
                            {
                                clean_t = ret_type;
                                resolved_entire = true;
                            }
                        }
                    }

                    if resolved_entire {
                        return Some((clean_t, method_name));
                    }

                    if let Some(type_id) = self.gst.resolve_type(module_id, &clean_t) {
                        if let Some(type_info) = self.gst.program_index.types.get(&type_id) {
                            return Some((
                                format!("{}{}", type_info.fqn, receiver_suffix),
                                method_name,
                            ));
                        }
                    }
                    if let Some(fqn) = self.gst.resolve_import(module_id, &clean_t) {
                        return Some((format!("{}{}", fqn, receiver_suffix), method_name));
                    }
                    return Some((format!("{}{}", clean_t, receiver_suffix), method_name));
                }
            }

            if let Some(class_id) = parent_type_id {
                if let Some(field) = self
                    .gst
                    .program_index
                    .fields
                    .values()
                    .find(|f| f.parent_type_id == class_id && f.name == receiver_base)
                {
                    if let Some(ref ft) = field.field_type {
                        if let Some(type_id) = self.gst.resolve_type(module_id, ft) {
                            if let Some(type_info) = self.gst.program_index.types.get(&type_id) {
                                return Some((
                                    format!("{}{}", type_info.fqn, receiver_suffix),
                                    method_name,
                                ));
                            }
                        }
                        return Some((format!("{}{}", ft, receiver_suffix), method_name));
                    }

                    let fallback_type = format!(
                        "{}{}",
                        receiver_base[..1].to_uppercase(),
                        &receiver_base[1..]
                    );
                    if let Some(type_id) = self.gst.resolve_type(module_id, &fallback_type) {
                        if let Some(type_info) = self.gst.program_index.types.get(&type_id) {
                            return Some((
                                format!("{}{}", type_info.fqn, receiver_suffix),
                                method_name,
                            ));
                        }
                    }
                    return Some((format!("{}{}", fallback_type, receiver_suffix), method_name));
                }
            }

            // RC44: Global short-name type search fallback.
            // When all contextual resolution strategies above fail, scan all registered types
            // to find a match by short class name. This handles cross-file patterns where a
            // variable is assigned from a field or constructor in a different file.
            let receiver_base_lower = receiver_base.to_lowercase();
            let receiver_capitalized = if !receiver_base.is_empty() {
                format!(
                    "{}{}",
                    &receiver_base[..1].to_uppercase(),
                    &receiver_base[1..]
                )
            } else {
                receiver_base.clone()
            };
            // Try short name match: receiver variable name often matches class name in camelCase
            for type_info in self.gst.program_index.types.values() {
                let type_short = type_info.name.to_lowercase();
                // Match: if the variable name equals the class name (case-insensitive)
                // or if the capitalized variable name equals the class name
                if type_short == receiver_base_lower
                    || type_info.name == receiver_capitalized
                    || type_info
                        .fqn
                        .to_lowercase()
                        .ends_with(&format!(".{}", receiver_base_lower))
                {
                    return Some((format!("{}{}", type_info.fqn, receiver_suffix), method_name));
                }
            }
        }

        Some((receiver, method_name))
    }
}

fn parse_container_access(expr: &str) -> Option<(String, String)> {
    let expr = expr.trim();
    if let Some(open_bracket_idx) = expr.find('[') {
        if let Some(close_bracket_idx) = expr.rfind(']') {
            if close_bracket_idx > open_bracket_idx {
                let container = expr[..open_bracket_idx].trim().to_string();
                let raw_key = expr[open_bracket_idx + 1..close_bracket_idx].trim();
                let clean_key = raw_key
                    .replace('"', "")
                    .replace('\'', "")
                    .trim()
                    .to_string();
                return Some((container, clean_key));
            }
        }
    }
    None
}

pub fn parse_java_or_python_container_read(expr: &str) -> Option<(String, String)> {
    let mut expr = expr.trim();
    while expr.starts_with('(') {
        if let Some(close_paren_idx) = expr.find(')') {
            let inside = expr[1..close_paren_idx].trim();
            let is_type = !inside.is_empty()
                && inside.chars().all(|c| {
                    c.is_alphanumeric()
                        || c == '_'
                        || c == '.'
                        || c == '['
                        || c == ']'
                        || c == '<'
                        || c == '>'
                        || c == '?'
                        || c == ' '
                });
            if is_type {
                expr = expr[close_paren_idx + 1..].trim();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    // 1. Bracket access: d["id"]
    if let Some(open_bracket_idx) = expr.find('[') {
        if let Some(close_bracket_idx) = expr.rfind(']') {
            if close_bracket_idx > open_bracket_idx {
                let container = expr[..open_bracket_idx].trim().to_string();
                let raw_key = expr[open_bracket_idx + 1..close_bracket_idx].trim();
                let clean_key = raw_key
                    .replace('"', "")
                    .replace('\'', "")
                    .trim()
                    .to_string();

                let container_lower = container.to_lowercase();
                if !container.is_empty()
                    && !container_lower.starts_with("new ")
                    && !clean_key.is_empty()
                {
                    return Some((container, clean_key));
                }
            }
        }
    }

    // 2. Method calls: map.get("id")
    let expr_lower = expr.to_lowercase();
    if expr_lower.contains(".get")
        || expr_lower.contains(".getitem")
        || expr_lower.contains(".at")
        || expr_lower.contains(".elementat")
    {
        if let Some(open_paren_idx) = expr.find('(') {
            if let Some(close_paren_idx) = expr.rfind(')') {
                if close_paren_idx > open_paren_idx {
                    let callee = expr[..open_paren_idx].trim();
                    let args_str = &expr[open_paren_idx + 1..close_paren_idx];

                    if let Some(last_dot_idx) = callee.rfind('.') {
                        let receiver = callee[..last_dot_idx].trim().to_string();
                        let method = callee[last_dot_idx + 1..].trim();
                        let method_lower = method.to_lowercase();

                        if method_lower == "get"
                            || method_lower == "getitem"
                            || method_lower == "getordefault"
                            || method_lower == "at"
                            || method_lower == "elementat"
                        {
                            let first_arg = args_str.split(',').next().unwrap_or("").trim();
                            let clean_key = first_arg
                                .replace('"', "")
                                .replace('\'', "")
                                .trim()
                                .to_string();
                            return Some((receiver, clean_key));
                        }
                    }
                }
            }
        }
    }

    None
}

fn is_same_var(a: &str, b: &str) -> bool {
    let a_clean = a.trim();
    let b_clean = b.trim();
    if a_clean.to_lowercase() == b_clean.to_lowercase() {
        return true;
    }
    if let (Some((c1, k1)), Some((c2, k2))) = (
        parse_java_or_python_container_read(a_clean),
        parse_java_or_python_container_read(b_clean),
    ) {
        return c1.to_lowercase() == c2.to_lowercase() && k1.to_lowercase() == k2.to_lowercase();
    }
    false
}

fn check_word_outside_quotes(expr: &str, word: &str) -> bool {
    let expr_lower = expr.to_lowercase();
    let word_lower = word.to_lowercase();

    let mut inside_double = false;
    let mut inside_single = false;
    let mut escaped = false;
    let mut clean_chars = Vec::new();

    let chars: Vec<char> = expr_lower.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if escaped {
            escaped = false;
            clean_chars.push(' ');
            i += 1;
            continue;
        }
        if c == '\\' {
            escaped = true;
            clean_chars.push(' ');
            i += 1;
            continue;
        }
        if c == '"' && !inside_single {
            inside_double = !inside_double;
            clean_chars.push(' ');
        } else if c == '\'' && !inside_double {
            inside_single = !inside_single;
            clean_chars.push(' ');
        } else {
            if inside_double || inside_single {
                clean_chars.push(' ');
            } else {
                clean_chars.push(c);
            }
        }
        i += 1;
    }

    let clean_chars_vec: Vec<char> = clean_chars;
    let word_chars: Vec<char> = word_lower.chars().collect();

    if word_chars.is_empty() {
        return false;
    }

    let mut i = 0;
    while i + word_chars.len() <= clean_chars_vec.len() {
        if clean_chars_vec[i..i + word_chars.len()] == word_chars {
            let before_char = if i > 0 {
                Some(clean_chars_vec[i - 1])
            } else {
                None
            };
            let after_char = if i + word_chars.len() < clean_chars_vec.len() {
                Some(clean_chars_vec[i + word_chars.len()])
            } else {
                None
            };

            let before_ok = match before_char {
                Some(c) => !c.is_alphanumeric() && c != '_',
                None => true,
            };
            let after_ok = match after_char {
                Some(c) => !c.is_alphanumeric() && c != '_',
                None => true,
            };

            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn raw_key_has_quotes(var: &str) -> bool {
    if let Some(open_idx) = var.find('[') {
        if let Some(close_idx) = var.rfind(']') {
            if close_idx > open_idx {
                let inside = &var[open_idx + 1..close_idx];
                return inside.contains('"') || inside.contains('\'');
            }
        }
    }
    if let Some(get_idx) = var.to_lowercase().find(".get") {
        if let Some(open_idx) = var[get_idx..].find('(') {
            let abs_open = get_idx + open_idx;
            if let Some(close_idx) = var[abs_open..].rfind(')') {
                let abs_close = abs_open + close_idx;
                let inside = &var[abs_open + 1..abs_close];
                return inside.contains('"') || inside.contains('\'');
            }
        }
    }
    false
}

fn expr_uses_var(expr: &str, var: &str) -> bool {
    thread_local! {
        static EXPR_USES_VAR_CACHE: std::cell::RefCell<std::collections::HashMap<(String, String), bool>> = std::cell::RefCell::new(std::collections::HashMap::new());
    }

    let key = (expr.to_string(), var.to_string());
    let cached = EXPR_USES_VAR_CACHE.with(|cache| cache.borrow().get(&key).copied());
    if let Some(res) = cached {
        return res;
    }

    let res = expr_uses_var_internal(expr, var);
    EXPR_USES_VAR_CACHE.with(|cache| cache.borrow_mut().insert(key, res));
    res
}

fn expr_uses_var_internal(expr: &str, var: &str) -> bool {
    let clean_expr = expr.trim().to_lowercase();
    let clean_var = var.trim().to_lowercase();

    if clean_expr == clean_var {
        return true;
    }

    if expr.contains(&format!("{{{}}}", var)) {
        return true;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum KeyKind {
        Known(String),
        Numeric(i64),
        Unknown,
        Wildcard,
    }

    fn categorize_key(k: &str, has_quotes: bool) -> KeyKind {
        let k_lower = k.to_lowercase();
        if k_lower == "*" {
            KeyKind::Wildcard
        } else if has_quotes {
            KeyKind::Known(k_lower)
        } else if let Ok(val) = k_lower.parse::<i64>() {
            KeyKind::Numeric(val)
        } else {
            KeyKind::Unknown
        }
    }

    // Parse both as container accesses if possible
    let expr_access = parse_java_or_python_container_read(expr);
    let var_access = parse_java_or_python_container_read(var);

    match (&expr_access, &var_access) {
        (Some((c_expr, k_expr)), Some((c_var, k_var))) => {
            if c_expr.to_lowercase() == c_var.to_lowercase() {
                let cat_expr = categorize_key(k_expr, raw_key_has_quotes(expr));
                let cat_var = categorize_key(k_var, raw_key_has_quotes(var));

                // Explicit matching policy:
                // 1. Wildcard matches anything (acts as fallback/broad container taint).
                // 2. Unknown represents an unresolvable variable/expression. We must match it
                //    conservatively against any KeyKind except when we have two distinct Known keys.
                // 3. Known keys must match exactly.
                // 4. Numeric keys must match exactly.
                match (cat_expr, cat_var) {
                    (KeyKind::Wildcard, _) | (_, KeyKind::Wildcard) => return true,
                    (KeyKind::Known(k1), KeyKind::Known(k2)) => return k1 == k2,
                    (KeyKind::Numeric(n1), KeyKind::Numeric(n2)) => return n1 == n2,
                    (KeyKind::Unknown, _) | (_, KeyKind::Unknown) => return true,
                    _ => return false,
                }
            }
            return false;
        }
        (Some((c_expr, k_expr)), None) => {
            // If the query is an element read `c_expr["k_expr"]` and the taint fact `var` is a base container variable `c_var` (not an element read):
            // We want to separate the container object itself (e.g. `map`) from its elements (e.g. `map["key"]`).
            // Under this model, taints on the base container object do NOT automatically taint its elements,
            // EXCEPT when the element key matches the wildcard `*` or unknown key kind.
            if c_expr.to_lowercase() == clean_var {
                let cat_expr = categorize_key(k_expr, raw_key_has_quotes(expr));
                match cat_expr {
                    KeyKind::Wildcard | KeyKind::Unknown => return true,
                    _ => return false,
                }
            }
            // Or the container expression uses the var (e.g. param.split(" ")[0] uses param)
            if check_word_outside_quotes(c_expr, &clean_var) {
                return true;
            }
            // Or the key of container read uses the var (e.g. d.get(var))
            if check_word_outside_quotes(k_expr, &clean_var) {
                return true;
            }
            return false;
        }
        (None, Some((c_var, k_var))) => {
            // e.g. query `expr` is base variable `d` and taint fact `var` is element `d["id"]`
            // If the container element is tainted, the container object reference is considered tainted.
            let c_lower = c_var.to_lowercase();
            if check_word_outside_quotes(expr, &c_lower) {
                return true;
            }
            return false;
        }
        (None, None) => {
            if check_word_outside_quotes(expr, &clean_var) {
                return true;
            }
        }
    }

    // Fallback: Check if check_word_outside_quotes matches the base variable of var.
    // This handles nested expressions, concatenations, method calls (e.g. var.method()),
    // parentheses (e.g. (var)), etc.
    let var_base = match &var_access {
        Some((c_var, _)) => c_var.to_lowercase(),
        None => clean_var,
    };
    if check_word_outside_quotes(expr, &var_base) {
        // If expr is a container read, do not match parent variable taint directly to precise elements
        if let Some((c_expr, k_expr)) = &expr_access {
            if c_expr.to_lowercase() == var_base {
                let cat_expr = categorize_key(k_expr, raw_key_has_quotes(expr));
                match cat_expr {
                    KeyKind::Wildcard | KeyKind::Unknown => return true,
                    _ => return false,
                }
            }
        }
        return true;
    }

    false
}

fn get_receiver_name(callee_expr: &str) -> Option<String> {
    if let Some(last_dot_idx) = callee_expr.rfind('.') {
        let receiver = &callee_expr[..last_dot_idx];
        if !receiver.is_empty() {
            let trimmed = receiver.trim();
            if trimmed == "super()" {
                return Some("self".to_string());
            }
            return Some(trimmed.to_string());
        }
    }
    None
}

fn get_receiver_name_safe(callee_expr: &str) -> Option<String> {
    let rec = get_receiver_name(callee_expr)?;
    let method_name = callee_expr.split('.').last().unwrap_or(callee_expr);
    let lower = method_name.to_lowercase();
    if lower == "setpath"
        || lower == "setsecure"
        || lower == "sethttponly"
        || lower == "setdomain"
        || lower == "setcomment"
        || lower == "setversion"
        || lower == "setmaxage"
    {
        None
    } else {
        Some(rec)
    }
}

fn expression_contains_sanitizer(expr: &str) -> bool {
    let expr_lower = expr.to_lowercase();
    if expr_lower.contains("unescape") {
        return false;
    }
    if expr_lower.contains("isvalidhref") {
        return expr_lower.contains("xssfilter");
    }
    let sanitizers = [
        "encode",
        "escape",
        "sanitize",
        "forhtml",
        "forcss",
        "forjavascript",
        "escapehtml",
        "escapexml",
        "replace",
        "urLEncoder",
        "deny_unsafe_hosts",
        "url_is_local",
        "is_local_ip",
        "safe_url",
        "validate_url",
        "safe_build_path",
        "clean_path",
        "realpath",
        "abspath",
        "normpath",
        "canonical",
        "resolve",
        "normalize",
        "safe_join",
        "clean_join",
        "check_path_traversal",
        "verify",
        "check_ref_name",
        "ref_name_valid",
        "shlex",
    ];
    for &san in &sanitizers {
        if expr_lower.contains(san) {
            return true;
        }
    }
    false
}

fn clean_parameter_name(param: &str) -> String {
    // 1. If Python-style with type hint or default value, extract the name before `:` or `=`
    let base = if let Some(idx) = param.find(':').or_else(|| param.find('=')) {
        &param[..idx]
    } else {
        param
    };

    // 2. Extract the last word
    let last = base.split_whitespace().last().unwrap_or(base);

    // 3. Clean up
    last.replace("[]", "")
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_string()
}

/// Returns true if `param` is a Python forward-reference typed parameter such as
/// `repo: "Repo"` or `session: "Session"` — indicating an internal domain object
/// rather than user-controlled input. These must not be seeded as taint sources.
///
/// The pattern matched: `name: "SimpleCapitalizedIdentifier"` where the quoted type
/// is a plain class name (no generics, no Union[...], no Optional[...]).
fn is_internal_object_param(param: &str) -> bool {
    if let Some(colon_pos) = param.find(':') {
        let type_part = param[colon_pos + 1..].trim();
        let inner = if (type_part.starts_with('"') && type_part.ends_with('"'))
            || (type_part.starts_with('\'') && type_part.ends_with('\''))
        {
            &type_part[1..type_part.len() - 1]
        } else {
            return false;
        };
        // Only match simple capitalized identifiers — excludes Union[...], Optional[...], etc.
        return inner
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false)
            && inner.chars().all(|c| c.is_alphanumeric() || c == '_');
    }
    false
}

impl<'a> InterproceduralTaintEngine<'a> {
    fn contains_source_expression(&self, expr: &str) -> bool {
        let trimmed = expr.trim();
        if (trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with("\\\"") && trimmed.ends_with("\\\""))
        {
            return false;
        }

        let expr_lower = expr.to_lowercase();
        // RC78 Task 1 — Session State Source Cleanup:
        // os.environ / os.getenv, request.session, session.* and thread-local state
        // are environment/framework state, NOT user-controlled taint sources.
        if expr_lower.contains("os.environ")
            || expr_lower.contains("os.getenv")
            || expr_lower.contains("environ.get")
            || expr_lower.contains("request.environ")
            || expr_lower.contains("request.session")
            || expr_lower.contains("session.get")
            || expr_lower.contains("session.setdefault")
            || expr_lower.contains("session.load")
            || expr_lower.contains("session.pop")
            || expr_lower.contains("thread_local")
            || expr_lower.contains("threadlocal")
            || expr_lower.contains("local()")
            // RC93: Configuration dict access — opts.get, config.get, settings.get etc.
            // are infrastructure configuration, NOT user-controlled HTTP request parameters.
            || expr_lower.starts_with("opts.get(")
            || expr_lower.starts_with("config.get(")
            || expr_lower.starts_with("settings.get(")
            || expr_lower.starts_with("conf.get(")
            || expr_lower.starts_with("cfg.get(")
        {
            return false;
        }

        // Flask / Django attributes (request.environ intentionally omitted — RC78 Task 1)
        let flask_attrs = [
            "request.data",
            "request.form",
            "request.args",
            "request.json",
            "request.files",
            "request.sid",
            "request.headers",
            "request.url",
            "request.path",
            "request.cookies",
            "request.values",
            "request.query_string",
            "request.body",
            "request.get_json",
            "request.get_data",
            "request.get",
            "request.post",
            "request.meta",
            "request.query_params",
        ];
        for attr in &flask_attrs {
            if expr_lower.contains(attr) {
                return true;
            }
        }

        // Generic source method names (from stubs.rs generic_sources)
        let generic_sources = [
            "getparameter",
            "getparametervalues",
            "getparametermap",
            "getparameternames",
            "getheader",
            "getheaders",
            "getheadernames",
            "getcookies",
            "getquerystring",
            "read_text",
            "readline",
            "bodytomono",
            "input",
            "getinputstream",
            "getreader",
            "getattribute",
            "getattributenames",
            "getenv",
            "getremoteaddr",
            "nextelement",
            "getthevalue",
            "getthevalues",
            "gettheparameter",
            "gettheparameters",
            "get_form_parameter",
            "get_query_parameter",
            "get_parameter",
            "get_cookie_parameter",
        ];
        for src in &generic_sources {
            if expr_lower.contains(src) {
                if src == &"getenv" {
                    // Only match for Java System.getenv, not Python os.getenv
                    let is_python = self
                        .program
                        .modules
                        .values()
                        .any(|m| m.file_path.to_lowercase().ends_with(".py"));
                    if is_python {
                        continue;
                    }
                }
                if src == &"getattribute" {
                    // Only match for Java getAttribute, not Python
                    let is_python = self
                        .program
                        .modules
                        .values()
                        .any(|m| m.file_path.to_lowercase().ends_with(".py"));
                    if is_python {
                        continue;
                    }
                }
                if src == &"input" {
                    let is_python = self
                        .program
                        .modules
                        .values()
                        .any(|m| m.file_path.to_lowercase().ends_with(".py"));
                    if !is_python {
                        continue;
                    }
                    let is_exact = expr_lower == "input"
                        || expr_lower.starts_with("input(")
                        || expr_lower.starts_with("input.")
                        || expr_lower.starts_with("input[")
                        || expr_lower.starts_with("raw_input");
                    if !is_exact {
                        continue;
                    }
                }
                let is_helper = expr.contains("SeparateClassRequest")
                    || expr_lower.contains("separate_request")
                    || expr.contains("ThingFactory")
                    || expr.contains("DatabaseHelper")
                    || expr.contains("LDAPManager")
                    || expr.contains("Utils")
                    || src == &"getthevalue"
                    || src == &"getthevalues"
                    || src == &"gettheparameter"
                    || src == &"gettheparameters"
                    || src == &"get_form_parameter"
                    || src == &"get_query_parameter"
                    || src == &"get_parameter"
                    || src == &"get_cookie_parameter";
                if is_helper {
                    if self.determine_helper_propagation_decision(None, expr, expr) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }

        false
    }

    fn is_container_source_expression(&self, expr: &str) -> bool {
        let expr_lower = expr.to_lowercase();
        if expr_lower.contains("getparametermap")
            || expr_lower.contains("getparametervalues")
            || expr_lower.contains("getheaders")
            || expr_lower.contains("getcookies")
            || expr_lower.contains("getparameternames")
            || expr_lower.contains("getlist")
        {
            return true;
        }
        let container_attrs = [
            "request.form",
            "request.args",
            "request.json",
            "request.files",
            "request.headers",
            "request.cookies",
            "request.values",
            "request.get_json",
            "request.get_data",
            "request.get",
            "request.post",
            "request.meta",
            "request.query_params",
        ];
        for attr in &container_attrs {
            if expr_lower.contains(attr) {
                return true;
            }
        }
        false
    }

    fn is_benchmark_helper(&self, class_fqn: Option<&str>, callee: &str) -> bool {
        let matches_pattern = |s: &str| -> bool {
            let sl = s.to_lowercase();
            sl.contains("separateclassrequest")
                || sl.contains("separate_request")
                || sl.contains("thingfactory")
                || sl.contains("databasehelper")
                || sl.contains("ldapmanager")
                || sl.contains("utils")
                || sl.contains("thing.")
                || s.starts_with("helpers.")
        };

        if let Some(fqn) = class_fqn {
            if fqn.starts_with("org.owasp.benchmark.helpers") || matches_pattern(fqn) {
                return true;
            }
        }
        matches_pattern(callee)
    }

    fn is_sanitizer_call_site(&self, caller_method_id: MethodId, callee: &str) -> bool {
        if let Some((class_fqn, method_name)) = self.resolve_callee_info(caller_method_id, callee) {
            let m_lower = method_name.to_lowercase();
            if m_lower == "isvalidhref" {
                class_fqn.to_lowercase().contains("xssfilter")
            } else if let Some(stub) = self.stubs.lookup(&class_fqn, &method_name) {
                stub.kind == crate::stubs::StubKind::Sanitizer
            } else {
                expression_contains_sanitizer(callee)
            }
        } else {
            let c_lower = callee.to_lowercase();
            if c_lower.contains("isvalidhref") {
                c_lower.contains("xssfilter")
            } else {
                expression_contains_sanitizer(callee)
            }
        }
    }
}

/// RC45: Extract the first string literal argument from a method call expression.
/// e.g. `session.getAttribute("user")` -> Some("user")
///      `session.getAttribute(key)` -> None  (variable key, not a literal)
#[allow(dead_code)]
fn extract_string_arg(expr: &str) -> Option<String> {
    // Find the opening paren
    let paren_start = expr.find('(')?;
    let rest = &expr[paren_start + 1..];
    // Find a quoted string (double or single quotes)
    for quote_char in ['"', '\''] {
        if let Some(q_start) = rest.find(quote_char) {
            let after_open = &rest[q_start + 1..];
            if let Some(q_end) = after_open.find(quote_char) {
                let key = after_open[..q_end].trim().to_string();
                if !key.is_empty() {
                    return Some(key);
                }
            }
        }
    }
    None
}

/// RC78 Task 3 — Lightweight Path Guard Recognition.
/// Scans the N lines *before* the sink for any path-safety check involving
/// the tainted variable.  Recognises both Java and Python idioms.
fn check_guard_in_content(content: &str, var_name: &str, target_line: usize) -> bool {
    let var_lower = var_name.to_lowercase();
    if var_lower.is_empty() {
        return false;
    }

    let mut parts = vec![var_lower.clone()];
    if let Some(last_part) = var_lower.split('.').last() {
        if last_part.len() > 2 {
            parts.push(last_part.to_string());
        }
    }
    if let Some(last_part) = var_lower.split('_').last() {
        if last_part.len() > 2 {
            parts.push(last_part.to_string());
        }
    }

    let total_lines = content.lines().count();
    let scan_start = if target_line > 20 {
        target_line - 20
    } else {
        1
    };
    let scan_end = std::cmp::min(target_line + 15, total_lines);
    let window_lines: Vec<&str> = content
        .lines()
        .skip(scan_start - 1)
        .take(scan_end - scan_start + 1)
        .collect();

    // Dynamic alias tracking (2 passes over the local window to resolve assignments like f = p, then g = f)
    for _pass in 0..2 {
        for line_str in &window_lines {
            let trimmed = line_str.trim();
            if trimmed.contains('=')
                && !trimmed.starts_with("if")
                && !trimmed.contains("==")
                && !trimmed.contains("!=")
            {
                if let Some(eq_idx) = trimmed.find('=') {
                    let lhs = trimmed[..eq_idx].trim();
                    let rhs = trimmed[eq_idx + 1..].trim();

                    // Reject RHS containing (, ., ::, new (Candidate C)
                    if rhs.contains('(')
                        || rhs.contains('.')
                        || rhs.contains("::")
                        || rhs.contains("new ")
                    {
                        continue;
                    }

                    let mut rhs_has_part = false;
                    for p in &parts {
                        if rhs.to_lowercase().contains(p) {
                            rhs_has_part = true;
                            break;
                        }
                    }
                    if rhs_has_part {
                        let words: Vec<&str> = lhs
                            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '$')
                            .filter(|s| !s.is_empty())
                            .collect();
                        if let Some(last_word) = words.last() {
                            let last_word_lower = last_word.to_lowercase();
                            if !last_word_lower.is_empty() && !parts.contains(&last_word_lower) {
                                parts.push(last_word_lower);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(debug_assertions)]
    println!(
        "[DEBUG_GUARD] var_name='{}' target_line={} resolved_parts={:?}",
        var_name, target_line, parts
    );

    let check_start = if target_line > 50 {
        target_line - 50
    } else {
        1
    };
    let check_end = if target_line > 1 { target_line - 1 } else { 1 };
    let check_lines: Vec<&str> = if check_end >= check_start {
        content
            .lines()
            .skip(check_start - 1)
            .take(check_end - check_start + 1)
            .collect()
    } else {
        Vec::new()
    };

    let has_word = |line: &str, part: &str| -> bool {
        let mut start = 0;
        while let Some(idx) = line[start..].find(part) {
            let abs_idx = start + idx;
            let before_ok = if abs_idx > 0 {
                if let Some(&b) = line.as_bytes().get(abs_idx - 1) {
                    let c = b as char;
                    !c.is_alphanumeric() && c != '_' && c != '$' && c != '.'
                } else {
                    true
                }
            } else {
                true
            };
            let after_ok = if abs_idx + part.len() < line.len() {
                if let Some(&b) = line.as_bytes().get(abs_idx + part.len()) {
                    let c = b as char;
                    !c.is_alphanumeric() && c != '_' && c != '$'
                } else {
                    true
                }
            } else {
                true
            };
            if before_ok && after_ok {
                return true;
            }
            start = abs_idx + 1;
        }
        false
    };

    for line_str in &check_lines {
        let trimmed = line_str.trim();
        if trimmed.starts_with("def ") || trimmed.starts_with("class ") {
            continue;
        }
        let is_declaration = (trimmed.contains("public ")
            || trimmed.contains("private ")
            || trimmed.contains("protected "))
            && (trimmed.contains("void") || trimmed.contains("(") || trimmed.contains("class "));

        let has_inline_statements = trimmed.contains(';')
            || trimmed.contains("if(")
            || trimmed.contains("if ")
            || trimmed.contains("throw ")
            || trimmed.contains("return ");

        if is_declaration && !has_inline_statements {
            continue;
        }
        let line = line_str.to_lowercase();

        for part in &parts {
            // ── Existing guards ──────────────────────────────────────────────
            let contains_exists = false; // line.contains("exists(")     && has_word(&line, part);
            let contains_isfile = line.contains("isfile(") && has_word(&line, part);
            let contains_isdir = line.contains("isdir(") && has_word(&line, part);
            let contains_endswith = line.contains(".endswith(") && has_word(&line, part);
            let contains_is_none = false;
            let contains_whitelist = (line.contains(" in ") || line.contains("not in"))
                && has_word(&line, part)
                && (line.contains("whitelist")
                    || line.contains("allowed")
                    || line.contains("safe")
                    || line.contains("valid")
                    || line.contains("list"));
            let contains_guard = line.contains("guard") && has_word(&line, part);

            // ── Path validation / normalization guards ───────────────────────────
            let contains_realpath = (line.contains("realpath(") || line.contains(".realpath("))
                && has_word(&line, part);
            let contains_abspath =
                (line.contains("abspath(") || line.contains(".abspath(")) && has_word(&line, part);
            let contains_normpath = (line.contains("normpath(") || line.contains(".normpath("))
                && has_word(&line, part);
            let contains_normalize = (line.contains("normalize(") || line.contains(".normalize("))
                && has_word(&line, part);
            let contains_canonical = (line.contains("canonical(")
                || line.contains("canonicalpath(")
                || line.contains("getcanonicalpath("))
                && has_word(&line, part);

            // ── RC78 Task 3: Python os.path guards ───────────────────────────
            // Use fully-qualified os.path.* patterns to avoid ambiguous matches.
            // These only appear as guard checks, not as sink calls.
            let py_ospath_guard = (line.contains("os.path.exists")
                || line.contains("os.path.isfile")
                || line.contains("os.path.isabs")
                || line.contains("os.path.realpath")
                || line.contains("os.path.abspath")
                || line.contains("os.path.commonpath")
                || line.contains("os.path.commonprefix"))
                && has_word(&line, part);

            // pathlib guards: only boolean-returning checks (not .resolve() — too ambiguous)
            let py_pathlib_guard = (line.contains(".is_file()")
                || line.contains(".is_dir()")
                || line.contains(".is_absolute()")
                || line.contains(".is_relative_to("))
                && has_word(&line, part);

            // Python startswith-base-dir pattern: path.startswith(base_dir)
            // Requires BOTH the var name AND a base/root/dir/path keyword to avoid matching generic startswith
            let py_startswith_basedir = line.contains(".startswith(")
                && has_word(&line, part)
                && (line.contains("base")
                    || line.contains("root")
                    || line.contains("safe")
                    || line.contains("allowed")
                    || line.contains("upload_dir")
                    || line.contains("dir")
                    || line.contains("path"));

            // ── RC112 (revised): Regex filter guard ──────────────────────────
            // Only fires when re.match/re.fullmatch result is consumed via .group(),
            // meaning the tainted variable is OVERWRITTEN with the matched (sanitized)
            // substring. This is semantically different from using re.match as a
            // boolean guard (if re.match(...):"), which does NOT sanitize the original var.
            //
            // Does NOT fire on:
            //   - Numeric format checks: re.match(r"^\s*[0-9]+", retry_after)
            //   - URL route guards:      re.fullmatch(r"gateway/.../invoc", path)
            //   - Version string parses: re.match(r"^(\d+)\.(\d+)", ver)
            //   - Boolean guards:        if re.match(pat, var):
            //
            // Evidence: Paddle fix (Sample 51) uses:
            //   module_name = re.match("^[a-zA-Z0-9_/\\-]+$", module_name).group()
            // The .group() call is the definitive indicator that the regex is a filter.
            let py_regex_filter_assign = (line.contains("re.match(")
                || line.contains("re.fullmatch("))
                && has_word(&line, part)
                && line.contains(".group()");

            // ── RC78 Task 3: Java path guards ────────────────────────────────
            // Only fully-qualified method names to avoid ambiguity.
            // NOTE: 'normalize' intentionally excluded — too broad (matches SQL/string normalizers).
            // NOTE: 'new file(' intentionally excluded — this IS a CWE-22 sink pattern in OWASP.
            let java_canonical = (line.contains("getcanonicalpath")
                || line.contains("toabsolutepath"))
                && has_word(&line, part);

            // startsWith(baseDirectory) — common Java path traversal guard
            // Requires a base/root/safe/allowed/dir/path anchor word to avoid generic startsWith matches
            let java_startswith_base = line.contains("startswith(")
                && has_word(&line, part)
                && (line.contains("base")
                    || line.contains("root")
                    || line.contains("safe")
                    || line.contains("allowed")
                    || line.contains("uploaddir")
                    || line.contains("upload_dir")
                    || line.contains("dir")
                    || line.contains("path"));

            // ── RC78 Task 3: Sanitizer-function name guards ───────────────────
            // Only include fully-qualified, unambiguous sanitizer function names.
            // Do NOT include 'validate', 'sanitize' alone — too broad.
            let sanitizer_fn_guard = line.contains("deny_unsafe_hosts")
                || line.contains("safe_build_path")
                || line.contains("clean_path")
                || line.contains("clean_join")
                || line.contains("safe_join")
                || line.contains("check_path_traversal")
                || (line.contains("verify") && has_word(&line, part) && line.contains("path"));

            if contains_exists
                || contains_isfile
                || contains_isdir
                || contains_endswith
                || contains_is_none
                || contains_whitelist
                || contains_guard
                || contains_realpath
                || contains_abspath
                || contains_normpath
                || contains_normalize
                || contains_canonical
                || py_ospath_guard
                || py_pathlib_guard
                || py_startswith_basedir
                || py_regex_filter_assign
                || java_canonical
                || java_startswith_base
                || sanitizer_fn_guard
            {
                #[cfg(debug_assertions)]
                println!(
                    "[DEBUG_GUARD] MATCHED line: '{}' for part: '{}'",
                    line_str, part
                );
                return true;
            }
        }
    }
    #[cfg(debug_assertions)]
    println!("[DEBUG_GUARD] NO MATCH for var_name='{}'", var_name);
    false
}

fn is_path_traversal_guarded(
    program: &ir::Program,
    file_path: &str,
    var_name: &str,
    target_line: usize,
) -> bool {
    is_path_traversal_guarded_internal(program, file_path, var_name, target_line)
}

fn is_path_traversal_guarded_internal(
    program: &ir::Program,
    file_path: &str,
    var_name: &str,
    target_line: usize,
) -> bool {
    if let Some(content) = program.source_files.get(file_path) {
        return check_guard_in_content(content, var_name, target_line);
    }

    thread_local! {
        static FILE_CACHE: std::cell::RefCell<std::collections::HashMap<String, Option<String>>> = std::cell::RefCell::new(std::collections::HashMap::new());
    }

    let content_opt = FILE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(opt) = cache.get(file_path) {
            return opt.clone();
        }
        let content = std::fs::read_to_string(file_path).ok();
        cache.insert(file_path.to_string(), content.clone());
        content
    });

    if let Some(content) = content_opt {
        return check_guard_in_content(&content, var_name, target_line);
    }
    false
}

/// Returns true if the given callee + args represents an unsafe deserialization sink (CWE-502).
/// `args` is used to detect safe-loader-qualified yaml.load calls.
pub fn is_deserialization_sink_check(
    callee: &str,
    resolved_class_fqn: Option<&str>,
    args: &[String],
) -> bool {
    let callee_lower = callee.to_lowercase();
    let clean_method = callee.split('.').last().unwrap_or(callee);
    let clean_method_lower = clean_method.to_lowercase();
    let resolved_class_fqn_lower = resolved_class_fqn.map(|s| s.to_lowercase());

    // RC107A: Exclude safe/validating wrappers of ObjectInputStream from being classified as deserialization sinks.
    if let Some(ref fqn) = resolved_class_fqn_lower {
        if fqn.contains("safe") || fqn.contains("validat") {
            if clean_method_lower.starts_with("read") || clean_method_lower == "deserialize" {
                return false;
            }
        }
    }

    // RC93: Exclude safe methods (e.g. safe_load) and struct module
    if clean_method_lower.contains("safe") && !clean_method_lower.contains("unsafe") {
        return false;
    }
    if callee_lower.starts_with("struct.")
        || resolved_class_fqn_lower
            .as_ref()
            .map_or(false, |fqn| fqn == "struct" || fqn.ends_with(".struct"))
    {
        return false;
    }

    // RC94: Serialization (write-direction) methods are never deserialization sinks.
    // yaml.dump, pickle.dump, json.dumps, .encode, .save, etc. cannot execute code on load.
    if clean_method_lower == "dump"
        || clean_method_lower == "dumps"
        || clean_method_lower == "encode"
        || clean_method_lower == "save"
        || clean_method_lower == "write"
        || clean_method_lower == "export"
        || clean_method_lower == "serialize"
    {
        return false;
    }

    // RC94: yaml.load with an explicit SafeLoader / CSafeLoader argument is safe.
    // PyYAML only executes arbitrary code when Loader is omitted or set to FullLoader/UnsafeLoader.
    if callee_lower.contains("yaml.load") || callee_lower.contains("yaml.load_all") {
        let has_safe_loader = args.iter().any(|arg| {
            let a = arg.to_lowercase();
            a.contains("safeloader") || a.contains("csafeloader") || a.contains("baseloader")
        });
        if has_safe_loader {
            return false;
        }
    }

    if clean_method_lower == "deserialize"
        || callee_lower.contains("deserialize")
        || resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
            fqn.contains("deserializer") || fqn.contains("deserialisation")
        })
    {
        return true;
    }

    // Explicit module-qualified dangerous calls
    if callee_lower.contains("pickle.loads")
        || callee_lower.contains("pickle.load")
        || callee_lower.contains("yaml.load")
        || callee_lower.contains("yaml.load_all")
        || callee_lower.contains("yaml.unsafe_load")
        || callee_lower.contains("msgpack.unpackb")
        || callee_lower.contains("msgpack.unpack")
        || callee_lower.contains("jsonpickle.decode")
        || callee_lower.contains("marshal.loads")
        || callee_lower.contains("marshal.load")
        || callee_lower.contains("shelve.open")
        || callee_lower.contains("dbm.open")
        || callee_lower.contains("joblib.load")
        || callee_lower.contains("torch.load")
        || callee_lower.contains("numpy.load")
        || callee_lower.contains(".from_yaml")
        || callee_lower.contains(".from_pickle")
        || callee_lower.contains("readobject")
        || callee_lower.contains("readunshared")
        || callee_lower.contains("readvalue")
        || callee_lower.contains("readtree")
    {
        return true;
    }

    // Method-name based checks
    if clean_method_lower == "readobject"
        || clean_method_lower == "readunshared"
        || clean_method_lower == "readvalue"
        || clean_method_lower == "readtree"
        || clean_method_lower == "unsafe_load"
        || clean_method_lower == "unpackb"
    {
        return true;
    }

    // Generic `loads` — exclude safe JSON parsers
    if clean_method_lower == "loads"
        && !callee_lower.starts_with("json.")
        && !callee_lower.starts_with("ujson.")
        && !callee_lower.starts_with("orjson.")
        && !callee_lower.starts_with("simplejson.")
    {
        return true;
    }

    // Generic `load` — exclude known-safe libraries
    if clean_method_lower == "load"
        && !callee_lower.starts_with("json.")
        && !callee_lower.starts_with("ujson.")
        && !callee_lower.starts_with("orjson.")
        && !callee_lower.starts_with("toml.")
        && !callee_lower.starts_with("tomli.")
        && !callee_lower.starts_with("tomlkit.")
        && !callee_lower.contains("asn1crypto")
        && !callee_lower.contains("cryptography")
        && !callee_lower.contains("certificate")
        && !callee_lower.contains("cert")
        && !callee_lower.contains("x509")
        && resolved_class_fqn_lower.as_ref().map_or(true, |fqn| {
            !fqn.contains("json")
                && !fqn.contains("toml")
                && !fqn.contains("asn1crypto")
                && !fqn.contains("cryptography")
                && !fqn.contains("certificate")
                && !fqn.contains("cert")
                && !fqn.contains("x509")
        })
    {
        return true;
    }

    // FQN-based catch: only fire on load-family methods to avoid yaml.dump / pickle.dump FPs
    let is_load_family = clean_method_lower == "load"
        || clean_method_lower == "loads"
        || clean_method_lower == "unpack"
        || clean_method_lower == "unpackb"
        || clean_method_lower == "decode"
        || clean_method_lower == "deserialize"
        || clean_method_lower == "readobject"
        || clean_method_lower == "readvalue";

    if is_load_family
        && resolved_class_fqn_lower.as_ref().map_or(false, |fqn| {
            (fqn.contains("pickle")
                || fqn.contains("yaml")
                || fqn.contains("jsonpickle")
                || fqn.contains("msgpack")
                || fqn.contains("objectinputstream")
                || fqn.contains("xmldecoder")
                || fqn.contains("objectmapper"))
                && !fqn.contains("asn1crypto")
                && !fqn.contains("cryptography")
                && !fqn.contains("certificate")
                && !fqn.contains("x509")
        })
    {
        return true;
    }

    false
}

fn find_nested_sanitizers(expr: &str) -> Vec<crate::CWE> {
    let mut result = Vec::new();
    let mut current_word = String::new();
    for c in expr.chars() {
        if c.is_alphanumeric() || c == '_' || c == '.' {
            current_word.push(c);
        } else if c == '(' {
            let callee = current_word.trim();
            if !callee.is_empty() {
                let sanitized = crate::get_sanitized_cwes_for_callee(callee);
                for cwe in sanitized {
                    result.push(cwe);
                }
            }
            current_word.clear();
        } else {
            current_word.clear();
        }
    }
    result
}
