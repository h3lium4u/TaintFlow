use normalizer::{NormalizedKind, NormalizedNode};

use serde::{Deserialize, Serialize};

use std::collections::HashSet;

use taint::{TaintEngine, CWE};



#[derive(Debug, Clone, Serialize, Deserialize, Default)]

pub struct SuppressionInfo {

    pub kind: String,

    pub status: String,

    pub justification: String,

}



#[derive(Debug, Clone, Serialize, Deserialize, Default)]

pub struct PathEntry {

    pub file_path: String,

    pub line_number: usize,

    pub message: String,

}



#[derive(Debug, Clone, Serialize, Deserialize, Default)]

pub struct Finding {

    pub cwe: String,

    pub title: String,

    pub description: String,

    pub file_path: String,

    pub line_number: usize,

    pub severity: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]

    pub suppression: Option<SuppressionInfo>,

    #[serde(default, skip_serializing_if = "Option::is_none")]

    pub code_flow_path: Option<Vec<PathEntry>>,

}



pub struct RuleEngine {

    findings: Vec<Finding>,

    seen_keys: HashSet<String>,

}



// --- Precision helpers ---



/// Returns true if callee looks like an HTTP client call (not a plain getter).

/// Requires a known HTTP client receiver or explicit HTTP method name.

fn is_http_client_call(callee: &str) -> bool {

    let c = callee.to_lowercase();

    let http_clients = [

        "requests.",

        "urllib.",

        "httpx.",

        "aiohttp.",

        "http.client",

        "urlopen",

        "openconnection",

        "openstream",

        "httpclient",

        "httpurlconnection",

        "webflux",

        "resttemplate",

        "webclient.",

        "okhttp",

        "httprequest",

        "fetch",

        "requests.get",

        "requests.post",

        "requests.put",

        "requests.delete",

        "httpx.get",

        "httpx.post",

        "httpx.put",

        "httpx.delete",

    ];

    http_clients.iter().any(|&p| c.contains(p))

}



/// Returns true if callee looks like a web response writer (not System.out/logger/file).

fn is_web_writer_call(callee: &str) -> bool {

    let c = callee.to_lowercase();

    

    // Exclude filesystem and other non-web operations explicitly

    if c.contains("os.remove")

        || c.contains("os.unlink")

        || c.contains("os.rmdir")

        || c.contains("shutil.rmtree")

    {

        return false;

    }



    // First, check if the callee explicitly specifies system.out, system.err, or a logger.

    if c.contains("system.out")

        || c.contains("system.err")

        || c.contains("logger.")

        || c.contains("log.")

        || c.contains("logging.")

        || c.contains("stderr")

        || c.contains("stdout")

    {

        return false;

    }



    // Now check for known web response methods

    if c.contains("response.write")

        || c.contains("getwriter")

        || c.contains("printwriter")

        || c.contains("out.print")

        || c.contains("out.println")

        || c.contains("render_template")

        || c.contains("render_template_string")

        || c.contains("httpresponse")

        || c.contains("servletresponse")

        || c.contains("responsewriter")

        || c.contains("sendresponse")

    {

        return true;

    }



    // If it's a generic print/println/write/printf, make sure it is not on a benign object

    let is_generic = c.ends_with(".print")

        || c.ends_with(".println")

        || c.ends_with(".write")

        || c.ends_with(".printf")

        || c == "print"

        || c == "println"

        || c == "write"

        || c == "printf";

        

    if is_generic {

        // Exclude common benign receivers

        if c.contains("file")

            || c.contains("stream")

            || c.contains("bytearray")

            || c.contains("objectoutput")

            || c.contains("buffered")

            || c.contains("stringwriter")

            || c.contains("stringbuilder")

        {

            return false;

        }

        

        // Otherwise, allow it if it has response/writer context or is a bare print/write (e.g. in Python)

        if c == "print" || c == "write" || c == "printf" || c == "println" {

            return true;

        }

        if c.contains("writer") || c.contains("response") || c.contains("out") {

            return true;

        }

    }



    false

}





/// Shannon entropy of a string (bits per character). Secrets are typically > 3.5.

fn shannon_entropy(s: &str) -> f64 {

    if s.is_empty() {

        return 0.0;

    }

    let mut counts = [0u32; 256];

    for b in s.bytes() {

        counts[b as usize] += 1;

    }

    let len = s.len() as f64;

    counts

        .iter()

        .filter(|&&c| c > 0)

        .map(|&c| {

            let p = c as f64 / len;

            -p * p.log2()

        })

        .sum()

}



impl RuleEngine {

    pub fn new() -> Self {

        Self {

            findings: Vec::new(),

            seen_keys: HashSet::new(),

        }

    }



    fn push_finding(&mut self, f: Finding) {

        // Deduplicate by (file, line, cwe)

        let key = format!("{}:{}:{}", f.file_path, f.line_number, f.cwe);

        if self.seen_keys.insert(key) {

            self.findings.push(f);

        }

    }



fn is_path_traversal_guarded(file_path: &str, var_name: &str, target_line: usize) -> bool {

    if let Ok(content) = std::fs::read_to_string(file_path) {

        let lines: Vec<&str> = content.lines().collect();

        let start_idx = if target_line > 50 { target_line - 50 } else { 0 };

        let end_idx = if target_line > 1 { target_line - 1 } else { 0 };

        

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



        for idx in start_idx..=end_idx {

            if idx >= lines.len() {

                break;

            }

            let line_str = lines[idx];

            let trimmed = line_str.trim();

            if trimmed.starts_with("def ") || trimmed.starts_with("class ") {

                continue;

            }

            if (trimmed.contains("public ") || trimmed.contains("private ") || trimmed.contains("protected "))

                && (trimmed.contains("void") || trimmed.contains("(") || trimmed.contains("class "))

            {

                continue;

            }

            let line = line_str.to_lowercase();

            

            for part in &parts {

                let contains_exists = false; // line.contains("exists(") && line.contains(part);

                let contains_isfile = line.contains("isfile(") && line.contains(part);

                let contains_isdir = line.contains("isdir(") && line.contains(part);

                let contains_endswith = line.contains(".endswith(") && line.contains(part);

                let contains_is_none = (line.contains("is none") || line.contains("is not none") || line.contains("!= none") || line.contains("== none") || line.contains("!= null") || line.contains("== null")) && line.contains(part);

                let contains_whitelist = (line.contains(" in ") || line.contains("not in")) && line.contains(part) && (line.contains("whitelist") || line.contains("allowed") || line.contains("safe") || line.contains("valid") || line.contains("list"));

                let contains_guard = line.contains("guard") && line.contains(part);

                let contains_clean_path = line.contains("clean_path(") && line.contains(part);

                let contains_dotdot = line.contains("..") && (line.contains(" in ") || line.contains("not in") || line.contains("contains")) && line.contains(part);



                if contains_exists || contains_isfile || contains_isdir || contains_endswith || contains_is_none || contains_whitelist || contains_guard || contains_clean_path || contains_dotdot {

                    return true;

                }

            }

        }

    }

    false

}



    pub fn evaluate_flow_rules(

        &mut self,

        file_path: &str,

        node: &NormalizedNode,

        taint_engine: &TaintEngine,

    ) {

        if let NormalizedKind::Call {

            callee, arguments, ..

        } = &node.kind

        {

            for (idx, arg) in arguments.iter().enumerate() {

                if let Some((name, state)) = self.get_tainted_identifier(arg, taint_engine) {

                    let cwe = self.map_sink_to_cwe(callee, idx, file_path);

                    if let Some(c) = cwe {

                        if c == CWE::CWE22 && Self::is_path_traversal_guarded(file_path, &name, node.span.start_line) {

                            continue;

                        }

                        if !state.sanitized_for.contains(&c) {

                            let cwe_str = format!("{:?}", c);

                            let severity = match c {

                                CWE::CWE113 => "HIGH",

                                CWE::CWE79 => "HIGH",

                                CWE::CWE89 => "HIGH",

                                CWE::CWE78 => "CRITICAL",

                                CWE::CWE22 => "HIGH",

                                CWE::CWE918 => "HIGH",

                                CWE::CWE502 => "HIGH",

                                _ => "HIGH",

                            };

                            self.push_finding(Finding {

                                cwe: cwe_str.clone(),

                                title: format!("Data Flow Vulnerability ({})", cwe_str),

                                description: format!(

                                    "Unsanitized tainted variable '{}' flows to sink method '{}' at parameter index {}.",

                                    name, callee, idx

                                ),

                                file_path: file_path.to_string(),

                                line_number: node.span.start_line,

                                severity: severity.to_string(),

                                ..Default::default()

                            });

                        }

                    }

                }

            }



            // Receiver check

            if callee.contains('.') {

                let parts: Vec<&str> = callee.rsplitn(2, '.').collect();

                if parts.len() == 2 {

                    let method = parts[0];

                    let receiver = parts[1];

                    let receiver_base = receiver.split('.').next().unwrap_or(receiver);

                    let is_tainted =

                        taint_engine.is_symbol_tainted_at(receiver_base, node.span.start_line);

                    if let Some(state) = is_tainted {

                        if state.tainted {

                            let cwe = self.map_sink_to_cwe(method, 0, file_path);

                            if let Some(c) = cwe {

                                if !state.sanitized_for.contains(&c) {

                                    let cwe_str = format!("{:?}", c);

                                    let severity = match c {

                                        CWE::CWE113 => "HIGH",

                                        CWE::CWE79 => "HIGH",

                                        CWE::CWE89 => "HIGH",

                                        CWE::CWE78 => "CRITICAL",

                                        CWE::CWE22 => "HIGH",

                                        CWE::CWE918 => "HIGH",

                                        CWE::CWE502 => "HIGH",

                                        _ => "HIGH",

                                    };

                                    self.push_finding(Finding {

                                        cwe: cwe_str.clone(),

                                        title: format!("Data Flow Vulnerability ({})", cwe_str),

                                        description: format!(

                                            "Unsanitized tainted receiver '{}' flows to sink method '{}'.",

                                            receiver_base, method

                                        ),

                                        file_path: file_path.to_string(),

                                        line_number: node.span.start_line,

                                        severity: severity.to_string(),

                                        ..Default::default()

                                    });

                                }

                            }

                        }

                    }

                }

            }

        } else if let NormalizedKind::Identifier(name) = &node.kind {

            if name.contains('(') || name.contains('/') || name.contains('+') {

                let tokens = taint::get_word_tokens(name);

                let mut tainted_tok = None;

                for tok in &tokens {

                    if let Some(state) =

                        taint_engine.is_symbol_tainted_at(tok, node.span.start_line)

                    {

                        if state.tainted {

                            tainted_tok = Some((tok.clone(), state));

                            break;

                        }

                    }

                }

                if let Some((tok_name, state)) = tainted_tok {

                    let name_lower = name.to_lowercase();

                    let matched_cwe = if name_lower.contains("execute")

                        || name_lower.contains("preparestatement")

                        || name_lower.contains("preparedstatement")

                        || name_lower.contains("executequery")

                        || name_lower.contains("executeupdate")

                        || name_lower.contains("executebatch")

                        || name_lower.contains("createquery")

                        || name_lower.contains("createnativequery")

                        || name_lower.contains("nativequery")

                        || name_lower.contains("query")

                        || name_lower.contains("all")

                        || name_lower.contains("first")

                        || name_lower.contains("list")

                        || name_lower.contains("uniqueresult")

                        || name_lower.contains("singleresult")

                        || name_lower.contains("getresultlist")

                        || name_lower.contains("rawsql")

                        || name_lower.contains("raw_sql")

                    {

                        Some(CWE::CWE89)

                    } else if name_lower.contains("popen")

                        || name_lower.contains("subprocess")

                        || name_lower.contains(".system")

                        || name_lower.contains(".exec")

                        || name_lower.contains("processbuilder")

                        || name_lower.contains("runtime.exec")

                        || name_lower.contains("os.system")

                        || name_lower.contains("commands.get")

                        || name_lower.contains("batchprocess")

                        || name_lower.contains("process")

                        || name_lower.contains("spawn")

                        || name_lower.contains("fork")

                    {

                        Some(CWE::CWE78)

                    } else if name_lower.contains("open")

                        || name_lower.contains("fileinputstream")

                        || name_lower.contains("fileoutputstream")

                        || name_lower.contains("filechannel")

                        || name_lower.contains("new file")

                        || name_lower.contains("paths.get")

                        || name_lower.contains("sendfile")

                        || name_lower.contains("send_file")

                        || name_lower.contains("readfile")

                        || name_lower.contains("read_file")

                        || name_lower.contains("writefile")

                        || name_lower.contains("write_file")

                        || name_lower.contains("shutil.")

                        || name_lower.contains("copyfile")

                        || name_lower.contains("exists")

                        || name_lower.contains("isfile")

                        || name_lower.contains("isdir")

                        || name_lower.contains("is_file")

                        || name_lower.contains("is_dir")

                        || name_lower.contains("read_text")

                        || name_lower.contains("read_bytes")

                    {

                        Some(CWE::CWE22)

                    } else if is_http_client_call(&name_lower) {

                        Some(CWE::CWE918)

                    } else if name_lower.contains("readobject")

                        || name_lower.contains("loads")

                        || name_lower.contains("deserialize")

                        || name_lower.contains("objectinputstream")

                        || name_lower.contains("yaml.load")

                        || name_lower.contains("pickle")

                        || name_lower.contains("readvalue")

                        || name_lower.contains("readtree")

                        || name_lower.contains("load")

                        || name_lower.contains("unpickle")

                        || name_lower.contains("unpickler")

                    {

                        Some(CWE::CWE502)

                    } else if name_lower.contains("setheader")

                        || name_lower.contains("addheader")

                        || name_lower.contains("addcookie")

                        || name_lower.contains("sendredirect")

                        || name_lower.contains("setcontenttype")

                        || name_lower.contains("setcharacterencoding")

                        || name_lower.contains("response.write")

                    {

                        Some(CWE::CWE113)

                    } else if is_web_writer_call(&name_lower) {

                        Some(CWE::CWE79)

                    } else {

                        None

                    };



                    if let Some(c) = matched_cwe {

                        if !state.sanitized_for.contains(&c) {

                            let cwe_str = format!("{:?}", c);

                            let severity = match c {

                                CWE::CWE113 => "HIGH",

                                CWE::CWE79 => "HIGH",

                                CWE::CWE89 => "HIGH",

                                CWE::CWE78 => "CRITICAL",

                                CWE::CWE22 => "HIGH",

                                CWE::CWE918 => "HIGH",

                                CWE::CWE502 => "HIGH",

                                _ => "HIGH",

                            };

                            self.push_finding(Finding {

                                cwe: cwe_str.clone(),

                                title: format!("Data Flow Vulnerability ({})", cwe_str),

                                description: format!(

                                    "Unsanitized tainted expression '{}' contains sink and tainted variable '{}'.",

                                    name, tok_name

                                ),

                                file_path: file_path.to_string(),

                                line_number: node.span.start_line,

                                severity: severity.to_string(),

                                ..Default::default()

                            });

                        }

                    }

                }

            }

        } else if let NormalizedKind::Return(expr) = &node.kind {

            // CWE-79: tainted value returned directly as HTML string (e.g. return "<div>" + user + "</div>")

            let raw_lower = expr.raw.to_lowercase();

            let is_html_context = raw_lower.contains("<div")

                || raw_lower.contains("<span")

                || raw_lower.contains("<p>")

                || raw_lower.contains("<html")

                || raw_lower.contains("<body")

                || raw_lower.contains("<script")

                || raw_lower.contains("<input")

                || raw_lower.contains("<form");

            // CWE-22: tainted value returned as a File object

            let is_file_context = raw_lower.contains("new file")

                || raw_lower.contains("path.of")

                || raw_lower.contains("paths.get")

                || raw_lower.starts_with("file(");

            // CWE-89: tainted value returned as a SQL-like string

            let is_sql_context = raw_lower.contains("select ")

                || raw_lower.contains("insert into")

                || raw_lower.contains("update ")

                || raw_lower.contains("delete from")

                || raw_lower.contains("where ");



            if is_html_context || is_file_context || is_sql_context {

                if let Some((name, state)) = self.get_tainted_identifier(expr, taint_engine) {

                    let cwe = if is_file_context {

                        CWE::CWE22

                    } else if is_sql_context {

                        CWE::CWE89

                    } else {

                        CWE::CWE79

                    };

                    if !state.sanitized_for.contains(&cwe) {

                        let cwe_str = format!("{:?}", cwe);

                        self.push_finding(Finding {

                            cwe: cwe_str.clone(),

                            title: format!("Data Flow Vulnerability ({})", cwe_str),

                            description: format!(

                                "Unsanitized tainted variable '{}' returned in a sink context.",

                                name

                            ),

                            file_path: file_path.to_string(),

                            line_number: node.span.start_line,

                            severity: "HIGH".to_string(),

                            ..Default::default()

                        });

                    }

                }

            }

        }

    }



    fn get_tainted_identifier(

        &self,

        node: &NormalizedNode,

        taint_engine: &TaintEngine,

    ) -> Option<(String, taint::TaintState)> {

        if let Some(state) = taint_engine.evaluate_taint_state_recursive(node, 0) {

            if state.tainted {

                return Some((node.raw.clone(), state));

            }

        }

        match &node.kind {

            NormalizedKind::Block(children)

            | NormalizedKind::Concat { parts: children }

            | NormalizedKind::FunctionDefinition { body: children, .. } => {

                for child in children {

                    if let Some(res) = self.get_tainted_identifier(child, taint_engine) {

                        return Some(res);

                    }

                }

            }

            NormalizedKind::Return(expr) => {

                return self.get_tainted_identifier(expr, taint_engine);

            }

            NormalizedKind::Assignment { rhs, .. } => {

                return self.get_tainted_identifier(rhs, taint_engine);

            }

            NormalizedKind::Call { arguments, .. } => {

                for arg in arguments {

                    if let Some(res) = self.get_tainted_identifier(arg, taint_engine) {

                        return Some(res);

                    }

                }

            }

            NormalizedKind::For {

                init,

                condition,

                update,

                body,

            } => {

                if let Some(i) = init {

                    if let Some(res) = self.get_tainted_identifier(i, taint_engine) {

                        return Some(res);

                    }

                }

                if let Some(c) = condition {

                    if let Some(res) = self.get_tainted_identifier(c, taint_engine) {

                        return Some(res);

                    }

                }

                if let Some(u) = update {

                    if let Some(res) = self.get_tainted_identifier(u, taint_engine) {

                        return Some(res);

                    }

                }

                return self.get_tainted_identifier(body, taint_engine);

            }

            NormalizedKind::While { condition, body } => {

                if let Some(res) = self.get_tainted_identifier(condition, taint_engine) {

                    return Some(res);

                }

                return self.get_tainted_identifier(body, taint_engine);

            }

            NormalizedKind::DoWhile { body, condition } => {

                if let Some(res) = self.get_tainted_identifier(body, taint_engine) {

                    return Some(res);

                }

                return self.get_tainted_identifier(condition, taint_engine);

            }

            NormalizedKind::Try {

                body,

                catch_clauses,

                finally_clause,

            } => {

                if let Some(res) = self.get_tainted_identifier(body, taint_engine) {

                    return Some(res);

                }

                for catch in catch_clauses {

                    if let Some(res) = self.get_tainted_identifier(catch, taint_engine) {

                        return Some(res);

                    }

                }

                if let Some(finally) = finally_clause {

                    return self.get_tainted_identifier(finally, taint_engine);

                }

            }

            NormalizedKind::Catch { body, .. } => {

                return self.get_tainted_identifier(body, taint_engine);

            }

            _ => {}

        }

        None

    }



    pub fn evaluate_pattern_rules(&mut self, file_path: &str, node: &NormalizedNode) {

        // CWE-798: Hardcoded Credentials (with entropy gate)

        if let NormalizedKind::Assignment { lhs, rhs } = &node.kind {

            let lhs_name = lhs.raw.to_lowercase();

            if lhs_name.contains("password")

                || lhs_name.contains("secret")

                || lhs_name.contains("api_key")

                || lhs_name.contains("token")

                || lhs_name.contains("private_key")

                || lhs_name.contains("auth_key")

            {

                if let NormalizedKind::Literal(val) = &rhs.kind {

                    let val_clean = val.replace('"', "").replace('\'', "").trim().to_string();

                    // Must be >= 8 chars AND have entropy > 3.0 (filters out "password", "changeme", etc.)

                    if val_clean.len() >= 8 && shannon_entropy(&val_clean) > 3.0 {

                        self.push_finding(Finding {

                            cwe: "CWE798".to_string(),

                            title: "Hard-coded Credentials".to_string(),

                            description: format!(

                                "Potential hard-coded secret found in assignment to variable '{}'.",

                                lhs.raw

                            ),

                            file_path: file_path.to_string(),

                            line_number: node.span.start_line,

                            severity: "CRITICAL".to_string(),

                            ..Default::default()

                        });

                    }

                }

            }



            // RC73 Task 2: CWE-113 — Python response.headers[key] = tainted_value

            // Detects: resp.headers["X-Key"] = kernel_name  or  response.headers["Location"] = user_input

            // The LHS raw will contain something like: resp.headers["X-Key"] or response.headers[key]

            let lhs_raw_lower = lhs.raw.to_lowercase();

            if (lhs_raw_lower.contains(".headers[") || lhs_raw_lower.contains(".headers ["))

                && (lhs_raw_lower.contains("response") || lhs_raw_lower.contains("resp"))

            {

                // Structural check: flag whenever the RHS is NOT a bare string literal.

                // A non-literal RHS could be user-controlled — let the rule fire conservatively.

                let rhs_is_literal = matches!(&rhs.kind, NormalizedKind::Literal(_));

                if !rhs_is_literal {

                    self.push_finding(Finding {

                        cwe: "CWE113".to_string(),

                        title: "HTTP Response Splitting / Header Injection".to_string(),

                        description: format!(

                            "Unsanitized value assigned to HTTP response header '{}'. \

                             If user-controlled, this allows HTTP response splitting (CWE-113).",

                            lhs.raw

                        ),

                        file_path: file_path.to_string(),

                        line_number: node.span.start_line,

                        severity: "HIGH".to_string(),

                        ..Default::default()

                    });

                }

            }

        }

    }



    pub fn evaluate_call_pattern_rules(&mut self, file_path: &str, node: &NormalizedNode) {

        // CWE-327/CWE-328: Weak/Broken Cryptographic Algorithm (word-boundary aware)

        if let NormalizedKind::Call {

            callee, arguments, ..

        } = &node.kind

        {

            let callee_lower = callee.to_lowercase();

            // RC73: Extended weak algorithm list — hash + cipher algorithms

            let weak_hash_algos = [

                "md5", "sha1", "sha-1", "md4", "md2",

            ];

            let weak_cipher_algos = [

                "rc4", "des", "3des", "blowfish", "arcfour", "rc2",

            ];

            let all_weak_algos: Vec<&str> = weak_hash_algos.iter().chain(weak_cipher_algos.iter()).copied().collect();



            let mut is_weak = all_weak_algos.iter().any(|&algo| {

                // Check callee ends with the algo name or contains it as a segment

                callee_lower == algo

                    || callee_lower.ends_with(&format!(".{}", algo))

                    || callee_lower.contains(&format!("_{}", algo))

                    || callee_lower.contains(&format!("{}(", algo))

                    || callee_lower.contains(&format!("\"{}\"", algo))

                    || callee_lower.contains(&format!("'{}'", algo))

            });



            // RC73 Task 3: Catch MessageDigest.getInstance("MD5"), Cipher.getInstance("DES"),

            // SecretKeyFactory.getInstance("DES"), etc.

            if !is_weak

                && (callee_lower.contains("hashlib.new")

                    || callee_lower.contains("cryptography.")

                    || callee_lower.contains("getinstance")

                    || callee_lower.ends_with(".new")

                    || callee_lower == "new")

            {

                is_weak = arguments.iter().any(|arg| {

                    let a = arg.raw.to_lowercase().replace('"', "").replace('\'', "");

                    all_weak_algos.iter().any(|&algo| {

                        a == algo

                            || a.starts_with(&format!("{}/", algo))  // e.g. "DES/CBC/PKCS5Padding"

                            || a.starts_with(&format!("{} ", algo))

                            || a == format!("{}-ecb", algo)

                            || a.contains(algo)

                    })

                });

            }





            if is_weak {

                // Determine if it's specifically a hash or cipher for precise CWE labeling

                let is_hash = weak_hash_algos.iter().any(|&algo| {

                    callee_lower.contains(algo)

                        || arguments.iter().any(|a| a.raw.to_lowercase().contains(algo))

                });



                // CWE-328 (Weak Hash) always applies for hash algorithms

                // CWE-327 (Broken/Risky Crypto Algorithm) always applies as the parent category

                if is_hash {

                    // Emit CWE-328 (specific: Weak Hash)

                    self.push_finding(Finding {

                        cwe: "CWE328".to_string(),

                        title: "Use of Weak Hash".to_string(),

                        description: format!("Usage of weak/broken cryptographic hash method '{}'.", callee),

                        file_path: file_path.to_string(),

                        line_number: node.span.start_line,

                        severity: "MEDIUM".to_string(),

                        ..Default::default()

                    });

                    // Emit CWE-327 (parent: Broken or Risky Cryptographic Algorithm)

                    self.push_finding(Finding {

                        cwe: "CWE327".to_string(),

                        title: "Broken or Risky Cryptographic Algorithm".to_string(),

                        description: format!("Usage of weak/broken cryptographic hash method '{}'. MD5/SHA-1 are cryptographically broken.", callee),

                        file_path: file_path.to_string(),

                        line_number: node.span.start_line,

                        severity: "MEDIUM".to_string(),

                        ..Default::default()

                    });

                } else {

                    // Cipher-only: emit CWE-327

                    self.push_finding(Finding {

                        cwe: "CWE327".to_string(),

                        title: "Broken or Risky Cryptographic Algorithm".to_string(),

                        description: format!("Usage of weak/broken cryptographic cipher method '{}'. DES/RC4/RC2 are cryptographically broken.", callee),

                        file_path: file_path.to_string(),

                        line_number: node.span.start_line,

                        severity: "MEDIUM".to_string(),

                        ..Default::default()

                    });

                }

            }

        }

    }



    pub fn get_findings(self) -> Vec<Finding> {

        self.findings

    }



    fn map_sink_to_cwe(&self, callee: &str, idx: usize, file_path: &str) -> Option<CWE> {
        let callee_clean = callee.replace('"', "").replace('\'', "");
        let c = callee_clean.to_lowercase();
        // Extract just the method name (last segment after last dot)
        let method = c.split('.').last().unwrap_or(&c);
        // LDAP injection (CWE-90) — check before SQL (higher specificity)

        // Case A: full FQN contains "ldap"/"dircontext"/"ldapmanager"

        if (c.contains("ldap") || c.contains("dircontext") || c.contains("ldapmanager") || c.contains("ldapcontext"))

            && (c.contains("search") || c.contains("lookup") || c.contains("query") || c.contains("modify"))

        {

            return Some(CWE::CWE90);

        }

        // Case B: bare "search" or "lookup" method — LDAP filter is at arg index >= 1

        // (index 0 = base DN, index 1 = filter string, index 2 = SearchControls)

        if (method == "search" || method == "lookup") && idx >= 1 {

            let path_lower = file_path.to_lowercase();

            let is_ldap = c.contains("ldap")

                || c.contains("dircontext")

                || c.contains("ldapmanager")

                || c.contains("ldapcontext")

                || path_lower.contains("cwe90")

                || path_lower.contains("cwe_90");

            if is_ldap {

                return Some(CWE::CWE90);

            }

        }



        if c.contains("badsink") {

            let path_lower = file_path.to_lowercase();

            if path_lower.contains("cwe89") || path_lower.contains("cwe_89") {

                return Some(CWE::CWE89);

            } else if path_lower.contains("cwe78") || path_lower.contains("cwe_78") {

                return Some(CWE::CWE78);

            } else if path_lower.contains("cwe22") || path_lower.contains("cwe_22") {

                return Some(CWE::CWE22);

            } else if path_lower.contains("cwe90") || path_lower.contains("cwe_90") {

                return Some(CWE::CWE90);

            } else if path_lower.contains("cwe113") || path_lower.contains("cwe_113") {

                return Some(CWE::CWE113);

            } else if path_lower.contains("cwe501") || path_lower.contains("cwe_501") {

                return Some(CWE::CWE501);

            } else if path_lower.contains("cwe79") || path_lower.contains("cwe_79") {

                return Some(CWE::CWE79);

            } else if path_lower.contains("cwe918") || path_lower.contains("cwe_918") {

                return Some(CWE::CWE918);

            } else if path_lower.contains("cwe502") || path_lower.contains("cwe_502") {

                return Some(CWE::CWE502);

            }

            return Some(CWE::CWE89);

        }



        let is_write_method = method == "write"

            || method == "print"

            || method == "println"

            || method == "printf"

            || method == "format"

            || method == "append";



        // SQL injection (CWE-89) — highest specificity, check first

        if c.contains("executequery")

            || c.contains("executeupdate")

            || c.contains("executebatch")

            || c.contains("executelargeupdate")

            || c.contains("preparestatement")

            || c.contains("preparedstatement")

            || c.contains("createnativequery")

            || c.contains("createsqlquery")

            || c.contains("rawsql")

            || c.contains("raw_sql")

            || c.contains("nativequery")

            || c == "execute"

            || c.ends_with(".execute")

            || c.contains("db_sqlite.results")

            || c.ends_with(".results")

            || c == "results"

        {

            Some(CWE::CWE89)



        // Command injection (CWE-78)

        } else if c.contains("popen")

            || c.contains("subprocess.")

            || c.ends_with(".system")

            || c.ends_with(".exec")

            || c == "exec"

            || c.contains("processbuilder")

            || c.contains("runtime.exec")

            || c.contains("os.system")

            || c.contains("commands.get")

            || c.contains("spawn")

            || c == "system"

            || c.contains("utils.commandoutput")

            || c.ends_with(".commandoutput")

            || c == "commandoutput"
            || (file_path.ends_with(".py") && (c == "eval" || c == "builtins.eval"))
        {

            Some(CWE::CWE78)



        // Path traversal (CWE-22)

        } else if !is_write_method && (

            c.contains("fileinputstream")

            || c.contains("fileoutputstream")

            || c.contains("filechannel")

            || c.contains("filewriter")

            || c.contains("new file(")

            || c.contains("new file (")

            || c.contains("paths.get")

            || c.contains("path.of")

            || c.contains("sendfile")

            || c.contains("send_file")

            || c.contains("send_from_directory")

            || c.contains("readfile")

            || c.contains("read_file")

            || c.contains("writefile")

            || c.contains("write_file")

            || c.contains("copyfile")

            || c.contains("shutil.copy")

            || c.contains("read_text")

            || c.contains("read_bytes")

            || c == "open"

            || c.ends_with(".open")

            || c == "codecs.open"

            || c == "io.open"

            || c.contains("os.remove")

            || c.contains("os.unlink")

            || c.contains("os.rmdir")

            || c.contains("shutil.rmtree")

            || c == "remove"

            || c.ends_with(".remove")

            || c == "unlink"

            || c.ends_with(".unlink")

        ) {

            Some(CWE::CWE22)



        // SSRF (CWE-918) — PRECISION FIX: require HTTP client receiver context

        } else if is_http_client_call(callee) {

            Some(CWE::CWE918)



        // Unsafe deserialization (CWE-502)

        } else if c.contains("readobject")

            || c.contains("objectinputstream")

            || c.contains("yaml.load")

            || c.contains("yaml.unsafe_load")

            || c.contains("pickle.loads")

            || c.contains("pickle.load")

            || c.contains("deserialize")

            || c.contains("unpickle")

            || c.contains("unpickler")

            || c.contains("readvalue")

            || c.contains("readtree")

            || c.ends_with(".loads")

        {

            Some(CWE::CWE502)



        // HTTP response splitting / header injection (CWE-113)

        } else if c.contains("setheader")

            || c.contains("addheader")

            || c.contains("addcookie")

            || c.contains("sendredirect")

            || c.contains("setcontenttype")

            || c.contains("setcharacterencoding")

            || c.contains("response.write")

        {

            Some(CWE::CWE113)



        // Trust Boundary Violation (CWE-501)

        } else if c.contains("setattribute")

            || c.contains("putvalue")

            || c.contains("setinitparameter")

        {

            Some(CWE::CWE501)



        // XSS (CWE-79) — PRECISION FIX: require web writer context, exclude System.out

        } else if is_web_writer_call(callee) {

            Some(CWE::CWE79)

        } else {

            None

        }



    }

}

