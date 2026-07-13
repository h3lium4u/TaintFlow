use v2_rules::{Matcher, Rule, RuleKind, RulePack, Severity};

// ---------------------------------------------------------------------------
// Internal helpers — reduce verbosity across 80+ rule definitions
// ---------------------------------------------------------------------------

fn rule(
    id: &str, name: &str, kind: RuleKind, lang: Option<&str>,
    cwe: Option<u32>, severity: Severity, category: &str,
    description: &str, matcher: Matcher,
) -> Rule {
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        kind,
        language: lang.map(|s| s.to_string()),
        cwe,
        severity,
        category: Some(category.to_string()),
        description: Some(description.to_string()),
        matcher,
    }
}

fn src(id: &str, name: &str, lang: &str, fn_name: &str, cwe: Option<u32>, cat: &str) -> Rule {
    rule(id, name, RuleKind::Source, Some(lang), cwe, Severity::Info, cat,
         &format!("{} is a user-controlled input source.", fn_name),
         Matcher::FunctionName(fn_name.to_string()))
}

fn src_qn(id: &str, name: &str, lang: &str, qn: &str, cwe: Option<u32>, cat: &str) -> Rule {
    rule(id, name, RuleKind::Source, Some(lang), cwe, Severity::Info, cat,
         &format!("{} is a user-controlled input source.", qn),
         Matcher::QualifiedName(qn.to_string()))
}

fn src_method(id: &str, name: &str, lang: &str, class: &str, method: &str, cwe: Option<u32>, cat: &str) -> Rule {
    rule(id, name, RuleKind::Source, Some(lang), cwe, Severity::Info, cat,
         &format!("{}.{} is a user-controlled input source.", class, method),
         Matcher::MethodName { class: class.to_string(), method: method.to_string() })
}

fn sink(id: &str, name: &str, lang: &str, fn_name: &str, cwe: u32, sev: Severity, cat: &str, desc: &str) -> Rule {
    rule(id, name, RuleKind::Sink, Some(lang), Some(cwe), sev, cat, desc,
         Matcher::FunctionName(fn_name.to_string()))
}

fn sink_qn(id: &str, name: &str, lang: &str, qn: &str, cwe: u32, sev: Severity, cat: &str, desc: &str) -> Rule {
    rule(id, name, RuleKind::Sink, Some(lang), Some(cwe), sev, cat, desc,
         Matcher::QualifiedName(qn.to_string()))
}

fn sink_method(id: &str, name: &str, lang: &str, class: &str, method: &str, cwe: u32, sev: Severity, cat: &str, desc: &str) -> Rule {
    rule(id, name, RuleKind::Sink, Some(lang), Some(cwe), sev, cat, desc,
         Matcher::MethodName { class: class.to_string(), method: method.to_string() })
}

fn san(id: &str, name: &str, lang: &str, fn_name: &str, cat: &str) -> Rule {
    rule(id, name, RuleKind::Sanitizer, Some(lang), None, Severity::Info, cat,
         &format!("{} sanitizes tainted input.", fn_name),
         Matcher::FunctionName(fn_name.to_string()))
}

fn san_qn(id: &str, name: &str, lang: &str, qn: &str, cat: &str) -> Rule {
    rule(id, name, RuleKind::Sanitizer, Some(lang), None, Severity::Info, cat,
         &format!("{} sanitizes tainted input.", qn),
         Matcher::QualifiedName(qn.to_string()))
}

fn san_method(id: &str, name: &str, lang: &str, class: &str, method: &str, cat: &str) -> Rule {
    rule(id, name, RuleKind::Sanitizer, Some(lang), None, Severity::Info, cat,
         &format!("{}.{} sanitizes tainted input.", class, method),
         Matcher::MethodName { class: class.to_string(), method: method.to_string() })
}

fn prop_method(id: &str, name: &str, lang: &str, class: &str, method: &str) -> Rule {
    rule(id, name, RuleKind::Propagator, Some(lang), None, Severity::Info, "propagator",
         &format!("{}.{} propagates taint from arguments.", class, method),
         Matcher::MethodName { class: class.to_string(), method: method.to_string() })
}

// ---------------------------------------------------------------------------
// 1. Core Pack — language-agnostic eval/exec and generic sanitizers
// ---------------------------------------------------------------------------

pub fn core_pack() -> RulePack {
    let mut p = RulePack::new("core");

    // Sources (generic)
    p.add_rule(src("core-src-001", "Generic user input", "any", "input",
                   None, "input"));
    p.add_rule(src("core-src-002", "Generic read", "any", "read",
                   None, "input"));

    // Eval / Code injection sinks (CWE-95, CWE-94)
    p.add_rule(sink("core-sink-001", "eval() Code Injection", "python", "eval",
                    95, Severity::Critical, "code-injection",
                    "Executing eval() on untrusted input enables arbitrary code execution."));
    p.add_rule(sink("core-sink-002", "exec() Code Injection", "python", "exec",
                    94, Severity::Critical, "code-injection",
                    "Executing exec() on untrusted input enables arbitrary code execution."));
    p.add_rule(sink("core-sink-003", "compile() Code Injection", "python", "compile",
                    94, Severity::Critical, "code-injection",
                    "Compiling and executing untrusted code strings is dangerous."));

    // Generic sanitizers
    p.add_rule(san("core-san-001", "html.escape sanitizer", "python", "html.escape", "xss"));
    p.add_rule(san_qn("core-san-002", "markupsafe.escape sanitizer", "python",
                      "markupsafe.escape", "xss"));
    p.add_rule(san_qn("core-san-003", "bleach.clean sanitizer", "python",
                      "bleach.clean", "xss"));
    p.add_rule(san_qn("core-san-004", "urllib.parse.quote sanitizer", "python",
                      "urllib.parse.quote", "ssrf"));
    p.add_rule(san_qn("core-san-005", "urllib.parse.quote_plus sanitizer", "python",
                      "urllib.parse.quote_plus", "ssrf"));
    p.add_rule(san_qn("core-san-006", "shlex.quote sanitizer", "python",
                      "shlex.quote", "command-injection"));
    p.add_rule(san("core-san-007", "os.path.realpath sanitizer", "python",
                   "os.path.realpath", "path-traversal"));
    p.add_rule(san_qn("core-san-008", "os.path.abspath sanitizer", "python",
                      "os.path.abspath", "path-traversal"));

    p
}

// ---------------------------------------------------------------------------
// 2. Python Pack — Python-specific sources
// ---------------------------------------------------------------------------

pub fn python_pack() -> RulePack {
    let mut p = RulePack::new("python");

    // --- Sources ---
    p.add_rule(src("py-src-001", "Python input() source", "python", "input",
                   None, "input"));
    p.add_rule(src_qn("py-src-002", "os.environ source", "python", "os.environ.get",
                      None, "environment"));
    p.add_rule(src_qn("py-src-003", "os.getenv source", "python", "os.getenv",
                      None, "environment"));
    p.add_rule(src_qn("py-src-004", "sys.argv source", "python", "sys.argv",
                      None, "cli-arg"));
    p.add_rule(src_qn("py-src-005", "flask request.args source", "python",
                      "flask.request.args.get", None, "http-param"));
    p.add_rule(src_qn("py-src-006", "flask request.form source", "python",
                      "flask.request.form.get", None, "http-param"));
    p.add_rule(src_qn("py-src-007", "flask request.json source", "python",
                      "flask.request.get_json", None, "http-param"));
    p.add_rule(src_qn("py-src-008", "django GET params source", "python",
                      "django.request.GET.get", None, "http-param"));
    p.add_rule(src_qn("py-src-009", "django POST params source", "python",
                      "django.request.POST.get", None, "http-param"));
    p.add_rule(src_qn("py-src-010", "subprocess stdout source", "python",
                      "subprocess.check_output", None, "subprocess-output"));
    p.add_rule(src_qn("py-src-011", "socket recv source", "python",
                      "socket.recv", None, "socket-input"));
    p.add_rule(src_qn("py-src-012", "socket recvfrom source", "python",
                      "socket.recvfrom", None, "socket-input"));
    p.add_rule(src_qn("py-src-013", "flask request.args dict", "python",
                      "flask.request.args", None, "http-param"));
    p.add_rule(src_qn("py-src-014", "flask request.form dict", "python",
                      "flask.request.form", None, "http-param"));
    p.add_rule(src_qn("py-src-015", "flask request.values", "python",
                      "flask.request.values", None, "http-param"));
    p.add_rule(src_qn("py-src-016", "flask request.json dict", "python",
                      "flask.request.json", None, "http-param"));
    p.add_rule(src_qn("py-src-017", "flask request.headers", "python",
                      "flask.request.headers", None, "http-header"));
    p.add_rule(src_qn("py-src-018", "flask request.cookies", "python",
                      "flask.request.cookies", None, "http-cookie"));
    p.add_rule(src_qn("py-src-019", "fastapi Request", "python",
                      "fastapi.Request", None, "http-param"));
    p.add_rule(src_qn("py-src-020", "starlette Request", "python",
                      "starlette.Request", None, "http-param"));
    p.add_rule(src_qn("py-src-021", "django GET dict", "python",
                      "django.request.GET", None, "http-param"));
    p.add_rule(src_qn("py-src-022", "django POST dict", "python",
                      "django.request.POST", None, "http-param"));
    p.add_rule(src_qn("py-src-023", "os.environ dict", "python",
                      "os.environ", None, "environment"));
    p.add_rule(src_qn("py-src-024", "argparse parse_args", "python",
                      "argparse.ArgumentParser.parse_args", None, "cli-arg"));
    p.add_rule(src_qn("py-src-025", "click option", "python",
                      "click.option", None, "cli-arg"));
    p.add_rule(src_qn("py-src-026", "click argument", "python",
                      "click.argument", None, "cli-arg"));

    // --- Python-specific sanitizers ---
    p.add_rule(san_qn("py-san-001", "html.escape", "python", "html.escape", "xss"));
    p.add_rule(san_qn("py-san-002", "re.escape", "python", "re.escape", "regex-injection"));
    p.add_rule(san_qn("py-san-003", "urllib.parse.urlencode", "python",
                      "urllib.parse.urlencode", "ssrf"));

    p
}

// ---------------------------------------------------------------------------
// 3. Java Pack — Java-specific sources and sanitizers
// ---------------------------------------------------------------------------

pub fn java_pack() -> RulePack {
    let mut p = RulePack::new("java");

    // --- Sources ---
    p.add_rule(src_method("java-src-001", "HttpServletRequest.getParameter", "java",
                          "HttpServletRequest", "getParameter", None, "http-param"));
    p.add_rule(src_method("java-src-002", "HttpServletRequest.getHeader", "java",
                          "HttpServletRequest", "getHeader", None, "http-header"));
    p.add_rule(src_method("java-src-003", "HttpServletRequest.getQueryString", "java",
                          "HttpServletRequest", "getQueryString", None, "http-param"));
    p.add_rule(src_method("java-src-004", "Scanner.nextLine source", "java",
                          "Scanner", "nextLine", None, "input"));
    p.add_rule(src_method("java-src-005", "Scanner.next source", "java",
                          "Scanner", "next", None, "input"));
    p.add_rule(src_method("java-src-006", "BufferedReader.readLine source", "java",
                          "BufferedReader", "readLine", None, "input"));
    p.add_rule(src_method("java-src-007", "System.getenv source", "java",
                          "System", "getenv", None, "environment"));
    p.add_rule(src_method("java-src-008", "System.console().readLine source", "java",
                          "Console", "readLine", None, "input"));
    p.add_rule(src_method("java-src-009", "ServletRequest.getParameter", "java",
                          "ServletRequest", "getParameter", None, "http-param"));
    p.add_rule(src_method("java-src-010", "ServletRequest.getParameterValues", "java",
                          "ServletRequest", "getParameterValues", None, "http-param"));
    p.add_rule(src_method("java-src-011", "HttpServletRequest.getCookies", "java",
                          "HttpServletRequest", "getCookies", None, "http-cookie"));
    p.add_rule(src_method("java-src-012", "HttpServletRequest.getParameterMap", "java",
                          "HttpServletRequest", "getParameterMap", None, "http-param"));
    p.add_rule(src_method("java-src-013", "HttpServletRequest.getInputStream", "java",
                          "HttpServletRequest", "getInputStream", None, "http-param"));
    p.add_rule(src_method("java-src-014", "HttpServletRequest.getReader", "java",
                          "HttpServletRequest", "getReader", None, "http-param"));
    p.add_rule(src("java-src-015", "Spring RequestParam annotation", "java",
                   "RequestParam", None, "http-param"));
    p.add_rule(src("java-src-016", "Spring PathVariable annotation", "java",
                   "PathVariable", None, "http-param"));
    p.add_rule(src("java-src-017", "Spring RequestBody annotation", "java",
                   "RequestBody", None, "http-param"));
    // p.add_rule(src_method("java-src-018", "HttpServletRequest.getHeaders", "java",
    //                       "HttpServletRequest", "getHeaders", None, "http-header"));

    // --- Java sanitizers ---
    p.add_rule(san_method("java-san-001", "PreparedStatement.setString", "java",
                          "PreparedStatement", "setString", "sql-injection"));
    p.add_rule(san_method("java-san-002", "Path.normalize", "java",
                          "Path", "normalize", "path-traversal"));
    p.add_rule(san_method("java-san-003", "StringEscapeUtils.escapeHtml4", "java",
                          "StringEscapeUtils", "escapeHtml4", "xss"));
    p.add_rule(san_method("java-san-004", "StringEscapeUtils.escapeSql", "java",
                          "StringEscapeUtils", "escapeSql", "sql-injection"));
    p.add_rule(san_method("java-san-005", "ESAPI.encoder().encodeForHTML", "java",
                          "Encoder", "encodeForHTML", "xss"));

    // --- Java Propagators ---
    p.add_rule(prop_method("java-prop-001", "java.net.URLDecoder.decode", "java", "URLDecoder", "decode"));
    p.add_rule(prop_method("java-prop-002", "java.net.URLEncoder.encode", "java", "URLEncoder", "encode"));
    p.add_rule(prop_method("java-prop-003", "java.lang.String.valueOf", "java", "String", "valueOf"));
    p.add_rule(prop_method("java-prop-004", "java.util.Base64.Decoder.decode", "java", "Decoder", "decode"));
    p.add_rule(prop_method("java-prop-005", "java.lang.Integer.parseInt", "java", "Integer", "parseInt"));
    p.add_rule(prop_method("java-prop-006", "java.util.Enumeration.nextElement", "java", "Enumeration", "nextElement"));
    
    // DB propagators
    p.add_rule(prop_method("java-prop-008", "java.sql.Connection.prepareStatement", "java", "Connection", "prepareStatement"));
    p.add_rule(prop_method("java-prop-009", "java.sql.Connection.prepareCall", "java", "Connection", "prepareCall"));
    p.add_rule(prop_method("java-prop-010", "java.sql.Connection.createStatement", "java", "Connection", "createStatement"));
    
    // Command propagators
    p.add_rule(prop_method("java-prop-011", "java.lang.ProcessBuilder.ProcessBuilder", "java", "ProcessBuilder", "ProcessBuilder"));
    p.add_rule(prop_method("java-prop-012", "java.lang.ProcessBuilder.command", "java", "ProcessBuilder", "command"));

    p
}

// ---------------------------------------------------------------------------
// 4. Web Pack — XSS (CWE-79), Open Redirect (CWE-601), CSRF (CWE-352)
// ---------------------------------------------------------------------------

pub fn web_pack() -> RulePack {
    let mut p = RulePack::new("web");

    // XSS sinks
    p.add_rule(sink("web-xss-001", "Flask render_template_string XSS", "python",
                    "render_template_string", 79, Severity::High, "xss",
                    "Rendering untrusted input in a template can cause XSS."));
    p.add_rule(sink_qn("web-xss-002", "Django mark_safe XSS", "python",
                       "django.utils.safestring.mark_safe", 79, Severity::High, "xss",
                       "mark_safe() bypasses Django's auto-escaping."));
    p.add_rule(sink_qn("web-xss-003", "Jinja2 Markup XSS", "python",
                       "jinja2.Markup", 79, Severity::High, "xss",
                       "Wrapping untrusted data in Markup() disables Jinja2 escaping."));
    p.add_rule(sink_method("web-xss-004", "PrintWriter.println XSS", "java",
                           "PrintWriter", "println", 79, Severity::High, "xss",
                           "Writing untrusted data directly to HTTP response can cause XSS."));
    p.add_rule(sink_method("web-xss-005", "HttpServletResponse.getWriter XSS", "java",
                           "PrintWriter", "print", 79, Severity::High, "xss",
                           "Writing untrusted data to response output can cause XSS."));

    // Open Redirect sinks (CWE-601)
    p.add_rule(sink("web-redir-001", "Flask redirect() Open Redirect", "python",
                    "redirect", 601, Severity::Medium, "open-redirect",
                    "Redirecting to a user-controlled URL is an open redirect vulnerability."));
    p.add_rule(sink_method("web-redir-002", "HttpServletResponse.sendRedirect", "java",
                           "HttpServletResponse", "sendRedirect", 601, Severity::Medium,
                           "open-redirect",
                           "sendRedirect() with untrusted input is an open redirect."));

    // CSRF (informational — architectural, not taint-based)
    p.add_rule(sink_method("web-csrf-001", "CSRF: missing token check", "java",
                           "HttpServletRequest", "getParameter", 352, Severity::Medium,
                           "csrf",
                           "Ensure CSRF token is validated on state-changing requests."));

    p
}

// ---------------------------------------------------------------------------
// 5. Database Pack — SQL Injection (CWE-89)
// ---------------------------------------------------------------------------

pub fn database_pack() -> RulePack {
    let mut p = RulePack::new("database");

    // Python SQL sinks
    p.add_rule(sink_method("db-sqli-001", "cursor.execute() SQL Injection", "python",
                           "cursor", "execute", 89, Severity::Critical, "sql-injection",
                           "Passing untrusted input to cursor.execute() enables SQL injection."));
    p.add_rule(sink_method("db-sqli-002", "db.execute() SQL Injection", "python",
                           "db", "execute", 89, Severity::Critical, "sql-injection",
                           "String-format SQL queries are vulnerable to injection."));
    p.add_rule(sink_method("db-sqli-003", "connection.execute() SQL Injection", "python",
                           "connection", "execute", 89, Severity::Critical, "sql-injection",
                           "Untrusted data in a SQL query enables injection attacks."));
    p.add_rule(sink_qn("db-sqli-004", "SQLAlchemy text() SQL Injection", "python",
                       "sqlalchemy.text", 89, Severity::High, "sql-injection",
                       "Using sqlalchemy.text() with untrusted input can bypass ORM protections."));

    // Java SQL sinks
    p.add_rule(sink_method("db-sqli-005", "Statement.execute() SQL Injection", "java",
                           "Statement", "execute", 89, Severity::Critical, "sql-injection",
                           "Dynamic SQL via Statement.execute() is vulnerable to injection."));
    p.add_rule(sink_method("db-sqli-006", "Statement.executeQuery() SQL Injection", "java",
                           "Statement", "executeQuery", 89, Severity::Critical, "sql-injection",
                           "Dynamic SQL queries are vulnerable to injection."));
    p.add_rule(sink_method("db-sqli-007", "Statement.executeUpdate() SQL Injection", "java",
                           "Statement", "executeUpdate", 89, Severity::Critical, "sql-injection",
                           "String-concatenated SQL update statements are vulnerable."));
    p.add_rule(sink_method("db-sqli-008", "EntityManager.createQuery SQL Injection", "java",
                           "EntityManager", "createQuery", 89, Severity::High, "sql-injection",
                           "JPQL queries built with untrusted input can be exploited."));

    p
}

// ---------------------------------------------------------------------------
// 6. Filesystem Pack — Path Traversal (CWE-22)
// ---------------------------------------------------------------------------

pub fn filesystem_pack() -> RulePack {
    let mut p = RulePack::new("filesystem");

    // Python path traversal sinks
    p.add_rule(sink("fs-trav-001", "open() Path Traversal", "python", "open",
                    22, Severity::High, "path-traversal",
                    "Opening files with user-controlled paths can traverse directories."));
    p.add_rule(sink_qn("fs-trav-002", "os.path.join Path Traversal", "python",
                       "os.path.join", 22, Severity::High, "path-traversal",
                       "os.path.join with untrusted components enables path traversal."));
    p.add_rule(sink_qn("fs-trav-003", "pathlib.Path Path Traversal", "python",
                       "pathlib.Path", 22, Severity::High, "path-traversal",
                       "Constructing paths from untrusted input enables traversal."));
    p.add_rule(sink_qn("fs-trav-004", "shutil.copy Path Traversal", "python",
                       "shutil.copy", 22, Severity::High, "path-traversal",
                       "Copying files with untrusted paths can overwrite arbitrary files."));

    // Java path traversal sinks
    p.add_rule(sink_method("fs-trav-005", "FileInputStream Path Traversal", "java",
                           "FileInputStream", "FileInputStream", 22, Severity::High,
                           "path-traversal",
                           "Opening files via FileInputStream with untrusted paths."));
    p.add_rule(sink_method("fs-trav-006", "FileReader Path Traversal", "java",
                           "FileReader", "FileReader", 22, Severity::High, "path-traversal",
                           "Opening files via FileReader with untrusted paths."));
    p.add_rule(sink_method("fs-trav-007", "File.getCanonicalPath check", "java",
                           "File", "getCanonicalPath", 22, Severity::Medium, "path-traversal",
                           "Canonical path should be validated against a safe base directory."));

    // Sanitizers
    p.add_rule(san_qn("fs-san-001", "os.path.realpath sanitizer", "python",
                      "os.path.realpath", "path-traversal"));
    p.add_rule(san_method("fs-san-002", "Path.normalize sanitizer", "java",
                          "Path", "normalize", "path-traversal"));
    p.add_rule(san_method("fs-san-003", "Path.toRealPath sanitizer", "java",
                          "Path", "toRealPath", "path-traversal"));

    p
}

// ---------------------------------------------------------------------------
// 7. Deserialization Pack — CWE-502
// ---------------------------------------------------------------------------

pub fn deserialization_pack() -> RulePack {
    let mut p = RulePack::new("deserialization");

    // Python
    p.add_rule(sink_qn("deser-001", "pickle.loads Insecure Deserialization", "python",
                       "pickle.loads", 502, Severity::Critical, "deserialization",
                       "pickle.loads() on untrusted data allows arbitrary code execution."));
    p.add_rule(sink_qn("deser-002", "pickle.load Insecure Deserialization", "python",
                       "pickle.load", 502, Severity::Critical, "deserialization",
                       "pickle.load() on untrusted data allows arbitrary code execution."));
    p.add_rule(sink_qn("deser-003", "yaml.load Insecure Deserialization", "python",
                       "yaml.load", 502, Severity::Critical, "deserialization",
                       "yaml.load() without Loader=SafeLoader can execute arbitrary Python."));
    p.add_rule(sink_qn("deser-004", "marshal.loads Insecure Deserialization", "python",
                       "marshal.loads", 502, Severity::Critical, "deserialization",
                       "marshal.loads() on untrusted data is dangerous."));
    p.add_rule(sink_qn("deser-005", "jsonpickle.decode Insecure Deserialization", "python",
                       "jsonpickle.decode", 502, Severity::Critical, "deserialization",
                       "jsonpickle.decode() allows arbitrary object construction."));

    // Java
    p.add_rule(sink_method("deser-006", "ObjectInputStream.readObject", "java",
                           "ObjectInputStream", "readObject", 502, Severity::Critical,
                           "deserialization",
                           "Java deserialization via readObject() with untrusted data."));
    p.add_rule(sink_method("deser-007", "XStream.fromXML", "java",
                           "XStream", "fromXML", 502, Severity::Critical, "deserialization",
                           "XStream deserialization of untrusted XML can execute code."));

    p
}

// ---------------------------------------------------------------------------
// 8. Cryptography Pack — CWE-327 Weak Crypto, CWE-319 Cleartext
// ---------------------------------------------------------------------------

pub fn cryptography_pack() -> RulePack {
    let mut p = RulePack::new("cryptography");

    // Weak hash algorithms (CWE-327)
    p.add_rule(sink_qn("crypto-001", "hashlib.md5 Weak Hash", "python",
                       "hashlib.md5", 327, Severity::Medium, "weak-cryptography",
                       "MD5 is cryptographically broken; use SHA-256 or better."));
    p.add_rule(sink_qn("crypto-002", "hashlib.sha1 Weak Hash", "python",
                       "hashlib.sha1", 327, Severity::Medium, "weak-cryptography",
                       "SHA-1 is deprecated for security use; use SHA-256 or better."));
    p.add_rule(sink_method("crypto-003", "Java MD5 Weak Hash", "java",
                           "MessageDigest", "getInstance", 327, Severity::Medium,
                           "weak-cryptography",
                           "Verify that MD5 or SHA-1 is not passed to MessageDigest.getInstance()."));

    // Weak ciphers (CWE-327)
    p.add_rule(sink_method("crypto-004", "DES Weak Cipher", "java",
                           "Cipher", "getInstance", 327, Severity::High,
                           "weak-cryptography",
                           "DES and 3DES are considered insecure; use AES-256."));
    p.add_rule(sink_qn("crypto-005", "Python DES usage", "python",
                       "Crypto.Cipher.DES.new", 327, Severity::High,
                       "weak-cryptography",
                       "DES cipher is insecure; prefer AES."));

    // Cleartext transmission (CWE-319)
    p.add_rule(sink_qn("crypto-006", "smtplib.SMTP cleartext", "python",
                       "smtplib.SMTP", 319, Severity::High, "cleartext-transmission",
                       "smtplib.SMTP() uses cleartext; use SMTP_SSL or starttls()."));
    p.add_rule(sink_qn("crypto-007", "ftplib.FTP cleartext", "python",
                       "ftplib.FTP", 319, Severity::High, "cleartext-transmission",
                       "FTP transmits credentials in cleartext; use FTPS."));
    p.add_rule(sink_method("crypto-008", "HttpURLConnection cleartext", "java",
                           "HttpURLConnection", "openConnection", 319, Severity::Medium,
                           "cleartext-transmission",
                           "HTTP connections are unencrypted; use HTTPS."));

    p
}

// ---------------------------------------------------------------------------
// 9. Authentication Pack — CWE-798, CWE-259
// ---------------------------------------------------------------------------

pub fn authentication_pack() -> RulePack {
    let mut p = RulePack::new("authentication");

    // Hardcoded credential sinks (CWE-798 / CWE-259)
    p.add_rule(sink("auth-001", "Hardcoded password in connect()", "python", "connect",
                    798, Severity::Critical, "hardcoded-credentials",
                    "Database connect() with a hardcoded password."));
    p.add_rule(sink_method("auth-002", "DriverManager.getConnection hardcoded", "java",
                           "DriverManager", "getConnection", 798, Severity::Critical,
                           "hardcoded-credentials",
                           "JDBC connection with hardcoded password string."));
    p.add_rule(sink("auth-003", "Hardcoded password in login()", "python", "login",
                    259, Severity::High, "hardcoded-credentials",
                    "login() called with a literal password string."));
    p.add_rule(sink_method("auth-004", "Spring @Value hardcoded", "java",
                           "BCryptPasswordEncoder", "encode", 259, Severity::Medium,
                           "hardcoded-credentials",
                           "Ensure passwords encoded here are not hardcoded literals."));

    p
}

// ---------------------------------------------------------------------------
// 10. Secrets Pack — Generic secret detection
// ---------------------------------------------------------------------------

pub fn secrets_pack() -> RulePack {
    let mut p = RulePack::new("secrets");

    // Secret leakage (CWE-200)
    p.add_rule(sink("sec-001", "print() Information Exposure", "python", "print",
                    200, Severity::Low, "information-exposure",
                    "Printing tainted data may expose sensitive information."));
    p.add_rule(sink_qn("sec-002", "logging.info Information Exposure", "python",
                       "logging.info", 200, Severity::Low, "information-exposure",
                       "Logging tainted data may expose sensitive information."));
    p.add_rule(sink_qn("sec-003", "logging.debug Information Exposure", "python",
                       "logging.debug", 200, Severity::Low, "information-exposure",
                       "Logging sensitive data at DEBUG level can expose it in logs."));
    p.add_rule(sink_method("sec-004", "System.out.println Information Exposure", "java",
                           "System", "out.println", 200, Severity::Low,
                           "information-exposure",
                           "Printing tainted data to stdout may expose sensitive information."));
    p.add_rule(sink_method("sec-005", "Logger.info Information Exposure", "java",
                           "Logger", "info", 200, Severity::Low, "information-exposure",
                           "Logging tainted data can leak sensitive information."));

    p
}

// ---------------------------------------------------------------------------
// 11. SSRF Pack — Server-Side Request Forgery (CWE-918)
// ---------------------------------------------------------------------------

pub fn ssrf_pack() -> RulePack {
    let mut p = RulePack::new("ssrf");

    // Python SSRF sinks
    p.add_rule(sink_qn("ssrf-001", "requests.get SSRF", "python",
                       "requests.get", 918, Severity::High, "ssrf",
                       "HTTP GET to a user-controlled URL enables SSRF."));
    p.add_rule(sink_qn("ssrf-002", "requests.post SSRF", "python",
                       "requests.post", 918, Severity::High, "ssrf",
                       "HTTP POST to a user-controlled URL enables SSRF."));
    p.add_rule(sink_qn("ssrf-003", "requests.request SSRF", "python",
                       "requests.request", 918, Severity::High, "ssrf",
                       "HTTP request to a user-controlled URL enables SSRF."));
    p.add_rule(sink_qn("ssrf-004", "urllib.request.urlopen SSRF", "python",
                       "urllib.request.urlopen", 918, Severity::High, "ssrf",
                       "urlopen() on a user-controlled URL enables SSRF."));
    p.add_rule(sink_qn("ssrf-005", "httpx.get SSRF", "python",
                       "httpx.get", 918, Severity::High, "ssrf",
                       "httpx.get() on user-controlled URL enables SSRF."));

    // Java SSRF sinks
    p.add_rule(sink_method("ssrf-006", "URL.openConnection SSRF", "java",
                           "URL", "openConnection", 918, Severity::High, "ssrf",
                           "Opening a connection to a user-controlled URL enables SSRF."));
    p.add_rule(sink_method("ssrf-007", "HttpURLConnection.connect SSRF", "java",
                           "HttpURLConnection", "connect", 918, Severity::High, "ssrf",
                           "Connecting to a user-controlled URL enables SSRF."));

    p
}

// ---------------------------------------------------------------------------
// 12. Command Injection Pack — CWE-78
// ---------------------------------------------------------------------------

pub fn command_injection_pack() -> RulePack {
    let mut p = RulePack::new("command-injection");

    // Python command injection sinks
    p.add_rule(sink_qn("cmd-001", "os.system Command Injection", "python",
                       "os.system", 78, Severity::Critical, "command-injection",
                       "os.system() with untrusted input enables OS command injection."));
    p.add_rule(sink_qn("cmd-002", "os.popen Command Injection", "python",
                       "os.popen", 78, Severity::Critical, "command-injection",
                       "os.popen() with untrusted input enables OS command injection."));
    p.add_rule(sink_qn("cmd-003", "subprocess.run Command Injection", "python",
                       "subprocess.run", 78, Severity::Critical, "command-injection",
                       "subprocess.run() with shell=True and untrusted input is dangerous."));
    p.add_rule(sink_qn("cmd-004", "subprocess.Popen Command Injection", "python",
                       "subprocess.Popen", 78, Severity::Critical, "command-injection",
                       "subprocess.Popen() with untrusted shell commands enables injection."));
    p.add_rule(sink_qn("cmd-005", "subprocess.call Command Injection", "python",
                       "subprocess.call", 78, Severity::Critical, "command-injection",
                       "subprocess.call() with untrusted input enables command injection."));
    p.add_rule(sink_qn("cmd-006", "subprocess.check_call Command Injection", "python",
                       "subprocess.check_call", 78, Severity::Critical, "command-injection",
                       "subprocess.check_call() with untrusted input enables injection."));

    // Java command injection sinks
    p.add_rule(sink_method("cmd-007", "Runtime.exec Command Injection", "java",
                           "Runtime", "exec", 78, Severity::Critical, "command-injection",
                           "Runtime.exec() with untrusted input enables OS command injection."));
    p.add_rule(sink_method("cmd-008", "ProcessBuilder.start Command Injection", "java",
                           "ProcessBuilder", "start", 78, Severity::Critical,
                           "command-injection",
                           "ProcessBuilder with untrusted commands enables injection."));

    // Sanitizers
    p.add_rule(san_qn("cmd-san-001", "shlex.quote sanitizer", "python",
                      "shlex.quote", "command-injection"));
    p.add_rule(san_qn("cmd-san-002", "shlex.split sanitizer", "python",
                      "shlex.split", "command-injection"));

    p
}

// ---------------------------------------------------------------------------
// 13. XXE Pack — CWE-611
// ---------------------------------------------------------------------------

pub fn xxe_pack() -> RulePack {
    let mut p = RulePack::new("xxe");

    // Python XML sinks
    p.add_rule(sink_qn("xxe-001", "xml.etree.ElementTree.parse XXE", "python",
                       "xml.etree.ElementTree.parse", 611, Severity::High, "xxe",
                       "ElementTree.parse() is vulnerable to XXE if the parser is not hardened."));
    p.add_rule(sink_qn("xxe-002", "xml.etree.ElementTree.fromstring XXE", "python",
                       "xml.etree.ElementTree.fromstring", 611, Severity::High, "xxe",
                       "fromstring() may be vulnerable to XXE."));
    p.add_rule(sink_qn("xxe-003", "lxml.etree.parse XXE", "python",
                       "lxml.etree.parse", 611, Severity::High, "xxe",
                       "lxml.etree.parse() without resolve_entities=False is vulnerable to XXE."));
    p.add_rule(sink_qn("xxe-004", "minidom.parseString XXE", "python",
                       "xml.dom.minidom.parseString", 611, Severity::High, "xxe",
                       "minidom.parseString() does not disable external entities by default."));

    // Java XML sinks
    p.add_rule(sink_method("xxe-005", "DocumentBuilder.parse XXE", "java",
                           "DocumentBuilder", "parse", 611, Severity::High, "xxe",
                           "DocumentBuilder.parse() without disabling external entities."));
    p.add_rule(sink_method("xxe-006", "SAXParser.parse XXE", "java",
                           "SAXParser", "parse", 611, Severity::High, "xxe",
                           "SAXParser.parse() without disabling external entities."));
    p.add_rule(sink_method("xxe-007", "XMLReader.parse XXE", "java",
                           "XMLReader", "parse", 611, Severity::High, "xxe",
                           "XMLReader.parse() without external entity restrictions."));

    p
}

// ---------------------------------------------------------------------------
// Registry of all packs
// ---------------------------------------------------------------------------

/// Return one instance of every embedded rule pack.
pub fn all_packs() -> Vec<RulePack> {
    vec![
        core_pack(),
        python_pack(),
        java_pack(),
        web_pack(),
        database_pack(),
        filesystem_pack(),
        deserialization_pack(),
        cryptography_pack(),
        authentication_pack(),
        secrets_pack(),
        ssrf_pack(),
        command_injection_pack(),
        xxe_pack(),
    ]
}

/// Build a `RuleRegistry` from every embedded pack.
pub fn full_registry() -> v2_rules::RuleRegistry {
    let mut registry = v2_rules::RuleRegistry::new();
    for pack in all_packs() {
        registry.load(&pack);
    }
    registry
}
