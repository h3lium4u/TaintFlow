use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Core Rule Structures
// ---------------------------------------------------------------------------

/// Severity level for a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

/// The kind of rule — what role does the matched call play.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleKind {
    Source,
    Sink,
    Sanitizer,
    Propagator,
}

/// Matcher describes how a call site is matched against a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Matcher {
    /// Matches a bare function name: `source()`, `eval()`
    FunctionName(String),
    /// Matches a qualified name: `os.system`, `subprocess.run`
    QualifiedName(String),
    /// Matches a class method: `Runtime.exec`
    MethodName { class: String, method: String },
}

impl Matcher {
    /// Returns the primary lookup key used to index this matcher.
    pub fn lookup_key(&self) -> &str {
        match self {
            Matcher::FunctionName(name) => name.as_str(),
            Matcher::QualifiedName(name) => name.as_str(),
            Matcher::MethodName { method, .. } => method.as_str(),
        }
    }

    /// Tests whether this matcher matches a given callee string.
    pub fn matches(&self, callee: &str) -> bool {
        match self {
            Matcher::FunctionName(name) => callee == name.as_str(),
            Matcher::QualifiedName(name) => callee == name.as_str(),
            Matcher::MethodName { class, method } => {
                // Accept both "Class.method" and bare "method"
                callee == format!("{}.{}", class, method).as_str()
                    || callee == method.as_str()
            }
        }
    }
}

/// A single taint rule (source, sink, sanitizer, or propagator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub kind: RuleKind,
    pub language: Option<String>,
    pub cwe: Option<u32>,
    pub severity: Severity,
    pub category: Option<String>,
    pub description: Option<String>,
    pub matcher: Matcher,
}

/// A named pack of rules covering all categories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulePack {
    pub name: String,
    pub rules: Vec<Rule>,
}

impl RulePack {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }
}

// ---------------------------------------------------------------------------
// Rule Registry — O(1) lookup structures
// ---------------------------------------------------------------------------

/// Efficient lookup registry. Indexes rules by their lookup key so that
/// the taint engine can query in O(1) per call site.
#[derive(Debug, Default)]
pub struct RuleRegistry {
    sources: HashMap<String, Vec<Rule>>,
    sinks: HashMap<String, Vec<Rule>>,
    sanitizers: HashMap<String, Vec<Rule>>,
    propagators: HashMap<String, Vec<Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load all rules from a RulePack, deduplicating by (id, kind).
    pub fn load(&mut self, pack: &RulePack) {
        for rule in &pack.rules {
            let key = rule.matcher.lookup_key().to_string();
            let map = match rule.kind {
                RuleKind::Source => &mut self.sources,
                RuleKind::Sink => &mut self.sinks,
                RuleKind::Sanitizer => &mut self.sanitizers,
                RuleKind::Propagator => &mut self.propagators,
            };
            let bucket = map.entry(key).or_default();
            // Deduplicate by rule ID.
            if !bucket.iter().any(|r| r.id == rule.id) {
                bucket.push(rule.clone());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Query API
    // -----------------------------------------------------------------------

    /// Returns true if `callee` matches any registered source rule.
    pub fn is_source(&self, callee: &str) -> bool {
        self.lookup_rules(&self.sources, callee).is_some()
    }

    /// Returns true if `callee` matches any registered sink rule.
    pub fn is_sink(&self, callee: &str) -> bool {
        self.lookup_rules(&self.sinks, callee).is_some()
    }

    /// Returns true if `callee` matches any registered sanitizer rule.
    pub fn is_sanitizer(&self, callee: &str) -> bool {
        self.lookup_rules(&self.sanitizers, callee).is_some()
    }

    /// Returns true if `callee` matches any registered propagator rule.
    pub fn is_propagator(&self, callee: &str) -> bool {
        self.lookup_rules(&self.propagators, callee).is_some()
    }

    /// Returns the matching source rules for `callee`.
    pub fn source_rules(&self, callee: &str) -> Vec<&Rule> {
        self.matching_rules(&self.sources, callee)
    }

    /// Returns the matching sink rules for `callee`.
    pub fn sink_rules(&self, callee: &str) -> Vec<&Rule> {
        self.matching_rules(&self.sinks, callee)
    }

    /// Returns the matching sanitizer rules for `callee`.
    pub fn sanitizer_rules(&self, callee: &str) -> Vec<&Rule> {
        self.matching_rules(&self.sanitizers, callee)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn lookup_rules<'a>(
        &'a self,
        map: &'a HashMap<String, Vec<Rule>>,
        callee: &str,
    ) -> Option<&'a Vec<Rule>> {
        // Fast-path: exact key match.
        if let Some(bucket) = map.get(callee) {
            if bucket.iter().any(|r| r.matcher.matches(callee)) {
                return Some(bucket);
            }
        }
        // Slow-path: qualified / method name with dot prefix.
        if callee.contains('.') {
            let method_part = callee.rsplit('.').next().unwrap_or(callee);
            if let Some(bucket) = map.get(method_part) {
                if bucket.iter().any(|r| r.matcher.matches(callee)) {
                    return Some(bucket);
                }
            }
        }
        None
    }

    fn matching_rules<'a>(
        &'a self,
        map: &'a HashMap<String, Vec<Rule>>,
        callee: &str,
    ) -> Vec<&'a Rule> {
        let mut out = Vec::new();
        if let Some(bucket) = map.get(callee) {
            for r in bucket {
                if r.matcher.matches(callee) {
                    out.push(r);
                }
            }
        }
        if callee.contains('.') {
            let method_part = callee.rsplit('.').next().unwrap_or(callee);
            if let Some(bucket) = map.get(method_part) {
                for r in bucket {
                    if r.matcher.matches(callee) && !out.iter().any(|x: &&Rule| x.id == r.id) {
                        out.push(r);
                    }
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Finding — produced when a sink is reached by a tainted path
// ---------------------------------------------------------------------------

/// Confidence in a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A taint finding: a tainted access path reached a sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub cwe: Option<u32>,
    pub severity: Severity,
    pub source_location: Option<String>,
    pub sink_location: Option<String>,
    pub access_path: String,
    pub call_trace: Vec<String>,
    pub confidence: Confidence,
}

// ---------------------------------------------------------------------------
// Built-in default rule pack
// ---------------------------------------------------------------------------

/// Returns a small built-in rule pack for testing and out-of-the-box coverage.
pub fn default_rule_pack() -> RulePack {
    let mut pack = RulePack::new("default");

    // ----- Python Sources -----
    for (id, name, matcher_str) in [
        ("py-src-001", "Python input()", "input"),
        ("py-src-002", "Python os.getenv", "os.getenv"),
        ("py-src-003", "Python sys.argv", "sys.argv"),
    ] {
        pack.add_rule(Rule {
            id: id.to_string(),
            name: name.to_string(),
            kind: RuleKind::Source,
            language: Some("python".to_string()),
            cwe: None,
            severity: Severity::Medium,
            category: Some("source".to_string()),
            description: None,
            matcher: if matcher_str.contains('.') {
                Matcher::QualifiedName(matcher_str.to_string())
            } else {
                Matcher::FunctionName(matcher_str.to_string())
            },
        });
    }

    // ----- Python Sinks -----
    for (id, name, matcher_str, cwe) in [
        ("py-sink-001", "Python eval()", "eval", 95u32),
        ("py-sink-002", "Python exec()", "exec", 95),
        ("py-sink-003", "Python os.system()", "os.system", 78),
        ("py-sink-004", "Python subprocess.run()", "subprocess.run", 78),
    ] {
        pack.add_rule(Rule {
            id: id.to_string(),
            name: name.to_string(),
            kind: RuleKind::Sink,
            language: Some("python".to_string()),
            cwe: Some(cwe),
            severity: Severity::High,
            category: Some("injection".to_string()),
            description: None,
            matcher: if matcher_str.contains('.') {
                Matcher::QualifiedName(matcher_str.to_string())
            } else {
                Matcher::FunctionName(matcher_str.to_string())
            },
        });
    }

    // ----- Python Sanitizers -----
    for (id, name, matcher_str) in [
        ("py-san-001", "Python html.escape", "html.escape"),
        ("py-san-002", "Python shlex.quote", "shlex.quote"),
    ] {
        pack.add_rule(Rule {
            id: id.to_string(),
            name: name.to_string(),
            kind: RuleKind::Sanitizer,
            language: Some("python".to_string()),
            cwe: None,
            severity: Severity::Info,
            category: Some("sanitizer".to_string()),
            description: None,
            matcher: Matcher::QualifiedName(matcher_str.to_string()),
        });
    }

    // ----- Java Sources -----
    pack.add_rule(Rule {
        id: "java-src-001".to_string(),
        name: "Java HttpServletRequest.getParameter".to_string(),
        kind: RuleKind::Source,
        language: Some("java".to_string()),
        cwe: None,
        severity: Severity::Medium,
        category: Some("source".to_string()),
        description: None,
        matcher: Matcher::MethodName {
            class: "HttpServletRequest".to_string(),
            method: "getParameter".to_string(),
        },
    });

    // ----- Java Sinks -----
    for (id, name, class, method, cwe) in [
        ("java-sink-001", "Java Runtime.exec", "Runtime", "exec", 78u32),
        ("java-sink-002", "Java ProcessBuilder.start", "ProcessBuilder", "start", 78),
    ] {
        pack.add_rule(Rule {
            id: id.to_string(),
            name: name.to_string(),
            kind: RuleKind::Sink,
            language: Some("java".to_string()),
            cwe: Some(cwe),
            severity: Severity::High,
            category: Some("injection".to_string()),
            description: None,
            matcher: Matcher::MethodName {
                class: class.to_string(),
                method: method.to_string(),
            },
        });
    }

    // ----- Java Sanitizers -----
    pack.add_rule(Rule {
        id: "java-san-001".to_string(),
        name: "Java StringEscapeUtils.escapeHtml4".to_string(),
        kind: RuleKind::Sanitizer,
        language: Some("java".to_string()),
        cwe: None,
        severity: Severity::Info,
        category: Some("sanitizer".to_string()),
        description: None,
        matcher: Matcher::MethodName {
            class: "StringEscapeUtils".to_string(),
            method: "escapeHtml4".to_string(),
        },
    });

    pack
}

/// Convenience: build a RuleRegistry pre-loaded with the default pack.
pub fn default_registry() -> RuleRegistry {
    let mut registry = RuleRegistry::new();
    registry.load(&default_rule_pack());
    registry
}

pub fn init() {
    println!("v2-rules initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> RuleRegistry {
        default_registry()
    }

    #[test]
    fn test_init() {
        init();
    }

    // --- Source recognition ---

    #[test]
    fn test_source_function_name() {
        let reg = make_registry();
        assert!(reg.is_source("input"));
    }

    #[test]
    fn test_source_qualified_name() {
        let reg = make_registry();
        assert!(reg.is_source("os.getenv"));
        assert!(reg.is_source("sys.argv"));
    }

    #[test]
    fn test_source_java_method() {
        let reg = make_registry();
        assert!(reg.is_source("getParameter"));
        assert!(reg.is_source("HttpServletRequest.getParameter"));
    }

    #[test]
    fn test_source_negative() {
        let reg = make_registry();
        assert!(!reg.is_source("eval"));
        assert!(!reg.is_source("unknown_fn"));
    }

    // --- Sink recognition ---

    #[test]
    fn test_sink_function_name() {
        let reg = make_registry();
        assert!(reg.is_sink("eval"));
        assert!(reg.is_sink("exec"));
    }

    #[test]
    fn test_sink_qualified_name() {
        let reg = make_registry();
        assert!(reg.is_sink("os.system"));
        assert!(reg.is_sink("subprocess.run"));
    }

    #[test]
    fn test_sink_java_method() {
        let reg = make_registry();
        assert!(reg.is_sink("exec"));
        assert!(reg.is_sink("Runtime.exec"));
        assert!(reg.is_sink("start"));
        assert!(reg.is_sink("ProcessBuilder.start"));
    }

    #[test]
    fn test_sink_negative() {
        let reg = make_registry();
        assert!(!reg.is_sink("input"));
        assert!(!reg.is_sink("unknown_sink"));
    }

    // --- Sanitizer recognition ---

    #[test]
    fn test_sanitizer_qualified_name() {
        let reg = make_registry();
        assert!(reg.is_sanitizer("html.escape"));
        assert!(reg.is_sanitizer("shlex.quote"));
    }

    #[test]
    fn test_sanitizer_java_method() {
        let reg = make_registry();
        assert!(reg.is_sanitizer("escapeHtml4"));
        assert!(reg.is_sanitizer("StringEscapeUtils.escapeHtml4"));
    }

    #[test]
    fn test_sanitizer_negative() {
        let reg = make_registry();
        assert!(!reg.is_sanitizer("eval"));
        assert!(!reg.is_sanitizer("unknown_san"));
    }

    // --- Rule loading ---

    #[test]
    fn test_rule_loading() {
        let pack = default_rule_pack();
        assert!(!pack.rules.is_empty());
    }

    #[test]
    fn test_load_multiple_packs() {
        let mut reg = RuleRegistry::new();
        reg.load(&default_rule_pack());
        reg.load(&default_rule_pack());  // load again — should deduplicate
        // eval should still only have 1 rule behind it
        assert_eq!(reg.sink_rules("eval").len(), 1);
    }

    // --- Rule lookup ---

    #[test]
    fn test_rule_lookup_returns_correct_rule() {
        let reg = make_registry();
        let rules = reg.source_rules("input");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "py-src-001");
    }

    // --- Rule matching ---

    #[test]
    fn test_function_name_matcher() {
        let m = Matcher::FunctionName("eval".to_string());
        assert!(m.matches("eval"));
        assert!(!m.matches("exec"));
    }

    #[test]
    fn test_qualified_name_matcher() {
        let m = Matcher::QualifiedName("os.system".to_string());
        assert!(m.matches("os.system"));
        assert!(!m.matches("system"));
    }

    #[test]
    fn test_method_name_matcher() {
        let m = Matcher::MethodName {
            class: "Runtime".to_string(),
            method: "exec".to_string(),
        };
        assert!(m.matches("Runtime.exec"));
        assert!(m.matches("exec"));
        assert!(!m.matches("start"));
    }

    // --- Rule-driven taint propagation ---

    #[test]
    fn test_rule_driven_source_detection() {
        let reg = make_registry();
        let callee = "input";
        assert!(reg.is_source(callee));
        assert!(!reg.is_sink(callee));
        assert!(!reg.is_sanitizer(callee));
    }

    #[test]
    fn test_rule_driven_sink_detection() {
        let reg = make_registry();
        let callee = "eval";
        assert!(reg.is_sink(callee));
        assert!(!reg.is_source(callee));
        assert!(!reg.is_sanitizer(callee));
    }

    #[test]
    fn test_rule_driven_sanitizer_detection() {
        let reg = make_registry();
        let callee = "html.escape";
        assert!(reg.is_sanitizer(callee));
        assert!(!reg.is_source(callee));
        assert!(!reg.is_sink(callee));
    }

    // --- Multiple rules ---

    #[test]
    fn test_multiple_rules_same_key() {
        let mut pack = RulePack::new("test");
        pack.add_rule(Rule {
            id: "src-a".to_string(),
            name: "Source A".to_string(),
            kind: RuleKind::Source,
            language: None,
            cwe: None,
            severity: Severity::High,
            category: None,
            description: None,
            matcher: Matcher::FunctionName("my_source".to_string()),
        });
        pack.add_rule(Rule {
            id: "src-b".to_string(),
            name: "Source B".to_string(),
            kind: RuleKind::Source,
            language: None,
            cwe: None,
            severity: Severity::Medium,
            category: None,
            description: None,
            matcher: Matcher::FunctionName("my_source".to_string()),
        });
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert_eq!(reg.source_rules("my_source").len(), 2);
    }

    // --- Duplicate rule handling ---

    #[test]
    fn test_duplicate_rule_deduplication() {
        let mut pack = RulePack::new("test");
        let rule = Rule {
            id: "dup-001".to_string(),
            name: "Dup Source".to_string(),
            kind: RuleKind::Source,
            language: None,
            cwe: None,
            severity: Severity::High,
            category: None,
            description: None,
            matcher: Matcher::FunctionName("dup_source".to_string()),
        };
        pack.add_rule(rule.clone());
        pack.add_rule(rule);  // duplicate
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        // Both rules in pack are deduplicated by ID during load
        assert_eq!(reg.source_rules("dup_source").len(), 1);
    }

    // --- Rule-driven sink reporting ---

    #[test]
    fn test_sink_rules_metadata() {
        let reg = make_registry();
        let rules = reg.sink_rules("eval");
        assert!(!rules.is_empty());
        let r = &rules[0];
        assert_eq!(r.cwe, Some(95));
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn test_finding_construction() {
        let finding = Finding {
            rule_id: "py-sink-001".to_string(),
            rule_name: "Python eval()".to_string(),
            cwe: Some(95),
            severity: Severity::High,
            source_location: Some("line 3".to_string()),
            sink_location: Some("line 7".to_string()),
            access_path: "x".to_string(),
            call_trace: vec!["main -> eval".to_string()],
            confidence: Confidence::High,
        };
        assert_eq!(finding.rule_id, "py-sink-001");
        assert_eq!(finding.cwe, Some(95));
    }
}
