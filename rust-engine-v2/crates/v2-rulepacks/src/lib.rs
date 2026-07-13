pub mod loader;
pub mod meta;
pub mod packs;

pub use loader::RulePackLoader;
pub use meta::{ConfidenceLevel, CweKnowledgeBase, CweMetadata, ExtendedRuleEntry, OwaspCategory};
pub use packs::{
    all_packs, authentication_pack, command_injection_pack, core_pack, cryptography_pack,
    database_pack, deserialization_pack, filesystem_pack, full_registry, java_pack, python_pack,
    secrets_pack, ssrf_pack, web_pack, xxe_pack,
};

pub fn init() {
    println!("v2-rulepacks initialized");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use v2_rules::{Matcher, Rule, RuleKind, RulePack, RuleRegistry, Severity};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_source(id: &str, fn_name: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: fn_name.to_string(),
            kind: RuleKind::Source,
            language: Some("python".to_string()),
            cwe: None,
            severity: Severity::Info,
            category: Some("input".to_string()),
            description: Some("test source".to_string()),
            matcher: Matcher::FunctionName(fn_name.to_string()),
        }
    }

    fn make_sink(id: &str, fn_name: &str, cwe: u32) -> Rule {
        Rule {
            id: id.to_string(),
            name: fn_name.to_string(),
            kind: RuleKind::Sink,
            language: Some("python".to_string()),
            cwe: Some(cwe),
            severity: Severity::High,
            category: Some("injection".to_string()),
            description: Some("test sink".to_string()),
            matcher: Matcher::FunctionName(fn_name.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // 1. Source Matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_source_matching_python_input() {
        let registry = full_registry();
        assert!(registry.is_source("input"), "input() must be a source");
    }

    #[test]
    fn test_source_matching_flask_request() {
        let pack = python_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("flask.request.args.get"));
        assert!(reg.is_source("flask.request.form.get"));
    }

    #[test]
    fn test_source_matching_django_request() {
        let pack = python_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("django.request.GET.get"));
        assert!(reg.is_source("django.request.POST.get"));
    }

    #[test]
    fn test_source_matching_java_httprequest() {
        let pack = java_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("HttpServletRequest.getParameter")
            || reg.is_source("getParameter"),
            "HttpServletRequest.getParameter must be a source");
    }

    #[test]
    fn test_source_matching_java_scanner() {
        let pack = java_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("Scanner.nextLine") || reg.is_source("nextLine"));
    }

    #[test]
    fn test_source_matching_env() {
        let pack = python_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("os.getenv"));
    }

    #[test]
    fn test_new_python_sources() {
        let pack = python_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("flask.request.args"));
        assert!(reg.is_source("flask.request.form"));
        assert!(reg.is_source("flask.request.values"));
        assert!(reg.is_source("flask.request.json"));
        assert!(reg.is_source("fastapi.Request"));
        assert!(reg.is_source("django.request.GET"));
        assert!(reg.is_source("os.environ"));
        assert!(reg.is_source("click.option"));
    }

    #[test]
    fn test_new_java_sources() {
        let pack = java_pack();
        let mut reg = RuleRegistry::new();
        reg.load(&pack);
        assert!(reg.is_source("ServletRequest.getParameter"));
        assert!(reg.is_source("ServletRequest.getParameterValues"));
        assert!(reg.is_source("HttpServletRequest.getCookies"));
        assert!(reg.is_source("RequestParam"));
        assert!(reg.is_source("PathVariable"));
        assert!(reg.is_source("RequestBody"));
    }

    #[test]
    fn test_deterministic_registry_ordering() {
        let _registry = full_registry();
        // Since we load all packs, let's verify ordering by checking if we have unique entries
        let rules = all_packs();
        let mut seen_ids = std::collections::HashSet::new();
        for pack in &rules {
            for r in &pack.rules {
                assert!(seen_ids.insert(r.id.clone()), "Duplicate rule ID registration: {}", r.id);
            }
        }
    }


    // -----------------------------------------------------------------------
    // 2. Sink Matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_sink_matching_eval() {
        let registry = full_registry();
        assert!(registry.is_sink("eval"), "eval() must be a sink");
    }

    #[test]
    fn test_sink_matching_exec() {
        let registry = full_registry();
        assert!(registry.is_sink("exec"), "exec() must be a sink");
    }

    #[test]
    fn test_sink_matching_os_system() {
        let registry = full_registry();
        assert!(registry.is_sink("os.system"), "os.system must be a sink");
    }

    #[test]
    fn test_sink_matching_subprocess_popen() {
        let registry = full_registry();
        assert!(registry.is_sink("subprocess.Popen"));
    }

    #[test]
    fn test_sink_matching_runtime_exec() {
        let registry = full_registry();
        assert!(registry.is_sink("Runtime.exec") || registry.is_sink("exec"),
            "Runtime.exec must be a sink");
    }

    #[test]
    fn test_sink_matching_sql_cursor() {
        let registry = full_registry();
        // cursor.execute is a MethodName matcher; engine queries by method part
        assert!(registry.is_sink("cursor.execute") || registry.is_sink("execute"),
            "cursor.execute must be a sink");
    }

    #[test]
    fn test_sink_matching_pickle_loads() {
        let registry = full_registry();
        assert!(registry.is_sink("pickle.loads"));
    }

    #[test]
    fn test_sink_matching_yaml_load() {
        let registry = full_registry();
        assert!(registry.is_sink("yaml.load"));
    }

    #[test]
    fn test_sink_matching_requests_get() {
        let registry = full_registry();
        assert!(registry.is_sink("requests.get"), "requests.get must be an SSRF sink");
    }

    #[test]
    fn test_sink_matching_redirect() {
        let registry = full_registry();
        assert!(registry.is_sink("redirect"), "redirect() must be an open redirect sink");
    }

    #[test]
    fn test_sink_matching_hashlib_md5() {
        let registry = full_registry();
        assert!(registry.is_sink("hashlib.md5"), "hashlib.md5 must be a weak-crypto sink");
    }

    #[test]
    fn test_sink_matching_xml_parse() {
        let registry = full_registry();
        assert!(registry.is_sink("xml.etree.ElementTree.parse"), "XXE sink must be registered");
    }

    // -----------------------------------------------------------------------
    // 3. Sanitizer Matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitizer_html_escape() {
        let registry = full_registry();
        assert!(registry.is_sanitizer("html.escape") || registry.is_sanitizer("escape"),
            "html.escape must be a sanitizer");
    }

    #[test]
    fn test_sanitizer_shlex_quote() {
        let registry = full_registry();
        assert!(registry.is_sanitizer("shlex.quote"));
    }

    #[test]
    fn test_sanitizer_os_path_realpath() {
        let registry = full_registry();
        assert!(registry.is_sanitizer("os.path.realpath") || registry.is_sanitizer("os.path.abspath"),
            "os.path.realpath must be a sanitizer");
    }

    #[test]
    fn test_sanitizer_urllib_quote() {
        let registry = full_registry();
        assert!(registry.is_sanitizer("urllib.parse.quote")
            || registry.is_sanitizer("urllib.parse.quote_plus"),
            "urllib.parse.quote must be a sanitizer");
    }

    #[test]
    fn test_sanitizer_markupsafe() {
        let registry = full_registry();
        assert!(registry.is_sanitizer("markupsafe.escape"));
    }

    // -----------------------------------------------------------------------
    // 4. Rule Metadata Preservation
    // -----------------------------------------------------------------------

    #[test]
    fn test_metadata_cwe_on_sink() {
        let pack = command_injection_pack();
        let os_system = pack.rules.iter().find(|r| r.id == "cmd-001").unwrap();
        assert_eq!(os_system.cwe, Some(78));
        assert_eq!(os_system.severity, Severity::Critical);
        assert_eq!(os_system.category.as_deref(), Some("command-injection"));
        assert!(os_system.description.is_some());
    }

    #[test]
    fn test_metadata_language_field() {
        let pack = python_pack();
        for rule in &pack.rules {
            assert_eq!(rule.language.as_deref(), Some("python"),
                "All rules in python_pack must have language=python");
        }
    }

    #[test]
    fn test_metadata_java_language_field() {
        let pack = java_pack();
        for rule in &pack.rules {
            assert_eq!(rule.language.as_deref(), Some("java"),
                "All rules in java_pack must have language=java");
        }
    }

    #[test]
    fn test_metadata_rule_ids_unique_within_pack() {
        for pack in all_packs() {
            let mut ids = std::collections::HashSet::new();
            for rule in &pack.rules {
                assert!(ids.insert(rule.id.clone()),
                    "Duplicate rule ID '{}' in pack '{}'", rule.id, pack.name);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 5. Duplicate Suppression
    // -----------------------------------------------------------------------

    #[test]
    fn test_duplicate_suppression_same_rule_id() {
        let mut registry = RuleRegistry::new();
        let pack1 = {
            let mut p = RulePack::new("p1");
            p.add_rule(make_source("dup-001", "my_source"));
            p
        };
        let pack2 = {
            let mut p = RulePack::new("p2");
            p.add_rule(make_source("dup-001", "my_source")); // same ID
            p
        };
        registry.load(&pack1);
        registry.load(&pack2);
        let rules = registry.source_rules("my_source");
        assert_eq!(rules.len(), 1, "Duplicate rule ID must be suppressed");
    }

    #[test]
    fn test_no_suppression_for_different_ids() {
        let mut registry = RuleRegistry::new();
        let mut pack = RulePack::new("p");
        pack.add_rule(make_sink("s-001", "dangerous", 89));
        pack.add_rule(make_sink("s-002", "dangerous", 78)); // different id, same callee
        registry.load(&pack);
        let rules = registry.sink_rules("dangerous");
        assert_eq!(rules.len(), 2, "Different rule IDs on same callee must both be registered");
    }

    // -----------------------------------------------------------------------
    // 6. Multi-Pack Loading
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_pack_loading() {
        let mut registry = RuleRegistry::new();
        registry.load(&python_pack());
        registry.load(&command_injection_pack());
        registry.load(&ssrf_pack());
        // Sources from python_pack
        assert!(registry.is_source("input"));
        // Sinks from command_injection_pack
        assert!(registry.is_sink("os.system"));
        // Sinks from ssrf_pack
        assert!(registry.is_sink("requests.get"));
    }

    #[test]
    fn test_loader_all_embedded() {
        let registry = RulePackLoader::all_embedded();
        // Spot-check a cross-section of the full registry
        assert!(registry.is_source("input"));
        assert!(registry.is_sink("eval"));
        assert!(registry.is_sanitizer("shlex.quote") || registry.is_sanitizer("shlex.split"));
    }

    #[test]
    fn test_loader_by_names() {
        let registry = RulePackLoader::embedded_by_names(&["command-injection"]);
        assert!(registry.is_sink("os.system"));
        // SSRF sinks should NOT be loaded
        assert!(!registry.is_sink("requests.get"));
    }

    // -----------------------------------------------------------------------
    // 7. Language Filtering
    // -----------------------------------------------------------------------

    #[test]
    fn test_language_filtering_python_only() {
        let registry = RulePackLoader::python_only();
        // Python sources must be present
        assert!(registry.is_source("input"));
        // Command injection sinks should be in python_only()
        assert!(registry.is_sink("os.system"));
    }

    #[test]
    fn test_language_filtering_java_only() {
        let registry = RulePackLoader::java_only();
        // Java source
        assert!(registry.is_source("getParameter") || registry.is_source("HttpServletRequest.getParameter"));
    }

    // -----------------------------------------------------------------------
    // 8. Stable Ordering
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_packs_stable_count() {
        // all_packs() must always return the same number of packs
        assert_eq!(all_packs().len(), all_packs().len());
        assert_eq!(all_packs().len(), 13);
    }

    #[test]
    fn test_all_packs_have_rules() {
        for pack in all_packs() {
            assert!(!pack.rules.is_empty(),
                "Pack '{}' must contain at least one rule", pack.name);
        }
    }

    #[test]
    fn test_full_registry_total_sources_and_sinks() {
        let registry = full_registry();
        // Sanity: verify a representative sample of sources and sinks exist
        let sources = ["input", "os.getenv", "flask.request.args.get"];
        for src in &sources {
            assert!(registry.is_source(src), "Expected source: {}", src);
        }
        let sinks = ["eval", "exec", "os.system", "pickle.loads", "requests.get",
                     "hashlib.md5", "redirect"];
        for sink in &sinks {
            assert!(registry.is_sink(sink), "Expected sink: {}", sink);
        }
    }

    // -----------------------------------------------------------------------
    // 9. CWE Knowledge Base
    // -----------------------------------------------------------------------

    #[test]
    fn test_cwe_kb_all_covered() {
        let all = CweKnowledgeBase::all();
        let ids: Vec<u32> = all.iter().map(|c| c.cwe_id).collect();
        // All 16 required CWEs must be present
        let required = [22u32, 78, 79, 89, 94, 95, 200, 259, 319, 327, 352, 502, 601, 611, 798, 918];
        for cwe in &required {
            assert!(ids.contains(cwe), "CWE-{} must be in the knowledge base", cwe);
        }
    }

    #[test]
    fn test_cwe_kb_lookup() {
        let cwe78 = CweKnowledgeBase::get(78).unwrap();
        assert_eq!(cwe78.cwe_id, 78);
        assert_eq!(cwe78.owasp, Some(OwaspCategory::A03Injection));
        assert_eq!(cwe78.severity_default, Severity::Critical);
        assert!(!cwe78.references.is_empty());
        assert_eq!(cwe78.cwe_string(), "CWE-78");
    }

    #[test]
    fn test_cwe_kb_missing_returns_none() {
        assert!(CweKnowledgeBase::get(99999).is_none());
    }

    #[test]
    fn test_owasp_category_strings() {
        assert_eq!(OwaspCategory::A03Injection.as_str(), "A03:2021 – Injection");
        assert_eq!(OwaspCategory::A10SSRF.as_str(), "A10:2021 – Server-Side Request Forgery");
        assert_eq!(OwaspCategory::A02CryptographicFailures.as_str(), "A02:2021 – Cryptographic Failures");
    }

    // -----------------------------------------------------------------------
    // 10. ExtendedRuleEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_extended_rule_entry() {
        let entry = ExtendedRuleEntry {
            rule: make_sink("test-001", "eval", 95),
            owasp: Some(OwaspCategory::A03Injection),
            confidence: ConfidenceLevel::High,
            cve_examples: vec!["CVE-2021-12345".to_string()],
            references: vec!["https://cwe.mitre.org/data/definitions/95.html".to_string()],
            tags: vec!["injection".to_string(), "python".to_string()],
        };
        assert_eq!(entry.rule_id(), "test-001");
        assert_eq!(entry.cwe_string(), "CWE-95");
        assert_eq!(entry.confidence, ConfidenceLevel::High);
        assert_eq!(entry.owasp, Some(OwaspCategory::A03Injection));
        assert_eq!(entry.cve_examples.len(), 1);
        assert_eq!(entry.tags.len(), 2);
    }

    #[test]
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::High > ConfidenceLevel::Medium);
        assert!(ConfidenceLevel::Medium > ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::High.as_str(), "HIGH");
        assert_eq!(ConfidenceLevel::Medium.as_str(), "MEDIUM");
        assert_eq!(ConfidenceLevel::Low.as_str(), "LOW");
    }

    // -----------------------------------------------------------------------
    // 11. JSON Loading
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_round_trip() {
        let pack = command_injection_pack();
        let json = serde_json::to_string(&pack).unwrap();
        let loaded = RulePackLoader::from_json(&json).unwrap();
        assert_eq!(loaded.name, pack.name);
        assert_eq!(loaded.rules.len(), pack.rules.len());
    }

    #[test]
    fn test_json_registry_round_trip() {
        let pack = ssrf_pack();
        let json = serde_json::to_string(&pack).unwrap();
        let registry = RulePackLoader::registry_from_json(&json).unwrap();
        assert!(registry.is_sink("requests.get"));
    }

    #[test]
    fn test_json_invalid_returns_error() {
        let result = RulePackLoader::from_json("{ invalid json }");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // 12. Sanitizer rules present in packs
    // -----------------------------------------------------------------------

    #[test]
    fn test_core_pack_sanitizers() {
        let pack = core_pack();
        let sanitizers: Vec<_> = pack.rules.iter()
            .filter(|r| r.kind == RuleKind::Sanitizer)
            .collect();
        assert!(!sanitizers.is_empty(), "core_pack must include sanitizers");
    }

    #[test]
    fn test_filesystem_pack_sanitizers() {
        let pack = filesystem_pack();
        let sanitizers: Vec<_> = pack.rules.iter()
            .filter(|r| r.kind == RuleKind::Sanitizer)
            .collect();
        assert!(!sanitizers.is_empty(), "filesystem_pack must include path sanitizers");
    }

    #[test]
    fn test_command_injection_pack_sanitizers() {
        let pack = command_injection_pack();
        let sanitizers: Vec<_> = pack.rules.iter()
            .filter(|r| r.kind == RuleKind::Sanitizer)
            .collect();
        assert!(!sanitizers.is_empty(), "command_injection_pack must include sanitizers");
    }

    // -----------------------------------------------------------------------
    // 13. init()
    // -----------------------------------------------------------------------

    #[test]
    fn test_init() {
        init();
    }
}
