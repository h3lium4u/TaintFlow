//! Integration tests for semantic summaries, cross-file vulnerability discovery,
//! broken sanitization chain heuristics, and multi-hop dataflow reachability
//! evaluated through the RuleEngine.

use normalizer::Normalizer;
use parser::UnifiedParser;
use rules::{evaluate_rules_recursive, RuleEngine};
use std::sync::Arc;
use taint::summary::ProjectSummaryRegistry;
use taint::{TaintEngine, CWE};

#[test]
fn test_cross_file_taint_propagation_and_rule_finding() {
    // Simulate multi-file project:
    // File 1: Helper.java defining query builder
    let file1_code = r#"
public class Helper {
    public static String assemble(String prefix, String data) {
        return prefix + " WHERE name = '" + data + "'";
    }
}
"#;
    // File 2: Controller.java calling Helper.assemble with tainted data and passing to sink
    let file2_code = r#"
public class Controller {
    public void handle(HttpServletRequest req) {
        String userInput = req.getParameter("name");
        String finalQuery = Helper.assemble("SELECT * FROM users", userInput);
        stmt.executeQuery(finalQuery);
    }
}
"#;

    // Index File 1 into ProjectSummaryRegistry
    let mut reg = ProjectSummaryRegistry::new();
    reg.index_code("Helper.java", file1_code, "java", None);

    assert_eq!(reg.len(), 1, "Helper.assemble should be indexed");
    let summary = reg.find_summary("Helper.assemble", 2).unwrap();
    assert!(summary.param_to_return.contains(&1));

    let reg_arc = Arc::new(reg);

    // Analyze File 2 with registry
    let ast2 = UnifiedParser::parse(file2_code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized2 = norm.normalize(&ast2, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.language = Some("java".to_string());
    taint_engine.summary_registry = Some(reg_arc.clone());
    taint_engine.propagate_node(&normalized2);

    // Verify finalQuery is tainted across files!
    let final_query_state = taint_engine.get_taint("finalQuery");
    assert!(
        final_query_state.is_some() && final_query_state.unwrap().tainted,
        "finalQuery must be tainted via cross-file propagation of parameter 1"
    );

    // Evaluate rules on File 2
    let mut rule_engine = RuleEngine::new();
    rule_engine.language = Some("java".to_string());
    rule_engine.summary_registry = Some(reg_arc);
    evaluate_rules_recursive(
        &mut rule_engine,
        "Controller.java",
        &normalized2,
        &taint_engine,
    );

    let findings = rule_engine.get_findings();
    let cwe89 = findings.iter().any(|f| f.cwe == "CWE89");
    assert!(
        cwe89,
        "CWE-89 finding must be detected when finalQuery flows into executeQuery"
    );
}

#[test]
fn test_cross_file_sink_invocation_finding() {
    // File 1: Service.java contains the sink execution
    let file1_code = r#"
public class Service {
    public void executeRaw(String query) {
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }
}
"#;
    // File 2: Endpoint.java calls Service.executeRaw(tainted)
    let file2_code = r#"
public class Endpoint {
    public void process(HttpServletRequest request) {
        String id = request.getParameter("id");
        service.executeRaw(id);
    }
}
"#;

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_code("Service.java", file1_code, "java", None);

    let reg_arc = Arc::new(reg);

    let ast2 = UnifiedParser::parse(file2_code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized2 = norm.normalize(&ast2, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.language = Some("java".to_string());
    taint_engine.summary_registry = Some(reg_arc.clone());
    taint_engine.propagate_node(&normalized2);

    let mut rule_engine = RuleEngine::new();
    rule_engine.language = Some("java".to_string());
    rule_engine.summary_registry = Some(reg_arc);
    evaluate_rules_recursive(
        &mut rule_engine,
        "Endpoint.java",
        &normalized2,
        &taint_engine,
    );

    let findings = rule_engine.get_findings();
    let cross_file_finding = findings.iter().find(|f| f.title.contains("Cross-File"));
    assert!(
        cross_file_finding.is_some(),
        "Must generate a Cross-File Data Flow Vulnerability finding for cross-file sink invocation"
    );
    let f = cross_file_finding.unwrap();
    assert_eq!(f.cwe, "CWE89");
    assert!(f.description.contains("executeRaw"));
}

#[test]
fn test_context_mismatch_broken_sanitization_chain() {
    // Code where HTML escaping is mistakenly used on a SQL query input
    let code = r#"
public class MismatchTest {
    public void test(HttpServletRequest request) {
        String input = request.getParameter("user");
        String htmlSafe = HtmlUtils.htmlEscape(input);
        stmt.executeQuery(htmlSafe);
    }
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.language = Some("java".to_string());
    taint_engine.propagate_node(&normalized);

    let mut rule_engine = RuleEngine::new();
    rule_engine.language = Some("java".to_string());
    evaluate_rules_recursive(
        &mut rule_engine,
        "MismatchTest.java",
        &normalized,
        &taint_engine,
    );

    let findings = rule_engine.get_findings();
    let mismatch_finding = findings
        .iter()
        .find(|f| f.title.contains("Broken Sanitization Chain"));
    assert!(
        mismatch_finding.is_some(),
        "Must detect Context Mismatch when HTML escaping is used before a SQL sink"
    );
}

// ── Multi-Hop Cross-File Analysis (Multi-Level Call Chains) ───────────────────

#[test]
fn test_multi_hop_cross_file_taint_reachability() {
    // File 1: DAO.java (leaf sink)
    let dao_code = r#"
public class UserDao {
    public void executeQueryLeaf(String query) {
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }
}
"#;

    // File 2: Service.java (intermediate wrapper)
    let service_code = r#"
public class UserService {
    public void queryIntermediate(String data) {
        UserDao dao = new UserDao();
        dao.executeQueryLeaf(data);
    }
}
"#;

    // File 3: Controller.java (entrypoint caller)
    let controller_code = r#"
public class UserController {
    public void handle(HttpServletRequest req) {
        String input = req.getParameter("id");
        UserService s = new UserService();
        s.queryIntermediate(input);
    }
}
"#;

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_code("UserDao.java", dao_code, "java", None);
    reg.index_code("UserService.java", service_code, "java", None);

    // Multi-hop fixpoint resolution connects UserService -> UserDao
    reg.resolve_inter_summary_dependencies();

    let reg_arc = Arc::new(reg);

    let ast = UnifiedParser::parse(controller_code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.language = Some("java".to_string());
    taint_engine.file_path = Some("UserController.java".to_string());
    taint_engine.summary_registry = Some(reg_arc.clone());
    taint_engine.propagate_node(&normalized);

    let mut rule_engine = RuleEngine::new();
    rule_engine.language = Some("java".to_string());
    rule_engine.summary_registry = Some(reg_arc);
    evaluate_rules_recursive(
        &mut rule_engine,
        "UserController.java",
        &normalized,
        &taint_engine,
    );

    let findings = rule_engine.get_findings();
    let multi_hop = findings
        .iter()
        .find(|f| f.title.contains("Cross-File") && f.cwe == "CWE89");
    assert!(
        multi_hop.is_some(),
        "Transitive multi-hop call chain (Controller -> Service -> DAO -> executeQuery) must be discovered"
    );
}

// ── Caller Context Isolation Across Successive Calls ─────────────────────────

#[test]
fn test_safe_and_unsafe_calls_to_same_helper_isolated() {
    let code = r#"
public class CallerContextTest {
    public static String wrap(String x) {
        return "PREFIX_" + x;
    }

    public void process(HttpServletRequest request) {
        // Safe call
        String safeOut = wrap("CONSTANT_LITERAL");
        stmt.executeQuery(safeOut);

        // Tainted call
        String tainted = request.getParameter("val");
        String taintedOut = wrap(tainted);
        stmt.executeQuery(taintedOut);
    }
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.language = Some("java".to_string());
    taint_engine.file_path = Some("CallerContextTest.java".to_string());
    taint_engine.propagate_node(&normalized);

    let mut rule_engine = RuleEngine::new();
    rule_engine.language = Some("java".to_string());
    evaluate_rules_recursive(
        &mut rule_engine,
        "CallerContextTest.java",
        &normalized,
        &taint_engine,
    );

    let findings = rule_engine.get_findings();
    // Only the call with tainted input should flag a vulnerability
    let tainted_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.cwe == "CWE89" && f.description.contains("taintedOut"))
        .collect();
    let safe_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.cwe == "CWE89" && f.description.contains("safeOut"))
        .collect();

    assert_eq!(
        tainted_findings.len(),
        1,
        "Tainted call must produce finding"
    );
    assert_eq!(
        safe_findings.len(),
        0,
        "Safe call must not produce finding due to leaked context"
    );
}
