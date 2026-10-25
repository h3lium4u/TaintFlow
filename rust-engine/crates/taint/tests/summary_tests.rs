//! Integration tests for semantic inference, cross-file function summaries,
//! and novel vulnerability discovery patterns.

use normalizer::Normalizer;
use parser::UnifiedParser;
use std::sync::Arc;
use taint::summary::{ProjectSummaryRegistry, SummaryInferer};
use taint::{TaintEngine, CWE};

#[test]
fn test_infer_param_to_return_python() {
    let code = r#"
def format_user_id(prefix, user_id):
    result = prefix + "_" + str(user_id)
    return result
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("utils.py", &normalized, "python", None);

    let summary = reg.find_summary("format_user_id", 2);
    assert!(
        summary.is_some(),
        "Summary must be found for format_user_id"
    );
    let summary = summary.unwrap();
    assert!(
        summary.param_to_return.contains(&0),
        "Parameter 0 (prefix) must influence return"
    );
    assert!(
        summary.param_to_return.contains(&1),
        "Parameter 1 (user_id) must influence return"
    );
    assert!(!summary.is_pure_predicate);
}

#[test]
fn test_infer_param_to_return_java() {
    let code = r#"
public class Formatter {
    public static String buildQuery(String table, String id) {
        String base = "SELECT * FROM " + table;
        return base + " WHERE id = " + id;
    }
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("Formatter.java", &normalized, "java", None);

    let summary = reg.find_summary("buildQuery", 2);
    assert!(summary.is_some(), "Summary must be found for buildQuery");
    let summary = summary.unwrap();
    assert!(summary.param_to_return.contains(&0));
    assert!(summary.param_to_return.contains(&1));
}

#[test]
fn test_infer_unrelated_param_no_return() {
    let code = r#"
def get_constant_value(untrusted_input):
    log_info(untrusted_input)
    return "SAFE_CONSTANT"
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("test.py", &normalized, "python", None);

    let summary = reg.find_summary("get_constant_value", 1).unwrap();
    assert!(
        summary.param_to_return.is_empty(),
        "Constant return must not be marked influenced by untrusted_input"
    );
}

#[test]
fn test_infer_param_to_receiver_mutation() {
    let code = r#"
class QueryBuilder:
    def __init__(self):
        self.parts = []

    def add_clause(self, clause):
        self.parts.append(clause)
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("builder.py", &normalized, "python", None);

    let summary = reg.find_summary("add_clause", 2);
    assert!(summary.is_some(), "add_clause summary must be indexed");
    let summary = summary.unwrap();
    assert!(
        summary.param_to_receiver.contains(&1),
        "Parameter 1 (clause) must mutate receiver object"
    );
}

#[test]
fn test_infer_sink_invocation_sql() {
    let code = r#"
public class DBService {
    public void executeHelper(String rawSql) {
        Statement stmt = conn.createStatement();
        stmt.executeQuery(rawSql);
    }
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("DBService.java", &normalized, "java", None);

    let summary = reg.find_summary("executeHelper", 1);
    assert!(summary.is_some(), "executeHelper summary must be found");
    let summary = summary.unwrap();
    assert_eq!(
        summary.sink_invocations.len(),
        1,
        "Should discover exactly 1 internal sink call"
    );
    let sink = &summary.sink_invocations[0];
    assert_eq!(sink.param_idx, 0);
    assert_eq!(sink.cwe, CWE::CWE89);
    assert_eq!(sink.severity, "HIGH");
}

#[test]
fn test_infer_sink_invocation_command() {
    let code = r#"
def run_system_cmd(command_str):
    import subprocess
    subprocess.Popen(command_str, shell=True)
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("cmd.py", &normalized, "python", None);

    let summary = reg.find_summary("run_system_cmd", 1);
    assert!(summary.is_some());
    let summary = summary.unwrap();
    assert_eq!(summary.sink_invocations.len(), 1);
    let sink = &summary.sink_invocations[0];
    assert_eq!(sink.param_idx, 0);
    assert_eq!(sink.cwe, CWE::CWE78);
    assert_eq!(sink.severity, "CRITICAL");
}

#[test]
fn test_infer_numeric_sanitization() {
    let code = r#"
public class SanitizerHelper {
    public static int parseId(String input) {
        int val = Integer.parseInt(input);
        return val;
    }
}
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("SanitizerHelper.java", &normalized, "java", None);

    let summary = reg.find_summary("parseId", 1).unwrap();
    let covered = summary.sanitizes_for.get(&0);
    assert!(covered.is_some(), "Parameter 0 should have sanitization");
    let cwes = covered.unwrap();
    assert!(cwes.contains(&CWE::CWE89));
    assert!(cwes.contains(&CWE::CWE78));
}

#[test]
fn test_infer_pure_predicate() {
    let code = r#"
def is_valid_age(age):
    return age > 0 and age < 120
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("val.py", &normalized, "python", None);

    let summary = reg.find_summary("is_valid_age", 1).unwrap();
    assert!(summary.is_pure_predicate);
}

#[test]
fn test_cross_file_taint_propagation_and_rule_finding() {
    use rules::RuleEngine;

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
    rules::evaluate_rules_recursive(
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
    use rules::RuleEngine;

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
    rules::evaluate_rules_recursive(
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
    use rules::RuleEngine;

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
    rules::evaluate_rules_recursive(
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
    use rules::RuleEngine;

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
    rules::evaluate_rules_recursive(
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

// ── Branch-Aware & Conditional Sanitization ───────────────────────────────────

#[test]
fn test_conditional_sanitization_does_not_suppress_vulnerability() {
    let code = r#"
def maybe_sanitize(raw_val, is_admin):
    if is_admin:
        cleaned = int(raw_val)
        return cleaned
    return raw_val
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("san.py", &normalized, "python", None);

    let summary = reg.find_summary("maybe_sanitize", 2).unwrap();
    // Sanitization occurred inside an `if` block, so it is conditional
    assert!(
        summary.sanitizes_for.is_empty(),
        "Conditional sanitization must NOT be registered as unconditional sanitization"
    );
    assert!(
        summary.conditional_sanitizes_for.contains_key(&0),
        "Parameter 0 must be flagged in conditional_sanitizes_for"
    );
}

// ── Caller Context Isolation Across Successive Calls ─────────────────────────

#[test]
fn test_safe_and_unsafe_calls_to_same_helper_isolated() {
    use rules::RuleEngine;

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
    rules::evaluate_rules_recursive(
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

// ── Disambiguation of Unrelated Functions Sharing a Name ──────────────────────

#[test]
fn test_unrelated_functions_sharing_name_disambiguated() {
    let file1 = r#"
package com.example.db;

public class SqlHelper {
    public static void run(String sql) {
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
    }
}
"#;
    let file2 = r#"
package com.example.log;

public class LogHelper {
    public static void run(String msg) {
        System.out.println(msg);
    }
}
"#;

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_code("SqlHelper.java", file1, "java", None);
    reg.index_code("LogHelper.java", file2, "java", None);

    let sql_summary = reg
        .find_summary("com.example.db.sqlhelper.run", 1)
        .or_else(|| reg.find_summary("sqlhelper.run", 1));
    assert!(sql_summary.is_some());
    assert_eq!(sql_summary.unwrap().sink_invocations.len(), 1);

    let log_summary = reg
        .find_summary("com.example.log.loghelper.run", 1)
        .or_else(|| reg.find_summary("loghelper.run", 1));
    assert!(log_summary.is_some());
    assert_eq!(log_summary.unwrap().sink_invocations.len(), 0);
}

// ── Validation Function Returning Data Is Not A Predicate ─────────────────────

#[test]
fn test_validate_function_returning_data_not_treated_as_predicate() {
    let code = r#"
def validate_identifier(ident):
    if len(ident) > 50:
        raise ValueError("Too long")
    return ident
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("check.py", &normalized, "python", None);

    let summary = reg.find_summary("validate_identifier", 1).unwrap();
    assert!(
        !summary.is_pure_predicate,
        "Function returning data must NOT be marked pure predicate simply due to 'validate' name"
    );
    assert!(
        summary.param_to_return.contains(&0),
        "ident must propagate to return value"
    );
}

// ── Sound Token Matching Prevents Substring False Positives ───────────────────

#[test]
fn test_sound_token_boundary_avoids_substring_false_positives() {
    let code = r#"
def process_data(id):
    # Variable 'hidden' contains letters 'id', but is completely independent of parameter 'id'
    hidden = "CONST_INTERNAL"
    return hidden
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut reg = ProjectSummaryRegistry::new();
    reg.index_node("token_test.py", &normalized, "python", None);

    let summary = reg.find_summary("process_data", 1).unwrap();
    assert!(
        summary.param_to_return.is_empty(),
        "Substring 'id' in 'hidden' must NOT falsely register as parameter influence"
    );
}
