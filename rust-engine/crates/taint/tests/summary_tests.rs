//! Integration tests for semantic inference, cross-file function summaries,
//! and novel vulnerability discovery patterns.

use normalizer::Normalizer;
use parser::UnifiedParser;
use std::sync::Arc;
use taint::summary::{ProjectSummaryRegistry, SummaryInferer};
use taint::CWE;

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
