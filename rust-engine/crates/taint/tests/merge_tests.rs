use taint::{TaintState, CWE};

#[test]
fn test_taint_path_merging_policy() {
    let path_a = TaintState {
        tainted: true,
        sanitized_for: vec![CWE::CWE89].into_iter().collect(),
        source_line: None,
        source_var: None,
    };

    let path_b = TaintState {
        tainted: true,
        sanitized_for: vec![].into_iter().collect(),
        source_line: None,
        source_var: None,
    };

    let mut merged_sanitized = path_a.sanitized_for.clone();
    merged_sanitized.retain(|cwe| path_b.sanitized_for.contains(cwe));

    let merged = TaintState {
        tainted: path_a.tainted || path_b.tainted,
        sanitized_for: merged_sanitized,
        source_line: None,
        source_var: None,
    };

    assert!(merged.tainted, "Taint should propagate (OR check)");
    assert!(
        merged.sanitized_for.is_empty(),
        "Sanitized CWE intersection should be empty"
    );
}
