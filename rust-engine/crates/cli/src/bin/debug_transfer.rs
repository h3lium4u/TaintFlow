use std::fs;
use parser::UnifiedParser;
use normalizer::Normalizer;
use taint::TaintEngine;
use rules::RuleEngine;

fn main() {
    let code_path = "../scratch/rc72_validation/cve_2021_25646_cmdinject.java";
    let code = fs::read_to_string(code_path).unwrap();

    let parsed = UnifiedParser::parse(&code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&parsed, "java");

    let mut taint_engine = TaintEngine::new(10, 5, 200);
    taint_engine.build_cha_from_code(&code);
    taint_engine.propagate_node(&normalized);

    println!("=== AST with Taint Evaluation ===");
    print_node(&normalized, 0, &taint_engine);

    println!("\n=== Taint Engine State ===");
    for (name, state) in &taint_engine.tainted_symbols {
        println!("Tainted Symbol: {} -> {:?}", name, state);
    }

    let mut rule_engine = RuleEngine::new();
    rules_eval_recursive(&mut rule_engine, code_path, &normalized, &taint_engine);
    println!("\n=== Rule Engine Findings ===");
    for finding in rule_engine.get_findings() {
        println!("Finding: [{}] on line {}: {}", finding.cwe, finding.line_number, finding.description);
    }
}

fn print_node(node: &normalizer::NormalizedNode, indent: usize, taint_engine: &TaintEngine) {
    let indent_str = "  ".repeat(indent);
    let taint_state = taint_engine.evaluate_taint_state_recursive(node, 0);
    println!("{}{:?}: raw='{}' -> Taint={:?}", indent_str, node.kind, node.raw.trim().replace('\n', " "), taint_state);
    match &node.kind {
        normalizer::NormalizedKind::Block(children)
        | normalizer::NormalizedKind::Concat { parts: children } => {
            for child in children {
                print_node(child, indent + 1, taint_engine);
            }
        }
        normalizer::NormalizedKind::Assignment { lhs, rhs } => {
            print_node(lhs, indent + 1, taint_engine);
            print_node(rhs, indent + 1, taint_engine);
        }
        normalizer::NormalizedKind::Call { arguments, .. } => {
            for arg in arguments {
                print_node(arg, indent + 1, taint_engine);
            }
        }
        normalizer::NormalizedKind::If { condition, consequent, alternate } => {
            print_node(condition, indent + 1, taint_engine);
            print_node(consequent, indent + 1, taint_engine);
            if let Some(alt) = alternate {
                print_node(alt, indent + 1, taint_engine);
            }
        }
        normalizer::NormalizedKind::For { init, condition, update, body } => {
            if let Some(i) = init { print_node(i, indent + 1, taint_engine); }
            if let Some(c) = condition { print_node(c, indent + 1, taint_engine); }
            if let Some(u) = update { print_node(u, indent + 1, taint_engine); }
            print_node(body, indent + 1, taint_engine);
        }
        normalizer::NormalizedKind::While { condition, body } => {
            print_node(condition, indent + 1, taint_engine);
            print_node(body, indent + 1, taint_engine);
        }
        normalizer::NormalizedKind::Return(expr) => {
            print_node(expr, indent + 1, taint_engine);
        }
        _ => {}
    }
}

fn rules_eval_recursive(
    rule_engine: &mut RuleEngine,
    file_path: &str,
    node: &normalizer::NormalizedNode,
    taint_engine: &TaintEngine,
) {
    rule_engine.evaluate_flow_rules(file_path, node, taint_engine);
    rule_engine.evaluate_pattern_rules(file_path, node);
    rule_engine.evaluate_call_pattern_rules(file_path, node);
    match &node.kind {
        normalizer::NormalizedKind::Block(children)
        | normalizer::NormalizedKind::Concat { parts: children }
        | normalizer::NormalizedKind::FunctionDefinition { body: children, .. } => {
            for child in children {
                rules_eval_recursive(rule_engine, file_path, child, taint_engine);
            }
        }
        normalizer::NormalizedKind::Assignment { lhs, rhs } => {
            rules_eval_recursive(rule_engine, file_path, lhs, taint_engine);
            rules_eval_recursive(rule_engine, file_path, rhs, taint_engine);
        }
        normalizer::NormalizedKind::If {
            condition,
            consequent,
            alternate,
        } => {
            rules_eval_recursive(rule_engine, file_path, condition, taint_engine);
            rules_eval_recursive(rule_engine, file_path, consequent, taint_engine);
            if let Some(alt) = alternate {
                rules_eval_recursive(rule_engine, file_path, alt, taint_engine);
            }
        }
        normalizer::NormalizedKind::Call { arguments, .. } => {
            for arg in arguments {
                rules_eval_recursive(rule_engine, file_path, arg, taint_engine);
            }
        }
        normalizer::NormalizedKind::Return(expr) => {
            rules_eval_recursive(rule_engine, file_path, expr, taint_engine);
        }
        _ => {}
    }
}
