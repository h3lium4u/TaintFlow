use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let holdout_path = base_dir.join("datasets/processed/external_holdout.jsonl");

    let file = File::open(&holdout_path).unwrap();
    let reader = BufReader::new(file);
    let mut target_line = None;
    for (idx, line) in reader.lines().enumerate() {
        if idx == 144 {
            target_line = Some(line.unwrap());
            break;
        }
    }

    let line_str = target_line.expect("Expected line 144 to exist");
    let entry: serde_json::Value = serde_json::from_str(&line_str).unwrap();
    let before = entry["before"].as_str().unwrap().to_string();

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    gst.load_file(&mut program, &before, "Test_CWE113.java", "java").unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    let engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);

    println!("=== SIMULATING CLEAN PROPAGATION FOR SAMPLE 98 ===");

    // We manually simulate the propagation on the key instructions.
    // Taint state is represented as a set of tainted variables.
    let mut tainted_vars = std::collections::HashSet::new();

    // 1. Initial source seeding
    tainted_vars.insert("socket.getInputStream()".to_string());
    println!("Initial State: {:?}", tainted_vars);

    // Instruction list to simulate:
    // Inst 1: readerInputStream = new InputStreamReader(socket.getInputStream(), "UTF-8")
    // Inst 2: readerBuffered = new BufferedReader(readerInputStream)
    // Inst 3: data = readerBuffered.readLine()

    let insts = vec![
        ("new InputStreamReader", Some("readerInputStream"), vec!["socket.getInputStream()", "\"UTF-8\""]),
        ("new BufferedReader", Some("readerBuffered"), vec!["readerInputStream"]),
        ("readerBuffered.readLine", Some("data"), vec![]),
    ];

    for (callee, dest, args) in insts {
        println!("\nEvaluating: dest={:?} | callee='{}' | args={:?}", dest, callee, args);
        println!("  Incoming facts: {:?}", tainted_vars);

        // Check fallback propagation logic
        let mut is_propagating = false;
        
        // Match logic:
        for arg in &args {
            for t_var in &tainted_vars {
                if expr_uses_var(arg, t_var) {
                    is_propagating = true;
                }
            }
        }
        if let Some(receiver) = get_receiver_name_safe(callee) {
            for t_var in &tainted_vars {
                if expr_uses_var(&receiver, t_var) {
                    is_propagating = true;
                }
            }
        }

        if is_propagating {
            if let Some(d) = dest {
                tainted_vars.insert(d.to_string());
                println!("  -> Propagated! Added: '{}'", d);
            }
        } else {
            println!("  -> No propagation.");
        }

        println!("  Outgoing facts: {:?}", tainted_vars);
    }
}

fn expr_uses_var(expr: &str, var: &str) -> bool {
    let expr_trimmed = expr.trim();
    let var_trimmed = var.trim();
    if expr_trimmed == var_trimmed {
        return true;
    }
    if expr_trimmed.starts_with(var_trimmed) && expr_trimmed[var_trimmed.len()..].starts_with('.') {
        return true;
    }
    false
}

fn get_receiver_name_safe(callee: &str) -> Option<String> {
    if callee.contains('.') {
        let parts: Vec<&str> = callee.split('.').collect();
        if parts.len() >= 2 {
            return Some(parts[..parts.len() - 1].join("."));
        }
    }
    None
}
