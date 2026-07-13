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
    let language = entry["language"].as_str().unwrap().to_string();
    let cwe = entry["cwe"].as_str().unwrap().to_string();
    let repo = entry["repo"].as_str().unwrap().to_string();

    println!("=== INSPECTING SAMPLE 144 (CWE-113) BEFORE CODE ===");
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    
    let filename = "Test_CWE113.java".to_string();

    gst.load_file(&mut program, &before, &filename, &language).unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    let engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);

    println!("\n=== INSTRUCTIONS IN PROGRAM ===");
    let mut keys: Vec<&ir::InstructionId> = program.instructions.keys().collect();
    keys.sort_by_key(|id| id.0);
    for id in keys {
        let inst = program.instructions.get(id).unwrap();
        if let ir::InstructionKind::Call { dest, callee, args } = &inst.kind {
            println!("  InstructionId({:?}) | dest: {:?} | callee: '{}' | args: {:?}", id, dest, callee, args);
            
            // Resolve callee info using engine
            let resolved = engine.resolve_callee_info(ir::MethodId(0), callee);
            println!("    -> Resolved FQN/Method: {:?}", resolved);
            
            // Show get_receiver_name_safe result
            let receiver = get_receiver_name_safe(callee);
            println!("    -> Receiver: {:?}", receiver);
        }
    }
}

fn get_receiver_name_safe(callee: &str) -> Option<String> {
    if callee.contains('.') {
        let parts: Vec<&str> = callee.split('.').collect();
        if parts.len() >= 2 {
            let receiver = parts[..parts.len() - 1].join(".");
            return Some(receiver);
        }
    }
    None
}
