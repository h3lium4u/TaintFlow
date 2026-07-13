use v2_frontend_base::LanguageFrontend;
use v2_frontend_python::PythonFrontend;
use v2_semantic::resolve_semantics;
use v2_cfg::CfgBuilder;


#[test]
fn test_vertical_slice_end_to_end() {
    let code = r#"
def check_value(x):
    y = 0
    if x > 10:
        y = x * 2
    else:
        y = x + 1
    return y
"#;

    println!("=== 1. PARSING & SEMANTIC ANALYSIS ===");
    let cst = v2_parser::parse_python(code).expect("Failed to parse Python code");
    let semantic_info = resolve_semantics(cst.as_ref());
    
    println!("Resolved {} scopes.", semantic_info.scopes.len());
    for (id, scope) in &semantic_info.scopes {
        println!("Scope {}: kind={:?}, name={}, symbols={:?}", id, scope.kind, scope.name, scope.symbols.keys());
    }

    println!("\n=== 2. TAC IR LOWERING ===");
    let frontend = PythonFrontend;
    let program = frontend.lower(code, &semantic_info, std::path::Path::new("main.py")).expect("Failed to lower to TAC IR");
    
    assert_eq!(program.methods.len(), 2);
    let method = program.methods.values().find(|m| m.name == "check_value").expect("Method check_value not found");
    println!("Lowered method '{}' with {} instructions:", method.name, method.body.len());
    
    for &inst_id in &method.body {
        let inst = program.instructions.get(&inst_id).unwrap();
        println!("  {:02}: {:?}", inst.id.0, inst.kind);
    }

    println!("\n=== 3. CFG GENERATION ===");
    let mut cfg_builder = CfgBuilder::new(&program);
    let cfg = cfg_builder.build(&method.body);

    println!("Basic Blocks:");
    for (id, block) in &cfg.blocks {
        print!("  Block {:?}: [", id.0);
        for &inst_id in &block.instructions {
            print!("{:?}, ", inst_id.0);
        }
        println!("]");
    }

    println!("Control Flow Edges:");
    for edge in &cfg.edges {
        println!("  Block {:?} --({:?})--> Block {:?}", edge.from.0, edge.kind, edge.to.0);
    }

    println!("\n=== 4. MERMAID CFG VISUALIZATION ===");
    let mermaid = generate_mermaid_cfg(&cfg, &program);
    println!("{}", mermaid);

    // Assert correct block and edge invariants
    assert_eq!(cfg.blocks.len(), 6); // Entry, Exit, + 4 instruction blocks
    
    // There must be conditional branch edges:
    // Block 1 -> Block 3 (True)
    // Block 1 -> Block 2 (False)
    assert!(cfg.edges.iter().any(|e| e.kind == v2_cfg::EdgeKind::BranchTrue));
    assert!(cfg.edges.iter().any(|e| e.kind == v2_cfg::EdgeKind::BranchFalse));
}

fn generate_mermaid_cfg(cfg: &v2_cfg::ControlFlowGraph, program: &v2_ir::Program) -> String {
    let mut output = String::new();
    output.push_str("graph TD\n");
    
    for (id, block) in &cfg.blocks {
        let label = if id.0 == 0 {
            "Entry".to_string()
        } else if id.0 == u32::MAX {
            "Exit".to_string()
        } else {
            let mut inst_strs = Vec::new();
            for &inst_id in &block.instructions {
                if let Some(inst) = program.instructions.get(&inst_id) {
                    inst_strs.push(format!("{:?}", inst.kind).replace('"', "'"));
                }
            }
            format!("Block {}\\n{}", id.0, inst_strs.join("\\n"))
        };
        output.push_str(&format!("    B{0}[\"{1}\"]\n", id.0, label));
    }
    
    for edge in &cfg.edges {
        let edge_label = match edge.kind {
            v2_cfg::EdgeKind::Fallthrough => "fallthrough",
            v2_cfg::EdgeKind::BranchTrue => "true",
            v2_cfg::EdgeKind::BranchFalse => "false",
            v2_cfg::EdgeKind::Unconditional => "jump",
            v2_cfg::EdgeKind::LoopBack => "backedge",
            v2_cfg::EdgeKind::Exception => "exception",
        };
        output.push_str(&format!("    B{} -->|{}| B{}\n", edge.from.0, edge_label, edge.to.0));
    }
    
    output
}
