use std::fs;

fn main() {
    let target_code = fs::read_to_string("C:/Users/F1ZZ4N/.gemini/antigravity/brain/988cfea0-b185-4e09-a632-4beb74653ac3/scratch/v7_pilot_test_0049_before.py").unwrap();
    let sibling_code = fs::read_to_string("C:/Users/F1ZZ4N/.gemini/antigravity/brain/988cfea0-b185-4e09-a632-4beb74653ac3/scratch/v7_pilot_test_0050_before.py").unwrap();
    let target_lang = "python".to_string();
    
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    
    gst.load_file(&mut program, &target_code, "paddle/hub.py", &target_lang).unwrap();
    gst.load_file(&mut program, &sibling_code, "paddle/utils/download.py", &target_lang).unwrap();
    
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
    
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    for (&method_id, method) in &program.methods {
        println!("Loaded method: '{}'", method.name);
        if method.name == "list" || method.name == "_git_archive_link" || method.name == "get_path_from_url" || method.name == "_wget_download" || method.name == "_download" || method.name == "_parse_repo_info" {
            println!("Method '{}' ID: {:?}, parameters: {:?}", method.name, method_id, method.parameters);
            println!("  Instructions:");
            fn print_insts(ids: &[ir::InstructionId], program: &ir::Program, indent: &str) {
                for &id in ids {
                    if let Some(inst) = program.instructions.get(&id) {
                        println!("    {}[{:?}] {:?}", indent, id, inst.kind);
                        match &inst.kind {
                            ir::InstructionKind::Branch { then_block, else_block, .. } => {
                                println!("    {}  Then:", indent);
                                print_insts(then_block, program, &format!("{}    ", indent));
                                if let Some(eb) = else_block {
                                    println!("    {}  Else:", indent);
                                    print_insts(eb, program, &format!("{}    ", indent));
                                }
                            }
                            ir::InstructionKind::Loop { body, .. } => {
                                println!("    {}  Body:", indent);
                                print_insts(body, program, &format!("{}    ", indent));
                            }
                            ir::InstructionKind::Try { body, catches, finally } => {
                                println!("    {}  Try Body:", indent);
                                print_insts(body, program, &format!("{}    ", indent));
                                println!("    {}  Catches:", indent);
                                print_insts(catches, program, &format!("{}    ", indent));
                                if let Some(f) = finally {
                                    println!("    {}  Finally:", indent);
                                    print_insts(f, program, &format!("{}    ", indent));
                                }
                            }
                            ir::InstructionKind::Catch { exception_var, body } => {
                                println!("    {}  Catch ({:?}):", indent, exception_var);
                                print_insts(body, program, &format!("{}    ", indent));
                            }
                            _ => {}
                        }
                    }
                }
            }
            print_insts(&method.body, &program, "");
        }
    }
    // std::process::exit(0);
    engine.seed_sources(None);
    engine.run();

    println!("=== Tainted Facts ===");
    for fact in &engine.tainted_facts {
        let node = icfg.nodes.get(&fact.node_id).unwrap();
        let method = program.methods.get(&node.method_id).unwrap();
        let file_path = gst.program_index.methods.get(&node.method_id)
            .and_then(|mi| gst.program_index.modules.get(&mi.module_id))
            .map(|mod_info| mod_info.file_path.as_str())
            .unwrap_or("unknown");
        println!("  Fact: var='{}' node={} (method='{}' in {})", fact.var, fact.node_id, method.name, file_path);
        
        // Trace parent chain
        let mut curr = fact.clone();
        let mut chain = Vec::new();
        while let Some(parent) = engine.parent_map.get(&curr) {
            chain.push(parent.clone());
            curr = parent.clone();
        }
        if !chain.is_empty() {
            println!("    Chain:");
            for p in chain {
                let p_node = icfg.nodes.get(&p.node_id).unwrap();
                let p_method = program.methods.get(&p_node.method_id).unwrap();
                println!("      <- var='{}' node={} (method='{}')", p.var, p.node_id, p_method.name);
            }
        }
    }
}


