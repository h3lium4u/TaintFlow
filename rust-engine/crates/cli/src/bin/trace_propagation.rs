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
    gst.load_file(&mut program, &before, "Test_CWE113.java", "java")
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    println!("=== VERIFYING TOUCHES SINK FACTS ===");
    for flow in &engine.flows {
        println!(
            "Flow: sink_node={} sink_var={}",
            flow.sink_node_id, flow.sink_var
        );
        let matching_facts: Vec<_> = engine
            .tainted_facts
            .iter()
            .filter(|f| f.node_id == flow.sink_node_id && f.var == flow.sink_var)
            .collect();
        println!("  Matching facts count: {}", matching_facts.len());
        for fact in matching_facts {
            println!("    Fact: node={} var={}", fact.node_id, fact.var);
            let mut curr = fact;
            let mut steps = 0;
            while let Some(parent) = engine.parent_map.get(curr) {
                steps += 1;
                curr = parent;
            }
            println!("      Trace steps: {}", steps);
            println!(
                "      Root source: var='{}' node={}",
                curr.var, curr.node_id
            );
        }
    }
}
