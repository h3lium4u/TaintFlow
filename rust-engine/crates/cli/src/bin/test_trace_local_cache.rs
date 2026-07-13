use std::fs;
use symbols::global::GlobalSymbolTable;
use ir::Program;
use serde::Deserialize;
use cfg::icfg::InterproceduralCFG;

#[derive(Deserialize)]
struct HoldoutEntry {
    before: String,
    repo: Option<String>,
    commit: Option<String>,
    language: String,
}

fn main() {
    let dataset_path = "D:/V2 Backup/datasets/processed/external_holdout.jsonl";
    let content = fs::read_to_string(dataset_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let entry: HoldoutEntry = serde_json::from_str(lines[84]).unwrap(); // Entry 84

    let mut gst = GlobalSymbolTable::new();
    let mut program = Program::new();
    let filename = "salt/returners/local_cache.py";
    gst.load_file(&mut program, &entry.before, filename, &entry.language).unwrap();

    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    println!("Seeding entrypoints:");
    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.to_string());
    engine.seed_sources(None);

    println!("Seeded facts count: {}", engine.tainted_facts.len());
    for fact in &engine.tainted_facts {
        println!("  Fact: node={}, var={}", fact.node_id, fact.var);
    }

    println!("Running taint propagation...");
    engine.run();

    println!("Tainted facts after execution: {}", engine.tainted_facts.len());
    for fact in &engine.tainted_facts {
        if fact.var.contains("path") || fact.var.contains("jid") || fact.var.contains("minions") {
            println!("  Tainted: node={}, var={}", fact.node_id, fact.var);
        }
    }
}
