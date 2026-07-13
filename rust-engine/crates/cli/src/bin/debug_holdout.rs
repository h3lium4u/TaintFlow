use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

struct Sample {
    before: String,
    after: String,
    language: String,
    cwe: String,
    repo: String,
    commit: String,
}

fn test_version(
    code: &str,
    lang: &str,
    cwe: &str,
    repo: &str,
    _commit: &str,
    idx: usize,
    _base_dir: &Path,
) {
    println!("Running sample {} | repo={} | cwe={}...", idx, repo, cwe);
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();

    // Determine target filename
    let filename = if lang.to_lowercase() == "java" {
        format!("Test_{}.java", cwe.replace("-", "_"))
    } else if repo.contains("OpenViking") {
        "tests/test_export_ovpack.py".to_string()
    } else {
        "test.py".to_string()
    };

    if let Err(e) = gst.load_file(&mut program, code, &filename, lang) {
        println!("Failed to load target file: {:?}", e);
        return;
    }

    // Load mock helpers
    if lang.to_lowercase() == "python" {
        if repo.contains("OpenViking") {
            let openviking_code = r#"
class AsyncOpenViking:
    async def import_ovpack(self, path, dest, force=False, vectorize=False):
        with open(path, "r") as f:
            pass
        return dest
"#;
            let _ = gst.load_file(&mut program, openviking_code, "openviking.py", "python");
        }
        if repo.contains("binderhub") {
            let config_code = r#"
class LoggingConfigurable:
    """Base class. self.spec is populated from the HTTP URL by the web handler."""
    def __init__(self, *args, **kwargs):
        self.spec = request.args.get('spec', '')
        self.url = ''
        self.repo = ''
        self.unresolved_ref = ''
        self.resolved_ref = ''
"#;
            let _ = gst.load_file(
                &mut program,
                config_code,
                "traitlets/config/__init__.py",
                "python",
            );
        }
    }

    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    println!("\n=== Types in Symbol Table ===");
    for (type_id, type_info) in &gst.program_index.types {
        println!(
            "  TypeId({:?}) | FQN: {} | Name: {}",
            type_id, type_info.fqn, type_info.name
        );
    }
    println!("\n=== Methods in Symbol Table ===");
    for (method_id, method_info) in &gst.program_index.methods {
        println!(
            "  MethodId({:?}) | FQN: {} | Parameters: {:?}",
            method_id, method_info.fqn, method_info.parameters
        );
    }

    println!("\n=== All Instructions in Program ===");
    let mut keys: Vec<&ir::InstructionId> = program.instructions.keys().collect();
    keys.sort_by_key(|id| id.0);
    for id in keys {
        let inst = program.instructions.get(id).unwrap();
        println!("  {:?} | {:?}", id, inst.kind);
    }

    println!("\n=== Call Graph Edges ===");
    for edge in &cg.edges {
        println!(
            "  Caller: {:?}, Callee: {:?}, Instruction: {:?}",
            edge.caller, edge.callee, edge.instruction_id
        );
    }

    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);

    println!("\n=== Seeded Taint Facts ===");
    for fact in &engine.tainted_facts {
        println!("  var='{}' domain={:?}", fact.var, fact.source_domain);
    }

    engine.run();

    println!("\n=== Tainted Facts after run ===");
    for fact in &engine.tainted_facts {
        let method_name = icfg
            .nodes
            .get(&fact.node_id)
            .and_then(|n| program.methods.get(&n.method_id))
            .map(|m| m.name.as_str())
            .unwrap_or("?");
        println!(
            "  node={} method='{}' var='{}'",
            fact.node_id, method_name, fact.var
        );

        let mut curr = fact;
        let mut path = vec![curr];
        while let Some(parent) = engine.parent_map.get(curr) {
            path.push(parent);
            curr = parent;
        }
        path.reverse();
        print!("    Path: ");
        for (step_idx, step) in path.iter().enumerate() {
            if step_idx > 0 {
                print!(" -> ");
            }
            print!("{}:{}", step.node_id, step.var);
        }
        println!();
    }

    println!("\nFlows detected: {}", engine.flows.len());
    for flow in &engine.flows {
        println!(
            "  Flow: sink_node={} sink_var='{}' cwe={:?}",
            flow.sink_node_id, flow.sink_var, flow.cwe
        );
        if let Some(fact) = engine
            .tainted_facts
            .iter()
            .find(|f| f.node_id == flow.sink_node_id && f.var == flow.sink_var)
        {
            println!("    Trace path:");
            let mut curr = fact;
            let mut path = vec![curr];
            while let Some(parent) = engine.parent_map.get(curr) {
                path.push(parent);
                curr = parent;
            }
            path.reverse();
            for (step_idx, step) in path.iter().enumerate() {
                let step_node = icfg.nodes.get(&step.node_id).unwrap();
                let step_method = program.methods.get(&step_node.method_id).unwrap();
                let step_inst = step_node
                    .instruction_id
                    .and_then(|id| program.instructions.get(&id));
                println!(
                    "      [{}] node={} method='{}' var='{}' inst={:?}",
                    step_idx,
                    step.node_id,
                    step_method.name,
                    step.var,
                    step_inst.map(|i| &i.kind)
                );
            }
        }
    }
}

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let holdout_path = base_dir.join("datasets/processed/v10_raw_acquired.jsonl");
    if !holdout_path.exists() {
        println!("Holdout file does not exist");
        return;
    }

    let file = File::open(&holdout_path).unwrap();
    let reader = BufReader::new(file);
    let mut github_samples = Vec::new();

    for line in reader.lines() {
        if let Ok(line_str) = line {
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line_str) {
                let repo = entry.get("repo").and_then(|v| v.as_str()).unwrap_or("");
                let source = entry.get("source").and_then(|v| v.as_str()).unwrap_or("");
                if source == "Vul4J" {
                    let before = entry
                        .get("before")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let after = entry
                        .get("after")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let language = entry
                        .get("language")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let cwe = entry
                        .get("cwe")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    github_samples.push(Sample {
                        before,
                        after,
                        language,
                        cwe,
                        repo: repo.to_string(),
                        commit: "".to_string(),
                    });
                }
            }
        }
    }

    let version = std::env::var("VERSION").unwrap_or_else(|_| "before".to_string());
    let target_repo = std::env::var("TARGET_REPO").ok();

    if let Some(repo_filter) = target_repo {
        if let Some((idx, sample)) = github_samples
            .iter()
            .enumerate()
            .find(|(_, s)| s.repo.contains(&repo_filter))
        {
            let code = if version == "before" {
                &sample.before
            } else {
                &sample.after
            };
            println!("--- Source Code ({}) ---", version);
            println!("{}", code);
            println!("-------------------");
            test_version(
                code,
                &sample.language,
                &sample.cwe,
                &sample.repo,
                &sample.commit,
                idx,
                base_dir,
            );
        } else {
            println!("No sample found for repo matching: {}", repo_filter);
        }
    } else {
        let target_idx_str = std::env::var("TARGET_IDX").unwrap_or_else(|_| "0".to_string());
        let target_idx: usize = target_idx_str.parse().unwrap_or(0);

        if target_idx < github_samples.len() {
            let sample = &github_samples[target_idx];
            let code = if version == "before" {
                &sample.before
            } else {
                &sample.after
            };
            println!("--- Source Code ({}) ---", version);
            println!("{}", code);
            println!("-------------------");
            test_version(
                code,
                &sample.language,
                &sample.cwe,
                &sample.repo,
                &sample.commit,
                target_idx,
                base_dir,
            );
        } else {
            println!(
                "Index {} out of bounds (len={})",
                target_idx,
                github_samples.len()
            );
        }
    }
}
