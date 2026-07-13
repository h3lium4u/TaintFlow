use ir::Program;
use serde::Deserialize;
use std::fs;
use symbols::global::GlobalSymbolTable;

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
    let entry: HoldoutEntry = serde_json::from_str(lines[89]).unwrap();

    let mut gst = GlobalSymbolTable::new();
    let mut program = Program::new();
    let filename = "salt/utils/gitfs.py";
    gst.load_file(&mut program, &entry.before, filename, &entry.language)
        .unwrap();

    let path_file = "D:/RepositoryCache/salt/salt/utils/path.py";
    if let Ok(path_content) = fs::read_to_string(path_file) {
        gst.load_file(&mut program, &path_content, "salt/utils/path.py", "python")
            .unwrap();
    }

    if let Some(m) = program.methods.get(&ir::MethodId(67)) {
        println!("Method {} has parameters: {:?}", m.name, m.parameters);
    } else {
        println!("MethodId(67) not found!");
    }
}
