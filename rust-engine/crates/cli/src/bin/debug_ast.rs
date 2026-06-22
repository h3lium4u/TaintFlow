use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn main() {
    let holdout_path = Path::new("d:/V2 approach/datasets/processed/external_holdout.jsonl");
    let file = File::open(&holdout_path).unwrap();
    let reader = BufReader::new(file);
    let entry: serde_json::Value = reader.lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .nth(13)
        .unwrap();
    
    let code = entry.get("before").unwrap().as_str().unwrap();
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    gst.load_file(&mut program, code, "test.py", "python").unwrap();

    for (id, method) in &program.methods {
        if method.name == "open_session" {
            println!("Method: open_session, ID: {:?}", id);
            for inst_id in &method.body {
                let inst = program.instructions.get(inst_id).unwrap();
                println!("  {:?} | {:?}", inst_id, inst.kind);
            }
        }
    }
}
