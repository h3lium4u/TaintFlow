use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[allow(dead_code)]
#[derive(Deserialize)]
struct HoldoutEntry {
    before: String,
    after: String,
    language: String,
    repo: Option<String>,
    source: Option<String>,
    cwe: Option<String>,
}

fn main() {
    let holdout_path = Path::new("d:/V2 approach/datasets/processed/external_holdout.jsonl");
    let file = File::open(&holdout_path).unwrap();
    let reader = BufReader::new(file);
    let mut count = 0;
    for line in reader.lines() {
        if let Ok(line_str) = line {
            if let Ok(entry) = serde_json::from_str::<HoldoutEntry>(&line_str) {
                let is_juliet = entry.repo.as_deref() == Some("Juliet")
                    || entry.source.as_deref() == Some("Juliet");
                if is_juliet {
                    if count == 37 {
                        // 75th sample in the combined list (since we add 2 samples per entry: before and after)
                        // 37 * 2 = 74, so entry 37's after is index 75.
                        println!("=== BEFORE CODE ===");
                        println!("{}", entry.before);
                        println!("=== AFTER CODE ===");
                        println!("{}", entry.after);
                        break;
                    }
                    count += 1;
                }
            }
        }
    }
}
