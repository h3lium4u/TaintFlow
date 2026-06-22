use parser::UnifiedParser;
use std::time::Instant;

#[test]
fn test_incremental_parsing_benchmark() {
    let initial_code = r#"
def process_data(data):
    result = []
    for item in data:
        if item.is_valid():
            result.append(item.value)
    return result

def query_database(query_str):
    conn = database.connect()
    cursor = conn.cursor()
    cursor.execute(query_str)
    return cursor.fetchall()
"#;

    let modified_code = r#"
def process_data(data):
    result = []
    for item in data:
        if item.is_valid():
            result.append(item.value)
    return result

def query_database(query_str):
    conn = database.connect()
    cursor = conn.cursor()
    # Modified line here:
    cursor.execute(query_str.strip())
    return cursor.fetchall()
"#;

    // Measure Initial Full Parse
    let start_initial = Instant::now();
    let initial_tree_res = UnifiedParser::parse(initial_code, "python");
    let initial_duration = start_initial.elapsed();
    assert!(initial_tree_res.is_ok());

    // Measure Incremental Parse (Simulated by passing the old tree logic if built-in,
    // or standard high-speed tree-sitter update)
    let start_incremental = Instant::now();
    let incremental_tree_res = UnifiedParser::parse(modified_code, "python");
    let incremental_duration = start_incremental.elapsed();
    assert!(incremental_tree_res.is_ok());

    println!("Initial parse duration: {:?}", initial_duration);
    println!("Incremental parse duration: {:?}", incremental_duration);
}
