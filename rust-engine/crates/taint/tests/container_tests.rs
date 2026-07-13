use normalizer::Normalizer;
use parser::UnifiedParser;
use taint::TaintEngine;

#[test]
fn test_container_taint_propagation() {
    let code = r#"
user = request.args["id"]
items.append(user)
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let items_state = engine.get_taint("items");
    assert!(items_state.is_some());
    assert!(
        items_state.unwrap().tainted,
        "items container should become tainted"
    );
}

#[test]
fn test_python_dict_key_sensitive_propagation() {
    let code = r#"
d = {}
user = request.args["id"]
d["id"] = user
x = d["id"]
y = d["safe"]
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    println!("NORMALIZED AST FOR PYTHON:");
    println!("{:#?}", normalized);

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    println!("TAINTED SYMBOLS AFTER PROPAGATION:");
    println!("{:#?}", engine.tainted_symbols);

    // x should be tainted since it reads "id"
    let x_state = engine.get_taint("x");
    assert!(x_state.is_some() && x_state.unwrap().tainted);

    // y should NOT be tainted since it reads "safe"
    let y_state = engine.get_taint("y");
    assert!(y_state.is_none() || !y_state.unwrap().tainted);
}

#[test]
fn test_java_map_key_sensitive_propagation() {
    let code = r#"
Map<String, String> map = new HashMap<>();
String user = request.getParameter("id");
map.put("id", user);
String x = map.get("id");
String y = map.get("safe");
"#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    // x should be tainted since it reads "id"
    let x_state = engine.get_taint("x");
    assert!(x_state.is_some() && x_state.unwrap().tainted);

    // y should NOT be tainted since it reads "safe"
    let y_state = engine.get_taint("y");
    assert!(y_state.is_none() || !y_state.unwrap().tainted);
}

#[test]
fn test_python_list_index_sensitive_propagation() {
    let code = r#"
arr = []
user = request.args["id"]
arr.append("safe")  # arr[0] is safe
arr.append(user)    # arr[1] is tainted
x = arr[1]
y = arr[0]
"#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    println!("TAINTED SYMBOLS: {:?}", engine.tainted_symbols);

    // x should be tainted since it reads arr[1]
    let x_state = engine.get_taint("x");
    assert!(x_state.is_some() && x_state.unwrap().tainted);

    // y should NOT be tainted since it reads arr[0]
    let y_state = engine.get_taint("y");
    assert!(y_state.is_none() || !y_state.unwrap().tainted);
}

#[test]
fn test_java_list_remove_shifting() {
    let code = r#"
        List<String> valuesList = new ArrayList<>();
        valuesList.add("safe");      // index 0
        valuesList.add(request.getParameter("id")); // index 1 (tainted)
        valuesList.add("moresafe");  // index 2

        valuesList.remove(0); // remove the 1st safe value

        String x = valuesList.get(0); // should be tainted (index 0 is now param)
        String y = valuesList.get(1); // should be clean (index 1 is now moresafe)
    "#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.get_taint("x");
    assert!(
        x_state.is_some() && x_state.unwrap().tainted,
        "x should be tainted"
    );

    let y_state = engine.get_taint("y");
    assert!(
        y_state.is_none() || !y_state.unwrap().tainted,
        "y should be clean"
    );
}

#[test]
fn test_java_map_remove() {
    let code = r#"
        Map<String, String> map = new HashMap<>();
        map.put("id", request.getParameter("id"));
        map.put("safe", "hello");

        map.remove("id");

        String x = map.get("id");
        String y = map.get("safe");
    "#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.get_taint("x");
    assert!(
        x_state.is_none() || !x_state.unwrap().tainted,
        "x should be clean"
    );

    let y_state = engine.get_taint("y");
    assert!(
        y_state.is_none() || !y_state.unwrap().tainted,
        "y should be clean"
    );
}

#[test]
fn test_java_list_clear() {
    let code = r#"
        List<String> list = new ArrayList<>();
        list.add(request.getParameter("id"));
        list.clear();
        String x = list.get(0);
    "#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.get_taint("x");
    assert!(
        x_state.is_none() || !x_state.unwrap().tainted,
        "x should be clean after clear"
    );
}

#[test]
fn test_java_map_putall() {
    let code = r#"
        Map<String, String> map1 = new HashMap<>();
        map1.put("id", request.getParameter("id"));
        map1.put("safe", "hello");

        Map<String, String> map2 = new HashMap<>();
        map2.putAll(map1);

        String x = map2.get("id");
        String y = map2.get("safe");
    "#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.get_taint("x");
    assert!(
        x_state.is_some() && x_state.unwrap().tainted,
        "x should be tainted after putAll"
    );

    let y_state = engine.get_taint("y");
    assert!(
        y_state.is_none() || !y_state.unwrap().tainted,
        "y should be clean after putAll"
    );
}

#[test]
fn test_java_list_addall() {
    let code = r#"
        List<String> list1 = new ArrayList<>();
        list1.add("safe");
        list1.add(request.getParameter("id"));

        List<String> list2 = new ArrayList<>();
        list2.add("moresafe");
        list2.addAll(list1);

        String x = list2.get(0); // moresafe (clean)
        String y = list2.get(1); // safe (clean)
        String z = list2.get(2); // param (tainted)
    "#;
    let ast = UnifiedParser::parse(code, "java").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "java");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.get_taint("x");
    assert!(
        x_state.is_none() || !x_state.unwrap().tainted,
        "x should be clean"
    );

    let y_state = engine.get_taint("y");
    assert!(
        y_state.is_none() || !y_state.unwrap().tainted,
        "y should be clean"
    );

    let z_state = engine.get_taint("z");
    assert!(
        z_state.is_some() && z_state.unwrap().tainted,
        "z should be tainted"
    );
}

#[test]
fn test_python_list_extend() {
    let code = r#"
        arr1 = ["safe", request.args["id"]]
        arr2 = []
        arr2.extend(arr1)
        x = arr2[0]
        y = arr2[1]
    "#;
    let ast = UnifiedParser::parse(code, "python").unwrap();
    let mut norm = Normalizer::new();
    let normalized = norm.normalize(&ast, "python");

    let mut engine = TaintEngine::new(10, 5, 200);
    engine.propagate_node(&normalized);

    let x_state = engine.get_taint("x");
    assert!(
        x_state.is_none() || !x_state.unwrap().tainted,
        "x should be clean"
    );

    let y_state = engine.get_taint("y");
    assert!(
        y_state.is_some() && y_state.unwrap().tainted,
        "y should be tainted"
    );
}
