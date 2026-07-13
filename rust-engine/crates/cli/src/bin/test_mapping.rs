fn main() {
    let callee = "new java.io.File";
    let class_fqn = "java.io.File";
    let method_name = "<init>";

    let res1 = taint::map_sink_to_cwe_heuristic(method_name, None);
    let res2 = taint::map_sink_to_cwe_heuristic(callee, None);
    let res3 = taint::map_sink_to_cwe_heuristic(class_fqn, None);

    println!("callee: {}", callee);
    println!("  res1: {:?}", res1);
    println!("  res2: {:?}", res2);
    println!("  res3: {:?}", res3);
}
