use cfg::icfg::InterproceduralCFG;
use ir::Program;
use symbols::call_graph::CallGraph;
use symbols::global::GlobalSymbolTable;
use taint::InterproceduralTaintEngine;

#[test]
fn test_interproc_map_key_sensitivity_repro() {
    let code = r#"
    public class Test {
        public void bad(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
            String param = request.getParameter("BenchmarkTest00094");
            String bar = "safe!";
            java.util.HashMap<String, Object> map52993 = new java.util.HashMap<String, Object>();
            map52993.put("keyA-52993", "a_Value");
            map52993.put("keyB-52993", param);
            map52993.put("keyC", "another_Value");
            bar = (String) map52993.get("keyB-52993");
            bar = (String) map52993.get("keyA-52993");

            // Sink
            java.io.PrintWriter writer = response.getWriter();
            writer.println(bar); // Should be CLEAN!
        }
    }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();
    gst.load_file(&mut program, code, "Test.java", "java").unwrap();
    gst.resolve_inheritance_hierarchy();

    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    


    engine.run();

    assert!(engine.flows.is_empty(), "Should have no flows because bar was reassigned to a safe key");
}

#[test]
fn test_interproc_map_method_get_repro() {
    let code_main = r#"
    public class Test {
        public void bad(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
            String param = request.getParameter("BenchmarkTest00094");
            java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
            map.put("keyB", param);
            
            Helper helper = new Helper();
            String bar = helper.getVal(map);

            // Sink
            java.io.PrintWriter writer = response.getWriter();
            writer.println(bar); // Should be TAINTED!
        }
    }
    "#;

    let code_helper = r#"
    import java.util.Map;
    public class Helper {
        public String getVal(Map<String, Object> m) {
            return (String) m.get("keyB");
        }
    }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();
    gst.load_file(&mut program, code_main, "Test.java", "java").unwrap();
    gst.load_file(&mut program, code_helper, "Helper.java", "java").unwrap();
    gst.resolve_inheritance_hierarchy();

    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    assert!(!engine.flows.is_empty(), "Should have found taint flow through map.get inside helper method");
}

#[test]
fn test_interproc_arraylist_precision() {
    let code = r#"
    public class Test {
        public void bad(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {
            String param = request.getParameter("BenchmarkTest00094");
            String bar = "alsosafe";
            if (param != null) {
                java.util.List<String> valuesList = new java.util.ArrayList<String>();
                valuesList.add("safe");
                valuesList.add(param);
                valuesList.add("moresafe");

                valuesList.remove(0); // remove the 1st safe value -> shifts param to 0, moresafe to 1

                bar = valuesList.get(1); // get index 1 ("moresafe", which is clean)
            }

            // Sink
            java.io.PrintWriter writer = response.getWriter();
            writer.println(bar); // Should be CLEAN!
        }
    }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();
    gst.load_file(&mut program, code, "Test.java", "java").unwrap();
    gst.resolve_inheritance_hierarchy();

    println!("=== INSTRUCTIONS ===");
    for (id, inst) in &program.instructions {
        println!("  inst {}: {:?}", id.0, inst.kind);
    }

    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    assert!(engine.flows.is_empty(), "Should have no flows because bar was retrieved from a safe index");
}
