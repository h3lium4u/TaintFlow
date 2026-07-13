use cfg::icfg::InterproceduralCFG;
use ir::Program;
use symbols::call_graph::CallGraph;
use symbols::global::GlobalSymbolTable;
use taint::InterproceduralTaintEngine;

#[test]
fn test_java_interprocedural_taint() {
    let controller_code = r#"
        package org.example.controller;
        import org.springframework.beans.factory.annotation.Autowired;
        import org.springframework.web.bind.annotation.RestController;
        import org.springframework.web.bind.annotation.GetMapping;
        import org.springframework.web.bind.annotation.RequestParam;
        import org.example.service.UserService;

        @RestController
        public class UserController {
            @Autowired
            private UserService userService;

            @GetMapping("/users")
            public Object getUser(@RequestParam String id) {
                return userService.getUser(id);
            }
        }
    "#;

    let service_code = r#"
        package org.example.service;
        import org.springframework.beans.factory.annotation.Autowired;
        import org.springframework.stereotype.Service;
        import org.example.repo.UserRepository;

        @Service
        public class UserService {
            @Autowired
            private UserRepository userRepo;

            public Object getUser(String id) {
                return userRepo.find(id);
            }
        }
    "#;

    let repo_code = r#"
        package org.example.repo;
        import org.springframework.stereotype.Repository;

        @Repository
        public class UserRepository {
            public Object find(String id) {
                db.execute("SELECT * FROM users WHERE id = " + id);
                return null;
            }
        }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, controller_code, "UserController.java", "java")
        .unwrap();
    gst.load_file(&mut program, service_code, "UserService.java", "java")
        .unwrap();
    gst.load_file(&mut program, repo_code, "UserRepository.java", "java")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    // Verify that the taint reached the sink
    assert!(
        !engine.flows.is_empty(),
        "Java taint flow to sink should be discovered"
    );

    let flow_found = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("db.execute") && flow.sink_var == "id"
    });
    assert!(flow_found, "Taint flow to db.execute(id) was not found");
}

#[test]
fn test_python_interprocedural_taint() {
    let app_code = r#"
        from helpers import query_helper
        @app.route("/users")
        def get_user(id):
            return query_helper(id)
    "#;

    let helpers_code = r#"
        from db import query_db
        def query_helper(val):
            return query_db(val)
    "#;

    let db_code = r#"
        def query_db(q):
            execute("SELECT * FROM users WHERE id = " + q)
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, app_code, "app.py", "python")
        .unwrap();
    gst.load_file(&mut program, helpers_code, "helpers.py", "python")
        .unwrap();
    gst.load_file(&mut program, db_code, "db.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    // Verify that taint reaches the sink in Python
    assert!(
        !engine.flows.is_empty(),
        "Python taint flow to sink should be discovered"
    );

    let flow_found = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("execute") && flow.sink_var == "q"
    });
    assert!(flow_found, "Taint flow to execute(q) was not found");
}
#[test]
fn test_java_library_stubs_and_sanitizer() {
    let controller_code = r#"
        package org.example.controller;
        import org.springframework.web.bind.annotation.RestController;
        import org.springframework.web.bind.annotation.GetMapping;
        import org.springframework.web.client.RestTemplate;
        import org.example.service.UserService;

        @RestController
        public class UserController {
            private UserService userService;

            @GetMapping("/fetch")
            public void fetchAndQuery() {
                RestTemplate rest = new RestTemplate();
                String data = rest.getForObject("http://api.com", String.class);
                userService.process(data);
                userService.processSafe(data);
            }
        }
    "#;

    let service_code = r#"
        package org.example.service;
        import jakarta.persistence.EntityManager;
        import org.apache.commons.text.StringEscapeUtils;

        public class UserService {
            private EntityManager em;

            public void process(String data) {
                em.createNativeQuery(data);
            }

            public void processSafe(String data) {
                String safeData = StringEscapeUtils.escapeSql(data);
                em.createNativeQuery(safeData);
            }
        }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, controller_code, "UserController.java", "java")
        .unwrap();
    gst.load_file(&mut program, service_code, "UserService.java", "java")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    println!("--- JAVA CALL GRAPH EDGES ---");
    for edge in &cg.edges {
        println!("  CG Edge: {:?} -> {:?}", edge.caller, edge.callee);
    }
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    println!("--- JAVA PROGRAM INSTRUCTIONS ---");
    for (id, inst) in &program.instructions {
        println!("  {:?}: {:?}", id, inst);
    }
    println!("--- JAVA ICFG NODES ---");
    for (id, node) in &icfg.nodes {
        println!(
            "  {:?}: label='{}', inst={:?}",
            id, node.label, node.instruction_id
        );
    }
    println!("--- JAVA ICFG EDGES ---");
    for edge in &icfg.edges {
        println!("  Edge: {} -> {}", edge.from, edge.to);
    }
    engine.seed_sources(None);
    println!("--- JAVA SEEDED FACTS ---");
    for fact in &engine.tainted_facts {
        println!("  Node {}: var='{}'", fact.node_id, fact.var);
    }
    engine.run();
    println!("--- JAVA DETECTED FLOWS ---");
    for flow in &engine.flows {
        println!(
            "  Flow: sink_node={} sink_var='{}'",
            flow.sink_node_id, flow.sink_var
        );
    }
    println!("--- JAVA SUPPRESSED FLOWS ---");
    for flow in &engine.suppressed_flows {
        println!(
            "  Suppressed Flow: sink_node={} sink_var='{}' reason='{}'",
            flow.sink_node_id, flow.sink_var, flow.reason
        );
    }

    // Verify the flows
    let has_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("createNativeQuery") && flow.sink_var == "data"
    });
    assert!(
        has_flow,
        "Taint flow from RestTemplate to createNativeQuery should be found"
    );

    let has_sanitized_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("createNativeQuery") && flow.sink_var == "safeData"
    });
    assert!(
        !has_sanitized_flow,
        "Taint flow to safeData should be sanitized"
    );
}

#[test]
fn test_python_library_stubs_and_sanitizer() {
    let app_code = r#"
        from pathlib import Path
        import subprocess
        import html

        def run_untrusted():
            p = Path("info.txt")
            untrusted = p.read_text()
            subprocess.run(untrusted)

        def run_safe():
            p = Path("info.txt")
            untrusted = p.read_text()
            safe = shlex.quote(untrusted)
            subprocess.run(safe)
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, app_code, "app.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    println!("--- PROGRAM INSTRUCTIONS ---");
    for (id, inst) in &program.instructions {
        println!("  {:?}: {:?}", id, inst);
    }
    println!("--- ICFG NODES ---");
    for (id, node) in &icfg.nodes {
        println!(
            "  {:?}: label='{}', inst={:?}",
            id, node.label, node.instruction_id
        );
    }
    engine.seed_sources(None);
    engine.run();

    // Verify the flows
    let has_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("subprocess.run") && flow.sink_var == "untrusted"
    });
    assert!(
        has_flow,
        "Taint flow from Path.read_text to subprocess.run should be found"
    );

    let has_safe_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("subprocess.run") && flow.sink_var == "safe"
    });
    assert!(
        !has_safe_flow,
        "Taint flow to safe parameter should be sanitized"
    );
}

#[test]
fn test_python_collections_tracking() {
    let app_code = r#"
        def test_dict_propagation():
            d = {}
            d["id"] = request.args["id"]
            x = d["id"]
            db.execute("SELECT * FROM users WHERE id = " + x)

        def test_dict_quote_normalization():
            d = {}
            d["id"] = request.args["id"]
            x = d['id']
            db.execute("SELECT * FROM users WHERE id = " + x)

        def test_dict_strong_update():
            d = {}
            d["id"] = request.args["id"]
            d["id"] = "safe_value"
            x = d["id"]
            db.execute("SELECT * FROM users WHERE id = " + x)
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, app_code, "app.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    println!("DEBUG: all flows: {:?}", engine.flows);
    for (&node_id, node) in &icfg.nodes {
        if let Some(inst_id) = node.instruction_id {
            println!(
                "DEBUG: node {}: label={:?}, inst={:?}",
                node_id,
                node.label,
                program.instructions.get(&inst_id)
            );
        }
    }

    // Verify propagation and quote normalization succeeded
    let has_prop_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        let method = program.methods.get(&node.method_id).unwrap();
        method.name.contains("test_dict_propagation") && flow.sink_var == "x"
    });
    assert!(has_prop_flow, "Python dict write/read propagation failed");

    let has_quote_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        let method = program.methods.get(&node.method_id).unwrap();
        method.name.contains("test_dict_quote_normalization") && flow.sink_var == "x"
    });
    assert!(has_quote_flow, "Python dict quote normalization failed");

    // Verify strong update killed the taint
    let has_killed_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        let method = program.methods.get(&node.method_id).unwrap();
        method.name.contains("test_dict_strong_update") && flow.sink_var == "x"
    });
    assert!(
        !has_killed_flow,
        "Python dict strong update failed to kill taint"
    );
}

#[test]
fn test_java_collections_tracking() {
    let app_code = r#"
        package org.example;

        public class ArrayTest {
            public void testArrayPropagation() {
                String[] arr = new String[5];
                arr[0] = request.getParameter("id");
                String x = arr[0];
                db.execute("SELECT * FROM users WHERE id = " + x);
            }

            public void testArrayStrongUpdate() {
                String[] arr = new String[5];
                arr[0] = request.getParameter("id");
                arr[0] = "safe_value";
                String x = arr[0];
                db.execute("SELECT * FROM users WHERE id = " + x);
            }
        }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, app_code, "ArrayTest.java", "java")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    // Verify propagation succeeded
    let has_prop_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        let method = program.methods.get(&node.method_id).unwrap();
        method.name.contains("testArrayPropagation") && flow.sink_var == "x"
    });
    assert!(has_prop_flow, "Java array write/read propagation failed");

    // Verify strong update killed the taint
    let has_killed_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        let method = program.methods.get(&node.method_id).unwrap();
        method.name.contains("testArrayStrongUpdate") && flow.sink_var == "x"
    });
    assert!(
        !has_killed_flow,
        "Java array strong update failed to kill taint"
    );
}

#[test]
fn test_python_flask_loop_and_cond_taint() {
    let app_code = r#"
        def benchmark():
            param = ""
            for name in request.headers.keys():
                if request.headers.get_all(name):
                    param = name
                    break
            
            bar = param
            import codecs
            fileTarget = codecs.open(bar, 'r', 'utf-8')
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, app_code, "app.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    // Verify the flows
    let has_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("codecs.open") && flow.sink_var == "bar"
    });
    assert!(
        has_flow,
        "Taint flow from request.headers.keys() loop variable and request.headers.get_all to codecs.open should be found"
    );
}

#[test]
fn test_benchmark_00610() {
    let app_code = r#"
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00610', methods=['GET'])
	def BenchmarkTest00610_get():
		return BenchmarkTest00610_post()

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00610', methods=['POST'])
	def BenchmarkTest00610_post():
		RESPONSE = ""

		import helpers.utils
		param = ""
		
		for name in request.headers.keys():
			if name.lower() in helpers.utils.commonHeaderNames:
				continue
			
			if request.headers.get_all(name):
				param = name
				break

		bar = "This should never happen"
		if 'should' in bar:
			bar = param

		import codecs
		import helpers.utils

		try:
			fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')

			RESPONSE += (
				f"Access to file: '{escape_for_html(fileTarget.name)}' created."
			)

			RESPONSE += (
				" And file already exists."
			)

		except FileNotFoundError:
			RESPONSE += (
				" But file doesn't exist yet."
			)

		return RESPONSE
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, app_code, "app.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    // Verify the flows
    let has_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("codecs.open") && flow.sink_var == "bar"
    });
    assert!(
        has_flow,
        "Taint flow for BenchmarkTest00610 to codecs.open should be found"
    );
}

#[test]
fn test_rc41_stub_sprint() {
    // 1. Java Collection API Iterator / Enumeration / Session / Cookie
    let java_code = r#"
        import java.util.Enumeration;
        import java.util.Iterator;
        import javax.servlet.http.HttpServletRequest;
        import javax.servlet.http.HttpSession;
        import javax.servlet.http.Cookie;

        public class Test {
            public void test(HttpServletRequest request) {
                // Iterator test
                Iterator<String> it = (Iterator<String>) request.getAttribute("foo");
                if (it.hasNext()) {
                    String val = it.next();
                    java.sql.Connection conn = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
                    java.sql.PreparedStatement stmt = conn.prepareStatement(val);
                    stmt.execute();
                }

                // Cookie test
                Cookie[] cookies = request.getCookies();
                for (Cookie cookie : cookies) {
                    String cval = cookie.getValue();
                    org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate(cval);
                }

                // LDAP test
                org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
                javax.naming.directory.DirContext ctx = ads.getDirContext();
                ctx.search("base", (String) request.getParameter("filter"), null);
            }
        }
    "#;

    // 2. Python ZipFile, tarfile, Popen stubs
    let python_code = r#"
        import zipfile
        import tarfile
        import subprocess

        def test_python(tainted_input):
            # zipfile
            zipfile.ZipFile(tainted_input)
            zf = zipfile.ZipFile("safe")
            zf.extract(tainted_input)

            # tarfile
            tarfile.open(tainted_input)

            # subprocess Popen
            subprocess.Popen(tainted_input)
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, java_code, "Test.java", "java")
        .unwrap();
    gst.load_file(&mut program, python_code, "test.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    println!("DEBUG: seeded facts: {:#?}", engine.tainted_facts);
    engine.run();

    println!("DEBUG: all flows: {:#?}", engine.flows);
    for (&node_id, node) in &icfg.nodes {
        if let Some(inst_id) = node.instruction_id {
            println!(
                "DEBUG: node {}: label={:?}, inst={:?}",
                node_id,
                node.label,
                program.instructions.get(&inst_id)
            );
        }
    }

    // Verify Java flows
    let has_stmt_execute = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("execute") && flow.sink_var == "stmt"
    });
    assert!(
        has_stmt_execute,
        "Taint should propagate through Iterator to stmt.execute"
    );

    let has_jdbc_update = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("batchUpdate") && flow.sink_var == "cval"
    });
    assert!(
        has_jdbc_update,
        "Taint should propagate through Cookie to batchUpdate"
    );

    let has_ldap_search = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("search") && (flow.sink_var == "request" || flow.sink_var == "ctx")
    });
    assert!(
        has_ldap_search,
        "Taint should flow to LDAPManager getDirContext/search"
    );

    // Verify Python flows
    let has_zipfile = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("ZipFile") && flow.sink_var == "tainted_input"
    });
    assert!(
        has_zipfile,
        "Taint should flow to zipfile.ZipFile constructor"
    );

    let has_tarfile = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("open") && flow.sink_var == "tainted_input"
    });
    assert!(has_tarfile, "Taint should flow to tarfile.open");

    let has_popen = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("Popen") && flow.sink_var == "tainted_input"
    });
    assert!(has_popen, "Taint should flow to subprocess.Popen");
}

#[test]
fn test_benchmark_00323_pruning() {
    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    let code = r#"
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest00323 extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00323");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) {
            bar = "This_should_always_happen";
        } else {
            bar = param;
        }

        request.getSession().putValue("userid", bar);
    }
}
    "#;

    gst.load_file(&mut program, code, "BenchmarkTest00323.java", "java")
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    println!("ICFG Nodes:");
    for (id, node) in &icfg.nodes {
        println!(
            "  Node {}: {:?} (label: '{}', inst_id: {:?})",
            id, node.kind, node.label, node.instruction_id
        );
    }
    println!("ICFG Edges:");
    for edge in &icfg.edges {
        println!("  Edge: {} -> {}", edge.from, edge.to);
    }

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    println!("Seeded facts:");
    for fact in &engine.tainted_facts {
        println!("  Node {}: var='{}'", fact.node_id, fact.var);
    }

    engine.run();

    println!("Detected Flows:");
    for flow in &engine.flows {
        println!(
            "  Flow: sink_node={} sink_var='{}'",
            flow.sink_node_id, flow.sink_var
        );
    }

    assert!(
        engine.flows.is_empty(),
        "Expected no flows due to branch pruning!"
    );
}

#[test]
fn test_rc98_deserialization_and_ssrf() {
    let code = r#"
        import pickle
        import requests
        import httpx
        import urllib.request

        def test_pickle(tainted_bytes):
            data = pickle.loads(tainted_bytes)
            dangerous_sink(data)

        def test_ssrf(tainted_url):
            requests.get(url=tainted_url)
            httpx.post(tainted_url)
            urllib.request.urlopen(tainted_url)
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, code, "test.py", "python")
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    println!("--- TEST ALL INSTRUCTIONS ---");
    for (id, inst) in &program.instructions {
        println!("  {:?}: {:?}", id, inst);
    }
    println!("--- TEST ALL METHODS ---");
    for (id, method) in &program.methods {
        println!(
            "  {:?}: name='{}', parameters={:?}",
            id, method.name, method.parameters
        );
    }
    println!("--- TEST ICFG NODES ---");
    for (id, node) in &icfg.nodes {
        println!(
            "  {:?}: label='{}', inst={:?}, method={:?}",
            id, node.label, node.instruction_id, node.method_id
        );
    }
    println!("--- TEST ICFG EDGES ---");
    for edge in &icfg.edges {
        println!("  {:?} -> {:?} ({:?})", edge.from, edge.to, edge.kind);
    }
    println!("--- TEST CALL GRAPH EDGES ---");
    for edge in &cg.edges {
        println!(
            "  {:?} -> {:?} (inst={:?})",
            edge.caller, edge.callee, edge.instruction_id
        );
    }
    println!("--- TEST METHOD ENTRY/EXIT MAPS ---");
    for (m_id, entry) in &icfg.method_entry_node {
        let exit = icfg.method_exit_node.get(m_id).unwrap();
        let method = program.methods.get(m_id).unwrap();
        println!(
            "  Method {:?} ({}) -> Entry: {}, Exit: {}",
            m_id, method.name, entry, exit
        );
    }
    println!("--- TEST INSTRUCTION TO NODES ---");
    for (inst_id, nodes) in &icfg.instruction_to_nodes {
        println!("  Inst {:?} -> Nodes {:?}", inst_id, nodes);
    }

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    println!("Detected Flows: {:?}", engine.flows);

    // Verify pickle flow to dangerous_sink
    let has_pickle_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("dangerous_sink") && flow.sink_var == "data"
    });
    assert!(
        has_pickle_flow,
        "Taint should propagate through pickle.loads to dangerous_sink"
    );

    // Verify SSRF flow to requests.get
    let has_requests_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("requests.get") && flow.cwe == taint::CWE::CWE918
    });
    assert!(
        has_requests_flow,
        "SSRF to requests.get was not found or has wrong CWE"
    );

    // Verify SSRF flow to httpx.post
    let has_httpx_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("httpx.post") && flow.cwe == taint::CWE::CWE918
    });
    assert!(
        has_httpx_flow,
        "SSRF to httpx.post was not found or has wrong CWE"
    );

    // Verify SSRF flow to urlopen
    let has_urlopen_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("urlopen") && flow.cwe == taint::CWE::CWE918
    });
    assert!(
        has_urlopen_flow,
        "SSRF to urllib.request.urlopen was not found or has wrong CWE"
    );
}

#[test]
fn test_python_subscript_dispatch_and_subprocess() {
    let code = r#"
        from pathlib import Path
        import subprocess

        def _get_download(url, filename):
            subprocess.run(["wget", url, "-O", filename])

        def _wget_download(url, filename):
            subprocess.Popen(f"wget {url} -O {filename}", shell=True)

        _download_methods = {
            'get': _get_download,
            'wget': _wget_download,
        }

        def download(method, url, filename):
            _download_methods[method](url, filename)

        def main(request):
            user_input = request.get_parameter("url")
            download('get', user_input, 'output.txt')
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    gst.load_file(&mut program, code, "app.py", "python")
        .unwrap();
    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    println!("--- TEST CALL GRAPH EDGES ---");
    for edge in &cg.edges {
        let caller = program.methods.get(&edge.caller).unwrap();
        let callee = program.methods.get(&edge.callee).unwrap();
        println!(
            "  {} -> {} (inst={:?})",
            caller.name, callee.name, edge.instruction_id
        );
    }

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.seed_sources(None);
    engine.run();

    println!("Detected Flows: {:?}", engine.flows);

    // Verify command injection flow through get_download to subprocess.run
    let has_run_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("subprocess.run") && flow.cwe == taint::CWE::CWE78
    });
    assert!(
        has_run_flow,
        "Command injection to subprocess.run was not found or has wrong CWE"
    );

    // Verify command injection flow through wget_download to subprocess.Popen
    let has_popen_flow = engine.flows.iter().any(|flow| {
        let node = icfg.nodes.get(&flow.sink_node_id).unwrap();
        node.label.contains("subprocess.Popen") && flow.cwe == taint::CWE::CWE78
    });
    assert!(
        has_popen_flow,
        "Command injection to subprocess.Popen was not found or has wrong CWE"
    );
}
