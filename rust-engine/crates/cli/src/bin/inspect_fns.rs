fn main() {
    let code = r#"
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import org.apache.commons.lang3.StringEscapeUtils;
            try {
                String unescapedURL = URLDecoder.decode(url, StandardCharsets.UTF_8.name());
                /*
                    StringEscapeUtils is deprecated starting with version 3.6 of commons-lang3, however the indicated replacement comes from
                    commons-text, which is not an OSGi bundle
                */
                unescapedURL = StringEscapeUtils.unescapeXml(unescapedURL);
                // Percent-encode characters that are not allowed in unquoted
                // HTML attributes: ", ', >, <, ` and space. We don't encode =
                // since this would break links with query parameters.
                String encodedUrl = unescapedURL.replaceAll("\"", "%22")
                        .replaceAll("'", "%27")
                        .replaceAll(">", "%3E")
                        .replaceAll("<", "%3C")
                        .replaceAll("`", "%60")
                        .replaceAll(" ", "%20");
                int qMarkIx = encodedUrl.indexOf('?');
                if (qMarkIx > 0) {
                    encodedUrl = encodedUrl.substring(0, qMarkIx) + encodedUrl.substring(qMarkIx).replaceAll(":", "%3A");
                }

                encodedUrl = mangleNamespaces(encodedUrl);
                if (xssFilter.isValidHref(encodedUrl)) {
                    return encodedUrl;
                }
            } catch (UnsupportedEncodingException e) {
                LOGGER.error("Unable to decode url: {}.", url);
            }
"#;

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = "Test_CWE_79.java";

    println!("Loading file...");
    let loaded = gst.load_file(&mut program, code, filename, "java").is_ok();
    println!("Loaded: {}", loaded);

    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    println!("Methods:");
    for (id, m) in &program.methods {
        println!("  ID: {:?}, Name: {}, Params: {:?}", id, m.name, m.parameters);
    }

    println!("Instructions:");
    for (id, inst) in &program.instructions {
        println!("  ID: {:?}, Kind: {:?}", id, inst.kind);
    }

    println!("CallGraph edges:");
    for edge in &cg.edges {
        println!("  Caller: {:?}, Callee: {:?}, Inst: {:?}", edge.caller, edge.callee, edge.instruction_id);
    }

    println!("ICFG Nodes of interest:");
    for (id, node) in &icfg.nodes {
        if let Some(inst_id) = node.instruction_id {
            if inst_id.0 == 11 || inst_id.0 == 13 || inst_id.0 == 12 {
                println!("  Node ID: {}, Inst: {:?}, Kind: {:?}", id, inst_id, node.kind);
                for edge in &icfg.edges {
                    if edge.to == *id {
                        println!("    Predecessor: From = {}, Kind = {:?}", edge.from, edge.kind);
                    }
                    if edge.from == *id {
                        println!("    Successor: To = {}, Kind = {:?}", edge.to, edge.kind);
                    }
                }
            }
        }
    }

    let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine.target_file = Some(filename.to_string());
    engine.seed_sources(None);

    println!("Tainted facts after seeding:");
    for fact in &engine.tainted_facts {
        println!("  Node: {:?}, Var: {}, Domain: {:?}", fact.node_id, fact.var, fact.source_domain);
    }

    engine.run();

    println!("Flows detected:");
    for flow in &engine.flows {
        println!("  Sink Node: {:?}, Var: {}, CWE: {:?}", flow.sink_node_id, flow.sink_var, flow.cwe);
    }

    /*
    println!("All final tainted facts:");
    for fact in &engine.tainted_facts {
        println!("  Node: {:?}, Var: {}, Domain: {:?}", fact.node_id, fact.var, fact.source_domain);
    }
    */

    println!("Suppressed flows:");
    for sup in &engine.suppressed_flows {
        println!("  Sink Node: {:?}, Var: {}, Sink Domain: {:?}, Reason: {}", sup.sink_node_id, sup.sink_var, sup.sink_domain, sup.reason);
    }
}
