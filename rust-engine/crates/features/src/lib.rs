use cfg::ControlFlowGraph;
use rules::Finding;
use std::collections::HashSet;
use symbols::SymbolTable;
use taint::TaintEngine;

#[derive(Debug, Clone)]
pub struct FeatureVector(pub [f32; 55]);

pub struct FeatureExtractor;

fn get_longest_path(cfg: &ControlFlowGraph) -> f32 {
    let entry_node = cfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, cfg::CfgNodeKind::Entry));
    let exit_node = cfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, cfg::CfgNodeKind::Exit));
    if entry_node.is_none() || exit_node.is_none() {
        return 0.0;
    }
    let entry_id = entry_node.unwrap().id;
    let exit_id = exit_node.unwrap().id;

    fn dfs(
        curr: u32,
        target: u32,
        edges: &[cfg::CfgEdge],
        visited: &mut HashSet<u32>,
        steps: &mut i32,
        max_path_found: &mut i32,
        aborted: &mut bool,
    ) -> Option<i32> {
        *steps += 1;
        if *steps > 5000 {
            *aborted = true;
            return None;
        }
        if curr == target {
            let path_len = visited.len() as i32;
            *max_path_found = (*max_path_found).max(path_len);
            return Some(0);
        }
        visited.insert(curr);
        let mut max_dist = None;
        for edge in edges {
            if edge.from == curr && !visited.contains(&edge.to) {
                if let Some(d) = dfs(
                    edge.to,
                    target,
                    edges,
                    visited,
                    steps,
                    max_path_found,
                    aborted,
                ) {
                    max_dist = Some(max_dist.unwrap_or(-1).max(d + 1));
                }
            }
        }
        visited.remove(&curr);
        max_dist
    }

    let mut visited = HashSet::new();
    let mut steps = 0;
    let mut max_path_found = 1;
    let mut aborted = false;
    let result = dfs(
        entry_id,
        exit_id,
        &cfg.edges,
        &mut visited,
        &mut steps,
        &mut max_path_found,
        &mut aborted,
    );

    if aborted {
        max_path_found as f32
    } else {
        result.unwrap_or(0) as f32
    }
}

/// Count distinct acyclic paths from entry to exit, capped at 50.
/// Structurally independent from path length: a graph can have many short
/// paths or few long paths. Used for feat_23.
fn get_path_count(cfg: &ControlFlowGraph) -> f32 {
    let entry_node = cfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, cfg::CfgNodeKind::Entry));
    let exit_node = cfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, cfg::CfgNodeKind::Exit));
    if entry_node.is_none() || exit_node.is_none() {
        return 0.0;
    }
    let entry_id = entry_node.unwrap().id;
    let exit_id = exit_node.unwrap().id;

    fn dfs(
        curr: u32,
        target: u32,
        edges: &[cfg::CfgEdge],
        visited: &mut HashSet<u32>,
        path_count: &mut i32,
        steps: &mut i32,
    ) {
        *steps += 1;
        if *steps > 5000 || *path_count >= 50 {
            return;
        }
        if curr == target {
            *path_count += 1;
            return;
        }
        visited.insert(curr);
        for edge in edges {
            if edge.from == curr && !visited.contains(&edge.to) {
                dfs(edge.to, target, edges, visited, path_count, steps);
            }
        }
        visited.remove(&curr);
    }

    let mut visited = HashSet::new();
    let mut path_count = 0;
    let mut steps = 0;
    dfs(
        entry_id,
        exit_id,
        &cfg.edges,
        &mut visited,
        &mut path_count,
        &mut steps,
    );
    path_count as f32
}

impl FeatureExtractor {
    pub fn extract(
        code: &str,
        findings: &[Finding],
        cfg: &ControlFlowGraph,
        symbols: &SymbolTable,
        taint: &TaintEngine,
    ) -> FeatureVector {
        let mut features = [0.0f32; 55];
        let code_lower = code.to_lowercase();

        // 1. Taint Subsystem (feat_0 to feat_11)
        let source_keywords = [
            // Python
            "request.args",
            "request.form",
            "request.json",
            "request.cookies",
            "request.headers",
            "request.values",
            "request.stream",
            "request.url",
            "request.referrer",
            "request.get",
            "request.post",
            "request.body",
            "request.meta",
            "input(",
            "sys.argv",
            "environ",
            "getenv",
            "environ.get(",
            // Java
            "getparameter",
            "getheader",
            "getcookies",
            "getquerystring",
            "nextline",
            "readline",
            // RC10: new Java sources
            "getsession",
            "getattribute",
            "getinputstream",
            "getreader",
            "getpart",
            "getrequesturi",
            "getrequesturl",
            "getpathinfo",
            // FastAPI
            "query(",
            "body(",
            "path(",
            "cookie(",
            "header(",
            // SQLAlchemy
            "session.query",
            "objects.all",
            "objects.filter",
            // Spring extras
            "@modelattribute",
            "@sessionattribute",
            "@cookievalue",
            // Hibernate
            "session.get(",
            "session.load(",
            "session.createquery",
            // Jackson
            "readvalue(",
            "readtree(",
            "objectmapper",
            // Gson
            "fromjson(",
            "gson.fromjson",
            // JdbcTemplate
            "jdbctemplate",
        ];
        let actual_source_count = source_keywords
            .iter()
            .map(|&s| code_lower.matches(s).count())
            .sum::<usize>() as f32;
        features[0] = actual_source_count;

        let sink_keywords = [
            "execute",
            "query",
            "executequery",
            "executeupdate",
            "executebatch",
            "createquery",
            "createnativequery",
            "run",
            "popen",
            "system",
            "subprocess",
            "processbuilder",
            "open",
            "fileinputstream",
            "readobject",
            "loads",
            "urlopen",
            "get",
            "post",
            "getwriter",
            "println",
            "sendredirect",
            "setheader",
            "addheader",
            "path(",
            "new file",
        ];
        let actual_sink_count = sink_keywords
            .iter()
            .map(|&s| code_lower.matches(s).count())
            .sum::<usize>() as f32;
        features[1] = actual_sink_count;

        let validated_paths_count = taint.validated_paths_count as f32;
        features[2] = validated_paths_count;

        // Path depth estimates using graph DFS search
        let longest_val = get_longest_path(cfg);

        // feat_3: distinct taint source category count (how many attack surface channels present)
        // Completely independent from CFG structure (feat_4 = longest CFG path)
        let src_cats: f32 = [
            ["request.args", "request.form", "request.json"]
                .iter()
                .any(|&s| code_lower.contains(s)),
            ["input(", "sys.argv", "readline", "stdin"]
                .iter()
                .any(|&s| code_lower.contains(s)),
            ["os.environ", "os.getenv", "environ", "getenv"]
                .iter()
                .any(|&s| code_lower.contains(s)),
            ["request.cookies", "request.headers", "request.files"]
                .iter()
                .any(|&s| code_lower.contains(s)),
            [
                "request.get",
                "request.post",
                "request.body",
                "request.meta",
            ]
            .iter()
            .any(|&s| code_lower.contains(s)),
            ["getParameter", "getHeader", "getCookies", "getQueryString"]
                .iter()
                .any(|&s| code_lower.contains(s)),
        ]
        .iter()
        .filter(|&&b| b)
        .count() as f32;
        features[3] = src_cats;
        // feat_4: DFS longest path length from entry to exit
        features[4] = longest_val.min(100.0);

        let sanitizer_kws = ["strip", "escape", "sanitize", "encode", "replace", "clean"];
        let sanitizer_count = sanitizer_kws
            .iter()
            .map(|&s| code_lower.matches(s).count())
            .sum::<usize>() as f32;
        features[5] = sanitizer_count; // sanitized paths count
                                       // feat_6: binary indicator of unsanitized taint paths
                                       // Changed from continuous count to binary to break near-linear derivation from feat_2
        features[6] = if validated_paths_count > 0.0 && sanitizer_count < validated_paths_count {
            1.0
        } else {
            0.0
        };

        let all_symbols: Vec<&symbols::Symbol> = symbols
            .scopes
            .iter()
            .flat_map(|s| s.symbols.values())
            .collect();
        // feat_7: actual alias transition count
        features[7] = taint.alias_transition_count as f32;

        let container_propagation_count = (code_lower.matches("append").count()
            + code_lower.matches("add").count()
            + code_lower.matches("put").count()) as f32;
        features[8] = container_propagation_count;
        features[9] = validated_paths_count / (actual_source_count + 1.0);

        let total_symbols_count = symbols
            .scopes
            .iter()
            .map(|s| s.symbols.len())
            .sum::<usize>();
        features[10] = taint.tainted_symbols.len() as f32 / (total_symbols_count + 1) as f32;
        features[11] = taint.observed_max_alias_depth as f32;

        // 2. CFG Subsystem (feat_12 to feat_23)
        features[12] = (cfg.nodes.len() as f32).min(1000.0);

        let branch_nodes_count = cfg
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, cfg::CfgNodeKind::Branch))
            .count() as f32;
        let loop_nodes_count = cfg
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, cfg::CfgNodeKind::Loop))
            .count() as f32;
        let exception_nodes_count = cfg
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, cfg::CfgNodeKind::Catch))
            .count() as f32;

        // Cyclomatic complexity based on decision points
        let cyclomatic_complexity =
            branch_nodes_count + loop_nodes_count + exception_nodes_count + 1.0;
        features[13] = cyclomatic_complexity.min(50.0);

        // feat_14/15/16: structural CFG counts -- not gated on taint flow
        // feat_15: raw loop node count, unconditional (removed max(1.0) floor that caused
        // correlation with feat_46 when validated_paths>0)
        features[14] = if validated_paths_count > 0.0 {
            branch_nodes_count / 2.0
        } else {
            0.0
        };
        features[15] = loop_nodes_count; // raw loop node count, unconditional
        features[16] = if validated_paths_count > 0.0 {
            exception_nodes_count / 2.0
        } else {
            0.0
        };

        features[17] = cfg.edges.len() as f32 / (cfg.nodes.len() + 1) as f32;

        // feat_18: count Return nodes (explicit returns) instead of Exit nodes
        // The Exit node is always exactly 1, making feat_18 constant = causing correlation with feat_17
        features[18] = cfg
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, cfg::CfgNodeKind::Return))
            .count() as f32;

        features[19] = if branch_nodes_count > 0.0 { 2.0 } else { 0.0 };
        features[20] = if loop_nodes_count > 0.0 { 2.0 } else { 0.0 };
        features[21] = exception_nodes_count; // Catch count
                                              // feat_22: binary exception handling flag (1 if any try/catch block exists, else 0)
                                              // Decoupled from feat_21 (raw Catch count): diverges for multi-handler blocks
        let has_exception = cfg
            .nodes
            .iter()
            .any(|n| matches!(n.kind, cfg::CfgNodeKind::Try | cfg::CfgNodeKind::Catch));
        features[22] = if has_exception { 1.0 } else { 0.0 };

        // feat_23: distinct path count from entry to exit (capped at 50)
        // Structurally independent from path length -- a graph can have many short
        // paths or few long paths. Previously avg path length was near-perfectly
        // correlated with longest path (feat_4).
        features[23] = get_path_count(cfg);

        // 3. Symbol Subsystem (feat_24 to feat_31)
        features[24] = total_symbols_count as f32;
        features[25] = symbols.scopes.len() as f32;

        features[26] = all_symbols
            .iter()
            .filter(|s| {
                matches!(s.kind, symbols::SymbolKind::Import)
                    && sink_keywords.iter().any(|&k| s.name.contains(k))
            })
            .count() as f32;

        features[27] = all_symbols
            .iter()
            .filter(|s| {
                matches!(s.kind, symbols::SymbolKind::Import)
                    && sanitizer_kws.iter().any(|&k| s.name.contains(k))
            })
            .count() as f32;

        features[28] = all_symbols
            .iter()
            .filter(|s| matches!(s.kind, symbols::SymbolKind::Parameter))
            .count() as f32;
        features[29] = all_symbols
            .iter()
            .filter(|s| matches!(s.kind, symbols::SymbolKind::Field))
            .count() as f32;
        features[30] = all_symbols
            .iter()
            .filter(|s| matches!(s.kind, symbols::SymbolKind::Import))
            .count() as f32;

        features[31] = if symbols.scopes.len() > 1 { 1.0 } else { 0.0 };

        // 4. Rule Subsystem (feat_32 to feat_47)
        features[32] = if !findings.is_empty() { 1.0 } else { 0.0 };
        features[33] = if findings.iter().any(|f| {
            f.description.contains("args")
                || f.description.contains("form")
                || f.description.contains("json")
        }) {
            1.0
        } else {
            0.0
        };
        // feat_34: multi-source taint indicator -- fires when multiple distinct taint sources detected
        // Changed from description keyword 'query'/'execute' which was identical to CWE-89 tag
        // in feat_36, causing correlation 0.972
        features[34] = if actual_source_count > 1.0 { 1.0 } else { 0.0 };
        features[35] = if findings
            .iter()
            .any(|f| f.description.contains("env") || f.description.contains("getenv"))
        {
            1.0
        } else {
            0.0
        };

        features[36] = if findings.iter().any(|f| f.cwe == "CWE-89") {
            1.0
        } else {
            0.0
        };
        features[37] = if findings.iter().any(|f| f.cwe == "CWE-78") {
            1.0
        } else {
            0.0
        };
        features[38] = if findings.iter().any(|f| f.cwe == "CWE-22") {
            1.0
        } else {
            0.0
        };
        features[39] = if findings.iter().any(|f| f.cwe == "CWE-918") {
            1.0
        } else {
            0.0
        };
        features[40] = if findings.iter().any(|f| f.cwe == "CWE-502") {
            1.0
        } else {
            0.0
        };
        features[41] = if findings.iter().any(|f| f.cwe == "CWE-327") {
            1.0
        } else {
            0.0
        };

        features[42] = if code_lower.contains("escape")
            || code_lower.contains("sanitize")
            || code_lower.contains("replace")
        {
            1.0
        } else {
            0.0
        };
        features[43] = if code_lower.contains("quote") || code_lower.contains("escape") {
            1.0
        } else {
            0.0
        };
        features[44] = if code_lower.contains("canonicalize")
            || code_lower.contains("abspath")
            || code_lower.contains("realpath")
        {
            1.0
        } else {
            0.0
        };
        features[45] = if code_lower.contains("match")
            || code_lower.contains("regex")
            || code_lower.contains("re.sub")
        {
            1.0
        } else {
            0.0
        };

        features[46] = if !findings.is_empty() && validated_paths_count > 0.0 {
            1.0
        } else {
            0.0
        };
        features[47] = if cyclomatic_complexity > 2.0
            && findings
                .iter()
                .any(|f| f.description.to_lowercase().contains("unsanitized"))
        {
            1.0
        } else {
            0.0
        };

        // 5. RC2 Semantic Counts
        features[48] = findings.len() as f32;

        let unique_cwes: std::collections::HashSet<&str> = findings
            .iter()
            .map(|f| f.cwe.as_str())
            .filter(|c| !c.is_empty())
            .collect();
        features[49] = unique_cwes.len() as f32;

        // 6. RC6 Security Context Features
        let trusted_keywords = ["environ", "getenv", "sys.argv"];
        let trusted_source_count = trusted_keywords
            .iter()
            .map(|&s| code_lower.matches(s).count())
            .sum::<usize>() as f32;

        features[50] = sanitizer_count / validated_paths_count.max(1.0);
        features[51] = actual_sink_count / sanitizer_count.max(1.0);
        features[52] = (if sanitizer_count > 0.0 {
            validated_paths_count
        } else {
            0.0
        }) / validated_paths_count.max(1.0);
        features[53] = validated_paths_count / (cfg.nodes.len() as f32).max(1.0);
        features[54] = trusted_source_count / actual_source_count.max(1.0);

        FeatureVector(features)
    }
}
