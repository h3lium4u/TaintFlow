import sys
import json
import ast
import re

class TaintState:
    def __init__(self, tainted=False):
        self.tainted = tainted
        self.sanitized_for = []

def is_source(name):
    name_clean = name.replace('"', "").replace('\'', "")
    sources = [
        "request.args", "request.form", "request.json", "request.cookies", "request.headers",
        "request.files", "request.data", "input(", "sys.argv", "os.environ", "os.getenv",
        "request.GET", "request.POST", "request.body", "request.META", "getparameter",
        "getheader", "getcookies", "getquerystring", "nextline", "readline", "system.getenv",
        "@requestparam", "@pathvariable", "@requestbody", "@requestheader"
    ]
    return any(s in name_clean.lower() for s in sources)

def is_sink(name):
    name_clean = name.replace('"', "").replace('\'', "").lower()
    sinks = [
        "execute", "query", "run", "popen", "system", "subprocess", "open", "readobject",
        "loads", "urlopen", "get", "post"
    ]
    return any(s in name_clean for s in sinks)

def map_sink_to_cwe(callee):
    callee_clean = callee.replace('"', "").replace('\'', "").lower()
    if "execute" in callee_clean or "query" in callee_clean:
        return "CWE-89"
    elif "run" in callee_clean or "popen" in callee_clean or "system" in callee_clean:
        return "CWE-78"
    elif "open" in callee_clean or "file" in callee_clean:
        return "CWE-22"
    elif "urlopen" in callee_clean or "get" in callee_clean or "post" in callee_clean:
        return "CWE-918"
    elif "loads" in callee_clean or "readobject" in callee_clean:
        return "CWE-502"
    return None

class PythonCfgNode:
    def __init__(self, node_id, kind):
        self.id = node_id
        self.kind = kind  # 'Entry', 'Exit', 'Statement', 'Branch', 'Loop', 'Try', 'Catch', 'Finally', 'Return'

class PythonCfgEdge:
    def __init__(self, from_id, to_id):
        self.from_id = from_id
        self.to_id = to_id

class PythonCFGBuilder:
    def __init__(self, max_nodes=1000):
        self.nodes = []
        self.edges = []
        self.next_id = 0
        self.max_nodes = max_nodes
        self.exit_id = None
        self.entry_id = None

    def next_node_id(self):
        if len(self.nodes) >= self.max_nodes:
            return None
        nid = self.next_id
        self.next_id += 1
        return nid

    def build(self, tree):
        self.entry_id = self.next_node_id()
        self.nodes.append(PythonCfgNode(self.entry_id, 'Entry'))
        
        self.exit_id = self.next_node_id()
        self.nodes.append(PythonCfgNode(self.exit_id, 'Exit'))
        
        if hasattr(tree, 'body'):
            body_entry = self.build_block(tree.body, self.entry_id, self.exit_id)
            if body_entry is not None:
                self.edges.append(PythonCfgEdge(self.entry_id, body_entry))
        else:
            self.edges.append(PythonCfgEdge(self.entry_id, self.exit_id))
            
        return self

    def build_block(self, ast_nodes, parent_entry, target_exit):
        current_exit = target_exit
        last_entry = None
        for child in reversed(ast_nodes):
            entry = self.build_node(child, parent_entry, current_exit)
            if entry is not None:
                last_entry = entry
                current_exit = entry
        return last_entry

    def build_node(self, node, parent_entry, target_exit):
        if len(self.nodes) >= self.max_nodes:
            return None

        if isinstance(node, ast.If):
            branch_id = self.next_node_id()
            if branch_id is None:
                return None
            self.nodes.append(PythonCfgNode(branch_id, 'Branch'))
            
            cons_entry = self.build_block(node.body, branch_id, target_exit)
            if cons_entry is not None:
                self.edges.append(PythonCfgEdge(branch_id, cons_entry))
            else:
                self.edges.append(PythonCfgEdge(branch_id, target_exit))
                
            if node.orelse:
                alt_entry = self.build_block(node.orelse, branch_id, target_exit)
                if alt_entry is not None:
                    self.edges.append(PythonCfgEdge(branch_id, alt_entry))
                else:
                    self.edges.append(PythonCfgEdge(branch_id, target_exit))
            else:
                self.edges.append(PythonCfgEdge(branch_id, target_exit))
                
            return branch_id
            
        elif isinstance(node, (ast.For, ast.While)):
            loop_id = self.next_node_id()
            if loop_id is None:
                return None
            self.nodes.append(PythonCfgNode(loop_id, 'Loop'))
            self.edges.append(PythonCfgEdge(loop_id, target_exit))
            
            body_entry = self.build_block(node.body, loop_id, loop_id)
            if body_entry is not None:
                self.edges.append(PythonCfgEdge(loop_id, body_entry))
                
            return loop_id
            
        elif isinstance(node, ast.Try):
            try_id = self.next_node_id()
            if try_id is None:
                return None
            self.nodes.append(PythonCfgNode(try_id, 'Try'))
            
            handler_ids = []
            for handler in node.handlers:
                catch_id = self.next_node_id()
                if catch_id is not None:
                    self.nodes.append(PythonCfgNode(catch_id, 'Catch'))
                    handler_ids.append(catch_id)
                    
            finally_id = None
            if node.finalbody:
                finally_id = self.next_node_id()
                if finally_id is not None:
                    self.nodes.append(PythonCfgNode(finally_id, 'Finally'))
                    
            end_exit = finally_id if finally_id is not None else target_exit
            
            body_entry = self.build_block(node.body, try_id, end_exit)
            if body_entry is not None:
                self.edges.append(PythonCfgEdge(try_id, body_entry))
                
            for h_id in handler_ids:
                self.edges.append(PythonCfgEdge(try_id, h_id))
                self.edges.append(PythonCfgEdge(h_id, end_exit))
                
            if finally_id is not None:
                self.edges.append(PythonCfgEdge(finally_id, target_exit))
                if body_entry is None:
                    self.edges.append(PythonCfgEdge(try_id, finally_id))
                    
            return try_id
            
        elif isinstance(node, ast.Return):
            return_id = self.next_node_id()
            if return_id is None:
                return None
            self.nodes.append(PythonCfgNode(return_id, 'Return'))
            self.edges.append(PythonCfgEdge(return_id, self.exit_id))
            return return_id
            
        else:
            node_id = self.next_node_id()
            if node_id is None:
                return None
            self.nodes.append(PythonCfgNode(node_id, 'Statement'))
            self.edges.append(PythonCfgEdge(node_id, target_exit))
            return node_id

def get_shortest_path_py(cfg):
    entry_id = cfg.entry_id
    exit_id = cfg.exit_id
    if entry_id is None or exit_id is None:
        return 0.0
        
    from collections import deque
    queue = deque([entry_id])
    distances = {entry_id: 0}
    
    while queue:
        curr = queue.popleft()
        dist = distances[curr]
        if curr == exit_id:
            return float(dist)
        for edge in cfg.edges:
            if edge.from_id == curr and edge.to_id not in distances:
                distances[edge.to_id] = dist + 1
                queue.append(edge.to_id)
    return 0.0

def get_longest_path_py(cfg):
    entry_id = cfg.entry_id
    exit_id = cfg.exit_id
    if entry_id is None or exit_id is None:
        return 0.0
        
    visited = set()
    steps = [0]
    max_path_found = [1]
    aborted = [False]
    
    def dfs(curr, target):
        steps[0] += 1
        if steps[0] > 5000:
            aborted[0] = True
            return None
        if curr == target:
            path_len = len(visited)
            max_path_found[0] = max(max_path_found[0], path_len)
            return 0
        visited.add(curr)
        max_dist = -1
        for edge in cfg.edges:
            if edge.from_id == curr and edge.to_id not in visited:
                d = dfs(edge.to_id, target)
                if d is not None and d >= 0:
                    max_dist = max(max_dist, d + 1)
        visited.remove(curr)
        return max_dist if max_dist >= 0 else None

    result = dfs(entry_id, exit_id)
    if aborted[0]:
        return float(max_path_found[0])
    return float(result) if result is not None else 0.0

def get_average_path_length_py(cfg):
    entry_id = cfg.entry_id
    exit_id = cfg.exit_id
    if entry_id is None or exit_id is None:
        return 0.0
        
    visited = set()
    total_len = [0]
    path_count = [0]
    steps = [0]
    
    def dfs(curr, target, current_len):
        steps[0] += 1
        if steps[0] > 5000:
            return
        if path_count[0] >= 1000:
            return
        if curr == target:
            total_len[0] += current_len
            path_count[0] += 1
            return
        visited.add(curr)
        for edge in cfg.edges:
            if edge.from_id == curr and edge.to_id not in visited:
                dfs(edge.to_id, target, current_len + 1)
        visited.remove(curr)

    dfs(entry_id, exit_id, 0)
    if path_count[0] > 0:
        return float(total_len[0]) / path_count[0]
    elif steps[0] > 5000:
        return 1.0  # never return 0 on abort
    return 0.0

def get_path_count_py(cfg):
    """Count the number of distinct acyclic paths from entry to exit.
    This is structurally independent from path length (shortest/longest/average)
    because a graph can have many short paths or few long paths.
    Capped at 50 to avoid exponential explosion on highly branched CFGs."""
    entry_id = cfg.entry_id
    exit_id = cfg.exit_id
    if entry_id is None or exit_id is None:
        return 0.0

    visited = set()
    path_count = [0]
    steps = [0]

    def dfs(curr, target):
        steps[0] += 1
        if steps[0] > 5000 or path_count[0] >= 50:
            return
        if curr == target:
            path_count[0] += 1
            return
        visited.add(curr)
        for edge in cfg.edges:
            if edge.from_id == curr and edge.to_id not in visited:
                dfs(edge.to_id, target)
        visited.remove(curr)

    dfs(entry_id, exit_id)
    return float(path_count[0])


class Analyzer(ast.NodeVisitor):
    def __init__(self, code, max_alias_depth=10):
        self.code = code
        self.code_lower = code.lower()
        self.max_alias_depth = max_alias_depth
        self.symbols = [] # list of (name, kind, type_name)
        self.scopes_count = 1
        self.tainted_symbols = {} # name -> TaintState
        self.validated_paths_count = 0
        self.observed_max_alias_depth = 0
        self.alias_transition_count = 0
        self.findings = [] # list of dict(cwe, description)
        self.aliases = {}
        self.cfg = None
        
        # CFG counts
        self.cfg_nodes = 0
        self.cfg_edges = 0
        self.branch_nodes = 0
        self.loop_nodes = 0
        self.exception_nodes = 0
        self.finally_blocks = 0
        self.exit_nodes = 0

    def analyze_python(self):
        try:
            tree = ast.parse(self.code)
            self.visit(tree)
            self.build_cfg_python(tree)
            self.run_rules_and_taint_python(tree)
            return True
        except Exception as e:
            return False

    def build_cfg_python(self, tree):
        self.cfg = PythonCFGBuilder(max_nodes=1000).build(tree)
        self.cfg_nodes = len(self.cfg.nodes)
        self.cfg_edges = len(self.cfg.edges)
        self.branch_nodes = sum(1 for n in self.cfg.nodes if n.kind == 'Branch')
        self.loop_nodes = sum(1 for n in self.cfg.nodes if n.kind == 'Loop')
        self.exception_nodes = sum(1 for n in self.cfg.nodes if n.kind == 'Catch')
        self.finally_blocks = sum(1 for n in self.cfg.nodes if n.kind == 'Finally')
        self.exit_nodes = sum(1 for n in self.cfg.nodes if n.kind == 'Return')

    def run_rules_and_taint_python(self, tree):
        # Pass 1: Build the complete alias map
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = []
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        targets.append(target.id)
                    elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                        targets.append(f"{target.value.id}.{target.attr}")
                if isinstance(node.value, ast.Name):
                    rhs_name = node.value.id
                    for t in targets:
                        self.aliases.setdefault(rhs_name, []).append(t)

        # Pass 2: Propagate taint
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = []
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        targets.append(target.id)
                    elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                        targets.append(f"{target.value.id}.{target.attr}")
                
                # Check rhs for sources or taint
                rhs_raw = ast.unparse(node.value) if hasattr(ast, 'unparse') else ""
                rhs_tainted = False
                if is_source(rhs_raw):
                    rhs_tainted = True
                else:
                    for sub in ast.walk(node.value):
                        if isinstance(sub, ast.Name) and sub.id in self.tainted_symbols:
                            if self.tainted_symbols[sub.id].tainted:
                                rhs_tainted = True
                
                if rhs_tainted:
                    for t in targets:
                        self.tainted_symbols[t] = TaintState(True)
                        self.propagate_aliases(t, 1)

            elif isinstance(node, ast.Call):
                callee_name = ""
                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    callee_name = f"{node.func.value.id}.{node.func.attr}"
                
                callee_lower = callee_name.lower()
                if any(x in callee_lower for x in ["md5", "sha1", "rc4", "des"]):
                    self.findings.append({
                        "cwe": "CWE-327",
                        "description": f"Usage of weak/broken cryptographic signature or method '{callee_name}'."
                    })

                if callee_lower.endswith((".append", ".add", ".put", "extend")):
                    container_var = callee_name.split('.')[0]
                    any_arg_tainted = False
                    for arg in node.args:
                        arg_raw = ast.unparse(arg) if hasattr(ast, 'unparse') else ""
                        if is_source(arg_raw):
                            any_arg_tainted = True
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Name) and sub.id in self.tainted_symbols:
                                if self.tainted_symbols[sub.id].tainted:
                                    any_arg_tainted = True
                    if any_arg_tainted and container_var:
                        self.tainted_symbols[container_var] = TaintState(True)

                if is_sink(callee_name):
                    any_arg_tainted = False
                    for arg in node.args:
                        arg_raw = ast.unparse(arg) if hasattr(ast, 'unparse') else ""
                        if is_source(arg_raw):
                            any_arg_tainted = True
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Name) and sub.id in self.tainted_symbols:
                                if self.tainted_symbols[sub.id].tainted:
                                    any_arg_tainted = True
                    if any_arg_tainted:
                        self.validated_paths_count += 1
                        cwe = map_sink_to_cwe(callee_name)
                        if cwe:
                            self.findings.append({
                                "cwe": cwe,
                                "description": f"Unsanitized flow to sink {callee_name} with tainted arg"
                            })

    def propagate_aliases(self, src_name, depth):
        if depth > self.max_alias_depth:
            return
        self.observed_max_alias_depth = max(self.observed_max_alias_depth, depth)
        
        targets_to_taint = []
        if src_name in self.aliases:
            for alias in self.aliases[src_name]:
                if alias not in self.tainted_symbols or not self.tainted_symbols[alias].tainted:
                    targets_to_taint.append(alias)
                    
        for target in targets_to_taint:
            self.tainted_symbols[target] = TaintState(True)
            self.alias_transition_count += 1
            self.propagate_aliases(target, depth + 1)

    def visit_FunctionDef(self, node):
        self.scopes_count += 1
        for arg in node.args.args:
            self.symbols.append((arg.arg, "Parameter", None))
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.scopes_count += 1
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.symbols.append((alias.name, "Import", None))

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.symbols.append((alias.name, "Import", None))

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                kind = "Field" if target.id.startswith("self.") else "Variable"
                self.symbols.append((target.id, kind, None))
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                fullname = f"{target.value.id}.{target.attr}"
                kind = "Field" if fullname.startswith("self.") else "Variable"
                self.symbols.append((fullname, kind, None))
        self.generic_visit(node)

    def compute_v4_features(self):
        features = [0.0] * 48
        
        # 1. Taint Subsystem (feat_0 to feat_11)
        source_keywords = [
            "request.args", "request.form", "request.json", "request.cookies", "request.headers",
            "getparameter", "getheader", "getcookies", "getquerystring", "nextline", "readline",
            "input(", "sys.argv", "environ", "getenv"
        ]
        actual_source_count = float(sum(self.code_lower.count(s) for s in source_keywords))
        features[0] = actual_source_count

        sink_keywords = [
            "execute", "query", "run", "popen", "system", "subprocess", "open", "readobject",
            "loads", "urlopen", "get", "post"
        ]
        actual_sink_count = float(sum(self.code_lower.count(s) for s in sink_keywords))
        features[1] = actual_sink_count

        features[2] = float(self.validated_paths_count)

        shortest_val = get_shortest_path_py(self.cfg)
        longest_val = get_longest_path_py(self.cfg)
        path_count_val = get_path_count_py(self.cfg)

        # feat_3: distinct taint source category count (how many different input channels are present)
        # Web params/form/JSON, user input, env vars, IO streams -- each is a distinct attack surface
        # Completely independent from CFG structure (feat_4 = longest CFG path)
        src_cats = [
            any(s in self.code_lower for s in ["request.args", "request.form", "request.json", "request.get", "request.post"]),
            any(s in self.code_lower for s in ["input(", "sys.argv", "readline", "stdin"]),
            any(s in self.code_lower for s in ["os.environ", "os.getenv", "environ", "getenv"]),
            any(s in self.code_lower for s in ["request.cookies", "request.headers", "request.files"]),
            any(s in self.code_lower for s in ["request.get", "request.post", "request.body", "request.meta"]),
            any(s in self.code_lower for s in ["getparameter", "getheader", "getcookies", "getquerystring"]),
        ]
        features[3] = float(sum(src_cats))
        # feat_4: DFS longest path length from entry to exit
        features[4] = min(100.0, longest_val)

        sanitizer_kws = ["strip", "escape", "sanitize", "encode", "replace", "clean"]
        sanitizer_count = float(sum(self.code_lower.count(s) for s in sanitizer_kws))
        features[5] = sanitizer_count
        # feat_6: binary indicator of unsanitized taint paths (1 if any path avoids sanitization)
        # Changed from continuous count (validated_paths - sanitizer_count) which was derived
        # nearly linearly from feat_2 (validated_paths_count), causing correlation 0.969
        features[6] = 1.0 if (self.validated_paths_count > 0 and sanitizer_count < self.validated_paths_count) else 0.0

        # feat_7: actual alias transition count
        features[7] = float(self.alias_transition_count)
        
        container_propagation_count = float(self.code_lower.count("append") + self.code_lower.count("add") + self.code_lower.count("put"))
        features[8] = container_propagation_count
        features[9] = float(self.validated_paths_count) / (actual_source_count + 1.0)

        total_symbols_count = float(len(self.symbols))
        features[10] = float(len(self.tainted_symbols)) / (total_symbols_count + 1.0)
        features[11] = float(self.observed_max_alias_depth)

        # 2. CFG Subsystem (feat_12 to feat_23)
        features[12] = min(1000.0, float(self.cfg_nodes))
        
        cyclomatic_complexity = float(self.branch_nodes + self.loop_nodes + self.exception_nodes + 1.0)
        features[13] = min(50.0, cyclomatic_complexity)

        # feat_14/15/16: structural CFG counts — not gated on taint flow
        # feat_15 previously used max(1.0) floor which caused it to always equal 1 when
        # validated_paths>0, perfectly correlating with feat_46. Remove the floor.
        features[14] = float(self.branch_nodes / 2.0) if self.validated_paths_count > 0 else 0.0
        features[15] = float(self.loop_nodes)  # raw loop node count, unconditional
        features[16] = float(self.exception_nodes / 2.0) if self.validated_paths_count > 0 else 0.0

        features[17] = float(self.cfg_edges) / (self.cfg_nodes + 1.0)
        # feat_18: count Return nodes (explicit return statements) instead of Exit nodes
        # The Exit node is always exactly 1 per CFG, making feat_18 effectively constant
        # when CFG parses successfully — causing near-perfect correlation with feat_17
        features[18] = float(sum(1 for n in self.cfg.nodes if n.kind == 'Return'))
        features[19] = 2.0 if self.branch_nodes > 0 else 0.0
        features[20] = 2.0 if self.loop_nodes > 0 else 0.0
        features[21] = float(self.exception_nodes)  # Catch node count
        # feat_22: binary exception handling flag (1 if any try/catch block exists, else 0)
        # Decoupled from feat_21 (raw Catch count): diverges in graphs with multiple handlers
        # where feat_21>1 but feat_22=1.0, and in code without exceptions both are 0
        has_exception = any(n.kind in ('Try', 'Catch') for n in self.cfg.nodes)
        features[22] = 1.0 if has_exception else 0.0
        
        # feat_23: distinct path count from entry to exit (capped at 50)
        # This is structurally independent from path length — a graph can have
        # many short paths or few long paths. Previously avg path length was
        # near-perfectly correlated with longest path (feat_4).
        features[23] = path_count_val

        # 3. Symbol Subsystem (feat_24 to feat_31)
        features[24] = total_symbols_count
        features[25] = float(self.scopes_count)

        features[26] = float(sum(1 for s in self.symbols if s[1] == "Import" and any(k in s[0].lower() for k in sink_keywords)))
        features[27] = float(sum(1 for s in self.symbols if s[1] == "Import" and any(k in s[0].lower() for k in sanitizer_kws)))

        features[28] = float(sum(1 for s in self.symbols if s[1] == "Parameter"))
        features[29] = float(sum(1 for s in self.symbols if s[1] == "Field"))
        features[30] = float(sum(1 for s in self.symbols if s[1] == "Import"))
        features[31] = 1.0 if self.scopes_count > 1 else 0.0

        # 4. Rule Subsystem (feat_32 to feat_47)
        features[32] = 1.0 if len(self.findings) > 0 else 0.0
        features[33] = 1.0 if any("args" in f["description"] or "form" in f["description"] or "json" in f["description"] for f in self.findings) else 0.0
        # feat_34: multi-source taint indicator -- fires when multiple distinct taint sources detected
        # Changed from description keyword 'query'/'execute' which was identical to CWE-89 tag
        # in feat_36, causing correlation 0.972
        features[34] = 1.0 if actual_source_count > 1.0 else 0.0
        features[35] = 1.0 if any("env" in f["description"] or "getenv" in f["description"] for f in self.findings) else 0.0

        features[36] = 1.0 if any(f["cwe"] == "CWE-89" for f in self.findings) else 0.0
        features[37] = 1.0 if any(f["cwe"] == "CWE-78" for f in self.findings) else 0.0
        features[38] = 1.0 if any(f["cwe"] == "CWE-22" for f in self.findings) else 0.0
        features[39] = 1.0 if any(f["cwe"] == "CWE-918" for f in self.findings) else 0.0
        features[40] = 1.0 if any(f["cwe"] == "CWE-502" for f in self.findings) else 0.0
        features[41] = 1.0 if any(f["cwe"] == "CWE-327" for f in self.findings) else 0.0

        features[42] = 1.0 if any(s in self.code_lower for s in ["escape", "sanitize", "replace"]) else 0.0
        features[43] = 1.0 if any(s in self.code_lower for s in ["quote", "escape"]) else 0.0
        features[44] = 1.0 if any(s in self.code_lower for s in ["canonicalize", "abspath", "realpath"]) else 0.0
        features[45] = 1.0 if any(s in self.code_lower for s in ["match", "regex", "re.sub"]) else 0.0

        features[46] = 1.0 if (len(self.findings) > 0 and self.validated_paths_count > 0) else 0.0
        features[47] = 1.0 if (features[13] > 2.0 and any("unsanitized" in f["description"].lower() for f in self.findings)) else 0.0

        return features

def main():
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stdout.reconfigure(encoding='utf-8')
    if len(sys.argv) < 2 or sys.argv[1] != "--extract":
        sys.stderr.write("Usage: taintflow-cli --extract\n")
        sys.exit(1)

    code = sys.stdin.read()
    analyzer = Analyzer(code)
    
    success = analyzer.analyze_python()
    if not success:
        sys.stderr.write("Extraction failed: Python parsing error\n")
        sys.exit(1)

    feats = analyzer.compute_v4_features()
    output = {
        "features": feats
    }
    print(json.dumps(output))

if __name__ == "__main__":
    main()
