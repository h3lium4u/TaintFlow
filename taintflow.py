import sys
import os
import json
import subprocess
import pickle
import numpy as np
import time
import re

# Paths to Rust CLI binary and models
CLI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rust-engine", "target", "release", "taintflow-cli.exe")
MODEL_PKL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_v11.pkl")
MODEL_ONNX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_v11.onnx")

# Fallback paths (model_rc4)
if not os.path.exists(MODEL_PKL_PATH):
    MODEL_PKL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_rc4.pkl")
if not os.path.exists(MODEL_ONNX_PATH):
    MODEL_ONNX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_rc4.onnx")

# Keyword definitions from rule engine
SOURCE_KWS = ["request.args", "request.form", "request.json", "request.cookies", "request.headers",
              "getparameter", "getheader", "getcookies", "getquerystring", "nextline", "readline",
              "input(", "sys.argv", "os.environ", "os.getenv", "system.getenv",
              "request.get", "request.post", "request.meta", "request.body",
              "query(", "body(", "path(", "cookie(", "header(",
              "session.query", "objects.all", "objects.filter",
              "@modelattribute", "@sessionattribute", "@cookievalue",
              "session.get(", "session.load(", "session.createquery",
              "readvalue(", "readtree(", "objectmapper",
              "fromjson(", "gson.fromjson", "jdbctemplate"]

SINK_KWS = ["execute", "query", "preparestatement", "preparedstatement",
            "run", "popen", "system", "subprocess", "exec",
            "open", "fileinputstream", "fileoutputstream", "filechannel",
            "readobject", "loads", "deserialize",
            "urlopen", "get", "post", "openconnection", "openstream",
            "setheader", "addheader", "addcookie", "sendredirect",
            "setcontenttype", "setcharacterencoding",
            "write", "print", "println", "getwriter"]

SANITIZER_KWS = ["strip", "escape", "sanitize", "encode", "replace", "clean"]

class CodeAnalyzer:
    def __init__(self, code, language):
        self.code = code
        self.language = language.lower()
        self.lines = code.splitlines()
        self.functions = {}  # name -> {params: [], body: [], calls: []}
        self.parse_functions()

    def parse_functions(self):
        if self.language == "python":
            current_func = None
            func_indent = 0
            for line in self.lines:
                stripped = line.strip()
                if not stripped: continue
                match = re.match(r'^( *)\bdef\s+(\w+)\s*\(([^)]*)\):', line)
                if match:
                    indent = len(match.group(1))
                    name = match.group(2)
                    params = [p.strip().split(':')[0].split('=')[0].strip() for p in match.group(3).split(',') if p.strip()]
                    current_func = name
                    func_indent = indent
                    self.functions[name] = {"params": params, "body": [], "calls": []}
                elif current_func:
                    lead_spaces = len(line) - len(line.lstrip())
                    if lead_spaces > func_indent or not stripped:
                        self.functions[current_func]["body"].append(line)
                    else:
                        current_func = None
        else:  # Java
            for idx, line in enumerate(self.lines):
                match = re.search(r'\b(public|private|protected|static|\s) +([\w\d<>\?\[\]]+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w\d,\s]+)?\s*\{', line)
                if match:
                    name = match.group(3)
                    if name in ["if", "for", "while", "switch", "catch"]: continue
                    raw_params = match.group(4)
                    params = []
                    for p in raw_params.split(','):
                        p = p.strip()
                        if p:
                            parts = p.split()
                            if parts:
                                params.append(parts[-1])
                    body = []
                    brace_count = 1
                    for sub_line in self.lines[idx+1:]:
                        body.append(sub_line)
                        brace_count += sub_line.count('{') - sub_line.count('}')
                        if brace_count <= 0:
                            break
                    self.functions[name] = {"params": params, "body": body, "calls": []}

        # Resolve function calls
        for func_name, info in self.functions.items():
            body_text = "\n".join(info["body"])
            for other_func in self.functions:
                if other_func != func_name:
                    if re.search(r'\b' + re.escape(other_func) + r'\s*\(', body_text):
                        info["calls"].append(other_func)

def compute_rc5_features(code, language, taint_paths_count):
    analyzer = CodeAnalyzer(code, language)
    
    # 1. Call Chain Depth
    def get_max_call_depth(func, visited, memo):
        if func in memo:
            return memo[func]
        if func in visited:
            return 0
        visited.add(func)
        max_depth = 0
        for child in analyzer.functions.get(func, {}).get("calls", []):
            max_depth = max(max_depth, get_max_call_depth(child, visited, memo) + 1)
        visited.remove(func)
        memo[func] = max_depth
        return max_depth

    memo = {}
    max_call_chain = 0
    for func in analyzer.functions:
        max_call_chain = max(max_call_chain, get_max_call_depth(func, set(), memo))

    # 2. Distances
    sources_lines = []
    sinks_lines = []
    sanitizers_lines = []

    for idx, line in enumerate(analyzer.lines):
        line_lower = line.lower()
        if any(s in line_lower for s in SOURCE_KWS):
            sources_lines.append(idx)
        if any(s in line_lower for s in SINK_KWS):
            sinks_lines.append(idx)
        if any(s in line_lower for s in SANITIZER_KWS):
            sanitizers_lines.append(idx)

    sink_reachable_dist = 99999.0
    if sources_lines and sinks_lines:
        for src in sources_lines:
            for snk in sinks_lines:
                dist = abs(snk - src)
                if dist < sink_reachable_dist:
                    sink_reachable_dist = float(dist)

    sanitizer_dist = 99999.0
    if sanitizers_lines and sinks_lines:
        for san in sanitizers_lines:
            for snk in sinks_lines:
                dist = abs(snk - san)
                if dist < sanitizer_dist:
                    sanitizer_dist = float(dist)

    # 3. Taint Assignments
    multi_hop_count = 0
    cross_func_depth = 0

    if taint_paths_count > 0:
        current_tainted = set()
        for line in analyzer.lines:
            line_lower = line.lower()
            if any(s in line_lower for s in SOURCE_KWS):
                parts = line.split('=')
                if len(parts) > 1:
                    lhs_parts = parts[0].strip().split()
                    if lhs_parts:
                        lhs_var = lhs_parts[-1].strip()
                        current_tainted.add(lhs_var)
                        multi_hop_count += 1
            elif '=' in line:
                parts = line.split('=')
                lhs = parts[0].strip().split()
                rhs = parts[1].strip()
                if lhs:
                    lhs_var = lhs[-1].strip()
                    if any(re.search(r'\b' + re.escape(t) + r'\b', rhs) for t in current_tainted):
                        current_tainted.add(lhs_var)
                        multi_hop_count += 1

        for func_name, info in analyzer.functions.items():
            body_text = "\n".join(info["body"])
            for other_func in analyzer.functions:
                if other_func != func_name:
                    for t in current_tainted:
                        if re.search(r'\b' + re.escape(other_func) + r'\s*\([^)]*\b' + re.escape(t) + r'\b', body_text):
                            cross_func_depth += 1
                            break

    if sink_reachable_dist == 99999.0:
        sink_reachable_dist = 0.0
    if sanitizer_dist == 99999.0:
        sanitizer_dist = 0.0

    return {
        "cross_function_taint_depth": float(cross_func_depth),
        "call_chain_depth": float(max_call_chain),
        "sink_reachability_depth": float(sink_reachable_dist),
        "sanitizer_distance": float(sanitizer_dist),
        "multi_hop_taint_count": float(multi_hop_count)
    }


# Recommendation mappings
RECOMMENDATIONS = {
    "CWE-89": "Use parameterized queries, prepared statements, or ORM frameworks instead of raw SQL concatenation.",
    "CWE89": "Use parameterized queries, prepared statements, or ORM frameworks instead of raw SQL concatenation.",
    "CWE-78": "Avoid executing shell commands directly. Use built-in subprocess APIs with argument arrays, and sanitize user input.",
    "CWE78": "Avoid executing shell commands directly. Use built-in subprocess APIs with argument arrays, and sanitize user input.",
    "CWE-22": "Sanitize input paths using canonicalization, check against an allowed list, or restrict file access to specific directories.",
    "CWE22": "Sanitize input paths using canonicalization, check against an allowed list, or restrict file access to specific directories.",
    "CWE-918": "Restrict outgoing requests using an allowed list of domains, validate input URLs, and avoid resolving external IP addresses.",
    "CWE918": "Restrict outgoing requests using an allowed list of domains, validate input URLs, and avoid resolving external IP addresses.",
    "CWE-502": "Avoid untrusted deserialization. Use safer serialization formats like JSON or Protocol Buffers.",
    "CWE502": "Avoid untrusted deserialization. Use safer serialization formats like JSON or Protocol Buffers.",
    "CWE-798": "Remove hardcoded credentials. Load secrets securely from environment variables, vault services, or configuration files.",
    "CWE798": "Remove hardcoded credentials. Load secrets securely from environment variables, vault variables, or vaults.",
    "CWE-327": "Replace weak cryptographic algorithms (MD5/SHA1/RC4/DES) with secure standards like SHA-256, AES-GCM, or bcrypt.",
    "CWE327": "Replace weak cryptographic algorithms (MD5/SHA1/RC4/DES) with secure standards like SHA-256, AES-GCM, or bcrypt."
}

def load_model():
    """
    Loads the ML model (RC7 CatBoost) from Pickle plus config.
    Returns a dict with model, config, feature list, and threshold.
    """
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_v11_config.json")
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as cf:
                config = json.load(cf)
        except Exception:
            pass

    # Pickle (RC7 model stored as dict {model, config})
    if os.path.exists(MODEL_PKL_PATH):
        try:
            with open(MODEL_PKL_PATH, "rb") as f:
                payload = pickle.load(f)
            if isinstance(payload, dict) and "model" in payload:
                model = payload["model"]
                cfg = payload.get("config", config)
            else:
                model = payload
                cfg = config
            return {
                "type": "PICKLE",
                "model": model,
                "features": cfg.get("features", []),
                "threshold": float(cfg.get("threshold", 0.5)),
            }
        except Exception:
            pass

    return None

def analyze_file(file_path, model_info=None):
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        return {"error": f"Failed to read file: {e}"}

    # Run Rust CLI
    try:
        res = subprocess.run(
            [CLI_PATH, "--extract"],
            input=code,
            text=True,
            capture_output=True,
            shell=False,
            encoding="utf-8"
        )
        if res.returncode != 0:
            return {"error": f"CLI extraction failed: {res.stderr}"}
        
        output_data = json.loads(res.stdout)
    except Exception as e:
        return {"error": f"CLI execution failed: {e}"}

    findings = output_data.get("findings", [])
    features = output_data.get("features", [0.0] * 55)

    # 1. Build RC7 62-feature vector (matches train_rc7.py exactly)
    f = [float(x) for x in features]  # all 55 raw CLI features
    language = "java" if file_path.lower().endswith(".java") else "python"

    # Binary indicators
    has_src  = 1.0 if f[0] > 0 else 0.0
    has_sink = 1.0 if f[1] > 0 else 0.0
    has_taint = 1.0 if f[2] > 0 else 0.0
    has_san  = 1.0 if f[5] > 0 else 0.0

    # Ratios
    src_to_sink   = f[0] / max(1.0, f[1])
    san_to_src    = f[5] / max(1.0, f[0])
    find_density  = f[48] / max(1.0, f[24])

    # RC5 inter-procedural
    raw_taint_paths = f[2]
    rc5 = compute_rc5_features(code, language, raw_taint_paths)
    cross_func = min(1.0 if rc5["cross_function_taint_depth"] > 2 else rc5["cross_function_taint_depth"], 1.0)
    call_chain = rc5["call_chain_depth"]
    sink_dist  = min(rc5["sink_reachability_depth"], 200.0)
    san_dist   = min(rc5["sanitizer_distance"], 200.0)
    multi_hop  = rc5["multi_hop_taint_count"]

    # Log transforms
    log_src  = np.log1p(f[0])
    log_sink = np.log1p(f[1])
    log_sym  = np.log1p(f[24])
    log_find = np.log1p(f[48])

    # Assemble all 55 raw + engineered features in same order as training
    # Dropped during training: raw_28, raw_31, raw_36, raw_37, raw_38, raw_39, raw_40
    # + has_findings and taint_to_src_ratio and log_taint and cwe_diversity (also dropped)
    # We build the full feature dict keyed by name then select config features.
    feat_dict = {f"raw_{i}": f[i] for i in range(55)}
    total_symbols = max(100.0, float(f[24]))
    feat_dict.update({
        "has_sources": has_src, "has_sinks": has_sink, "has_taint": has_taint,
        "has_sanitizers": has_san, "has_findings": 1.0 if f[48] > 0 else 0.0,
        "src_to_sink_ratio": src_to_sink, "san_to_src_ratio": san_to_src,
        "find_density": find_density, "taint_to_src_ratio": f[2] / max(1.0, f[0]),
        "cross_func_depth": cross_func, "call_chain_depth": call_chain,
        "sink_reach_dist": sink_dist, "sanitizer_dist": san_dist, "multi_hop_count": multi_hop,
        "log_src": log_src, "log_sink": log_sink, "log_taint": np.log1p(f[2]),
        "log_symbols": log_sym, "log_findings": log_find, "cwe_diversity": f[49],
        
        # V11 Features
        "taint_paths_norm": f[2] / total_symbols,
        "sources_norm": f[0] / total_symbols,
        "sinks_norm": f[1] / total_symbols,
        "sanitizers_norm": f[5] / total_symbols,
        "findings_norm": f[48] / total_symbols,
        "CWE_matches_norm": f[49] / total_symbols,
        "cross_function_taint_depth_norm": rc5["cross_function_taint_depth"] / total_symbols,
        "call_chain_depth_norm": rc5["call_chain_depth"] / total_symbols,
        "sink_reachability_depth_norm": rc5["sink_reachability_depth"] / total_symbols,
        "sanitizer_distance_norm": rc5["sanitizer_distance"] / total_symbols,
        "multi_hop_taint_count_norm": rc5["multi_hop_taint_count"] / total_symbols,
        "sanitizer_coverage_ratio": float(f[50]),
        "sink_to_sanitizer_ratio": float(f[51]),
        "taint_termination_rate": float(f[52]),
        "validated_path_density": float(f[53]),
        "trusted_source_ratio": float(f[54])
    })

    # Select only the features the trained model expects (from config)
    model_features = model_info.get("features", []) if model_info else []
    if model_features:
        row = [feat_dict.get(name, 0.0) for name in model_features]
    else:
        # Fallback: use the 62-feature ordering from RC7
        row = list(feat_dict.values())

    X_input = np.array([row], dtype=np.float32)

    # 2. Run Inference
    probability = 0.5
    prediction = "UNKNOWN"
    threshold = model_info.get("threshold", 0.5) if model_info else 0.5

    if model_info is not None:
        try:
            if model_info["type"] == "PICKLE":
                probs = model_info["model"].predict_proba(X_input)
                probability = float(probs[0, 1])

            # RC8 Taint-Gated Inference
            # If the Rust CLI reports zero taint paths AND zero findings,
            # the file is structurally safe — cap probability at 0.45.
            # We also cap to (threshold - 0.001) so the gate is always
            # effective regardless of the active decision threshold.
            raw_taint_paths_val = float(features[2]) if len(features) > 2 else 0.0
            raw_findings_val = float(f[48]) if len(f) > 48 else 0.0
            if raw_taint_paths_val == 0 and raw_findings_val == 0:
                gate_cap = min(0.45, threshold - 0.001)
                probability = min(probability, gate_cap)

            prediction = "VULNERABLE" if probability >= threshold else "SAFE"
        except Exception:
            pass

    risk_score = round(probability * 100.0, 1)

    mapped_findings = []
    for f in findings:
        cwe = f.get("cwe", "CWE-Other")
        
        # Calculate confidence
        has_taint_path = features[2] > 0.0
        if cwe in ["CWE-89", "CWE89", "CWE-78", "CWE78", "CWE-22", "CWE22", "CWE-918", "CWE918", "CWE-502", "CWE502"]:
            confidence = 0.92 if has_taint_path else 0.65
        elif cwe in ["CWE-798", "CWE798"]:
            confidence = 0.88
        elif cwe in ["CWE-327", "CWE327"]:
            confidence = 0.80
        else:
            confidence = 0.70

        # Standardize CWE names
        cwe_display = cwe
        if not cwe.startswith("CWE-"):
            if cwe.startswith("CWE"):
                cwe_display = f"CWE-{cwe[3:]}"
            else:
                cwe_display = f"CWE-{cwe}"

        mapped_findings.append({
            "cwe": cwe_display,
            "severity": f.get("severity", "MEDIUM"),
            "confidence": round(confidence, 2),
            "file": os.path.basename(file_path),
            "line": f.get("line_number", 1),
            "description": f.get("description", ""),
            "recommendation": RECOMMENDATIONS.get(cwe, "Follow language-specific secure coding standards.")
        })
        
    return {
        "risk_score": risk_score,
        "probability": round(probability, 4),
        "prediction": prediction,
        "findings": mapped_findings
    }

def scan_directory(dir_path, model_info=None):
    all_findings = []
    max_risk = 0.0
    max_prob = 0.5
    vulnerable_any = False
    
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith((".py", ".java")):
                path = os.path.join(root, file)
                res = analyze_file(path, model_info)
                if "error" not in res:
                    all_findings.extend(res["findings"])
                    max_risk = max(max_risk, res["risk_score"])
                    max_prob = max(max_prob, res["probability"])
                    if res["prediction"] == "VULNERABLE":
                        vulnerable_any = True
                        
    return {
        "risk_score": max_risk,
        "probability": max_prob,
        "prediction": "VULNERABLE" if vulnerable_any else "SAFE",
        "findings": all_findings
    }

def print_human_readable(result):
    findings = result.get("findings", [])
    print(f"================================================================================")
    print(f"TaintFlow RC4 Flagship Scanner Report")
    print(f"ML Scan Prediction: {result['prediction']} | Risk Score: {result['risk_score']}/100 (Prob: {result['probability']:.4f})")
    print(f"================================================================================")
    
    if not findings:
        print("No vulnerabilities found! Clean scan.")
        return

    print(f"Found {len(findings)} issues:\n")
    for idx, f in enumerate(findings, 1):
        print(f"[{idx}] {f['severity']} - {f['cwe']} (Confidence: {f['confidence']:.2f})")
        print(f"File: {f['file']}:{f['line']}")
        print(f"Description: {f['description']}")
        print(f"Recommendation: {f['recommendation']}")
        print("-" * 80)

def generate_html_report(result, output_path="taintflow-report.html"):
    findings = result.get("findings", [])
    total = len(findings)
    critical = sum(1 for f in findings if f["severity"].upper() == "CRITICAL")
    high = sum(1 for f in findings if f["severity"].upper() == "HIGH")
    medium = sum(1 for f in findings if f["severity"].upper() == "MEDIUM")
    low = sum(1 for f in findings if f["severity"].upper() == "LOW")

    rows_html = ""
    for idx, f in enumerate(findings, 1):
        sev_class = f["severity"].lower()
        rows_html += f"""
        <tr class="finding-row">
            <td><span class="badge badge-{sev_class}">{f['severity']}</span></td>
            <td><strong>{f['cwe']}</strong></td>
            <td><code>{f['file']}:{f['line']}</code></td>
            <td>{f['description']}</td>
            <td><span class="confidence-val">{int(f['confidence'] * 100)}%</span></td>
            <td><div class="rec-box">{f['recommendation']}</div></td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TaintFlow RC4 Security Scan Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --primary: #6366f1;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --success: #10b981;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(16, 185, 129, 0.1) 0px, transparent 50%);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2.5rem;
            line-height: 1.5;
        }}

        header {{
            margin-bottom: 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        h1 {{
            font-size: 2.25rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #818cf8, #34d399);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .subtitle {{
            color: var(--text-secondary);
            margin-top: 0.25rem;
            font-size: 0.95rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.5rem;
        }}

        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px -10px rgba(99, 102, 241, 0.2);
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            margin-top: 0.5rem;
            color: var(--text-primary);
        }}

        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            backdrop-filter: blur(12px);
            margin-bottom: 2rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            background: rgba(15, 23, 42, 0.6);
            padding: 1rem 1.25rem;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            padding: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
            font-size: 0.9rem;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        .finding-row {{
            transition: background-color 0.15s;
        }}

        .finding-row:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.15); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.15); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.3); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.15); color: var(--low); border: 1px solid rgba(59, 130, 246, 0.3); }}

        code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            color: #f472b6;
            font-size: 0.85rem;
        }}

        .rec-box {{
            background: rgba(99, 102, 241, 0.05);
            border-left: 3px solid var(--primary);
            padding: 0.5rem 0.75rem;
            border-radius: 0 6px 6px 0;
            font-size: 0.85rem;
            color: #cbd5e1;
        }}

        .confidence-val {{
            font-weight: 600;
            color: var(--success);
        }}

        footer {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.8rem;
            margin-top: 3rem;
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>TaintFlow RC4 Scanner</h1>
            <p class="subtitle">Security Static Analysis & Deep ML Vulnerability Scan Report</p>
        </div>
        <div style="text-align: right">
            <p style="font-weight: 600; font-size: 0.95rem">Engine Status: <span style="color: var(--success)">ACTIVE</span></p>
            <p style="color: var(--text-secondary); font-size: 0.8rem">June 11, 2026</p>
        </div>
    </header>

    <div class="stats-grid">
        <div class="stat-card" style="border-left: 4px solid var(--primary)">
            <div class="stat-label">ML Risk Score</div>
            <div class="stat-value" style="color: { 'var(--critical)' if result['prediction'] == 'VULNERABLE' else 'var(--success)' }">{result['risk_score']}% ({result['prediction']})</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Total Issues</div>
            <div class="stat-value">{total}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--critical)">
            <div class="stat-label">Critical</div>
            <div class="stat-value" style="color: var(--critical)">{critical}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--high)">
            <div class="stat-label">High</div>
            <div class="stat-value" style="color: var(--high)">{high}</div>
        </div>
        <div class="stat-card" style="border-left: 4px solid var(--medium)">
            <div class="stat-label">Medium</div>
            <div class="stat-value" style="color: var(--medium)">{medium}</div>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 10%">Severity</th>
                    <th style="width: 12%">CWE</th>
                    <th style="width: 15%">Location</th>
                    <th style="width: 28%">Description</th>
                    <th style="width: 10%">Confidence</th>
                    <th style="width: 25%">Remediation Guidance</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else f'<tr><td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 3rem;">No vulnerabilities found. TaintFlow RC4 Clean Scan.</td></tr>'}
            </tbody>
        </table>
    </div>

    <footer>
        <p>TaintFlow Flagship Security Engine. All rights reserved &copy; 2026.</p>
    </footer>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"Generated beautiful HTML report at {output_path}")

def main():
    if len(sys.argv) < 3 or sys.argv[1] != "scan":
        print("Usage: taintflow scan <file_or_directory> [--json] [--html <output_file>]")
        sys.exit(1)

    target = sys.argv[2]
    as_json = "--json" in sys.argv
    as_html = "--html" in sys.argv

    html_out = "taintflow-report.html"
    if as_html:
        try:
            html_out = sys.argv[sys.argv.index("--html") + 1]
        except Exception:
            pass

    # Load ML model
    model_info = load_model()

    if os.path.isdir(target):
        results = scan_directory(target, model_info)
    else:
        results = analyze_file(target, model_info)
        if "error" in results:
            if as_json:
                print(json.dumps(results))
            else:
                print(f"Error: {results['error']}")
            sys.exit(1)

    if as_json:
        print(json.dumps(results, indent=2))
    elif as_html:
        generate_html_report(results, html_out)
    else:
        print_human_readable(results)

if __name__ == "__main__":
    main()
