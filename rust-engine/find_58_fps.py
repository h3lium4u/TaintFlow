import json, re, sys

sys.stdout.reconfigure(encoding='utf-8')

# Replicate the exact guard detection logic of the rust-engine for CWE-22

NULL_PATTERNS = ["is none", "is not none", "!= none", "== none", "!= null", "== null"]

GUARD_PATTERNS = [
    # python / java common guards
    "isfile(", "isdir(", ".endswith(", "whitelist", "realpath(", "abspath(", "normpath(",
    "normalize(", "canonical", "guard", "deny_unsafe_hosts", "safe_build_path",
    "clean_path", "clean_join", "safe_join", "check_path_traversal", "verify",
    # python specific
    "os.path.exists", "os.path.isfile", "os.path.isabs", "os.path.realpath",
    "os.path.abspath", "os.path.commonpath", "os.path.commonprefix",
    ".is_file()", ".is_dir()", ".is_absolute()", ".is_relative_to(",
    # java specific
    "getcanonicalpath", "toabsolutepath", "startswith("
]

def has_word(line_lower, part_lower):
    start = 0
    while True:
        idx = line_lower.find(part_lower, start)
        if idx == -1:
            return False
        before_ok = True
        if idx > 0:
            c = line_lower[idx - 1]
            before_ok = not (c.isalnum() or c in '_$.')
        after_ok = True
        end_idx = idx + len(part_lower)
        if end_idx < len(line_lower):
            c = line_lower[end_idx]
            after_ok = not (c.isalnum() or c in '_$')
        if before_ok and after_ok:
            return True
        start = idx + 1
    return False

def get_tainted_vars_and_sinks(code, lang):
    lines = code.splitlines()
    tainted_vars = set()
    
    # Simple heuristic to extract variable name and sink lines
    # In Java, the tainted var is usually 'param' or 'bar' or 'fileName' or 'fileURI'
    # In Python, it is 'filename' or 'path' or 'temp_path' or 'user_input'
    if lang == 'java':
        var_candidates = ['param', 'bar', 'fileName', 'fileURI']
    else:
        var_candidates = ['filename', 'path', 'temp_path', 'user_input', 'payload', 'val', 'filePath']
        
    # Sinks
    sink_lines = []
    for idx, line in enumerate(lines):
        line_lower = line.lower()
        if lang == 'java':
            if any(k in line for k in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
                if 'import' not in line:
                    sink_lines.append(idx + 1)
        else:
            if any(k in line_lower for k in ['open(', 'os.path', 'pathlib', 'read(', 'write(']) and not line.strip().startswith('#'):
                sink_lines.append(idx + 1)
                
    return var_candidates, sink_lines

def check_guard_in_content_sim(code, var_name, target_line, lang, check_null):
    lines = code.splitlines()
    window_size = 30
    start = max(0, target_line - window_size - 1)
    end = min(target_line, len(lines))
    check_lines = lines[start:end]
    
    parts = [var_name]
    if '.' in var_name:
        parts.append(var_name.split('.')[-1])
        
    for line_str in check_lines:
        trimmed = line_str.strip()
        if trimmed.startswith('def ') or trimmed.startswith('class '):
            continue
        is_declaration = False
        if lang == 'java':
            is_declaration = (('public ' in trimmed or 'private ' in trimmed or 'protected ' in trimmed)
                              and ('void' in trimmed or '(' in trimmed or 'class ' in trimmed))
        
        has_inline = ';' in trimmed or 'if(' in trimmed or 'if ' in trimmed or 'throw ' in trimmed or 'return ' in trimmed
        if is_declaration and not has_inline:
            continue
            
        line = line_str.lower()
        for part in parts:
            part_lower = part.lower()
            
            # Check standard guards
            for g_pat in GUARD_PATTERNS:
                if g_pat in line and has_word(line, part_lower):
                    # Exception cases for startswith/endswith to match rust engine
                    if g_pat == "startswith(" or g_pat == ".endswith(":
                        if not any(k in line for k in ["base", "root", "safe", "allowed", "dir", "path"]):
                            continue
                    return True, line_str.strip(), g_pat
            
            # Check null/None guard if enabled
            if check_null:
                if any(p in line for p in NULL_PATTERNS) and has_word(line, part_lower):
                    return True, line_str.strip(), "null_guard"
                    
    return False, None, None

# Load dataset
all_samples = []
for lang, path in [('java', '../benchmarks/benchmark_java.jsonl'), ('python', '../benchmarks/benchmark_python.jsonl')]:
    with open(path, encoding='utf-8') as f:
        for line in f:
            entry = json.loads(line.strip())
            m = re.search(r'(?:public class|class)\s+(\w+)', entry.get('code', ''))
            cls = m.group(1) if m else 'UNKNOWN'
            if not entry['vulnerable'] and entry.get('cwe', '') == 'CWE-22':
                all_samples.append({
                    'class': cls,
                    'code': entry['code'],
                    'language': lang
                })

print(f"Total safe CWE-22 samples: {len(all_samples)}")

def extract_guard_var(line):
    line_lower = line.lower()
    for p in [r'(\w+)\s*!=\s*null', r'(\w+)\s*==\s*null', r'(\w+)\s+is\s+none', r'(\w+)\s+is\s+not\s+none']:
        m = re.search(p, line_lower)
        if m: return m.group(1)
    if 'getheader' in line_lower: return 'request.getHeader(...)'
    if 'getattribute' in line_lower: return 'session.getAttribute(...)'
    return 'UNKNOWN'

new_fps = []
for s in all_samples:
    code = s['code']
    cls = s['class']
    lang = s['language']
    
    var_candidates, sink_lines = get_tainted_vars_and_sinks(code, lang)
    if not sink_lines:
        continue
        
    sink_line = sink_lines[0]
    
    # Find which candidate var is actually used/tainted near the sink or has a null guard
    # Let's test each candidate
    for var in var_candidates:
        # Does a null guard fire for this var in RC356?
        fired_356, guard_line_356, guard_type_356 = check_guard_in_content_sim(code, var, sink_line, lang, check_null=True)
        # Does a guard fire in RC357?
        fired_357, guard_line_357, guard_type_357 = check_guard_in_content_sim(code, var, sink_line, lang, check_null=False)
        
        # If it was guarded in RC356 but NOT in RC357, then it is one of the 58 new FPs!
        if fired_356 and not fired_357:
            new_fps.append({
                'benchmark_id': cls,
                'language': lang,
                'guard_expression': guard_line_356,
                'guard_variable': extract_guard_var(guard_line_356),
                'tainted_variable': var,
                'sink_variable': var,
                'guard_type': guard_type_356
            })
            break

print(f"Replicated new FPs count: {len(new_fps)}")
for fp in new_fps[:10]:
    print(fp)
