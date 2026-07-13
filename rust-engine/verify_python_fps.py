import json, re, sys
sys.stdout.reconfigure(encoding='utf-8')

# Load latest FPs
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_latest = json.load(f)
latest_owasp_cwe22_fps = [x for x in fps_latest if x.get('cwe') == 'CWE-22' and x.get('dataset') == 'OWASP']

# Load python entry data to make sure we parse properly
python_fps = [x for x in latest_owasp_cwe22_fps if x.get('language') == 'python']
print(f"Total Python CWE-22 FPs in latest: {len(python_fps)}")

NULL_PATTERNS = ["is none", "is not none", "!= none", "== none", "!= null", "== null"]

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

def find_sink_line_and_tainted_var_precise(code, lang):
    lines = code.splitlines()
    sink_line = 0
    sink_var = "fileName"
    
    if lang == 'java':
        for idx, line in enumerate(lines):
            if any(k in line for k in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
                if 'import' not in line:
                    sink_line = idx + 1
                    break
    else:
        # Python sinks
        for idx, line in enumerate(lines):
            line_lower = line.lower()
            if any(k in line_lower for k in ['open(', 'os.path', 'pathlib', 'read(', 'write(']) and not line.strip().startswith('#') and not 'import' in line_lower:
                sink_line = idx + 1
                # Try extract variable
                m = re.search(r'open\(([^,)]+)', line_lower)
                if m:
                    sink_var = m.group(1).strip()
                break
                
    tainted_var = 'param'
    if lang == 'python':
        # In python, the source gets request.args.get() or request.form.get() or request.values.get()
        # Find variable assigned from request
        for line in lines:
            if 'request.' in line or 'get(' in line:
                m = re.search(r'(\w+)\s*=', line)
                if m:
                    tainted_var = m.group(1)
                    break
    return sink_line, tainted_var, sink_var

python_results = []
for fp in python_fps:
    code = fp['code']
    m = re.search(r'class (\w+)|def (\w+)', code)
    cls = m.group(1) or m.group(2) if m else 'UNKNOWN'
    
    sink_line, tainted_var, sink_var = find_sink_line_and_tainted_var_precise(code, 'python')
    if sink_line == 0:
        continue
        
    # Check for null check
    lines = code.splitlines()
    window_start = max(0, sink_line - 31)
    window_lines = lines[window_start:sink_line]
    
    guard_line = None
    for line in window_lines:
        line_lower = line.lower()
        if any(p in line_lower for p in NULL_PATTERNS):
            guard_line = line.strip()
            break
            
    if guard_line:
        # Extract variable in guard
        m = re.search(r'([a-zA-Z0-9_.]+)\s+is\s+(?:not\s+)?none', guard_line.lower())
        guard_var = m.group(1) if m else "UNKNOWN"
        if guard_var == "UNKNOWN":
            m2 = re.search(r'([a-zA-Z0-9_.]+)\s*(?:!=|==)\s*none', guard_line.lower())
            if m2:
                guard_var = m2.group(1)
                
        equals = (guard_var.lower() == tainted_var.lower())
        aliases = equals
        is_container = False
        
        # In python, we don't have Servlet cookies/headers/session structures checked for None in the same way,
        # but let's check.
        if guard_var.lower() in ['cookies', 'headers', 'session']:
            is_container = True
            
        python_results.append({
            'benchmark_id': cls,
            'guard_expression': guard_line,
            'guard_variable': guard_var,
            'tainted_variable': tainted_var,
            'sink_variable': sink_var,
            'equals': equals,
            'aliases': aliases,
            'is_container': is_container
        })

print(f"Total Python new FPs identified (null guard fired): {len(python_results)}")
for r in python_results:
    print(r)
