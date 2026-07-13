import json, re, sys

sys.stdout.reconfigure(encoding='utf-8')

# Load the exact 65 CWE-22 FPs in the latest run (RC357/RC358)
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_latest = json.load(f)
latest_owasp_cwe22_fps = [x for x in fps_latest if x.get('cwe') == 'CWE-22' and x.get('dataset') == 'OWASP']

print(f"Total CWE-22 FPs in latest run: {len(latest_owasp_cwe22_fps)}")

# Java FPs
java_fps = [x for x in latest_owasp_cwe22_fps if x.get('language') == 'java']
# Python FPs
python_fps = [x for x in latest_owasp_cwe22_fps if x.get('language') == 'python']

print(f"Java: {len(java_fps)}, Python: {len(python_fps)}")

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

def check_guard_in_content_rust_style(code, var_name, target_line, lang, check_null):
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
            if check_null:
                if any(p in line for p in NULL_PATTERNS) and has_word(line, part_lower):
                    return True, line_str.strip()
    return False, None

def find_sink_line_and_tainted_var_precise(code, lang):
    lines = code.splitlines()
    sink_line = 0
    sink_var = "fileName"
    
    if lang == 'java':
        for idx, line in enumerate(lines):
            if any(k in line for k in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
                if 'import' not in line:
                    sink_line = idx + 1
                    # Extract variable in sink
                    m = re.search(r'new\s+File\(([^)]+)\)', line)
                    if m:
                        sink_var = m.group(1).strip()
                    break
    else:
        for idx, line in enumerate(lines):
            line_lower = line.lower()
            if any(k in line_lower for k in ['open(', 'os.path', 'pathlib', 'read(', 'write(']) and not line.strip().startswith('#'):
                sink_line = idx + 1
                # Try extract variable
                m = re.search(r'open\(([^,)]+)', line_lower)
                if m:
                    sink_var = m.group(1).strip()
                break
                
    tainted_var = 'param'
    if lang == 'python':
        for line in lines:
            if 'request.get' in line or 'request.args' in line or 'request.form' in line:
                m = re.search(r'(\w+)\s*=', line)
                if m:
                    tainted_var = m.group(1)
                    break
    return sink_line, tainted_var, sink_var

# Check which of the 65 FPs are "new" in RC357 (meaning null guard fired in RC356)
new_fps_list = []
baseline_fps_list = []

for fp in latest_owasp_cwe22_fps:
    code = fp['code']
    lang = fp['language']
    m = re.search(r'(?:public class|class)\s+(\w+)', code)
    cls = m.group(1) if m else 'UNKNOWN'
    
    sink_line, tainted_var, sink_var = find_sink_line_and_tainted_var_precise(code, lang)
    if sink_line == 0:
        continue
        
    # Check if a null guard would have fired on either the container/source variable or the path variable itself in RC356.
    # What are the variables checked for null in the window?
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
        # Extract the variable name in the guard
        m = re.search(r'([a-zA-Z0-9_.]+)\s*(?:!=|==)\s*null', guard_line)
        guard_var = m.group(1) if m else "UNKNOWN"
        if guard_var == "UNKNOWN":
            m2 = re.search(r'([a-zA-Z0-9_.]+)\s+is\s+(?:not\s+)?none', guard_line.lower())
            if m2:
                guard_var = m2.group(1)
                
        # Relationship analysis:
        equals = (guard_var.lower() == tainted_var.lower())
        aliases = False
        is_container = False
        
        gv_lower = guard_var.lower()
        if gv_lower in ['thecookies', 'headers', 'names', 'session']:
            is_container = True
            aliases = False
        elif gv_lower == 'values' or gv_lower == 'querystring':
            is_container = True
            aliases = True
        elif 'getheader' in gv_lower or 'getattribute' in gv_lower:
            is_container = True
            aliases = True
            
        if equals:
            aliases = True
            is_container = False
            
        new_fps_list.append({
            'benchmark_id': cls,
            'language': lang,
            'guard_expression': guard_line,
            'guard_variable': guard_var,
            'tainted_variable': tainted_var,
            'sink_variable': sink_var,
            'equals': equals,
            'aliases': aliases,
            'is_container': is_container
        })
    else:
        baseline_fps_list.append({
            'benchmark_id': cls,
            'language': lang
        })

print(f"Total new FPs identified (null guard fired in RC356): {len(new_fps_list)}")
print(f"Total baseline FPs identified (no null guard fired in RC356): {len(baseline_fps_list)}")

# Print exact totals
same_count = sum(1 for r in new_fps_list if r['equals'])
alias_count = sum(1 for r in new_fps_list if r['aliases'] and not r['equals'])
container_count = sum(1 for r in new_fps_list if r['is_container'])
other_count = sum(1 for r in new_fps_list if not r['aliases'] and not r['is_container'])

print(f"\nExact totals of new FPs by category:")
print(f"Guard Variable == Tainted Variable: {same_count}")
print(f"Guard Variable Aliases Tainted Variable: {alias_count}")
print(f"Guard Variable is Container/Source Object: {container_count}")
print(f"Other/Unrelated: {other_count}")

# Print detail
for r in sorted(new_fps_list, key=lambda x: x['benchmark_id']):
    print(f"{r['benchmark_id']:<20} | Guard: {r['guard_variable']:<15} | Tainted: {r['tainted_variable']:<10} | Same: {str(r['equals']):<5} | Alias: {str(r['aliases']):<5} | Container: {str(r['is_container'])}")
