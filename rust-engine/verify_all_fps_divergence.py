import json, re, sys

sys.stdout.reconfigure(encoding='utf-8')

# Load all 417 FPs from latest run
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_latest = json.load(f)
owasp_fps = [x for x in fps_latest if x.get('dataset') == 'OWASP']

print(f"Total FPs in latest: {len(owasp_fps)}")

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
            # Check file and path sinks
            if any(k in line for k in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
                if 'import' not in line:
                    sink_line = idx + 1
                    # Extract variable in sink
                    m = re.search(r'new\s+File\(([^)]+)\)', line)
                    if m:
                        sink_var = m.group(1).strip()
                    break
            # Also check other sinks like SQL / XSS / etc.
            if any(k in line for k in ['executeQuery', 'executeUpdate', 'execute(', 'getWriter().println', 'getWriter().print', 'response.getWriter']):
                sink_line = idx + 1
                break
    else:
        for idx, line in enumerate(lines):
            line_lower = line.lower()
            if any(k in line_lower for k in ['open(', 'os.path', 'pathlib', 'read(', 'write(']) and not line.strip().startswith('#'):
                sink_line = idx + 1
                break
                
    tainted_var = 'param'
    if lang == 'python':
        for line in lines:
            if 'request.' in line or 'get(' in line:
                m = re.search(r'(\w+)\s*=', line)
                if m:
                    tainted_var = m.group(1)
                    break
    return sink_line, tainted_var, sink_var

new_fps = []

for fp in owasp_fps:
    code = fp['code']
    lang = fp['language']
    m = re.search(r'(?:public class|class)\s+(\w+)', code)
    cls = m.group(1) if m else 'UNKNOWN'
    
    sink_line, tainted_var, sink_var = find_sink_line_and_tainted_var_precise(code, lang)
    if sink_line == 0:
        # Fallback to scanning lines for keywords to find sink line
        lines = code.splitlines()
        for idx, line in enumerate(lines):
            if any(k in line.lower() for k in ['sink', 'file', 'writer', 'sql', 'query', 'run', 'execute']):
                sink_line = idx + 1
                break
                
    if sink_line == 0:
        continue
        
    # Check if a null guard would have fired on this benchmark under RC356
    # Let's check all variables in the window
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
            
        new_fps.append({
            'benchmark_id': cls,
            'language': lang,
            'guard_expression': guard_line,
            'guard_variable': guard_var,
            'tainted_variable': tainted_var,
            'sink_variable': sink_var,
            'equals': equals,
            'aliases': aliases,
            'is_container': is_container,
            'cwe': fp.get('cwe', '')
        })

print(f"Total new FPs identified across all CWEs: {len(new_fps)}")

same_count = sum(1 for r in new_fps if r['equals'])
alias_count = sum(1 for r in new_fps if r['aliases'] and not r['equals'])
container_count = sum(1 for r in new_fps if r['is_container'])
other_count = sum(1 for r in new_fps if not r['aliases'] and not r['is_container'])

print(f"\nExact totals of new FPs by category:")
print(f"Guard Variable == Tainted Variable: {same_count}")
print(f"Guard Variable Aliases Tainted Variable: {alias_count}")
print(f"Guard Variable is Container/Source Object: {container_count}")
print(f"Other/Unrelated: {other_count}")

# Save the final results JSON
with open('final_divergence_results.json', 'w', encoding='utf-8') as f:
    json.dump(new_fps, f, indent=2)
