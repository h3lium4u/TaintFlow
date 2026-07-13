import json, re, sys
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8')

# Reconstruct all 58 new FPs precisely by loading current FPs and matching them with the dataset.
# The 58 new FPs are those present in RC357/RC358 FP set (417) but not present in RC356 (359).
# Since we don't have the full RC356 FP list file, we know that in RC357 we changed contains_is_none to false.
# So a benchmark is a new FP if and only if:
# 1. It is a safe (TN expected) sample.
# 2. It has a flow under RC357 (which means it's in our current 417 FPs list).
# 3. It had its flow suppressed in RC356 because contains_is_none = true matched a null check on the tainted path or its container.

# Load current FPs
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_latest = json.load(f)
latest_owasp_fps = [x for x in fps_latest if x.get('dataset') == 'OWASP']
latest_fp_classes = set()
for x in latest_owasp_fps:
    m = re.search(r'(?:public class|class)\s+(\w+)', x['code'])
    if m:
        latest_fp_classes.add(m.group(1))

# Load all safe samples from dataset
all_safe_samples = []
for lang, path in [('java', '../benchmarks/benchmark_java.jsonl'), ('python', '../benchmarks/benchmark_python.jsonl')]:
    with open(path, encoding='utf-8') as f:
        for line in f:
            entry = json.loads(line.strip())
            m = re.search(r'(?:public class|class)\s+(\w+)', entry.get('code', ''))
            cls = m.group(1) if m else 'UNKNOWN'
            if not entry['vulnerable']:
                all_safe_samples.append({
                    'class': cls,
                    'code': entry['code'],
                    'language': lang,
                    'cwe': entry.get('cwe', '')
                })

# The 58 new FPs are exactly those safe samples in the current FP set where the null guard fires.
# Let's run the check_guard_in_content simulation using the exact same logic.
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

def find_sink_line_and_tainted_var(code, lang):
    lines = code.splitlines()
    sink_line = 0
    # Common sinks
    if lang == 'java':
        for idx, line in enumerate(lines):
            if any(k in line for k in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
                if 'import' not in line:
                    sink_line = idx + 1
                    break
            # Other CWE sinks
            if any(k in line for k in ['response.addCookie', 'response.sendRedirect', 'response.addHeader', 'setAttribute']):
                sink_line = idx + 1
                break
    else:
        for idx, line in enumerate(lines):
            line_lower = line.lower()
            if any(k in line_lower for k in ['open(', 'os.path', 'pathlib', 'read(', 'write(', 'subprocess', 'eval(', 'exec(']) and not line.strip().startswith('#'):
                sink_line = idx + 1
                break
                
    # Find all potential variable declarations/assignments in the file to test
    # Word regex
    words = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', code)
    candidate_vars = set()
    for w in words:
        if w not in ['String', 'int', 'boolean', 'double', 'float', 'void', 'public', 'private', 'class', 'static', 'null', 'true', 'false', 'import', 'package', 'request', 'response', 'session', 'out', 'System']:
            if len(w) > 2:
                candidate_vars.add(w)
                
    return sink_line, candidate_vars

# Now trace all 58 new FPs
new_fps_list = []

for s in all_safe_samples:
    cls = s['class']
    if cls not in latest_fp_classes:
        continue
    
    code = s['code']
    lang = s['language']
    
    sink_line, candidate_vars = find_sink_line_and_tainted_var(code, lang)
    if sink_line == 0:
        continue
        
    # Check if a null guard would have fired on ANY of the candidate variables in RC356
    fired_any = False
    guard_expr = None
    guard_var = None
    tainted_var = None
    
    for var in candidate_vars:
        # Check if RC356 null guard fires
        fired, line_str = check_guard_in_content_rust_style(code, var, sink_line, lang, check_null=True)
        if fired:
            # Check if RC357 (without null guard) does NOT fire
            fired_357, _ = check_guard_in_content_rust_style(code, var, sink_line, lang, check_null=False)
            if not fired_357:
                fired_any = True
                guard_expr = line_str
                # Parse guard variable name
                m = re.search(r'([a-zA-Z0-9_.]+)\s*(?:!=|==)\s*null', line_str)
                if m:
                    guard_var = m.group(1)
                else:
                    m2 = re.search(r'([a-zA-Z0-9_.]+)\s+is\s+(?:not\s+)?none', line_str.lower())
                    if m2:
                        guard_var = m2.group(1)
                    else:
                        guard_var = var
                tainted_var = var
                break
                
    if fired_any:
        new_fps_list.append({
            'benchmark_id': cls,
            'language': lang,
            'guard_expression': guard_expr,
            'guard_variable': guard_var,
            'tainted_variable': tainted_var,
            'sink_variable': 'bar' if 'bar' in code else 'param',
            'cwe': s['cwe']
        })

print(f"Total new FPs extracted: {len(new_fps_list)}")

# Classification rules:
# 1. Guard Expression matches the tainted variable directly (same variable)
# 2. Guard Variable aliases tainted variable (e.g. param = request.getHeader(...) and guard is request.getHeader(...))
# 3. Guard Variable is container or source object (e.g. cookie array, headers, enumeration)
# 4. Other/unrelated

def classify_fp(fp, code):
    gv = fp['guard_variable'].lower()
    tv = fp['tainted_variable'].lower()
    
    if gv == tv:
        return 'SAME', 'No'
    
    # Check alias / container
    if any(k in gv for k in ['cookie', 'header', 'session', 'enumeration', 'names', 'values']):
        return 'CONTAINER_SOURCE', 'Yes'
        
    if gv in tv or tv in gv:
        return 'ALIAS', 'Yes'
        
    return 'OTHER', 'No'

same_count = 0
alias_count = 0
container_count = 0
other_count = 0

print(f"\n{'Benchmark ID':<25} | {'Guard Expr':<45} | {'Guard Var':<12} | {'Tainted Var':<12} | {'Same':<4} | {'Alias':<5} | {'Container'}")
print("-" * 125)
for fp in sorted(new_fps_list, key=lambda x: x['benchmark_id']):
    code = next(s['code'] for s in all_safe_samples if s['class'] == fp['benchmark_id'])
    category, is_container = classify_fp(fp, code)
    
    same = 'Yes' if category == 'SAME' else 'No'
    alias = 'Yes' if category == 'ALIAS' else 'No'
    container = 'Yes' if category == 'CONTAINER_SOURCE' else 'No'
    
    if category == 'SAME': same_count += 1
    elif category == 'ALIAS': alias_count += 1
    elif category == 'CONTAINER_SOURCE': container_count += 1
    else: other_count += 1
    
    print(f"{fp['benchmark_id']:<25} | {fp['guard_expression'][:45]:<45} | {fp['guard_variable'][:12]:<12} | {fp['tainted_variable'][:12]:<12} | {same:<4} | {alias:<5} | {container}")

print(f"\nExact totals:")
print(f"Total analyzed: {len(new_fps_list)}")
print(f"Guard Variable == Tainted Variable: {same_count}")
print(f"Guard Variable Aliases Tainted Variable: {alias_count}")
print(f"Guard Variable is Container/Source Object: {container_count}")
print(f"Other/Unrelated: {other_count}")
