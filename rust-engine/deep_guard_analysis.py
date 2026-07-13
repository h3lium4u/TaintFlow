"""
Deep analysis: For each of the 39 safe CWE-22 benchmarks in the current FP set
with null patterns, identify:
1. What is the actual sink (L78: new FileInputStream(new File(fileName)))
2. What is the tainted flow path: source → intermediate vars → sink
3. Where does the null guard appear relative to the tainted flow
4. Is the null guard on the same var as the tainted var that reaches the sink
"""
import json, sys, re
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8')

NULL_PATTERNS = ['is none', 'is not none', '!= none', '== none', '!= null', '== null']

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


def find_null_guard_match_for_var(code, var_name, target_line_num, window_size=30):
    """Simulate RC356 null guard firing for a given variable at a given line."""
    lines = code.splitlines()
    start = max(0, target_line_num - window_size - 1)
    end = min(target_line_num, len(lines))
    check_lines = lines[start:end]
    
    parts = [var_name]
    if '.' in var_name:
        parts.append(var_name.split('.')[-1])
    
    for line_str in check_lines:
        trimmed = line_str.strip()
        if trimmed.startswith('def ') or trimmed.startswith('class '):
            continue
        is_decl = (
            ('public ' in trimmed or 'private ' in trimmed or 'protected ' in trimmed)
            and ('void' in trimmed or '(' in trimmed or 'class ' in trimmed)
        )
        has_inline = (';' in trimmed or 'if(' in trimmed or 'if ' in trimmed
                      or 'throw ' in trimmed or 'return ' in trimmed)
        if is_decl and not has_inline:
            continue
        
        line = line_str.lower()
        for part in parts:
            if any(p in line for p in NULL_PATTERNS) and has_word(line, part.lower()):
                return True, line_str.strip()
    
    return False, None


def analyze_benchmark(code, cls):
    """
    Fully analyze a CWE-22 benchmark by:
    1. Finding sink line(s)
    2. Tracing what variables are used at the sink
    3. For each variable, checking if null guard fires in window
    4. Checking what variable the null guard is actually on
    """
    lines = code.splitlines()
    
    # SINK PATTERNS - comprehensive
    SINK_PATS = [
        (r'new\s+(?:java\.io\.)?FileInputStream\s*\(', 'FileInputStream'),
        (r'new\s+(?:java\.io\.)?FileOutputStream\s*\(', 'FileOutputStream'),
        (r'new\s+(?:java\.io\.)?FileReader\s*\(', 'FileReader'),
        (r'new\s+(?:java\.io\.)?FileWriter\s*\(', 'FileWriter'),
        (r'new\s+(?:java\.io\.)?File\s*\(', 'new File'),
        (r'Paths\.get\s*\(', 'Paths.get'),
        (r'Path\.of\s*\(', 'Path.of'),
        (r'Files\.\w+\s*\(', 'Files.*'),
        (r'getServletContext\(\)\.getRealPath', 'getRealPath'),
        (r'getResourceAsStream\s*\(', 'getResourceAsStream'),
    ]
    
    sink_lines = []
    for i, line in enumerate(lines):
        for pat, desc in SINK_PATS:
            if re.search(pat, line, re.IGNORECASE):
                sink_lines.append((i + 1, desc, line.strip()))
                break
    
    if not sink_lines:
        return None, 'NO_SINK_FOUND'
    
    sink_line_num, sink_desc, sink_line_content = sink_lines[0]
    
    # Extract variables appearing in the sink line
    # The sink is typically: new File(fileName) or new File(someDir + var)
    # Common variable patterns in sink lines
    vars_in_sink = set()
    
    # Look for variable names (word tokens that are not Java keywords)
    JAVA_KW = {'new', 'null', 'true', 'false', 'this', 'super', 'return', 'throw',
                'java', 'io', 'file', 'for', 'while', 'if', 'else', 'try', 'catch',
                'finally', 'class', 'public', 'private', 'protected', 'static', 'final',
                'import', 'package', 'String', 'int', 'long', 'byte', 'boolean', 'FileInputStream'}
    
    for tok in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', sink_line_content):
        if tok not in JAVA_KW and len(tok) > 1:
            vars_in_sink.add(tok)
    
    # For each variable in the sink, check null guard window
    null_guard_results = {}
    for var in vars_in_sink:
        fired, guard_line = find_null_guard_match_for_var(code, var, sink_line_num)
        if fired:
            null_guard_results[var] = guard_line
    
    # Track taint chain: for each var in sink, is it derived from user input?
    # User input indicators
    INPUT_PATS = [
        r'getParameter', r'getHeader', r'getAttribute', r'getCookies', 
        r'getQueryString', r'getRequestURI', r'getPathInfo', r'nextElement',
        r'URLDecoder',
    ]
    tainted_vars = set()
    for var in vars_in_sink:
        # Check if this var is assigned from user input anywhere in the code
        for pat in INPUT_PATS:
            if re.search(r'\b' + re.escape(var) + r'\b.*' + pat, code) or \
               re.search(pat + r'.*\b' + re.escape(var) + r'\b\s*=', code):
                tainted_vars.add(var)
                break
        # Also check if it's assigned from another tainted var via concatenation
        # (e.g., fileName = TESTFILES_DIR + bar where bar could be param)
        assign_m = re.search(r'\b' + re.escape(var) + r'\b\s*=\s*(.+);', code)
        if assign_m:
            rhs = assign_m.group(1)
            # Does RHS contain any user-input-derived variable?
            for pat in INPUT_PATS:
                if re.search(pat, rhs):
                    tainted_vars.add(var)
                    break
    
    return {
        'sink_line': sink_line_num,
        'sink_desc': sink_desc,
        'sink_content': sink_line_content[:100],
        'vars_in_sink': sorted(vars_in_sink),
        'null_guarded_vars': null_guard_results,  # {var: guard_line}
        'tainted_vars': sorted(tainted_vars),
        'has_null_guard_firing': len(null_guard_results) > 0,
    }, 'OK'


# ─── Load data ────────────────────────────────────────────────────────────────
java_samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        java_samples.append({'class': cls, 'vulnerable': entry['vulnerable'],
                              'cwe': entry.get('cwe', '?'), 'code': entry.get('code', '')})

safe_cwe22 = [s for s in java_samples if not s['vulnerable'] and s['cwe'] == 'CWE-22']

with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_current = json.load(f)
owasp_fps = [x for x in fps_current if x.get('dataset') == 'OWASP']
fp_classes = set()
for x in owasp_fps:
    m = re.search(r'public class (\w+)', x['code'])
    if m:
        fp_classes.add(m.group(1))

candidates = [s for s in safe_cwe22
              if any(p in s['code'].lower() for p in NULL_PATTERNS)
              and s['class'] in fp_classes]

print(f'Analyzing {len(candidates)} candidates...')
print()

# ─── Run analysis ─────────────────────────────────────────────────────────────
results = []
for s in candidates:
    analysis, status = analyze_benchmark(s['code'], s['class'])
    results.append({'class': s['class'], 'status': status, 'analysis': analysis})

# ─── Summary ──────────────────────────────────────────────────────────────────
ok = [r for r in results if r['status'] == 'OK' and r['analysis']]
no_sink = [r for r in results if r['status'] == 'NO_SINK_FOUND' or (r['analysis'] is None)]

print(f'Successfully analyzed: {len(ok)}')
print(f'No sink found: {len(no_sink)}')
print()

# Relationship classification
CATEGORIES = Counter()
detailed_rows = []

for r in ok:
    a = r['analysis']
    cls = r['class']
    
    if not a['null_guarded_vars']:
        CATEGORIES['NULL_GUARD_NOT_FIRING'] += 1
        detailed_rows.append((cls, 'NULL_GUARD_NOT_FIRING', '', '', '', a['sink_desc']))
        continue
    
    for guard_var, guard_line in a['null_guarded_vars'].items():
        # Is this guard var tainted (user-input derived)?
        guard_var_is_tainted = guard_var in a['tainted_vars']
        # Is this guard var the direct sink var?
        guard_var_at_sink = guard_var in a['vars_in_sink']
        
        # What does the guard var represent?
        gv_lower = guard_var.lower()
        if any(k in gv_lower for k in ['cookie', 'header', 'session', 'value', 'enum', 'names']):
            category = 'CONTAINER_VAR'
        elif guard_var_is_tainted and guard_var_at_sink:
            category = 'SAME_AS_SINK_VAR'
        elif guard_var_is_tainted:
            category = 'TAINTED_BUT_NOT_AT_SINK'
        else:
            category = 'NON_TAINTED_VAR'
        
        CATEGORIES[category] += 1
        guard_short = (guard_line or '')[:60]
        detailed_rows.append((cls, category, guard_var, str(a['tainted_vars']), 
                               str(a['vars_in_sink']), guard_short))

print('=== CATEGORY BREAKDOWN ===')
for cat, count in sorted(CATEGORIES.items(), key=lambda x: -x[1]):
    print(f'  {cat:<35}: {count}')

print()
print(f'{"Benchmark":<30} {"Category":<30} {"Guard Var":<15} {"Tainted Vars":<20} Guard Line')
print('-' * 120)
for cls, cat, gvar, tvars, svars, gline in sorted(detailed_rows):
    print(f'{cls:<30} {cat:<30} {gvar:<15} {tvars:<20} {gline}')

# Show the no_sink cases - what do they look like?
print(f'\n=== NO SINK FOUND (need investigation) ===')
for r in no_sink[:5]:
    print(f'  {r["class"]}')
    lines = next(s['code'] for s in candidates if s['class'] == r['class']).splitlines()
    for i, l in enumerate(lines[25:55], 26):
        if l.strip() and not l.strip().startswith('*'):
            print(f'    L{i}: {l.strip()[:100]}')
    print()
