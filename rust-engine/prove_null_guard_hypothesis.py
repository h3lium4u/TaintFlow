"""
Complete proof of the variable-scope hypothesis.
Fixed: better tainted var extraction and sink line finding for ALL OWASP CWE-22 patterns.
"""

import json, sys, re
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8')

NULL_PATTERNS = ['is none', 'is not none', '!= none', '== none', '!= null', '== null']

def has_word(line_lower, part_lower):
    """Exact replica of Rust has_word() with word-boundary checking."""
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


def find_null_guard_match(code, var_name, target_line_num, window_size=30):
    """Simulate RC356 check_guard_in_content with null guard enabled."""
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
        is_declaration = (
            ('public ' in trimmed or 'private ' in trimmed or 'protected ' in trimmed)
            and ('void' in trimmed or '(' in trimmed or 'class ' in trimmed)
        )
        has_inline = (
            ';' in trimmed or 'if(' in trimmed or 'if ' in trimmed
            or 'throw ' in trimmed or 'return ' in trimmed
        )
        if is_declaration and not has_inline:
            continue
        
        line = line_str.lower()
        for part in parts:
            part_lower = part.lower()
            null_present = any(p in line for p in NULL_PATTERNS)
            if null_present and has_word(line, part_lower):
                return True, line_str.strip()
    return False, None


def extract_guard_variable(guard_line):
    """Extract the exact variable being null-checked."""
    if not guard_line:
        return None
    line = guard_line.strip()
    line_lower = line.lower()
    
    # Match patterns:
    # if (X != null) / if (X == null) 
    # X != null (in compound condition)
    # X is None / X is not None
    
    patterns = [
        r'(\w[\w.]*)\s*!=\s*null',
        r'(\w[\w.]*)\s*==\s*null',
        r'null\s*!=\s*(\w[\w.]*)',
        r'null\s*==\s*(\w[\w.]*)',
        r'(\w[\w.]*)\s*!=\s*none',
        r'(\w[\w.]*)\s*==\s*none',
        r'(\w+)\s+is\s+none',
        r'(\w+)\s+is\s+not\s+none',
    ]
    
    for pattern in patterns:
        m = re.search(pattern, line_lower)
        if m:
            candidate = m.group(1).strip().strip('()')
            if candidate and candidate not in ('null', 'none', 'true', 'false'):
                return candidate
    return 'UNKNOWN'


def classify_relationship(guard_var_lower, tainted_var_lower, code):
    """
    Classify the relationship between guard variable and tainted variable.
    Categories:
    - SAME: identical variable names
    - ALIAS: guard_var is derived from tainted_var or vice versa
    - CONTAINER: guard_var is a source container (array, enumeration, session)
    - METHOD_RESULT: guard_var is result of a getter call
    - OTHER: no clear relationship
    """
    if not guard_var_lower or not tainted_var_lower:
        return 'UNKNOWN'
    
    # Direct match (case-insensitive)
    if guard_var_lower == tainted_var_lower:
        return 'SAME'
    
    # Container keywords: things that hold request data but are not path values
    CONTAINER_KW = [
        'cookie', 'cookies', 'thecookie',
        'header', 'headers', 'theheader',
        'values', 'value', 'enumeration',
        'names', 'name',
        'session',
        'parts', 'tokens',
        'attribute',
    ]
    for kw in CONTAINER_KW:
        if kw in guard_var_lower and guard_var_lower != tainted_var_lower:
            # Make sure it's not just the tainted var containing a similar substring
            if kw not in tainted_var_lower:
                return 'CONTAINER'
    
    # Method call result
    if '(' in guard_var_lower or ')' in guard_var_lower:
        return 'METHOD_RESULT'
    
    # Partial alias: guard var appears in tainted var name or vice versa
    if guard_var_lower in tainted_var_lower or tainted_var_lower in guard_var_lower:
        return 'PARTIAL_ALIAS'
    
    return 'OTHER'


def extract_tainted_var_and_sink(code):
    """
    Extract the primary tainted variable and the CWE-22 sink line.
    Handles the full range of OWASP CWE-22 source patterns.
    """
    lines = code.splitlines()
    tainted_var = None
    sink_line_num = 0
    
    # ── Source extraction: try patterns in priority order ────────────────────
    # Priority: the variable that directly gets user input
    source_priority = [
        # Direct getParameter assignment
        (r'(\w+)\s*=\s*request\.getParameter\s*\(', 10),
        # Assigned inside loop/if from source
        (r'(\w+)\s*=\s*.*theCookie\.getValue\s*\(', 9),
        (r'(\w+)\s*=\s*.*URLDecoder\.decode\s*\(', 9),
        (r'(\w+)\s*=\s*.*headers\.nextElement\s*\(', 8),
        (r'(\w+)\s*=\s*.*getHeader\s*\(', 8),
        (r'(\w+)\s*=\s*.*getAttribute\s*\(\s*"', 7),
        (r'(\w+)\s*=\s*.*getQueryString\s*\(', 7),
        (r'(\w+)\s*=\s*.*getRequestURI\s*\(', 7),
        (r'(\w+)\s*=\s*.*getPathInfo\s*\(', 7),
        # Iterator variable that gets assigned the value
        (r'(\w+)\s*=\s*\w+\.nextElement\s*\(', 6),
        # Name-based assignment (e.g., param = name in header loop)
        (r'String\s+param\s*=\s*"noCookieValueSupplied"', -1),  # sentinel default
    ]
    
    best_score = -999
    best_var = None
    
    for pat, score in source_priority:
        m = re.search(pat, code)
        if m:
            if score > best_score:
                if score == -1:
                    # Special case: "noCookieValueSupplied" means param is the var
                    best_var = 'param'
                    best_score = 0
                else:
                    cand = m.group(1)
                    if cand not in ('void', 'static', 'public', 'private', 'class', 'String'):
                        best_var = cand
                        best_score = score
    
    tainted_var = best_var
    
    # Special handling: if we found "String param = empty string", look for what
    # param gets assigned to later (like param = name or similar)
    if tainted_var == 'param':
        # Check if param gets reassigned to a name variable 
        m = re.search(r'param\s*=\s*(\w+)\s*;', code)
        if m and m.group(1) not in ('null', 'param', 'empty'):
            # param is a consolidation point, the var reaching sink is still param
            pass
    
    # ── Sink line extraction ──────────────────────────────────────────────────
    SINK_PATTERNS = [
        r'new\s+File\s*\(',
        r'new\s+FileInputStream\s*\(',
        r'new\s+FileOutputStream\s*\(',
        r'new\s+FileReader\s*\(',
        r'getRealPath\s*\(',
        r'Paths\.get\s*\(',
        r'Path\.of\s*\(',
        r'Files\.newInputStream',
        r'Files\.newOutputStream',
        r'Files\.readAllBytes',
        r'Files\.write',
        r'getResourceAsStream\s*\(',
        r'new\s+FileWriter\s*\(',
        r'getServletContext\(\)\.getRealPath',
    ]
    
    for i, line in enumerate(lines):
        for pat in SINK_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                sink_line_num = i + 1
                break
        if sink_line_num:
            break
    
    return tainted_var, sink_line_num


# ─── Load dataset ─────────────────────────────────────────────────────────────
java_samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        java_samples.append({
            'class': cls, 'vulnerable': entry['vulnerable'],
            'cwe': entry.get('cwe', '?'), 'code': entry.get('code', ''),
        })

safe_cwe22 = [s for s in java_samples if not s['vulnerable'] and s['cwe'] == 'CWE-22']
print(f'Safe CWE-22 Java samples: {len(safe_cwe22)}')

# Load current FP set (RC357/RC358 - identical FP sets)
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_current = json.load(f)
owasp_fps = [x for x in fps_current if x.get('dataset') == 'OWASP']
fp_classes = set()
for x in owasp_fps:
    m = re.search(r'public class (\w+)', x['code'])
    if m:
        fp_classes.add(m.group(1))
print(f'Current FP classes: {len(fp_classes)}')

# ─── Full analysis ────────────────────────────────────────────────────────────
all_results = []
parse_failures = []
no_null = []
not_in_fp = []

for s in safe_cwe22:
    code = s['code']
    cls = s['class']
    code_lower = code.lower()
    
    # Filter: must have null pattern
    has_null = any(p in code_lower for p in NULL_PATTERNS)
    if not has_null:
        no_null.append(cls)
        continue
    
    # Must be in current FP set (i.e., RC357 shows it as FP)
    if cls not in fp_classes:
        not_in_fp.append(cls)
        continue
    
    # Extract tainted var and sink line
    tainted_var, sink_line = extract_tainted_var_and_sink(code)
    
    if not tainted_var or sink_line == 0:
        parse_failures.append({'class': cls, 'tainted': tainted_var, 'sink': sink_line})
        # Even on parse failure, try searching for guard on 'param' as default
        tainted_var = 'param'
        sink_line_fallback = 0
        # find sink line via any pattern
        lines = code.splitlines()
        for i, l in enumerate(lines):
            if re.search(r'new\s+File\s*\(|getRealPath\s*\(|Paths\.get', l, re.IGNORECASE):
                sink_line_fallback = i + 1
                break
        if sink_line_fallback == 0:
            all_results.append({
                'class': cls, 'status': 'TOTAL_PARSE_FAILURE',
                'tainted_var': None, 'sink_line': 0,
                'guard_fired_rc356': False, 'guard_line': None,
                'guard_var': None, 'relationship': 'UNKNOWN',
                'guard_var_lower': None, 'tainted_var_lower': None,
            })
            continue
        sink_line = sink_line_fallback
    
    # Simulate RC356 null guard
    fired, guard_line = find_null_guard_match(code, tainted_var, sink_line)
    
    guard_var = None
    relationship = 'N/A'
    if fired:
        guard_var = extract_guard_variable(guard_line)
        relationship = classify_relationship(
            (guard_var or '').lower(),
            (tainted_var or '').lower(),
            code
        )
    
    all_results.append({
        'class': cls, 'status': 'ANALYZED',
        'tainted_var': tainted_var, 'sink_line': sink_line,
        'guard_fired_rc356': fired,
        'guard_line': guard_line,
        'guard_var': guard_var,
        'relationship': relationship,
        'guard_var_lower': (guard_var or '').lower(),
        'tainted_var_lower': (tainted_var or '').lower(),
    })

# ─── Results ──────────────────────────────────────────────────────────────────
guarded = [r for r in all_results if r['guard_fired_rc356']]
not_guarded = [r for r in all_results if not r['guard_fired_rc356']]
total_failures = [r for r in all_results if r['status'] == 'TOTAL_PARSE_FAILURE']

print(f'\n=== COVERAGE ===')
print(f'Safe CWE-22 Java total:                   {len(safe_cwe22)}')
print(f'  No null pattern (unaffected):            {len(no_null)}')
print(f'  Not in current FP set (still TN in RC357): {len(not_in_fp)}')
print(f'  Analyzed (null + in FP set):              {len(all_results)}')
print(f'    Total parse failures:                   {len(total_failures)}')
print(f'    Null guard fired in RC356:              {len(guarded)}')
print(f'    Null guard NOT fired in RC356:          {len(not_guarded) - len(total_failures)}')

print(f'\n=== RELATIONSHIP BREAKDOWN for guarded benchmarks ===')
rel_counts = Counter(r['relationship'] for r in guarded)
print(f'Total (null guard fired in RC356 = were suppressed): {len(guarded)}')
for rel, count in sorted(rel_counts.items(), key=lambda x: -x[1]):
    print(f'  {rel:<20}: {count:>4} ({count*100//max(len(guarded),1)}%)')

print(f'\n=== DETAILED TABLE (guarded in RC356) ===')
print(f'{"Benchmark":<30} {"Tainted":<12} {"Guard Var":<30} {"Rel":<15} Guard Expression')
print('-' * 110)
for r in sorted(guarded, key=lambda x: x['class']):
    gl = (r['guard_line'] or '')[:55]
    print(f'{r["class"]:<30} {(r["tainted_var"] or "?"):<12} {(r["guard_var"] or "?"):<30} {r["relationship"]:<15} {gl}')

# ─── Quantify the hypothesis ──────────────────────────────────────────────────
print(f'\n=== HYPOTHESIS VERDICT ===')
same_count = rel_counts.get('SAME', 0)
container_count = rel_counts.get('CONTAINER', 0)
alias_count = rel_counts.get('PARTIAL_ALIAS', 0) + rel_counts.get('ALIAS', 0)
other_count = rel_counts.get('OTHER', 0) + rel_counts.get('METHOD_RESULT', 0)
unknown_count = rel_counts.get('UNKNOWN', 0)

print(f'Null guard on SAME variable as tainted var: {same_count}')
print(f'Null guard on CONTAINER variable:           {container_count}')
print(f'Null guard on ALIAS of tainted var:         {alias_count}')
print(f'Null guard on OTHER variable:               {other_count}')
print(f'UNKNOWN/parse failure:                      {unknown_count}')

# Save
with open('rc357_hypothesis_proof.json', 'w', encoding='utf-8') as f:
    json.dump(all_results, f, indent=2)
print(f'\nFull results saved to rc357_hypothesis_proof.json')
print(f'Parse failures detail:')
for pf in parse_failures[:10]:
    print(f'  {pf["class"]}: tainted={pf["tainted"]}, sink_line={pf["sink"]}')
