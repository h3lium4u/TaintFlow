"""
Precise identification: Which of the 165 CWE-22 safe samples
actually had their flow suppressed by the null guard (contains_is_none)?

We know:
- RC356: 359 FPs total
- RC357: 417 FPs total
- Delta: +58 FPs

The null-guard suppression only fires when:
1. The null pattern appears in the same line window as the tainted variable
2. The variable name appears as a word boundary match (has_word check)
3. check_guard_in_content returns True -> postprocess_fact adds CWE22 to sanitized_for
4. -> flow is suppressed

For the 58 newly-FP samples, the null check was previously catching them
as guards. The other 107 safe CWE-22 samples with null patterns still 
remained suppressed (by OTHER guards that still exist).

Let us sample the code of the 58 new FPs to understand what pattern
they use. We need the v2_fps_latest.json (RC357/RC358 FP set, 417 entries)
and compare to what was already FP in RC356.

Since we don't have the RC356 JSON file, we'll approximate:
- Load all 417 current FPs
- Load the 165 safe CWE-22 samples with null patterns  
- Identify which ones are IN the current FP list
"""
import json, sys, re

sys.stdout.reconfigure(encoding='utf-8')

NULL_PATTERNS = ['is none', 'is not none', '!= none', '== none', '!= null', '== null']

def get_class_name(code):
    m = re.search(r'public class (\w+)', code)
    if m: return m.group(1)
    m = re.search(r'class (\w+)', code)
    if m: return m.group(1)
    return 'UNKNOWN'

# Load current FP set (RC357/RC358, identical)
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_current = json.load(f)

owasp_fps = [x for x in fps_current if x.get('dataset') == 'OWASP']
fp_classes = {get_class_name(x['code']): x for x in owasp_fps}
print(f'Current FP set: {len(fp_classes)} unique OWASP benchmarks')

# Load dataset safe CWE-22 samples
java_samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        java_samples.append({'class': cls, 'vulnerable': entry['vulnerable'],
                              'cwe': entry.get('cwe', '?'), 'code': entry.get('code', '')})

python_samples = []
with open('../benchmarks/benchmark_python.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        python_samples.append({'class': cls, 'vulnerable': entry['vulnerable'],
                                'cwe': entry.get('cwe', '?'), 'code': entry.get('code', '')})

all_samples = java_samples + python_samples

# Find safe CWE-22 samples with null patterns that ARE in current FP set
safe_cwe22_null_fp = []
safe_cwe22_null_not_fp = []
for s in all_samples:
    if not s['vulnerable'] and s['cwe'] == 'CWE-22':
        code_lower = s['code'].lower()
        has_null = any(p in code_lower for p in NULL_PATTERNS)
        if has_null:
            in_fp = s['class'] in fp_classes
            if in_fp:
                safe_cwe22_null_fp.append(s)
            else:
                safe_cwe22_null_not_fp.append(s)

print(f'\nSafe CWE-22 with null patterns IN current FP set: {len(safe_cwe22_null_fp)}')
print(f'Safe CWE-22 with null patterns NOT in FP set: {len(safe_cwe22_null_not_fp)}')

# These not-in-FP ones are the ones where null guard is still suppressing
# or where another guard is suppressing

# Analyze what OTHER guards exist in the not-FP ones
GUARD_PATTERNS = {
    'isfile': 'isfile(',
    'isdir': 'isdir(',
    'endswith': '.endswith(',
    'whitelist': 'whitelist',
    'realpath': 'realpath(',
    'abspath': 'abspath(',
    'canonical': 'canonical',
    'startswith_base': 'startswith(',
    'os.path.exists': 'os.path.exists',
    'os.path.isfile': 'os.path.isfile',
    'getcanonicalpath': 'getcanonicalpath',
}

print('\n=== Samples with null but NOT FP (other guard present) ===')
for s in sorted(safe_cwe22_null_not_fp, key=lambda x: x['class'])[:20]:
    code_lower = s['code'].lower()
    other_guards = [name for name, pat in GUARD_PATTERNS.items() if pat in code_lower]
    print(f'  {s["class"]:<45} other guards: {", ".join(other_guards) if other_guards else "NONE"}')

# Now examine the FP samples: what's the structure of the null check?
print('\n=== Sample FP (in current set, safe CWE-22, has null) - code context ===')
for s in sorted(safe_cwe22_null_fp, key=lambda x: x['class'])[:5]:
    print(f'\n--- {s["class"]} ---')
    lines = s['code'].splitlines()
    for i, line in enumerate(lines):
        if any(p in line.lower() for p in NULL_PATTERNS):
            start = max(0, i-3)
            end = min(len(lines), i+4)
            print(f'  Null check at line {i+1}:')
            for j in range(start, end):
                marker = '>>>' if j == i else '   '
                print(f'  {marker} {lines[j]}')
            break

# Summary
print(f'\n=== SUMMARY ===')
print(f'Total safe CWE-22 benchmarks: 238')
print(f'  With null/none patterns: 165')
print(f'    IN current FP set: {len(safe_cwe22_null_fp)}')
print(f'    NOT in FP set (still suppressed): {len(safe_cwe22_null_not_fp)}')
print(f'  Without null patterns: {238 - 165}')
print(f'    IN current FP set: {238 - 165 - len([s for s in all_samples if not s["vulnerable"] and s["cwe"] == "CWE-22" and not any(p in s["code"].lower() for p in NULL_PATTERNS) and s["class"] not in fp_classes])}')
