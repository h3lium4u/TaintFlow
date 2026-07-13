"""
Definitive RC357 regression analysis.

The single change in RC357 is:
  contains_is_none = false  (was: checks for "is none", "is not none", "!= none", "== none", "!= null", "== null")

Effect: `check_guard_in_content` no longer treats null/None checks on path variables as guards.
This means benchmarks that had null/none checks on the tainted path variable 
previously returned True from `is_path_traversal_guarded` and suppressed the flow.
Now they return False, allowing the flow to proceed to the sink.

For SAFE benchmarks (vulnerable=False), this means:
- Previously: null check on path var -> guarded -> no flow -> TN
- Now: null check on path var -> NOT guarded -> flow found -> FP

We need to find which SAFE OWASP benchmarks contain null/none check patterns
on path-traversal-related variables AND are CWE-22 benchmarks.
These are the 58 new FPs.
"""
import json, sys, re

sys.stdout.reconfigure(encoding='utf-8')

# Load dataset
java_samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        java_samples.append({
            'class': cls,
            'vulnerable': entry['vulnerable'],
            'cwe': entry.get('cwe', '?'),
            'code': entry.get('code', ''),
        })

python_samples = []
with open('../benchmarks/benchmark_python.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        python_samples.append({
            'class': cls,
            'vulnerable': entry['vulnerable'],
            'cwe': entry.get('cwe', '?'),
            'code': entry.get('code', ''),
        })

all_samples = java_samples + python_samples

# Null/none check patterns that were previously recognized as guards
NULL_PATTERNS = [
    'is none', 'is not none', '!= none', '== none',
    '!= null', '== null',
]

def has_null_guard_pattern(code):
    """Check if source contains a null/none check pattern."""
    code_lower = code.lower()
    return any(p in code_lower for p in NULL_PATTERNS)

def get_path_vars(code):
    """Extract likely path-traversal variable names from source."""
    vars_found = set()
    # Common parameter names in CWE-22 tests
    for m in re.finditer(r'(?:String|str|var)\s+(\w+)\s*=.*(?:getParameter|request\.|param)', code):
        vars_found.add(m.group(1))
    # getParameter call assignments
    for m in re.finditer(r'(\w+)\s*=\s*[^;]*getParameter', code):
        vars_found.add(m.group(1))
    return vars_found

# Analyze safe CWE-22 samples
safe_cwe22 = [s for s in all_samples if not s['vulnerable'] and s['cwe'] == 'CWE-22']
safe_cwe22_with_null = [s for s in safe_cwe22 if has_null_guard_pattern(s['code'])]

print(f'Total safe CWE-22 OWASP samples: {len(safe_cwe22)}')
print(f'Safe CWE-22 with null/none patterns: {len(safe_cwe22_with_null)}')

# Also check other CWEs
for cwe in ['CWE-79', 'CWE-89', 'CWE-78', 'CWE-90', 'CWE-113']:
    safe_cwe = [s for s in all_samples if not s['vulnerable'] and s['cwe'] == cwe]
    with_null = [s for s in safe_cwe if has_null_guard_pattern(s['code'])]
    if with_null:
        print(f'Safe {cwe} with null/none: {len(with_null)} out of {len(safe_cwe)}')

print()
print('=== Safe CWE-22 benchmarks with null/none check patterns ===')
print('%-50s %-10s %s' % ('Benchmark', 'CWE', 'Null pattern found'))
print('-' * 100)
for s in sorted(safe_cwe22_with_null, key=lambda x: x['class']):
    # Find which null pattern
    code_lower = s['code'].lower()
    patterns = [p for p in NULL_PATTERNS if p in code_lower]
    print('%-50s %-10s %s' % (s['class'], s['cwe'], ', '.join(patterns[:3])))

# Also examine the code context around null checks
print()
print('=== Code context for first 3 samples ===')
for s in safe_cwe22_with_null[:3]:
    print(f'\n--- {s["class"]} ({s["cwe"]}) ---')
    lines = s['code'].splitlines()
    code_lower = s['code'].lower()
    for i, line in enumerate(lines):
        line_lower = line.lower()
        if any(p in line_lower for p in NULL_PATTERNS):
            start = max(0, i-2)
            end = min(len(lines), i+3)
            print(f'  [L{i+1}] NULL CHECK CONTEXT:')
            for j in range(start, end):
                marker = '>>>' if j == i else '   '
                print(f'  {marker} {lines[j]}')
