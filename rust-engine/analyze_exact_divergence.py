import json, sys, re
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8')

# The previous script returned "NULL_GUARD_NOT_FIRING" because of mismatching variables, 
# wrong line window calculation, or case-insensitive string search failures in our python replica.
# Let's fix the logic and print the full code and actual variables at the null check and sink
# for each of the 39 Java safe CWE-22 candidate benchmarks that became FPs in RC357.

java_samples = {}
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (BenchmarkTest\d+)', entry.get('code', ''))
        if m:
            java_samples[m.group(1)] = {
                'vulnerable': entry['vulnerable'],
                'cwe': entry.get('cwe', '?'),
                'code': entry.get('code', '')
            }

# Load current FPs
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_current = json.load(f)
owasp_fps = [x for x in fps_current if x.get('dataset') == 'OWASP']
fp_classes = set()
for x in owasp_fps:
    m = re.search(r'public class (BenchmarkTest\d+)', x['code'])
    if m:
        fp_classes.add(m.group(1))

# Candidates (safe CWE-22 Java benchmarks that are currently FPs)
candidates = [cls for cls, s in java_samples.items() 
              if not s['vulnerable'] and s['cwe'] == 'CWE-22' and cls in fp_classes]

print(f"Total candidate Java benchmarks to analyze: {len(candidates)}")

def analyze_exact_divergence(cls):
    sample = java_samples[cls]
    code = sample['code']
    lines = code.splitlines()
    
    # 1. Find the null guard(s) in the source code
    # We search for null check lines
    null_checks = []
    for idx, line in enumerate(lines):
        line_lower = line.lower()
        if 'null' in line_lower and ('==' in line_lower or '!=' in line_lower or 'if' in line_lower):
            null_checks.append((idx + 1, line.strip()))
            
    # 2. Find the sink line
    sink_line = None
    sink_var = None
    for idx, line in enumerate(lines):
        if any(kw in line for kw in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
            if 'import' not in line:
                sink_line = idx + 1
                # Try to find what variable is passed into the sink constructor
                m = re.search(r'new\s+(?:java\.io\.)?File(?:InputStream|OutputStream|Reader|Writer)?\(\s*(?:new\s+(?:java\.io\.)?File\(\s*)?([a-zA-Z0-9_]+)\s*\)?\s*\)', line)
                if m:
                    sink_var = m.group(1)
                else:
                    m2 = re.search(r'\((?:new\s+File\()?\s*([a-zA-Z0-9_]+)\s*\)?\)', line)
                    if m2:
                        sink_var = m2.group(1)
                break
                
    # 3. Find the tainted variable name at the null guard point.
    # In most of these tests:
    # String param = ...
    # if (theCookies != null) { ... param = theCookie.getValue() } or similar.
    # Let's inspect the lines around null checks to see the guard variable and the tainted variable.
    guard_expr = "N/A"
    guard_var = "N/A"
    tainted_var_at_guard = "param" # Default for these templates
    
    if null_checks:
        line_num, guard_expr = null_checks[0]
        # Extract variable in null check
        # e.g., if (theCookies != null) -> theCookies
        m = re.search(r'if\s*\(\s*([a-zA-Z0-9_]+)\s*(?:!=|==)', guard_expr)
        if m:
            guard_var = m.group(1)
        else:
            # check request.getHeader(...) != null
            if 'getheader' in guard_expr.lower():
                guard_var = 'request.getHeader(...)'
            elif 'getattribute' in guard_expr.lower():
                guard_var = 'session.getAttribute(...)'
                
    # Let's trace if the guard variable equals the tainted variable
    equals = (guard_var == tainted_var_at_guard)
    
    # Let's determine if they alias
    # If guard_var is theCookies and tainted_var is param, do they alias? No.
    # If guard_var is request.getHeader(...) and param is assigned from it, they alias or are the same.
    # Let's write a heuristic classification based on known OWASP templates.
    is_container = False
    aliases = False
    
    if guard_var in ['theCookies', 'headers', 'names', 'values']:
        is_container = True
        aliases = False
    elif 'getHeader' in guard_var or 'getAttribute' in guard_var:
        is_container = True
        aliases = True # It is the source of the tainted var
        
    if equals:
        aliases = True
        
    return {
        'benchmark_id': cls,
        'guard_expression': guard_expr,
        'guard_variable': guard_var,
        'tainted_variable': tainted_var_at_guard,
        'sink_variable': sink_var or "fileName",
        'equals': equals,
        'aliases': aliases,
        'is_container': is_container
    }

results = []
for cls in sorted(candidates):
    results.append(analyze_exact_divergence(cls))

print(json.dumps(results[:15], indent=2))

# Write detailed breakdown stats
same_count = sum(1 for r in results if r['equals'])
alias_count = sum(1 for r in results if r['aliases'] and not r['equals'])
container_count = sum(1 for r in results if r['is_container'])
other_count = sum(1 for r in results if not r['aliases'] and not r['is_container'])

print(f"\nExact totals:")
print(f"Total analyzed: {len(results)}")
print(f"Guard Variable == Tainted Variable: {same_count}")
print(f"Guard Variable Aliases Tainted Variable: {alias_count}")
print(f"Guard Variable is Container/Source Object: {container_count}")
print(f"Other/Unrelated: {other_count}")

# Save full results
with open('exact_divergence_results.json', 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2)
