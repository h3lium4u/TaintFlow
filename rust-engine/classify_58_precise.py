import json, re, sys

sys.stdout.reconfigure(encoding='utf-8')

# Load dataset
java_samples = {}
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (BenchmarkTest\d+)', entry.get('code', ''))
        if m:
            java_samples[m.group(1)] = entry['code']

from analyze_semantics_58 import all_58_ids

NULL_PATTERNS = ["is none", "is not none", "!= none", "== none", "!= null", "== null"]

classified_records = []

for bid in sorted(all_58_ids):
    code = java_samples.get(bid)
    if not code:
        continue
        
    lines = code.splitlines()
    
    # Identify type of dead-end / override structure
    override_type = "Only Null/Existence Checks"
    exact_code = []
    
    # 1. Ternary Constant Mapping
    # e.g., bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    ternary_lines = []
    for idx, l in enumerate(lines, 1):
        if '?' in l and ':' in l and ('param' in l or 'bar' in l):
            ternary_lines.append((idx, l.strip()))
            
    # 2. List/Collection Safe Override
    # e.g., valuesList.get(1)
    list_lines = []
    for idx, l in enumerate(lines, 1):
        if 'valuesList.get(1)' in l or 'valuesList.get(i)' in l or 'List<' in l:
            if 'bar =' in l or 'bar=' in l or 'get(1)' in l:
                list_lines.append((idx, l.strip()))
                
    # 3. Map Safe Override
    # e.g., map.get("keyA")
    map_lines = []
    for idx, l in enumerate(lines, 1):
        if 'map' in l.lower() and '.get(' in l.lower():
            map_lines.append((idx, l.strip()))
            
    # 4. Constant Overwrite / String Literal Assign
    # e.g. bar = "bob"; bar = "bob's your uncle";
    constant_assign_lines = []
    for idx, l in enumerate(lines, 1):
        if ('bar =' in l or 'bar=' in l) and not any(k in l for k in ['param', 'request', 'Cookie', 'Header', 'valuesList', 'map', 'doSomething', 'append']):
            # Ensure it is assigning a literal string
            if '"' in l:
                constant_assign_lines.append((idx, l.strip()))
                
    # 5. Helper/Reflection Overwrite
    # e.g. thing.doSomething(g12345)
    reflection_lines = []
    for idx, l in enumerate(lines, 1):
        if 'doSomething' in l or 'reflection' in l.lower() or 'thing.do' in l.lower():
            reflection_lines.append((idx, l.strip()))
            
    # 6. If-branch Overwrite (statically true conditional block)
    # e.g. if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    if_override_lines = []
    for idx, l in enumerate(lines, 1):
        if 'if (' in l or 'if(' in l:
            if 'This_should_always_happen' in l or 'This should never happen' in l:
                if_override_lines.append((idx, l.strip()))
                
    # Classify based on collected patterns
    if ternary_lines:
        override_type = "Ternary Constant Mapping"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in ternary_lines]
    elif list_lines:
        override_type = "List/Collection Safe Override"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in list_lines]
    elif map_lines:
        override_type = "Map Safe Override"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in map_lines]
    elif constant_assign_lines:
        override_type = "Constant Overwrite"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in constant_assign_lines]
    elif reflection_lines:
        override_type = "Reflection/Helper Override"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in reflection_lines]
    elif if_override_lines:
        override_type = "If-branch Overwrite"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in if_override_lines]
    else:
        # Check if there is a default fallback or only null check
        null_lines = []
        for idx, l in enumerate(lines, 1):
            if any(p in l.lower() for p in NULL_PATTERNS):
                null_lines.append((idx, l.strip()))
        override_type = "Only Null/Existence Checks"
        exact_code = [f"Line {idx}: {code_line}" for idx, code_line in null_lines[:3]]
        
    classified_records.append({
        'benchmark_id': bid,
        'present': "NO", # Since none of these are *real* path sanitizers like startsWith(base) or getCanonicalPath
        'type': override_type,
        'code': "\n".join(exact_code),
        'would_stop': "YES" if override_type != "Only Null/Existence Checks" else "NO"
    })

# Verify results and print frequency table
from collections import Counter
counts = Counter(r['type'] for r in classified_records)

print("=== FREQUENCY TABLE ===")
for t, count in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"{t:<35} : {count}")

with open('exact_58_semantic_classification.json', 'w', encoding='utf-8') as f:
    json.dump(classified_records, f, indent=2)
