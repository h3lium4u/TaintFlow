import json, re, sys

with open('rc357_exact_58_divergence.json', encoding='utf-8') as f:
    records = json.load(f)

# Let's inspect each of the 58 benchmarks in detail to see if they have ternary constant assignments or other structures.
# In OWASP, the "safe" templates are typically made safe by:
# 1. Ternary constant mapping (e.g. bar = condition ? constant : param where condition is statically true)
# 2. String manipulation or switch-case mapping (e.g. assigning a constant to bar)
# 3. Whitelist validation (e.g. check against whitelist, but wait, those would be guarded by whitelist guard, not null guard!)
# 
# Let's write a script that does a very thorough regex search for ternary constant mapping on each file.

with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    java_samples = {}
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (BenchmarkTest\d+)', entry.get('code', ''))
        if m:
            java_samples[m.group(1)] = entry['code']

from analyze_semantics_58 import all_58_ids

for bid in sorted(all_58_ids):
    code = java_samples.get(bid)
    if not code:
        continue
    
    # Check for ternary condition
    ternaries = []
    for idx, l in enumerate(code.splitlines(), 1):
        if '?' in l and ':' in l:
            ternaries.append((idx, l.strip()))
            
    # Check if there is any other assignment to bar that overrides param
    bar_overrides = []
    for idx, l in enumerate(code.splitlines(), 1):
        if 'bar =' in l or 'bar=' in l:
            if 'param' not in l and 'request' not in l and 'Cookie' not in l and 'Header' not in l:
                # e.g., bar = "constant";
                bar_overrides.append((idx, l.strip()))
                
    print(f"{bid:<20} | Ternaries: {len(ternaries)} | Bar overrides: {len(bar_overrides)}")
    if ternaries:
        for idx, t in ternaries:
            print(f"  [L{idx}] {t}")
    if bar_overrides:
        for idx, o in bar_overrides:
            print(f"  [L{idx}] OVERRIDE: {o}")
