import json, sys, re
sys.stdout.reconfigure(encoding='utf-8')

# Load the source code of BenchmarkTest00022
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        if 'BenchmarkTest00022' in entry.get('code', ''):
            code = entry['code']
            break

# Print non-boilerplate lines
lines = code.splitlines()
for idx, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith('*') or stripped.startswith('/**') or stripped == '':
        continue
    print(f"L{idx+1:2d}: {line}")
