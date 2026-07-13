import json, sys, re
sys.stdout.reconfigure(encoding='utf-8')

NULL_PATTERNS = ['is none', 'is not none', '!= none', '== none', '!= null', '== null']

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

# Show ALL lines of BenchmarkTest00063 (remove boilerplate)
s = next(x for x in safe_cwe22 if x['class'] == 'BenchmarkTest00063')
print('=== BenchmarkTest00063 FULL CODE ===')
lines = s['code'].splitlines()
for i, line in enumerate(lines):
    stripped = line.strip()
    # Skip comment lines and empty
    if stripped.startswith('*') or stripped.startswith('/**') or stripped == '':
        continue
    print(f'L{i+1:3d}: {line}')
