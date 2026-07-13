import json, sys, re
sys.stdout.reconfigure(encoding='utf-8')

NULL_PATTERNS = ['is none', 'is not none', '!= none', '== none', '!= null', '== null']

# Load safe CWE-22 Java benchmarks that are in FP set AND have null patterns
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

# Candidates
candidates = [s for s in safe_cwe22
              if any(p in s['code'].lower() for p in NULL_PATTERNS)
              and s['class'] in fp_classes]

print(f'Candidates: {len(candidates)}')
print()

# For first 5, show the actual sink (what line has the path variable flow into)
for s in candidates[:5]:
    print(f'=== {s["class"]} ===')
    lines = s['code'].splitlines()
    for i, line in enumerate(lines):
        if any(kw in line.lower() for kw in ['getoutputstream', 'getwriter', 'forward', 'redirect', 'sendredirect',
                                               'response', 'servlet', 'new file', 'path', 'realpath',
                                               'dispatch', 'setcontenttype']):
            if 'param' in line.lower() or 'value' in line.lower():
                print(f'  L{i+1}: {line.strip()[:120]}')
    print()
