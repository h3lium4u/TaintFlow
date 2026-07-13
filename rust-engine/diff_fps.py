import sys, re, json
sys.stdout.reconfigure(encoding='utf-8')

def get_sample_flows(logfile):
    with open(logfile, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')
    lines = text.splitlines()
    
    owasp_start = None
    vul4j_start = None
    for i, l in enumerate(lines):
        if 'Scanning OWASP' in l:
            owasp_start = i
        if 'Scanning Vul4J' in l and owasp_start is not None:
            vul4j_start = i
            break
    
    owasp_lines = lines[owasp_start:vul4j_start]
    diag_idx = [i for i, l in enumerate(owasp_lines)
                if l.startswith('[RC108A_DIAGNOSTIC]') and 'OWASP' in l]
    
    results = []
    for k in range(len(diag_idx)):
        start = diag_idx[k]
        end = diag_idx[k+1] if k+1 < len(diag_idx) else len(owasp_lines)
        segment = owasp_lines[start:end]
        timing_lines = [l for l in segment
                        if l.startswith('[TIMING]') and 'repo=OWASP' in l]
        has_flow = len(timing_lines) > 0
        found_cwe = None
        if has_flow:
            m = re.search(r'cwe=(CWE-\d+)', timing_lines[0])
            found_cwe = m.group(1) if m else 'UNKNOWN'
        results.append({'has_flow': has_flow, 'found_cwe': found_cwe})
    return results

r356 = get_sample_flows('RC356_BASELINE_RECOVERY_VALIDATION.log')
r357 = get_sample_flows('RC357_OWASP_VALIDATION.log')

print('RC356 samples: %d, with flow: %d' % (len(r356), sum(1 for x in r356 if x['has_flow'])))
print('RC357 samples: %d, with flow: %d' % (len(r357), sum(1 for x in r357 if x['has_flow'])))

# Load dataset
java_samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        java_samples.append({'class': cls, 'vulnerable': entry['vulnerable'], 'cwe': entry.get('cwe', '?')})

python_samples = []
with open('../benchmarks/benchmark_python.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        python_samples.append({'class': cls, 'vulnerable': entry['vulnerable'], 'cwe': entry.get('cwe', '?')})

all_samples = java_samples + python_samples
print('Dataset total: %d' % len(all_samples))

# Align and find FPs
fps_356 = []
fps_357 = []
new_fps = []
resolved = []

for i in range(len(all_samples)):
    s356 = r356[i]
    s357 = r357[i]
    sample = all_samples[i]
    if not sample['vulnerable']:
        if s356['has_flow']:
            fps_356.append(sample['class'])
        if s357['has_flow']:
            fps_357.append(sample['class'])
        if s357['has_flow'] and not s356['has_flow']:
            new_fps.append({
                'class': sample['class'],
                'cwe': sample['cwe'],
                'found_cwe': s357['found_cwe'],
            })
        elif s356['has_flow'] and not s357['has_flow']:
            resolved.append({
                'class': sample['class'],
                'cwe': sample['cwe'],
            })

print('RC356 FPs: %d' % len(fps_356))
print('RC357 FPs: %d' % len(fps_357))
print('NEW FPs in RC357: %d' % len(new_fps))
print('Resolved FPs: %d' % len(resolved))
print()
print('=== NEW FP REGRESSIONS (RC357 vs RC356) ===')
print('%-45s %-12s %-12s' % ('Benchmark', 'Expected CWE', 'Found CWE'))
print('-' * 70)
for x in sorted(new_fps, key=lambda x: x['class']):
    print('%-45s %-12s %-12s' % (x['class'], x['cwe'], x.get('found_cwe', '?')))

# Save
with open('rc357_new_fps.json', 'w', encoding='utf-8') as f:
    json.dump(new_fps, f, indent=2)
print('\nSaved to rc357_new_fps.json')
