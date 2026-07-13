import json, sys, re

sys.stdout.reconfigure(encoding='utf-8')

def get_class_name(code_str):
    m = re.search(r'public class (BenchmarkTest\d+)', code_str)
    if m: return m.group(1)
    m = re.search(r'public class (\w+Servlet\w*)', code_str)
    if m: return m.group(1)
    m = re.search(r'public class (\w+)', code_str)
    if m: return m.group(1)
    return 'UNKNOWN'

def get_cwe_from_source(code_str):
    m = re.search(r'CWE-(\d+)', code_str)
    if m: return 'CWE-' + m.group(1)
    return 'UNKNOWN'

# Load current FP list (RC357=RC358 identical FP set, 417 each)
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_current = json.load(f)

owasp_fps = [x for x in fps_current if x.get('dataset') == 'OWASP']
print(f'Total OWASP FPs current (RC357/RC358): {len(owasp_fps)}')

# Extract class names
fp_classes = set()
fp_details = []
for x in owasp_fps:
    cls = get_class_name(x['code'])
    cwe = get_cwe_from_source(x['code'])
    fp_details.append((cls, cwe))
    fp_classes.add(cls)

fp_details.sort()
print(f'Unique benchmark classes: {len(fp_classes)}')
print('\nFirst 30 FP benchmarks:')
for cls, cwe in fp_details[:30]:
    print(f'  {cls:<50} {cwe}')

# Save to file for further analysis
with open('fp_current_list.txt', 'w', encoding='utf-8') as f:
    for cls, cwe in sorted(set(fp_details)):
        f.write(f'{cls}\t{cwe}\n')
print('\nSaved to fp_current_list.txt')
