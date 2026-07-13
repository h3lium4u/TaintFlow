import json, sys, re

sys.stdout.reconfigure(encoding='utf-8')

# Load current FP list
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_current = json.load(f)

owasp_fps = [x for x in fps_current if x.get('dataset') == 'OWASP']

# Print the first sample code to understand format
sample = owasp_fps[0]
print('Keys:', list(sample.keys()))
print('Language:', sample.get('language'))
print('CWE in record:', sample.get('cwe', 'N/A'))
print('Code sample (first 2000 chars):')
print(sample['code'][:2000])
