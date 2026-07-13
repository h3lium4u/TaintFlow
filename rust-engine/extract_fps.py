import sys, json, re

sys.stdout.reconfigure(encoding='utf-8')

def extract_fp_codes(logfile, dataset='OWASP'):
    with open(logfile, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')
    lines = text.splitlines()

    fps = []
    # Method 1: look for JSON fp dump blocks
    # The harness pushes all_fps as a JSON array near the end
    # Try to find the printed all_fps JSON block
    full_text_joined = '\n'.join(lines)
    
    # Look for the printed FP list - usually after "All FPs:"
    fp_json_match = re.search(r'All FPs[^\[]*(\[.*?\])', full_text_joined, re.DOTALL)
    if fp_json_match:
        try:
            fp_list = json.loads(fp_json_match.group(1))
            fps = [x['code'] for x in fp_list if x.get('dataset') == dataset]
            return fps, 'json_block'
        except:
            pass
    
    # Method 2: look for [FP] prefix lines with BenchmarkTest
    for l in lines:
        if '[FP]' in l and 'BenchmarkTest' in l:
            m = re.search(r'BenchmarkTest\d+', l)
            if m:
                fps.append(m.group(0))
    if fps:
        return fps, 'fp_prefix'
    
    # Method 3: look for DIAGNOSTIC lines with the word "FP" and benchmark name
    for i, l in enumerate(lines):
        if 'DIAGNOSTIC FOR' in l and 'BenchmarkTest' in l:
            bench = re.search(r'BenchmarkTest\d+', l)
            if bench:
                # look at surrounding lines for FP verdict
                context = '\n'.join(lines[max(0,i):min(len(lines),i+20)])
                if 'false_positive' in context.lower() or 'FP' in context:
                    fps.append(bench.group(0))
    
    return fps, 'no_match'


fps357, method357 = extract_fp_codes('RC357_OWASP_VALIDATION.log')
fps356, method356 = extract_fp_codes('RC356_BASELINE_RECOVERY_VALIDATION.log')

print(f"RC357 FPs: {len(fps357)} (method: {method357})")
print(f"RC356 FPs: {len(fps356)} (method: {method356})")

# Show unique new FPs in RC357
fps357_set = set(fps357)
fps356_set = set(fps356)
new_fps = fps357_set - fps356_set
print(f"\nNew FPs in RC357 (not in RC356): {len(new_fps)}")
for f in sorted(new_fps):
    print(" ", f)
