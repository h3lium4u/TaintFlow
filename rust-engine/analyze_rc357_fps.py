"""
RC357 vs RC356 regression analysis.
Identifies the 58 new OWASP FPs introduced by the null-guard-recovery experiment.

Strategy:
1. Load OWASP dataset (ordered, with vulnerable flags)
2. Parse TIMING lines from both logs - each TIMING line = one flow found
3. Match TIMING lines to samples by position/order
4. Classify: FP = flow found on safe sample
5. Diff the two FP sets
"""
import json, sys, re

sys.stdout.reconfigure(encoding='utf-8')

# ─── Load OWASP dataset ────────────────────────────────────────────
# Java only (Python is a separate file and has smaller count)
java_samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        java_samples.append({
            'class': cls,
            'vulnerable': entry.get('vulnerable', False),
            'cwe': entry.get('cwe', 'UNKNOWN'),
            'code': entry.get('code', ''),
        })

python_samples = []
try:
    with open('../benchmarks/benchmark_python.jsonl', encoding='utf-8') as f:
        for line in f:
            entry = json.loads(line.strip())
            m = re.search(r'class (\w+)', entry.get('code', ''))
            cls = m.group(1) if m else 'UNKNOWN'
            python_samples.append({
                'class': cls,
                'vulnerable': entry.get('vulnerable', False),
                'cwe': entry.get('cwe', 'UNKNOWN'),
                'code': entry.get('code', ''),
            })
except FileNotFoundError:
    pass

all_samples = java_samples + python_samples
print(f"Total OWASP samples: {len(all_samples)} (Java: {len(java_samples)}, Python: {len(python_samples)})")
safe_samples = {s['class']: s for s in all_samples if not s['vulnerable']}
print(f"Safe (TN expected): {len(safe_samples)}")

# ─── Parse TIMING lines from a log to get the ordered list of flows ──
def parse_owasp_flows(logfile):
    """
    Returns a list of dicts {cwe, pos} for each TIMING line in the OWASP section.
    TIMING lines appear exactly once per sample that produced a flow.
    Samples that produce NO flow have no TIMING line.
    """
    with open(logfile, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')
    lines = text.splitlines()
    
    # Find OWASP section
    owasp_start = None
    vul4j_start = None
    for i, l in enumerate(lines):
        if 'Scanning OWASP' in l:
            owasp_start = i
        if 'Scanning Vul4J' in l and owasp_start is not None:
            vul4j_start = i
            break
    
    owasp_lines = lines[owasp_start:vul4j_start]
    
    # Extract TIMING lines - each corresponds to one flow found
    flows = []
    for l in owasp_lines:
        if l.startswith('[TIMING]') and 'repo=OWASP' in l:
            m = re.search(r'cwe=(CWE-\d+)', l)
            cwe = m.group(1) if m else 'UNKNOWN'
            flows.append({'cwe': cwe, 'line': l})
    
    return flows

flows356 = parse_owasp_flows('RC356_BASELINE_RECOVERY_VALIDATION.log')
flows357 = parse_owasp_flows('RC357_OWASP_VALIDATION.log')
print(f"\nRC356 OWASP flows (TIMING lines): {len(flows356)}")
print(f"RC357 OWASP flows (TIMING lines): {len(flows357)}")

# ─── Use the FP JSON files to get exact FP benchmark lists ───────────
# The v2_fps_latest.json is from the LAST run (RC358).
# RC357 and RC358 have identical FP=417, so the FP set is the same.
# We need RC356's FP set.
#
# The key insight: The OWASP samples are processed in the SAME ORDER every run
# (deterministic). TIMING lines appear for samples that produced flows.
# We can match the ordered sequence of TIMING lines to the ordered sample list.
# This lets us identify EXACTLY which samples produced flows in each run.

# But wait: The number of TIMING lines (2601 for RC357) != number of samples (3149).
# 3149 - 2601 = 548 samples produced no flow in RC357.
# This doesn't map 1-to-1 because some samples may produce multiple flows? No.
# Actually multiple TIMING lines can appear per sample if the engine runs multiple targets.
# The RC108A_DIAGNOSTIC lines (3149) DO map 1-to-1 with samples.

# Better: use the RC108A_DIAGNOSTIC lines as sample markers, then look for
# TIMING lines between consecutive DIAGNOSTIC lines.

def parse_per_sample_results(logfile):
    """
    Returns list of {class, cwe, has_flow, found_cwe} for each OWASP sample.
    """
    with open(logfile, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')
    lines = text.splitlines()
    
    # Find OWASP section
    owasp_start = None
    vul4j_start = None
    for i, l in enumerate(lines):
        if 'Scanning OWASP' in l:
            owasp_start = i
        if 'Scanning Vul4J' in l and owasp_start is not None:
            vul4j_start = i
            break
    
    owasp_lines = lines[owasp_start:vul4j_start]
    
    # Find all RC108A_DIAGNOSTIC lines (one per sample)
    diag_indices = []
    for i, l in enumerate(owasp_lines):
        if l.startswith('[RC108A_DIAGNOSTIC]') and 'Repo: OWASP' in l:
            diag_indices.append(i)
    
    # For each sample, check if there's a TIMING line between this diagnostic and the next
    results = []
    for k, idx in enumerate(diag_indices):
        end_idx = diag_indices[k + 1] if k + 1 < len(diag_indices) else len(owasp_lines)
        segment = owasp_lines[idx:end_idx]
        timing_lines = [l for l in segment if l.startswith('[TIMING]') and 'repo=OWASP' in l]
        has_flow = len(timing_lines) > 0
        found_cwe = None
        if has_flow:
            m = re.search(r'cwe=(CWE-\d+)', timing_lines[0])
            found_cwe = m.group(1) if m else 'UNKNOWN'
        # Extract filename from diagnostic
        fn_m = re.search(r'Filename: ([^,]+)', segment[0])
        filename = fn_m.group(1).strip() if fn_m else 'UNKNOWN'
        results.append({'filename': filename, 'has_flow': has_flow, 'found_cwe': found_cwe})
    
    return results

print("\nParsing per-sample results from RC356...")
per_sample_356 = parse_per_sample_results('RC356_BASELINE_RECOVERY_VALIDATION.log')
print(f"RC356 per-sample results: {len(per_sample_356)}")

print("Parsing per-sample results from RC357...")
per_sample_357 = parse_per_sample_results('RC357_OWASP_VALIDATION.log')
print(f"RC357 per-sample results: {len(per_sample_357)}")

# Align with the actual sample list
# The harness processes java_samples then python_samples in order
if len(per_sample_356) == len(all_samples) and len(per_sample_357) == len(all_samples):
    print("\nSample counts match! Proceeding with alignment.")
    
    # Find FPs in each run
    fps_356 = []
    fps_357 = []
    for i, (s356, s357, sample) in enumerate(zip(per_sample_356, per_sample_357, all_samples)):
        if not sample['vulnerable']:  # Safe sample = FP/TN test
            if s356['has_flow']:
                fps_356.append({'class': sample['class'], 'cwe': sample['cwe'], 'found_cwe': s356['found_cwe']})
            if s357['has_flow']:
                fps_357.append({'class': sample['class'], 'cwe': sample['cwe'], 'found_cwe': s357['found_cwe']})
    
    print(f"\nRC356 FPs: {len(fps_356)}")
    print(f"RC357 FPs: {len(fps_357)}")
    
    fps_356_set = {x['class'] for x in fps_356}
    fps_357_set = {x['class'] for x in fps_357}
    
    new_fps = fps_357_set - fps_356_set
    resolved_fps = fps_356_set - fps_357_set
    
    print(f"\nNEW FPs in RC357 (regressions): {len(new_fps)}")
    print(f"Resolved FPs (improvements): {len(resolved_fps)}")
    
    # Print the 58 new FPs with CWE info
    new_fp_details = [x for x in fps_357 if x['class'] in new_fps]
    new_fp_details.sort(key=lambda x: x['class'])
    
    print("\n=== NEW FP REGRESSIONS (RC357 vs RC356) ===")
    print(f"{'Benchmark':<45} {'Expected CWE':<15} {'Found CWE':<15}")
    print("-" * 75)
    for x in new_fp_details:
        print(f"{x['class']:<45} {x['cwe']:<15} {x.get('found_cwe','?'):<15}")
    
    # Save for further analysis
    with open('rc357_new_fps.json', 'w', encoding='utf-8') as f:
        json.dump(new_fp_details, f, indent=2)
    print(f"\nSaved to rc357_new_fps.json")

else:
    print(f"\nWARNING: Sample count mismatch!")
    print(f"  Dataset: {len(all_samples)}")
    print(f"  RC356 per-sample: {len(per_sample_356)}")
    print(f"  RC357 per-sample: {len(per_sample_357)}")
    # Check if python is not in the log
    print(f"\n  Java samples: {len(java_samples)}")
    print(f"  Python samples: {len(python_samples)}")
