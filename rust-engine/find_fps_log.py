import json, sys, re

sys.stdout.reconfigure(encoding='utf-8')

# Load the current FP JSON (RC357/RC358, count=417)
with open('../scratch/v2_fps_latest.json', encoding='utf-8') as f:
    fps_latest = json.load(f)

# Load the old baseline FP JSON (which has 182 FPs, not 359, but we can reconstruct RC356)
# Actually, let's extract the exact FPs from the RC357 and RC356 logs.
# In the validation logs, when a sample runs, the log outputs:
# "[DIAGNOSTIC] ... vulnerable=false pred=true" or similar for FPs, OR we can parse the benchmark names.
# Let's write a script to find all FPs from both logs.

def get_fps_from_log(logfile):
    with open(logfile, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')
    lines = text.splitlines()
    
    # We want to find OWASP benchmarks that are FPs.
    # The log outputs:
    # [TIMING] repo=OWASP cwe=...
    # [RC108A_DIAGNOSTIC] Repo: OWASP, Filename: Test_CWE_22.java (or similar)
    # But wait, does the log output the actual benchmark class name when a flow is found?
    # No, but in v2_validation.rs:
    # Let's search the log for "pred=true" or "False Positives" or similar diagnostics.
    # Let's inspect what diagnostics are logged for OWASP.
    fps = set()
    in_owasp = False
    current_benchmark = None
    for line in lines:
        if 'Scanning OWASP' in line:
            in_owasp = True
        if 'Scanning Vul4J' in line:
            in_owasp = False
        if not in_owasp:
            continue
            
        # In run_dataset, does it print the benchmark class name?
        # Let's search for "BenchmarkTest" in the log.
        if 'BenchmarkTest' in line:
            m = re.search(r'(BenchmarkTest\d+)', line)
            if m:
                current_benchmark = m.group(1)
    return fps

# Let's look at how the harness logs results or if there are other files in the scratch directory.
# Let's list files in scratch. We have:
# v2_fps_latest.json
# v2_fps_baseline.json
# suppressed_diagnostics.json
# v2_fns_latest.json
# diagnostic_*.txt files!
# Let's see if we can find the list of FPs by checking the code.
