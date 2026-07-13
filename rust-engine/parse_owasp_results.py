import sys, re, json
sys.stdout.reconfigure(encoding='utf-8')

def parse_owasp_fps_from_log(logfile):
    """
    Parse an OWASP validation log to find which benchmarks produced flows.
    
    Strategy: The harness writes each sample's code to all_fps when it's a FP.
    We parse the JSON file written by the harness instead.
    However since that file is overwritten, we must reconstruct from the logs.
    
    The log structure shows TIMING lines for each benchmark that ran.
    A FP = benchmark that:
      1. Is a TN-expected sample (safe variant in OWASP dataset)
      2. Has a flow found (engine produced a finding)
    
    We find the per-benchmark FP info from:
    - TIMING lines: repo=OWASP cwe=CWE-XX -> show when a finding was produced
    - DIAGNOSTIC lines: show which benchmark was processed
    
    Importantly: TIMING lines only appear when a flow IS found.
    No TIMING line = no flow = TN or FN.
    """
    with open(logfile, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='ignore')
    lines = text.splitlines()
    
    # Find section boundaries
    owasp_start = None
    vul4j_start = None
    for i, l in enumerate(lines):
        if 'Scanning OWASP' in l:
            owasp_start = i
        if 'Scanning Vul4J' in l:
            vul4j_start = i
            break
    
    if not owasp_start:
        print("ERROR: Could not find OWASP section")
        return {}
    
    owasp_lines = lines[owasp_start:vul4j_start]
    print(f"OWASP section: {len(owasp_lines)} lines ({owasp_start} to {vul4j_start})")
    
    # Count TIMING lines and DIAGNOSTIC lines in OWASP section
    timing_lines = [l for l in owasp_lines if l.startswith('[TIMING]') and 'repo=OWASP' in l]
    diagnostic_lines = [l for l in owasp_lines if 'DIAGNOSTIC FOR' in l or 'RC108A_DIAGNOSTIC' in l]
    
    print(f"TIMING lines: {len(timing_lines)}")
    print(f"DIAGNOSTIC lines: {len(diagnostic_lines)}")
    
    # Show first few TIMING and DIAGNOSTIC lines
    print("\nFirst 5 TIMING lines:")
    for l in timing_lines[:5]:
        print(" ", l[:200])
    print("\nFirst 5 DIAGNOSTIC lines:")
    for l in diagnostic_lines[:5]:
        print(" ", l[:200])
    
    return {}

parse_owasp_fps_from_log('RC357_OWASP_VALIDATION.log')
