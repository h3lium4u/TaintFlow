"""
Complete RC357 regression analysis.
The TIMING line appears for every sample (not just flows).
We must use the v2_fps_latest.json and reconstruct RC356's FP list.

Key facts:
- RC356: OWASP FP=359
- RC357: OWASP FP=417  
- Delta: +58 new FPs
- Both have TIMING lines = 3149 (one per sample)
- The actual FP list is stored in v2_fps_latest.json (overwritten each run)
- RC357 FP list was overwritten by RC358, but RC358 has SAME FP=417
- RC356 FP list: we need to reconstruct from scratch

Approach: Use the FP JSON from RC358/RC357 (identical) and compare to
the baseline FP JSON (v2_fps_baseline.json from an older run with ~182 FPs).

Actually the right approach is:
1. The harness outputs per-benchmark flow diagnostics for special samples
2. We can parse these from the log to identify which FPs are new

Better: Since the harness processes samples in a DETERMINISTIC ORDER,
we can correlate the JSON FP list with the dataset by matching source code.
The v2_fps_latest.json has 417 OWASP FP entries with full source code.
The dataset has 1562 safe OWASP samples.
Cross-referencing these gives us which safe samples ARE in the FP list.

For RC356, we need the FP list. We DON'T have v2_fps_rc356.json.
But we can reconstruct it: since RC356 has exactly 359 OWASP FPs,
and RC357 has exactly 417 FPs, and both runs are deterministic, 
we can identify which 58 samples changed by looking at the actual changes
introduced by RC357 (the null-guard-recovery commit).

The null-guard-recovery change is in interproc.rs.
Let us look at what the commit actually changed.
"""
import subprocess, sys, json, re

sys.stdout.reconfigure(encoding='utf-8')

# Get the diff between RC356 and RC357 commits
result = subprocess.run(
    ['git', 'diff', 'd8e9054', '1e484dc', '--', 'crates/taint/src/interproc.rs'],
    capture_output=True, text=True, cwd='.'
)
diff = result.stdout
print("=== RC357 commit diff vs RC356 ===")
print(f"Diff length: {len(diff)} chars")
print()
# Print first 200 lines
for line in diff.splitlines()[:200]:
    print(line)
