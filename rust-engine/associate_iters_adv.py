import re

path = 'd:/V2 Backup/rust-engine/RC119_FULL_GITHUB_VALIDATION_utf8.log'

with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    lines = [l.strip() for l in f]

# Let's find all diagnostic lines
diag_re = re.compile(r'\[DIAGNOSTIC\] GitHub Sample (\d+): cwe=(\S+) vulnerable=(\S+) pred=(\S+)')
timing_re = re.compile(r'\[TIMING\] repo=(\S+) cwe=(\S+) .*?engine=([\d.]+)(s|ms|us|μs) nodes=(\d+)')
eng_re = re.compile(r'\[ENGINE\] finished after (\d+) iterations')

# We can find all [ENGINE] finished after lines in the file and their line numbers
engine_lines = []
for idx, l in enumerate(lines):
    m = eng_re.search(l)
    if m:
        engine_lines.append((idx, int(m.group(1))))

print(f"Total engine finished lines: {len(engine_lines)}")

# We can find all [DIAGNOSTIC] lines and their line numbers
diag_lines = []
for idx, l in enumerate(lines):
    m = diag_re.search(l)
    if m:
        sid = int(m.group(1))
        diag_lines.append((idx, sid, m.group(2), m.group(3) == 'true', m.group(4) == 'true'))

# Since they are logged on different threads, let's look at the [TIMING] lines
# which are printed right after the solver ends on that thread!
# In v2_validation.rs:
#   engine.run();
#   let t_engine = t4.elapsed();
#   println!(\"[TIMING] repo={} cwe={} ... engine={:?} ...\");
# And then the diagnostic is buffered.
# So on any thread, the `[ENGINE] finished after` line is printed immediately before the `[TIMING]` line!
# Let's verify if they are printed consecutively.
# Yes, because they are both printed directly to stdout from the same thread execution!
# Let's find each [TIMING] line, and search backward for the closest [ENGINE] finished after line.
# Since they are printed consecutively, they should be very close (usually within 10 lines, with no other [ENGINE] lines in between on the same thread).
# Let's check:
timing_lines = []
for idx, l in enumerate(lines):
    m = timing_re.search(l)
    if m:
        timing_lines.append((idx, m.group(1), m.group(2)))

print(f"Total timing lines: {len(timing_lines)}")

# For each timing line, find the closest preceding [ENGINE] line
timing_to_iters = {}
for t_idx, repo, cwe in timing_lines:
    # Search backward for the closest [ENGINE] line
    closest_iters = None
    for j in range(t_idx - 1, -1, -1):
        m_e = eng_re.search(lines[j])
        if m_e:
            closest_iters = int(m_e.group(1))
            break
    timing_to_iters[t_idx] = closest_iters

# Now associate each [DIAGNOSTIC] line with a [TIMING] line.
# Since [DIAGNOSTIC] is printed at the end of the test run for each sample,
# we can look for the [TIMING] line that matches the repo and CWE, and is closest to the diagnostic line.
# Let's map:
sample_results = []
for d_idx, sid, cwe, vuln, pred in diag_lines:
    # Find the [TIMING] line matching this repo (if we can find repo in diagnostic log)
    # Actually, let's search backward from d_idx for the closest [TIMING] line
    # which has not been associated yet, or just the closest one matching cwe.
    # In parallel execution, the timing line might be printed anywhere before the diagnostic line.
    # But since each sample corresponds to one timing line and one diagnostic line,
    # let's match them by repository name (which is printed in both diagnostics and timing).
    # Wait, where is repo name printed in diagnostics?
    # It is printed in [FN_DIAGNOSTIC] or [FP_DIAGNOSTIC] which are printed in the same block as [DIAGNOSTIC]!
    # Let's find the repo name in the same block (backward/forward 100 lines from d_idx).
    repo_name = None
    for j in range(max(0, d_idx - 50), min(len(lines), d_idx + 50)):
        if "Repo:" in lines[j] or "repo=" in lines[j] or "[FP_DIAGNOSTIC] Repo:" in lines[j] or "[FN_DIAGNOSTIC] Repo:" in lines[j]:
            # extract repo name
            m_r = re.search(r'Repo:\s*(\S+)|repo=(\S+)', lines[j])
            if m_r:
                r_val = m_r.group(1) or m_r.group(2)
                repo_name = r_val.replace('https://github.com/', '').strip()
                break
    
    if not repo_name:
        # fallback search
        for j in range(d_idx - 1, -1, -1):
            if "Repo:" in lines[j] or "[FP_DIAGNOSTIC] Repo:" in lines[j] or "[FN_DIAGNOSTIC] Repo:" in lines[j]:
                m_r = re.search(r'Repo:\s*(\S+)', lines[j])
                if m_r:
                    repo_name = m_r.group(1).replace('https://github.com/', '').strip()
                    break
                    
    # Now find the timing line that matches repo_name and cwe
    matched_timing = None
    min_dist = 999999
    for t_idx, t_repo, t_cwe in timing_lines:
        t_repo_clean = t_repo.replace('https://github.com/', '').strip()
        if t_repo_clean == repo_name and t_cwe == cwe:
            dist = abs(d_idx - t_idx)
            if dist < min_dist:
                min_dist = dist
                matched_timing = t_idx
                
    iters = timing_to_iters.get(matched_timing) if matched_timing else None
    sample_results.append((sid, repo_name, cwe, vuln, pred, iters))

# Print results
print("\n=== ASSOCIATED SAMPLE ITERATIONS ===")
capped = []
for sid, repo, cwe, vuln, pred, iters in sorted(sample_results, key=lambda x: x[0]):
    if iters == 1000001 or iters is None:
        capped.append((sid, repo, cwe, vuln, pred, iters))
        print(f"Sample {sid}: Repo={repo}, CWE={cwe}, vuln={vuln}, pred={pred}, Iters={iters}")

print(f"Total capped/none samples: {len(capped)}")
