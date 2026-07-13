import re

path = 'd:/V2 Backup/rust-engine/RC119_FULL_GITHUB_VALIDATION_utf8.log'

with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Let's find each sample run and extract its stats
sample_blocks = re.split(r'\[DIAGNOSTIC\] GitHub Sample \d+:', content)
print(f"Total diagnostic blocks: {len(sample_blocks)}")

# Let's parse all categories and print totals
categories = ['CFG', 'Receiver-field', 'Return scan', 'Call', 'Exception', 'Array container', 'Initial']
stats = {cat: {'attempts': 0, 'enqueued': 0, 'duplicates': 0, 'insertions': 0} for cat in categories}

# Regex to find stats
# CFG:
#   attempts: 456
#   enqueued: 381
#   duplicates: 75
#   insertions: 381
pattern = re.compile(
    r'(CFG|Receiver-field|Return scan|Call|Exception|Array container|Initial):\s*'
    r'attempts:\s*(\d+)\s*'
    r'enqueued:\s*(\d+)\s*'
    r'duplicates:\s*(\d+)\s*'
    r'insertions:\s*(\d+)'
)

matches = pattern.findall(content)
print(f"Found matches: {len(matches)}")
for cat, att, enq, dup, ins in matches:
    stats[cat]['attempts'] += int(att)
    stats[cat]['enqueued'] += int(enq)
    stats[cat]['duplicates'] += int(dup)
    stats[cat]['insertions'] += int(ins)

print("\n=== AGGREGATED SOLVER PROPAGATION STATISTICS ===")
grand_total_attempts = 0
for cat, s in stats.items():
    att = s['attempts']
    enq = s['enqueued']
    dup = s['duplicates']
    ins = s['insertions']
    grand_total_attempts += att
    pct = (dup / att * 100.0) if att > 0 else 0.0
    print(f"{cat}:")
    print(f"  attempts: {att}")
    print(f"  enqueued: {enq}")
    print(f"  duplicates: {dup} ({pct:.2f}%)")
    print(f"  insertions: {ins}")

print(f"Grand Total Attempts across all samples: {grand_total_attempts}")

# Let's find samples that hit the 1,000,000 iteration cap in RC119
diag_re = re.compile(r'\[DIAGNOSTIC\] GitHub Sample (\d+): cwe=(\S+) vulnerable=(\S+) pred=(\S+)')
eng_re = re.compile(r'\[ENGINE\] finished after (\d+) iterations')
timing_re = re.compile(r'\[TIMING\] repo=(\S+) cwe=(\S+) .*?engine=([\d.]+)(s|ms|us|μs) nodes=(\d+)')

lines = content.split('\n')
capped_samples = []
for idx, l in enumerate(lines):
    m = diag_re.search(l)
    if m:
        sid = int(m.group(1))
        # Search backward for iterations and timing
        iters = None
        engine_s = 0.0
        repo = 'UNKNOWN'
        for j in range(idx - 1, max(0, idx - 200), -1):
            if iters is None:
                m_e = eng_re.search(lines[j])
                if m_e:
                    iters = int(m_e.group(1))
            m_t = timing_re.search(lines[j])
            if m_t:
                repo = m_t.group(1)
                val_str = m_t.group(3)
                unit_str = m_t.group(4)
                if unit_str == 's':
                    engine_s = float(val_str)
                elif unit_str == 'ms':
                    engine_s = float(val_str) / 1000.0
                elif unit_str in ['us', 'μs']:
                    engine_s = float(val_str) / 1000000.0
        
        if iters == 1000001:
            capped_samples.append((sid, repo, m.group(2), m.group(3) == 'true', m.group(4) == 'true', engine_s))

print(f"\n=== SAMPLES THAT HIT 1M ITERATIONS ({len(capped_samples)}) ===")
for sid, repo, cwe, vuln, pred, time in capped_samples:
    print(f"Sample {sid}: Repo={repo}, CWE={cwe}, vuln={vuln}, pred={pred}, time={time:.2f}s")
