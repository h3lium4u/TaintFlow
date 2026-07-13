import re, collections

# robust time parsing helper
def parse_time_to_seconds(val_str, unit_str):
    val = float(val_str)
    if unit_str == 's':
        return val
    elif unit_str == 'ms':
        return val / 1000.0
    elif unit_str in ['us', 'μs', 'ms']:
        return val / 1000000.0
    return val

def parse_log(path, is_utf16=False):
    enc = 'utf-16' if is_utf16 else 'utf-8'
    with open(path, 'r', encoding=enc, errors='ignore') as f:
        lines = [l.strip() for l in f]
    
    diags = {}
    
    diag_re = re.compile(r'\[DIAGNOSTIC\] GitHub Sample (\d+): cwe=(\S+) vulnerable=(\S+) pred=(\S+)')
    timing_re = re.compile(r'\[TIMING\] repo=(\S+) cwe=(\S+) .*?engine=([\d.]+)(s|ms|us|μs) nodes=(\d+)')
    
    # We will trace backward and forward to find the timing entry
    # timing lines can be before or after the diagnostic line
    diag_indices = []
    for idx, l in enumerate(lines):
        m = diag_re.search(l)
        if m:
            sid = int(m.group(1))
            diag_indices.append((sid, idx, m))
            
    diag_indices.sort(key=lambda x: x[1])
    
    for k, (sid, idx, m) in enumerate(diag_indices):
        cwe = m.group(2)
        vuln = m.group(3) == 'true'
        pred = m.group(4) == 'true'
        
        # Look around idx for timing line
        timing = None
        # look backward first (up to 100 lines)
        for j in range(idx - 1, max(0, idx - 100), -1):
            m_t = timing_re.search(lines[j])
            if m_t:
                repo_str = m_t.group(1).replace('https://github.com/', '')
                val_str = m_t.group(3)
                unit_str = m_t.group(4)
                timing = {
                    'repo': repo_str,
                    'engine_s': parse_time_to_seconds(val_str, unit_str),
                    'nodes': int(m_t.group(5))
                }
                break
        
        # if not found, look forward (up to 100 lines)
        if not timing:
            for j in range(idx + 1, min(len(lines), idx + 100)):
                m_t = timing_re.search(lines[j])
                if m_t:
                    repo_str = m_t.group(1).replace('https://github.com/', '')
                    val_str = m_t.group(3)
                    unit_str = m_t.group(4)
                    timing = {
                        'repo': repo_str,
                        'engine_s': parse_time_to_seconds(val_str, unit_str),
                        'nodes': int(m_t.group(5))
                    }
                    break
        
        diags[sid] = {
            'cwe': cwe,
            'vuln': vuln,
            'pred': pred,
            'repo': timing['repo'] if timing else 'UNKNOWN',
            'engine_s': timing['engine_s'] if timing else 0.0,
            'nodes': timing['nodes'] if timing else 0
        }
        
    return diags

d112c = parse_log('d:/V2 Backup/rust-engine/RC112C_OWASP_VALIDATION.log', is_utf16=True)
d119 = parse_log('d:/V2 Backup/rust-engine/RC119_FULL_GITHUB_VALIDATION_utf8.log', is_utf16=False)

# Let's fix the UNKNOWN repositories for samples by inheriting from neighboring samples if needed
# Actually, let's see which samples are UNKNOWN
def fix_unknowns(diags):
    sids = sorted(diags.keys())
    for idx, sid in enumerate(sids):
        if diags[sid]['repo'] == 'UNKNOWN':
            # find closest non-unknown
            # search backward
            b_repo = 'UNKNOWN'
            for j in range(idx - 1, -1, -1):
                if diags[sids[j]]['repo'] != 'UNKNOWN':
                    b_repo = diags[sids[j]]['repo']
                    break
            # search forward
            f_repo = 'UNKNOWN'
            for j in range(idx + 1, len(sids)):
                if diags[sids[j]]['repo'] != 'UNKNOWN':
                    f_repo = diags[sids[j]]['repo']
                    break
            
            # use backward if found, else forward
            if b_repo != 'UNKNOWN':
                diags[sid]['repo'] = b_repo
            elif f_repo != 'UNKNOWN':
                diags[sid]['repo'] = f_repo

fix_unknowns(d112c)
fix_unknowns(d119)

# ----------------------------------------------------
# 1. Overall Metrics
# ----------------------------------------------------
def get_metrics(diags):
    tp = fp = tn = fn = 0
    for sid, d in diags.items():
        v, p = d['vuln'], d['pred']
        if v and p: tp += 1
        elif not v and p: fp += 1
        elif not v and not p: tn += 1
        elif v and not p: fn += 1
    
    total = len(diags)
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    
    import math
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = (tp * tn - fp * fn) / math.sqrt(denom) if denom > 0 else 0.0
    
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'acc': acc, 'prec': prec, 'rec': rec, 'f1': f1, 'mcc': mcc}

m112c = get_metrics(d112c)
m119 = get_metrics(d119)

print("=== OVERALL METRICS ===")
metrics_keys = ['tp', 'fp', 'tn', 'fn', 'prec', 'rec', 'f1', 'mcc', 'acc']
for k in metrics_keys:
    val_prev = m112c[k]
    val_119 = m119[k]
    diff = val_119 - val_prev
    if k in ['tp', 'fp', 'tn', 'fn']:
        pct_change = (diff / val_prev * 100) if val_prev != 0 else 0
        better = "Better" if (k in ['tp', 'tn'] and diff > 0) or (k in ['fp', 'fn'] and diff < 0) else "Worse"
        if diff == 0: better = "Unchanged"
        print(f"{k.upper()}: Previous={val_prev}, RC119={val_119}, Delta={diff:+.0f} ({pct_change:+.2f}%), {better}")
    else:
        better = "Better" if diff > 0 else "Worse"
        if diff == 0: better = "Unchanged"
        print(f"{k.upper()}: Previous={val_prev*100:.2f}%, RC119={val_119*100:.2f}%, Delta={diff*100:+.2f}%, {better}")

# ----------------------------------------------------
# 2. Sample-Level Changes
# ----------------------------------------------------
changes = []
for sid in sorted(d119.keys()):
    v119, p119 = d119[sid]['vuln'], d119[sid]['pred']
    v112, p112 = d112c[sid]['vuln'], d112c[sid]['pred']
    c119 = 'TP' if v119 and p119 else 'FP' if not v119 and p119 else 'TN' if not v119 and not p119 else 'FN'
    c112 = 'TP' if v112 and p112 else 'FP' if not v112 and p112 else 'TN' if not v112 and not p112 else 'FN'
    if c119 != c112:
        changes.append((sid, d119[sid]['repo'], d119[sid]['cwe'], c112, c119))

print(f"\nTotal differences: {len(changes)}")
improved = regressed = 0
for sid, repo, cwe, prev, rc119 in changes:
    is_imp = (prev in ['FN', 'FP'] and rc119 in ['TP', 'TN'])
    if is_imp:
        improved += 1
        status = "Improved"
    else:
        regressed += 1
        status = "Regressed"
    print(f"Sample {sid}: Repo={repo}, CWE={cwe}, Previous={prev}, RC119={rc119}, Change={prev} -> {rc119} ({status})")

print(f"Improved: {improved}, Regressed: {regressed}, Unchanged: {130 - len(changes)}")

# ----------------------------------------------------
# 3. Repository Comparison
# ----------------------------------------------------
repos = set(d['repo'] for d in d119.values())
print("\n=== REPOSITORY COMPARISON ===")
for r in sorted(repos):
    # filter samples for this repo
    s112 = {sid: d for sid, d in d112c.items() if d['repo'] == r}
    s119 = {sid: d for sid, d in d119.items() if d['repo'] == r}
    
    met112 = get_metrics(s112)
    met119 = get_metrics(s119)
    
    # Runtimes
    rt112 = sum(d['engine_s'] for d in s112.values())
    rt119 = sum(d['engine_s'] for d in s119.values())
    rt_diff = rt119 - rt112
    
    # Quality improved or regressed
    quality = "Unchanged"
    # count how many samples improved or regressed in this repo
    r_changes = [c for c in changes if c[1] == r]
    r_improved = sum(1 for c in r_changes if c[3] in ['FN', 'FP'] and c[4] in ['TP', 'TN'])
    r_regressed = len(r_changes) - r_improved
    if r_improved > r_regressed: quality = "Improved"
    elif r_regressed > r_improved: quality = "Regressed"
    elif len(r_changes) > 0: quality = "Mixed"
    
    print(f"Repo: {r}")
    print(f"  Previous: TP={met112['tp']}, FP={met112['fp']}, TN={met112['tn']}, FN={met112['fn']}")
    print(f"  RC119   : TP={met119['tp']}, FP={met119['fp']}, TN={met119['tn']}, FN={met119['fn']}")
    print(f"  Runtime : Previous={rt112:.2f}s, RC119={rt119:.2f}s, Diff={rt_diff:+.2f}s ({rt_diff/rt112*100 if rt112>0 else 0:+.2f}%)")
    print(f"  Quality : {quality}")

# ----------------------------------------------------
# 4. CWE Comparison
# ----------------------------------------------------
cwes = set(d['cwe'] for d in d119.values())
print("\n=== CWE COMPARISON ===")
for c in sorted(cwes):
    s112 = {sid: d for sid, d in d112c.items() if d['cwe'] == c}
    s119 = {sid: d for sid, d in d119.items() if d['cwe'] == c}
    
    met112 = get_metrics(s112)
    met119 = get_metrics(s119)
    
    # Quality comparison
    quality = "Unchanged"
    c_changes = [ch for ch in changes if ch[2] == c]
    c_improved = sum(1 for ch in c_changes if ch[3] in ['FN', 'FP'] and ch[4] in ['TP', 'TN'])
    c_regressed = len(c_changes) - c_improved
    if c_improved > c_regressed: quality = "Improved"
    elif c_regressed > c_improved: quality = "Regressed"
    elif len(c_changes) > 0: quality = "Mixed"
    
    print(f"CWE: {c}")
    print(f"  Previous: TP={met112['tp']}, FP={met112['fp']}, TN={met112['tn']}, FN={met112['fn']}, Prec={met112['prec']*100:.1f}%, Rec={met112['rec']*100:.1f}%")
    print(f"  RC119   : TP={met119['tp']}, FP={met119['fp']}, TN={met119['tn']}, FN={met119['fn']}, Prec={met119['prec']*100:.1f}%, Rec={met119['rec']*100:.1f}%")
    print(f"  Quality : {quality}")

# ----------------------------------------------------
# 5. Runtime Details
# ----------------------------------------------------
print("\n=== RUNTIME STATISTICS ===")
rt112_all = [d['engine_s'] for d in d112c.values() if d['engine_s'] > 0]
rt119_all = [d['engine_s'] for d in d119.values() if d['engine_s'] > 0]

rt112_all.sort()
rt119_all.sort()

print(f"Total Runtime: Previous={sum(rt112_all):.2f}s, RC119={sum(rt119_all):.2f}s, Diff={sum(rt119_all)-sum(rt112_all):+.2f}s")
print(f"Mean Runtime: Previous={sum(rt112_all)/len(rt112_all):.2f}s, RC119={sum(rt119_all)/len(rt119_all):.2f}s")
print(f"Median Runtime: Previous={rt112_all[len(rt112_all)//2]:.2f}s, RC119={rt119_all[len(rt119_all)//2]:.2f}s")
print(f"Slowest Sample: Previous={rt112_all[-1]:.2f}s, RC119={rt119_all[-1]:.2f}s")
print(f"Fastest Sample: Previous={rt112_all[0]:.4f}s, RC119={rt119_all[0]:.4f}s")

# Let's find largest runtime improvement/regression sample-by-sample
rt_diffs = []
for sid in d119.keys():
    if sid in d112c and d119[sid]['engine_s'] > 0 and d112c[sid]['engine_s'] > 0:
        diff = d119[sid]['engine_s'] - d112c[sid]['engine_s']
        rt_diffs.append((sid, d119[sid]['repo'], d119[sid]['cwe'], diff))

rt_diffs.sort(key=lambda x: x[3])
print(f"Largest runtime improvement: Sample {rt_diffs[0][0]} ({rt_diffs[0][1]}, {rt_diffs[0][2]}): {rt_diffs[0][3]:.2f}s")
print(f"Largest runtime regression: Sample {rt_diffs[-1][0]} ({rt_diffs[-1][1]}, {rt_diffs[-1][2]}): {rt_diffs[-1][3]:+.2f}s")
