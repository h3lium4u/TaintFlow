import re

def parse_time_to_seconds(val_str, unit_str):
    val = float(val_str)
    if unit_str == 's':
        return val
    elif unit_str == 'ms':
        return val / 1000.0
    elif unit_str in ['us', 'μs', 'ms']: # some logs use 'us' or 'μs'
        return val / 1000000.0
    return val

def parse_log(path, is_utf16=False):
    enc = 'utf-16' if is_utf16 else 'utf-8'
    with open(path, 'r', encoding=enc, errors='ignore') as f:
        lines = [l.strip() for l in f]
    
    diags = {}
    
    diag_re = re.compile(r'\[DIAGNOSTIC\] GitHub Sample (\d+): cwe=(\S+) vulnerable=(\S+) pred=(\S+)')
    timing_re = re.compile(r'\[TIMING\] repo=(\S+) cwe=(\S+) .*?engine=([\d.]+)(s|ms|us|μs) nodes=(\d+)')
    eng_re = re.compile(r'\[ENGINE\] finished after (\d+) iterations')
    
    # We will trace backward from each diagnostic to find the timing and engine iterations
    diag_indices = []
    for idx, l in enumerate(lines):
        m = diag_re.search(l)
        if m:
            sid = int(m.group(1))
            diag_indices.append((sid, idx, m))
            
    diag_indices.sort(key=lambda x: x[1])
    
    prev_idx = 0
    for sid, idx, m in diag_indices:
        cwe = m.group(2)
        vuln = m.group(3) == 'true'
        pred = m.group(4) == 'true'
        
        # Search backward from idx to prev_idx for TIMING and ENGINE
        timing = None
        engine = None
        for j in range(idx - 1, prev_idx - 1, -1):
            if not timing:
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
            if not engine:
                m_e = eng_re.search(lines[j])
                if m_e:
                    engine = {
                        'iters': int(m_e.group(1))
                    }
            if timing and engine:
                break
        
        # If we didn't find timing within this block, let's look further back up to 100 lines
        if not timing:
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
                    
        if not engine:
            for j in range(idx - 1, max(0, idx - 100), -1):
                m_e = eng_re.search(lines[j])
                if m_e:
                    engine = {
                        'iters': int(m_e.group(1))
                    }
                    break
        
        diags[sid] = {
            'cwe': cwe,
            'vuln': vuln,
            'pred': pred,
            'repo': timing['repo'] if timing else 'UNKNOWN',
            'engine_s': timing['engine_s'] if timing else 0.0,
            'iters': engine['iters'] if engine else 0,
            'nodes': timing['nodes'] if timing else 0
        }
        prev_idx = idx
        
    return diags

d112c = parse_log('d:/V2 Backup/rust-engine/RC112C_OWASP_VALIDATION.log', is_utf16=True)
d119 = parse_log('d:/V2 Backup/rust-engine/RC119_FULL_GITHUB_VALIDATION_utf8.log', is_utf16=False)

print(f"RC112C keys: {len(d112c)}")
print(f"RC119 keys: {len(d119)}")

changes = []
for sid in sorted(d119.keys()):
    if sid in d112c:
        v119, p119 = d119[sid]['vuln'], d119[sid]['pred']
        v112, p112 = d112c[sid]['vuln'], d112c[sid]['pred']
        
        c119 = 'TP' if v119 and p119 else 'FP' if not v119 and p119 else 'TN' if not v119 and not p119 else 'FN'
        c112 = 'TP' if v112 and p112 else 'FP' if not v112 and p112 else 'TN' if not v112 and not p112 else 'FN'
        
        if c119 != c112:
            changes.append((sid, d119[sid]['repo'], d119[sid]['cwe'], c112, c119, d112c[sid]['engine_s'], d119[sid]['engine_s'], d112c[sid]['iters'], d119[sid]['iters']))

print(f"Total differences: {len(changes)}")
for sid, repo, cwe, prev, rc119, prev_rt, rc119_rt, prev_it, rc119_it in changes:
    print(f"Sample {sid}: Repo={repo}, CWE={cwe}, Change={prev} -> {rc119}, Runtime: {prev_rt:.4f}s -> {rc119_rt:.4f}s, Iters: {prev_it} -> {rc119_it}")
