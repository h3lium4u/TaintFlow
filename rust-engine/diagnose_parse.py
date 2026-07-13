import json, sys, re
sys.stdout.reconfigure(encoding='utf-8')

# Quick check on what parse failures look like
samples = []
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (\w+)', entry.get('code', ''))
        cls = m.group(1) if m else 'UNKNOWN'
        if not entry['vulnerable'] and entry.get('cwe', '') == 'CWE-22':
            samples.append({'class': cls, 'code': entry['code']})

print('Safe CWE-22 Java samples:', len(samples))

# Show examples of different source patterns
SOURCE_PATTERNS = [
    (r'(\w+)\s*=\s*request\.getParameter', 'getParameter'),
    (r'(\w+)\s*=\s*.*URLDecoder\.decode', 'URLDecoder'),
    (r'(\w+)\s*=\s*.*theCookie\.getValue', 'cookie.getValue'),
    (r'(\w+)\s*=\s*.*getHeader\s*\(', 'getHeader'),
    (r'(\w+)\s*=\s*.*headers\.nextElement', 'headers.nextElement'),
    (r'(\w+)\s*=\s*.*getAttribute\s*\(', 'getAttribute'),
    (r'(\w+)\s*=\s*.*getQueryString', 'getQueryString'),
    (r'(\w+)\s*=\s*.*getRequestURI', 'getRequestURI'),
    (r'(\w+)\s*=\s*.*getPathInfo', 'getPathInfo'),
    (r'(\w+)\s*=\s*request\.getHeaders', 'getHeaders iter'),
    (r'(\w+)\s*=\s*.*name\s*;', 'assign from name'),
    (r'param\s*=\s*(.+);', 'param = X'),
    (r'String\s+param\s*=', 'String param'),
]

# Count which patterns fire
pattern_counts = {name: 0 for _, name in SOURCE_PATTERNS}
no_match = []

for s in samples:
    found = False
    for pat, name in SOURCE_PATTERNS:
        m = re.search(pat, s['code'])
        if m:
            pattern_counts[name] += 1
            found = True
            break
    if not found:
        no_match.append(s['class'])

print('\nSource pattern counts:')
for name, count in sorted(pattern_counts.items(), key=lambda x: -x[1]):
    if count > 0:
        print(f'  {name:<30}: {count}')

print(f'\nNo pattern matched: {len(no_match)}')
for cls in no_match[:10]:
    print(f'  {cls}')
    # Show first few code lines
    code = next(s['code'] for s in samples if s['class'] == cls)
    relevant = [l for l in code.splitlines() if l.strip() and not l.strip().startswith('*')]
    for l in relevant[5:15]:
        print(f'    {l[:120]}')
    print()
