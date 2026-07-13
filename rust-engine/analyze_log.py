import re, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

LOG = "d:/V2 Backup/rust-engine/RC119_FULL_GITHUB_VALIDATION.log"
with open(LOG, "r", encoding="utf-16le", errors="replace") as f:
    lines = [l.rstrip('\r\n') for l in f.readlines()]
N = len(lines)

# Find the first GitHub DIAGNOSTIC line
diag_re = re.compile(r'\[DIAGNOSTIC\] GitHub Sample (\d+): cwe=(\S+) vulnerable=(\S+) pred=(\S+)')
first_github_diag_line = None
for i, l in enumerate(lines):
    if diag_re.search(l):
        first_github_diag_line = i
        break

print(f"First GitHub DIAGNOSTIC at line: {first_github_diag_line}")

# Aggregate all propagation stats from GitHub samples only (after first GitHub diag)
# Each block: ENGINE -> PROP STATS (CFG/ReceiverField/ReturnScan/Call/Exception/ArrayContainer/Initial)
# -> PRODUCTIVITY -> HOTSPOTS -> TIMING -> DIAGNOSTIC

# Extract all PROP STATS blocks after the first GitHub DIAGNOSTIC
# Actually, the ENGINE+PROP STATS for sample N appears BEFORE sample N's DIAGNOSTIC
# So we need all blocks that come AFTER first_github_diag_line - 10000 (rough)
# Better: Find all blocks in the ENTIRE log after line 16000 (GitHub section)

github_section_start = first_github_diag_line - 200  # Include the first block's ENGINE

# Parse all SOLVER PROPAGATION STATISTICS blocks in the github section
prop_blocks = []
i = github_section_start
while i < N:
    if 'SOLVER PROPAGATION STATISTICS' in lines[i]:
        block = {'line': i}
        j = i + 1
        current_cat = None
        while j < N and 'SOLVER PROPAGATION STATISTICS' not in lines[j] and '=== DIAGNOSTIC' not in lines[j]:
            l = lines[j].strip()
            if l == 'CFG:': current_cat = 'cfg'
            elif l == 'Receiver-field:': current_cat = 'rcv'
            elif l == 'Return scan:': current_cat = 'ret'
            elif l == 'Call:': current_cat = 'call'
            elif l == 'Exception:': current_cat = 'exc'
            elif l == 'Array container:': current_cat = 'arr'
            elif l == 'Initial:': current_cat = 'init'
            elif l.startswith('attempts:'):
                block[f'{current_cat}_attempts'] = int(l.split(':')[1].strip())
            elif l.startswith('enqueued:'):
                block[f'{current_cat}_enqueued'] = int(l.split(':')[1].strip())
            elif l.startswith('duplicates:'):
                block[f'{current_cat}_duplicates'] = int(l.split(':')[1].strip())
            elif l.startswith('insertions:'):
                block[f'{current_cat}_insertions'] = int(l.split(':')[1].strip())
            j += 1
        block['end_line'] = j
        if 'cfg_attempts' in block:
            prop_blocks.append(block)
        i = j
    else:
        i += 1

print(f"Total SOLVER PROP STATS blocks found in github section: {len(prop_blocks)}")

# Also parse productivity blocks
prod_blocks = []
i = github_section_start
while i < N:
    if 'Total invocations:' in lines[i] and 'Average' not in lines[i]:
        block = {'line': i}
        m = re.search(r'Total invocations: (\d+)', lines[i])
        if m: block['total'] = int(m.group(1))
        for j in range(i+1, min(i+25, N)):
            l = lines[j].strip()
            m2 = re.search(r'Empty invocations: (\d+)', l)
            if m2: block['empty'] = int(m2.group(1))
            m2 = re.search(r'Non-empty invocations: (\d+)', l)
            if m2: block['nonempty'] = int(m2.group(1))
            m2 = re.search(r'Total variables produced: (\d+)', l)
            if m2: block['vars'] = int(m2.group(1))
            m2 = re.search(r'Return expression matched: (\d+)', l)
            if m2: block['re_matched'] = int(m2.group(1))
            m2 = re.search(r'Return expression checked: (\d+)', l)
            if m2: block['re_checked'] = int(m2.group(1))
            m2 = re.search(r'Parameter lookup matched: (\d+)', l)
            if m2: block['pm_matched'] = int(m2.group(1))
            m2 = re.search(r'Parameter lookup attempted: (\d+)', l)
            if m2: block['pm_attempted'] = int(m2.group(1))
            m2 = re.search(r'Receiver lookup matched: (\d+)', l)
            if m2: block['rv_matched'] = int(m2.group(1))
            m2 = re.search(r'Receiver lookup attempted: (\d+)', l)
            if m2: block['rv_attempted'] = int(m2.group(1))
            m2 = re.search(r'Destination present: (\d+)', l)
            if m2: block['dest_present'] = int(m2.group(1))
            m2 = re.search(r'Destination absent: (\d+)', l)
            if m2: block['dest_absent'] = int(m2.group(1))
        if 'total' in block:
            prod_blocks.append(block)
        i += 25
    else:
        i += 1

print(f"Total PRODUCTIVITY blocks found: {len(prod_blocks)}")

# Aggregate all prop blocks
def agg(blocks, field, default=0):
    return sum(b.get(field, default) for b in blocks)

print(f"\n=== AGGREGATED PROPAGATION STATS (all {len(prop_blocks)} blocks) ===")
for cat, name in [('cfg','CFG'),('rcv','ReceiverField'),('ret','Return'),
                   ('call','Call'),('exc','Exception'),('arr','ArrayContainer'),('init','Initial')]:
    a = agg(prop_blocks, f'{cat}_attempts')
    e = agg(prop_blocks, f'{cat}_enqueued')
    d = agg(prop_blocks, f'{cat}_duplicates')
    ii = agg(prop_blocks, f'{cat}_insertions')
    pct = d*100/a if a > 0 else 0
    print(f"  {name:<18}: attempts={a:>12,}  enqueued={e:>12,}  dup={d:>12,}  ins={ii:>12,}  dup%={pct:.1f}%")

print(f"\n=== AGGREGATED PRODUCTIVITY (all {len(prod_blocks)} blocks) ===")
total_inv = agg(prod_blocks, 'total')
empty_inv = agg(prod_blocks, 'empty')
nonempty_inv = agg(prod_blocks, 'nonempty')
total_vars = agg(prod_blocks, 'vars')
re_checked = agg(prod_blocks, 're_checked')
re_matched = agg(prod_blocks, 're_matched')
pm_attempted = agg(prod_blocks, 'pm_attempted')
pm_matched = agg(prod_blocks, 'pm_matched')
rv_attempted = agg(prod_blocks, 'rv_attempted')
rv_matched = agg(prod_blocks, 'rv_matched')
dest_present = agg(prod_blocks, 'dest_present')
dest_absent = agg(prod_blocks, 'dest_absent')

print(f"  Total invocations:              {total_inv:>12,}")
print(f"  Empty invocations:              {empty_inv:>12,}  ({empty_inv*100/total_inv if total_inv else 0:.1f}%)")
print(f"  Non-empty invocations:          {nonempty_inv:>12,}  ({nonempty_inv*100/total_inv if total_inv else 0:.1f}%)")
print(f"  Total variables produced:       {total_vars:>12,}")
avg_per_nonempty = total_vars / nonempty_inv if nonempty_inv else 0
avg_per_inv = total_vars / total_inv if total_inv else 0
print(f"  Avg vars per non-empty:         {avg_per_nonempty:>12.4f}")
print(f"  Avg vars per invocation:        {avg_per_inv:>12.4f}")
print(f"  Return expression checked:      {re_checked:>12,}")
print(f"  Return expression matched:      {re_matched:>12,}  ({re_matched*100/re_checked if re_checked else 0:.1f}%)")
print(f"  Parameter lookup attempted:     {pm_attempted:>12,}")
print(f"  Parameter lookup matched:       {pm_matched:>12,}  ({pm_matched*100/pm_attempted if pm_attempted else 0:.1f}%)")
print(f"  Receiver lookup attempted:      {rv_attempted:>12,}")
print(f"  Receiver lookup matched:        {rv_matched:>12,}  ({rv_matched*100/rv_attempted if rv_attempted else 0:.1f}%)")
print(f"  Destination present:            {dest_present:>12,}")
print(f"  Destination absent:             {dest_absent:>12,}")
