with open('d:/V2 Backup/rust-engine/RC119_FULL_GITHUB_VALIDATION_utf8.log', 'r', encoding='utf-8', errors='ignore') as f:
    lines = [l.strip() for l in f]

out = []
for idx, l in enumerate(lines):
    # filter out non-ascii characters
    l_clean = ''.join(c if ord(c) < 128 else '?' for c in l)
    if '[DIAGNOSTIC] GitHub Sample 54' in l or '[TIMING]' in l or '[ENGINE]' in l or '=== DIAGNOSTIC FOR' in l:
        if 'Paddle' in l or 'Sample 54' in l or (idx > 15800 and idx < 16300):
            out.append(f"{idx}: {l_clean}")

for line in out[:100]:
    print(line)
