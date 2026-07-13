import os

def summarize_diff(diff_path):
    if not os.path.exists(diff_path):
        print(f"{diff_path} does not exist")
        return
    with open(diff_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        
    print(f"\n=== SUMMARY OF {diff_path} ===")
    added_lines = 0
    removed_lines = 0
    modified_funcs = []
    
    for l in lines:
        if l.startswith('+') and not l.startswith('+++'):
            added_lines += 1
        elif l.startswith('-') and not l.startswith('---'):
            removed_lines += 1
        elif l.startswith('@@'):
            # extract function context
            parts = l.strip().split('@@')
            if len(parts) > 2:
                func = parts[2].strip()
                if func and func not in modified_funcs:
                    modified_funcs.append(func)
                    
    print(f"Added lines: {added_lines}")
    print(f"Removed lines: {removed_lines}")
    print("Modified functions/scopes:")
    for f in modified_funcs:
        print(f"  {f}")

summarize_diff('icfg_diff.txt')
summarize_diff('v2_validation_diff.txt')
summarize_diff('ir_lib_diff.txt')
summarize_diff('interproc_diff.txt')
