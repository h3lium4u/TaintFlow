import subprocess

def save_git_diff(file_path, output_name):
    try:
        res = subprocess.run(
            ['git', 'diff', file_path],
            cwd='d:/V2 Backup',
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        with open(output_name, 'w', encoding='utf-8') as f:
            f.write(res.stdout)
        print(f"Diff for {file_path} saved to {output_name} ({len(res.stdout)} chars)")
    except Exception as e:
        print(f"Error saving diff for {file_path}: {e}")

save_git_diff('rust-engine/crates/cfg/src/icfg.rs', 'icfg_diff.txt')
save_git_diff('rust-engine/crates/cli/src/v2_validation.rs', 'v2_validation_diff.txt')
save_git_diff('rust-engine/crates/ir/src/lib.rs', 'ir_lib_diff.txt')
save_git_diff('rust-engine/crates/taint/src/interproc.rs', 'interproc_diff.txt')
