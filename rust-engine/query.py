import json

path = "d:/V2 Backup/datasets/processed/external_holdout.jsonl"
with open(path, "r", encoding="utf-8") as f:
    for i, line in enumerate(f):
        obj = json.loads(line)
        repo = obj.get("repo", "")
        if "salt" in repo or "transformers" in repo or "pygeoapi" in repo:
            print(f"Index: {i}")
            print(f"  Repo: {repo}")
            print(f"  CWE: {obj.get('cwe')}")
            print(f"  Commit: {obj.get('commit')}")
            print(f"  File: {obj.get('target_file')}")
            print()
