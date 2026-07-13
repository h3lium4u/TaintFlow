import re

print("Reading d:/V2 Backup/rust-engine/RC119_CLEAN.log...")
with open("d:/V2 Backup/rust-engine/RC119_CLEAN.log", "r", encoding="utf-8") as f:
    for i, line in enumerate(f):
        if any(term in line for term in ["finished", "iterations", "attempts", "invocations", "GitHub", "CWE"]):
            print(f"{i}: {line.strip()}")
            if i > 20000:
                print("Too many matches, stopping...")
                break
