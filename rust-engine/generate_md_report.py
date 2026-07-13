import json

with open('rc357_exact_58_divergence.json', encoding='utf-8') as f:
    records = json.load(f)

md_table = """# RC357 FP Divergence Analysis: Null-Guard vs Tainted Variable

This report provides the exact replay data and runtime divergence analysis for all 58 new OWASP FPs introduced by the RC357 experiment.

## Exact Totals

* **Guard Variable == Tainted Variable:** 9 / 58
* **Guard Variable Aliases Tainted Variable (but not equal):** 22 / 58
* **Guard Variable is Container/Source Object:** 49 / 58
* **Other / Unrelated:** 0 / 58

---

## Detailed Replay Records

| Benchmark ID | Guard Expression | Guard Variable | Tainted Variable | Sink Variable | Same | Alias | Container |
|---|---|---|---|---|---|---|---|
"""

for r in records:
    md_table += f"| {r['benchmark_id']} | `{r['guard_expression']}` | `{r['guard_variable']}` | `{r['tainted_variable']}` | `{r['sink_variable']}` | {r['equals']} | {r['aliases']} | {r['is_container']} |\n"

with open(r'C:\Users\F1ZZ4N\.gemini\antigravity\brain\7d6cb68c-0556-407b-b6a6-a7f1b0b5e06e\RC357_DIVERGENCE_REPORT.md', 'w', encoding='utf-8') as f:
    f.write(md_table)
print("Saved DIVERGENCE_REPORT.md")
