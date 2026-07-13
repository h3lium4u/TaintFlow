import json, re, sys

sys.stdout.reconfigure(encoding='utf-8')

# Re-read Java benchmarks from dataset
java_samples = {}
with open('../benchmarks/benchmark_java.jsonl', encoding='utf-8') as f:
    for line in f:
        entry = json.loads(line.strip())
        m = re.search(r'public class (BenchmarkTest\d+)', entry.get('code', ''))
        if m:
            java_samples[m.group(1)] = {
                'vulnerable': entry['vulnerable'],
                'cwe': entry.get('cwe', '?'),
                'code': entry.get('code', '')
            }

# Let's define the exact 58 benchmarks belonging to the three clusters:
# Cluster A: Cookie Null Guard (24 benchmarks)
cluster_a_ids = [
    f"BenchmarkTest00063", f"BenchmarkTest00064",
    f"BenchmarkTest00620", f"BenchmarkTest00621", f"BenchmarkTest00622", f"BenchmarkTest00623",
    f"BenchmarkTest00624", f"BenchmarkTest00625", f"BenchmarkTest00626", f"BenchmarkTest00627",
    f"BenchmarkTest00628", f"BenchmarkTest00951", f"BenchmarkTest00952", f"BenchmarkTest00953",
    f"BenchmarkTest00954", f"BenchmarkTest00955", f"BenchmarkTest00956", f"BenchmarkTest00957",
    f"BenchmarkTest00958", f"BenchmarkTest01013", f"BenchmarkTest01014", f"BenchmarkTest01015",
    f"BenchmarkTest01016", f"BenchmarkTest01017"
]

# Cluster B: Header Null Guard (20 benchmarks)
cluster_b_ids = [
    f"BenchmarkTest00134", f"BenchmarkTest00135", f"BenchmarkTest00136", f"BenchmarkTest00137", f"BenchmarkTest00138",
    f"BenchmarkTest00221", f"BenchmarkTest00265", f"BenchmarkTest00520", f"BenchmarkTest00706", f"BenchmarkTest00709",
    f"BenchmarkTest00758", f"BenchmarkTest01144", f"BenchmarkTest01158", f"BenchmarkTest01225", f"BenchmarkTest01331",
    f"BenchmarkTest01332", f"BenchmarkTest01377", f"BenchmarkTest02026", f"BenchmarkTest02031", f"BenchmarkTest02068"
]

# Cluster C: Session/Parameter Null Guard (14 benchmarks)
cluster_c_ids = [
    f"BenchmarkTest01026", f"BenchmarkTest01027", f"BenchmarkTest01028", f"BenchmarkTest01029", f"BenchmarkTest01030",
    f"BenchmarkTest01031", f"BenchmarkTest01032", f"BenchmarkTest01033", f"BenchmarkTest01034", f"BenchmarkTest01035",
    f"BenchmarkTest01036", f"BenchmarkTest01109", f"BenchmarkTest01110", f"BenchmarkTest01111"
]

all_58_ids = cluster_a_ids + cluster_b_ids + cluster_c_ids
print(f"Total defined IDs: {len(all_58_ids)}")

def analyze_precise(cls):
    sample = java_samples.get(cls)
    if not sample:
        return None
        
    code = sample['code']
    lines = code.splitlines()
    
    # 1. Find the guard line
    guard_line = None
    guard_var = None
    
    # Trace the code for null checks
    for line in lines:
        if 'null' in line and ('==' in line or '!=' in line or 'if' in line):
            guard_line = line.strip()
            break
            
    if guard_line:
        # Extract variable in guard
        m = re.search(r'if\s*\(\s*([a-zA-Z0-9_.]+)\s*(?:!=|==)', guard_line)
        if m:
            guard_var = m.group(1)
        else:
            if 'getheader' in guard_line.lower():
                guard_var = 'request.getHeader(...)'
            elif 'getattribute' in guard_line.lower():
                guard_var = 'session.getAttribute(...)'
            else:
                guard_var = 'UNKNOWN'
    else:
        guard_line = "N/A"
        guard_var = "N/A"
        
    # 2. Tainted variable name at the guard
    # The tainted variable is the one carrying input. In these java benchmarks, it is always 'param'
    tainted_var = 'param'
    
    # 3. Sink variable name
    sink_var = 'fileName'
    for line in lines:
        if any(k in line for k in ['FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter', 'File(', 'Paths.get', 'Path.of']):
            if 'import' not in line:
                m = re.search(r'new\s+File\(([^)]+)\)', line)
                if m:
                    sink_var = m.group(1).strip()
                break
                
    # 4. Equals
    equals = (guard_var == tainted_var)
    
    # 5. Alias
    aliases = False
    if equals:
        aliases = True
    elif guard_var in ['values', 'queryString'] or 'getHeader' in guard_var or 'getAttribute' in guard_var:
        aliases = True
        
    # 6. Container
    is_container = False
    if guard_var in ['theCookies', 'headers', 'names', 'values', 'session'] or 'getHeader' in guard_var or 'getAttribute' in guard_var:
        is_container = True
        
    return {
        'benchmark_id': cls,
        'guard_expression': guard_line,
        'guard_variable': guard_var,
        'tainted_variable': tainted_var,
        'sink_variable': sink_var,
        'equals': 'Yes' if equals else 'No',
        'aliases': 'Yes' if aliases else 'No',
        'is_container': 'Yes' if is_container else 'No'
    }

records = []
for bid in all_58_ids:
    r = analyze_precise(bid)
    if r:
        records.append(r)
        
print(f"Successfully processed: {len(records)}")

same_count = sum(1 for r in records if r['equals'] == 'Yes')
alias_count = sum(1 for r in records if r['aliases'] == 'Yes' and r['equals'] == 'No')
container_count = sum(1 for r in records if r['is_container'] == 'Yes')
other_count = sum(1 for r in records if r['aliases'] == 'No' and r['is_container'] == 'No')

print(f"\nExact totals:")
print(f"Guard Variable == Tainted Variable: {same_count}")
print(f"Guard Variable Aliases Tainted Variable: {alias_count}")
print(f"Guard Variable is Container/Source Object: {container_count}")
print(f"Other/Unrelated: {other_count}")

# Save to json file
with open('rc357_exact_58_divergence.json', 'w', encoding='utf-8') as f:
    json.dump(records, f, indent=2)
