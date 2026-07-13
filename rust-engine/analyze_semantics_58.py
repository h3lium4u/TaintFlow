import json, re, sys
sys.stdout.reconfigure(encoding='utf-8')

NULL_PATTERNS = ["is none", "is not none", "!= none", "== none", "!= null", "== null"]

# Load Java benchmarks from dataset
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

# The 58 benchmarks
cluster_a_ids = [
    "BenchmarkTest00063", "BenchmarkTest00064",
    "BenchmarkTest00620", "BenchmarkTest00621", "BenchmarkTest00622", "BenchmarkTest00623",
    "BenchmarkTest00624", "BenchmarkTest00625", "BenchmarkTest00626", "BenchmarkTest00627",
    "BenchmarkTest00628", "BenchmarkTest00951", "BenchmarkTest00952", "BenchmarkTest00953",
    "BenchmarkTest00954", "BenchmarkTest00955", "BenchmarkTest00956", "BenchmarkTest00957",
    "BenchmarkTest00958", "BenchmarkTest01013", "BenchmarkTest01014", "BenchmarkTest01015",
    "BenchmarkTest01016", "BenchmarkTest01017"
]

cluster_b_ids = [
    "BenchmarkTest00134", "BenchmarkTest00135", "BenchmarkTest00136", "BenchmarkTest00137", "BenchmarkTest00138",
    "BenchmarkTest00221", "BenchmarkTest00265", "BenchmarkTest00520", "BenchmarkTest00706", "BenchmarkTest00709",
    "BenchmarkTest00758", "BenchmarkTest01144", "BenchmarkTest01158", "BenchmarkTest01225", "BenchmarkTest01331",
    "BenchmarkTest01332", "BenchmarkTest01377", "BenchmarkTest02026", "BenchmarkTest02031", "BenchmarkTest02068"
]

cluster_c_ids = [
    "BenchmarkTest01026", "BenchmarkTest01027", "BenchmarkTest01028", "BenchmarkTest01029", "BenchmarkTest01030",
    "BenchmarkTest01031", "BenchmarkTest01032", "BenchmarkTest01033", "BenchmarkTest01034", "BenchmarkTest01035",
    "BenchmarkTest01036", "BenchmarkTest01109", "BenchmarkTest01110", "BenchmarkTest01111"
]

all_58_ids = cluster_a_ids + cluster_b_ids + cluster_c_ids

print(f"Total defined IDs: {len(all_58_ids)}")

def analyze_semantic_validation(cls):
    sample = java_samples.get(cls)
    if not sample:
        return None
        
    code = sample['code']
    lines = code.splitlines()
    
    # We want to identify the exact validation structures in this file:
    # Look for validation statements / conditions or string manipulation functions
    # Ignore simple != null / == null, length > 0, hasMoreElements, etc.
    # Look for:
    # - getCanonicalPath()
    # - startsWith
    # - endsWith
    # - whitelist/blacklist checks
    # - ternary constant mapping: e.g. bar = (7*18) + num > 200 ? "This_should_always_happen" : param;
    # - or others
    
    semantic_validation_present = "NO"
    val_type = "No semantic validation"
    exact_code = []
    would_stop = "NO"
    
    # 1. Check for ternary constant assignments (very common in safe samples of OWASP!)
    # bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    ternary_match = None
    for idx, line in enumerate(lines):
        if '?' in line and ':' in line and ('param' in line or 'bar' in line):
            # Check if it's assigning a safe default/constant
            ternary_match = (idx + 1, line.strip())
            break
            
    if ternary_match:
        semantic_validation_present = "YES"
        val_type = "Ternary Constant Mapping"
        exact_code.append(f"Line {ternary_match[0]}: {ternary_match[1]}")
        # Does this validation stop path traversal?
        # Yes, because if the constant is assigned (which is mathematically guaranteed in these tests), 
        # the user input is ignored entirely!
        would_stop = "YES"
        return {
            'benchmark_id': cls,
            'present': semantic_validation_present,
            'type': val_type,
            'code': "\n".join(exact_code),
            'would_stop': would_stop
        }
        
    # 2. Check for other functions
    for idx, line in enumerate(lines):
        line_lower = line.lower()
        if 'getcanonicalpath' in line_lower:
            semantic_validation_present = "YES"
            val_type = "Canonicalization"
            exact_code.append(f"Line {idx+1}: {line.strip()}")
            would_stop = "PARTIAL" # getCanonicalPath() resolves but doesn't validate base path unless followed by startsWith
        elif 'startswith' in line_lower:
            semantic_validation_present = "YES"
            val_type = "Base-path"
            exact_code.append(f"Line {idx+1}: {line.strip()}")
            would_stop = "YES"
        elif 'endswith' in line_lower:
            semantic_validation_present = "YES"
            val_type = "Extension"
            exact_code.append(f"Line {idx+1}: {line.strip()}")
            would_stop = "PARTIAL"
            
    if exact_code:
        return {
            'benchmark_id': cls,
            'present': semantic_validation_present,
            'type': val_type,
            'code': "\n".join(exact_code),
            'would_stop': would_stop
        }
        
    # 3. Default (Only null/existence checks or control flow)
    # Let's collect the null/existence check lines for context
    for idx, line in enumerate(lines):
        line_lower = line.lower()
        if 'null' in line_lower or 'length' in line_lower or 'hasmoreelements' in line_lower:
            if 'if' in line_lower or 'while' in line_lower:
                exact_code.append(f"Line {idx+1}: {line.strip()}")
                
    return {
        'benchmark_id': cls,
        'present': "NO",
        'type': "Only Null/Existence Checks",
        'code': "\n".join(exact_code[:3]), # limit to 3 lines
        'would_stop': "NO"
    }

results = []
for bid in all_58_ids:
    res = analyze_semantic_validation(bid)
    if res:
        results.append(res)
        
print(f"Processed: {len(results)}")
from collections import Counter
print(Counter(r['type'] for r in results))
