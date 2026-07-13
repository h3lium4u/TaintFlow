
import sys, json
from collections import Counter
sys.stdout.reconfigure(encoding='utf-8')

bench_path = r'D:\V2 Backup\benchmarks\benchmark_java.jsonl'
java_samples = []
with open(bench_path, 'r', errors='ignore') as f:
    for line in f:
        try:
            obj = json.loads(line.strip())
            java_samples.append(obj)
        except:
            pass

# KEY FINDINGS:
# 1. getCookies_enhanced_for: 314 total vulnerable samples (across taint CWEs)
#    But CWE-330 has 218 of these -> all detected by semantic rules!
#    So getCookies_enhanced_for for TAINT CWEs (not 330) = 314 - 218 = 96
#    These 96 are: CWE-22(16) + CWE-89(31) + CWE-78(11) + CWE-501(9) + CWE-614(3) + CWE-90(4) + CWE-643(2) = 76
#    Wait: 314-218=96 but 16+31+11+9+3+4+2=76. Remaining 20 are in CWE-327(10)+CWE-328(10) 
#    (also detected by semantic rules).
#    Actual taint-dependent getCookies_enhanced_for = 76 samples
#
# 2. Enumeration_propagation: 161 total
#    For taint CWEs: CWE-22(24) + CWE-79(27) + CWE-89(22) + CWE-78(16) + CWE-501(13) + CWE-614(7) + CWE-643(3) + CWE-90(6) = 118
#    (Excluding CWE-327(24) and CWE-328(19) which are semantic-detected)
#
# 3. getQueryString: 125 total 
#    For taint CWEs (excluding 327/328/330): CWE-22(15)+CWE-79(35)+CWE-89(36)+CWE-78(10)+CWE-501(8)+CWE-643(1)+CWE-90(0) = 105
#
# 4. HashMap_propagation: 119 total
#    For taint CWEs: CWE-22(10)+CWE-79(33)+CWE-89(16)+CWE-78(12)+CWE-501(9)+CWE-614(1)+CWE-643(1)+CWE-90(2) = 84
#    (CWE-327(21)+CWE-328(14) semantic)
#
# Now correlate with which ones are FN:
# Total FN=196. Breakdown by category:
# CWE-328 structural (SHA512): 40 FNs
# Python FNs: 172 vuln Python, some FNs there
# Java FNs = 196 - Python FNs

# Check Python FN contribution
py_path = r'D:\V2 Backup\benchmarks\benchmark_python.jsonl'
py_samples = []
with open(py_path, 'r', errors='ignore') as f:
    for line in f:
        try:
            obj = json.loads(line.strip())
            py_samples.append(obj)
        except:
            pass

py_vuln = [s for s in py_samples if s.get('vulnerable', False)]
py_nv = [s for s in py_samples if not s.get('vulnerable', False)]

print(f'Python: {len(py_vuln)} vuln, {len(py_nv)} nv')
cwe_py_vuln = Counter(s.get('cwe', '?') for s in py_vuln)
print('Python vuln by CWE:', dict(sorted(cwe_py_vuln.items())))

# Python CWE-327 (71 vuln): hashlib.md5 / hashlib.sha1 -> semantic rules detect
# Python CWE-22 (65 vuln): os.path traversal -> taint analysis
# Python CWE-78 (13 vuln): subprocess -> taint analysis
# Python CWE-89 (5 vuln): SQL injection -> taint analysis
# Python CWE-502 (18 vuln): pickle -> should be in stubs/semantic rules

# CWE-502 detection?
with open(r'D:\V2 Backup\rust-engine\crates\semantic_rules\src\lib.rs', 'r') as f:
    sem = f.read()
print('CWE-502 in semantic_rules:', 'CWE-502' in sem or 'CWE502' in sem or 'pickle' in sem)

with open(r'D:\V2 Backup\rust-engine\crates\taint\src\stubs.rs', 'r') as f:
    stubs = f.read()
print('pickle in stubs.rs:', 'pickle' in stubs.lower())

# Check sample Python CWE-502
cwe502 = [s for s in py_vuln if s.get('cwe', '') == 'CWE-502']
if cwe502:
    code = cwe502[0].get('code', '')
    print('Python CWE-502 sample:')
    for l in code.splitlines()[:30]:
        print(' ', l.rstrip())
