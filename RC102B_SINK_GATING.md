# RC102B: Sink Argument Gating Study

This study audits all False Positives in the casebook to evaluate the precision impact of refining sink argument taint sensitivity.

## Sink Audits & Parameter Specifics

| Sink Pattern | Current Behavior | Proposed Gated Behavior | FPs Resolved | Affected Cases |
| :--- | :--- | :--- | :---: | :--- |
| `open(path, mode)` & `os.open(...)` | Taints entire call if *any* argument is tainted. | Only taint-sensitive on the first argument (index `0` / `path`). Ignore `mode`/`flags` parameters. | **8 FPs** | Salt (Cases #39, #40, #43, #44, #48), Snowflake (Case #13, #15, #17) |
| `subprocess.run(...)` & `Popen(...)` | Flags any call with a list argument. | For list-based commands, only trigger CWE-78 if `shell=True` is explicitly passed. | **1 FP** | BinderHub (Case #10) |
| `torch.load(...)` | Flags all calls as CWE-502. | Do not flag as sink if the safety parameter `weights_only=True` is passed. | **2 FPs** | Transformers (Cases #35, #37) |
| `requests(...)` & `urllib(...)` | Flags any call. | URL argument remains sensitive. (No gating benefit for CWE-918 since URLs are indeed tainted). | **0 FPs** | Fides (Cases #4, #5, #6, #8, #9) |
| `yaml.load(...)` | Flags any call. | Unsafe load remains sensitive. (No FPs currently caused by yaml). | **0 FPs** | None |

## Estimated Impact

- **Total FP Reduction**: **11 FPs** (8 from `open` mode, 1 from `subprocess`, 2 from `torch.load`).
- **Precision Improvement**: GitHub Precision increases from **0.5328** to **0.5856**.
- **GitHub MCC Gain**: MCC increases from **0.1478** to **0.2970** (+0.1492).
- **TP Loss Risk**: **Zero**. Gating file mode/flags parameters or validating `weights_only=True` / non-shell subprocess parameters does not compromise legitimate exploit path tracking.
