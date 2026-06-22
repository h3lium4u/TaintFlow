# RC102B: Precision Hardening Roadmap & ROI Ranking

This document evaluates and ranks six proposed precision improvements for the TaintFlow engine based on implementation cost, time, and statistical impact.

## ROI Ranking Table

| Rank | Precision Improvement | Complexity | Eng. Time | FP Reduction | TP Loss Risk | GitHub MCC | Combined MCC | GitHub MCC Gain | Combined MCC Gain |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | **A) Sink Argument Gating** | Low | 1-2 days | **11** | Extremely Low | **0.3048** | **0.6106** | **+0.1570** | **+0.0055** |
| **2** | **C) Wrapper Propagation Refinement** | Medium | 5-7 days | **15** | Low | **0.3560** | **0.6127** | **+0.2082** | **+0.0076** |
| **3** | **D) Source Seeding Refinement** | Medium | 3-5 days | **13** | Low | **0.3307** | **0.6117** | **+0.1829** | **+0.0066** |
| **4** | **F) Field Sensitivity** | High | 3-4 weeks | **6** | Medium | **0.2373** | **0.6080** | **+0.0895** | **+0.0029** |
| **5** | **E) Alias Analysis** | Very High | 4-6 weeks | **6** | Medium-High | **0.2373** | **0.6080** | **+0.0895** | **+0.0029** |
| **6** | **B) Call-Site Context Sensitivity** | High | 2-3 weeks | **1** | Medium | **0.1636** | **0.6054** | **+0.0158** | **+0.0003** |

*Note: The combined baseline metrics are GitHub Precision = 0.5328, GitHub MCC = 0.1478, Combined Precision = 0.7627, Combined MCC = 0.6051.*

---

## Answers to Core Questions

### 1. What single change removes the most FPs?
**Wrapper Propagation Refinement** removes the most FPs (**15 FPs**), followed closely by **Source Seeding Refinement** (**13 FPs**). Together they address the engine's tendency to over-taint parameters of local helper methods and test frameworks.

### 2. What single change gives the biggest MCC increase?
**Wrapper Propagation Refinement** gives the largest single MCC increase, raising the GitHub MCC to **0.3560** (an increase of **+0.2082**).

### 3. What is the cheapest precision improvement?
**Sink Argument Gating** is by far the cheapest precision improvement. It requires only 1-2 days of engineering effort to refine the parameter indices of standard sinks (`open`, `subprocess.run`, `torch.load`), yet it eliminates **11 FPs** and yields a massive **+0.1570 GitHub MCC gain** with **zero TP loss risk**.

### 4. Is call-site context sensitivity justified before v1.0.0-beta?
**No**. Call-site context sensitivity (1-CFA) is extremely complex to implement and only resolves **1 FP** in the entire GitHub Holdout dataset. Developing 1-CFA before beta release is not justified when simpler refinements can eliminate over 70% of the FPs in a fraction of the time.

### 5. What precision is realistically achievable without alias analysis?
Without alias analysis, we can resolve **47 out of 53 FPs** (excluding only the 6 `FIELD_INSENSITIVE_PROPAGATION` cases). This yields a realistic maximum GitHub Precision of **0.8784** (65 / (65 + 9)) and a GitHub MCC of **0.6725**.

### 6. What GitHub MCC is realistically achievable under the current architecture?
Under the current architecture, by implementing Sink Argument Gating, Wrapper Propagation Refinement, and Source Seeding Refinement (which do not require changing the underlying CFG or alias engine), we can remove **39 FPs** (11 + 15 + 13). This reduces the GitHub FP count to 18, raising the GitHub Precision to **0.7831** (65 / 83) and the GitHub MCC to **0.5519**.

### 7. Recommend RC103.
For **RC103**, we recommend implementing **Sink Argument Gating** and **Source Seeding Refinement** (specifically ignoring automatic parameter source seeding in files with a `test_` prefix or `Test` class names). These two low-complexity changes will eliminate **24 FPs**, raising GitHub Precision to **0.6633** and GitHub MCC to **0.4357** in less than a week of engineering effort.
