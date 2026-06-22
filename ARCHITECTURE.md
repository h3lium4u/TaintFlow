# TaintFlow RC2 Architecture

**Version**: RC2  
**Engine**: Rust + Python ML  
**Date**: June 11, 2026

---

## 1. System Overview

TaintFlow RC2 is a production-grade static application security testing (SAST) tool built around a three-layer architecture:

1. **Rust Engine** — High-performance parsing, taint propagation, and feature extraction
2. **Python ML Layer** — LightGBM classifier trained on delta-encoded security features
3. **CLI / IDE Interface** — `taintflow.py` scanner + VS Code extension

```
┌─────────────────────────────────────────────────────────────────────┐
│                       TaintFlow RC2 Stack                           │
├──────────────────┬──────────────────────────────────────────────────┤
│   User Interface │  CLI (taintflow.py)  │  VS Code Extension        │
├──────────────────┼──────────────────────────────────────────────────┤
│   ML Layer       │  LightGBM RC2 (model_rc2.pkl / model_rc2.onnx)   │
├──────────────────┼──────────────────────────────────────────────────┤
│   Rust Engine    │  Parser → Normalizer → CFG → Symbols → Taint     │
│                  │  → Rules → Features → Delta Encoder               │
├──────────────────┴──────────────────────────────────────────────────┤
│   Source Code Input: Python (.py) / Java (.java)                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Parser Architecture (`crates/parser`)

The parser uses **tree-sitter** to generate concrete syntax trees (CSTs) for Python and Java. It normalizes the raw CST into a unified `AstNode` tree.

```
Source Code (string)
    │
    ├── Language Detection
    │     ├── Java keywords → tree-sitter-java grammar
    │     └── Default       → tree-sitter-python grammar
    │
    └── tree-sitter parse()
          │
          └── AstNode { id, kind, span, children, raw }
```

### Key `NodeKind` variants:
| Variant | Description |
| :--- | :--- |
| `FunctionDef` | Function / method definitions |
| `CallExpression` | Function calls (including method invocations) |
| `Assignment` | Variable assignments |
| `VariableDeclarator` | Java typed declarations |
| `IfStatement` | Conditional branches |
| `Identifier` | Variable / symbol references |
| `Literal` | String / numeric constants |
| `ReturnStatement` | Return values |
| `Import` | Module imports |

---

## 3. Normalizer (`crates/normalizer`)

The normalizer converts language-specific `AstNode` trees into a **unified `NormalizedNode` IR** that is language-agnostic.

Key transformations:
- Java `VariableDeclarator` → `TypeDeclaration` + `Assignment` block
- Java method calls (`obj.method(...)`) → unified `Call { callee: "obj.method", arguments }` 
- Python `setattr(obj, name, val)` → normalized `Assignment`
- Python `*args` / `**kwargs` → preserved as `star_args` / `kw_args` fields

The normalizer also builds a `type_table: HashMap<name, declared_type>` for downstream symbol resolution.

---

## 4. Symbol Table (`crates/symbols`)

The symbol table tracks variable declarations, scopes, and type information across the normalized AST.

```
NormalizedNode tree
    │
    └── SymbolTable.build()
          ├── Walks all Assignment nodes
          ├── Registers: name → SymbolEntry { declared_type, is_param, scope_depth }
          └── Resolves: function parameter typing (HttpServletRequest → taint source)
```

---

## 5. CFG Builder (`crates/cfg`)

The Control Flow Graph builder constructs a directed graph of basic blocks representing all possible execution paths through a function.

```
NormalizedNode tree
    │
    └── CfgBuilder.build()
          ├── Block { id, stmts: Vec<NormalizedNode> }
          ├── Entry block → statement blocks
          ├── If/else branching → two outgoing edges
          └── ControlFlowGraph { blocks, edges, entry }
```

The CFG is used by the feature engine to compute path metrics (cycle count, longest path, branching ratio).

---

## 6. Taint Engine (`crates/taint`)

The taint engine performs **interprocedural taint propagation** from known source patterns to known sinks.

```
Sources (seed taint):
    Python: input(), request.args[], sys.argv[], os.environ[]
    Java:   request.getParameter(), getHeader(), getQueryString()

Propagation:
    Assignment: if RHS is tainted → LHS becomes tainted
    Call args:  if any arg is tainted → propagate to return value

Sinks (validated paths):
    Python: cursor.execute(), os.system(), subprocess.run(), open(), pickle.loads(), requests.get()
    Java:   stmt.execute(), stmt.executeQuery(), Runtime.exec(), new File(), ObjectInputStream()

Output:
    tainted_symbols: HashMap<name, TaintState { tainted, sanitized_for }>
    validated_paths: Vec<TaintPath { source, sink, path_nodes }>
```

---

## 7. Rule Engine (`crates/rules`)

The rule engine evaluates pattern-based security rules against the normalized AST + taint analysis results.

| Rule | CWE | Trigger |
| :--- | :--- | :--- |
| `sql_injection` | CWE-89 | Tainted var reaches `execute()` / `executeQuery()` |
| `command_injection` | CWE-78 | Tainted var reaches `os.system()` / `Runtime.exec()` |
| `path_traversal` | CWE-22 | Tainted var reaches `open()` / `new File()` |
| `ssrf` | CWE-918 | Tainted var reaches `requests.get()` / `URLConnection` |
| `unsafe_deserialization` | CWE-502 | Tainted reaches `pickle.loads()` / `ObjectInputStream` |
| `hardcoded_credentials` | CWE-798 | Assignment of secret-keyword var to string literal |
| `weak_crypto` | CWE-327 | Call to `md5()`, `sha1()`, `DES`, `RC4` |

---

## 8. Feature Engine (`crates/features`)

The feature engine computes a **50-dimensional absolute feature vector** from the analysis results.

| Index Range | Category |
| :--- | :--- |
| feat_0 | Source count |
| feat_1 | Sink count |
| feat_2 | Validated taint paths count |
| feat_3 | Unique tainted symbols |
| feat_4 | Total AST nodes |
| feat_5 | Sanitizer count |
| feat_6–feat_8 | Taint depth (min, max, mean) |
| feat_9–feat_11 | CFG branching ratios |
| feat_12–feat_17 | CFG path metrics |
| feat_18–feat_35 | AST node type frequency histogram |
| feat_36–feat_47 | Security keyword density |
| feat_48 | Total findings count |
| feat_49 | Unique CWE count |

---

## 9. Delta Encoding Pipeline (Python)

The delta encoder transforms pairs of absolute feature vectors (before/after patch) into a **60-dimensional delta representation** for model training and inference.

```
(before_vector[50], after_vector[50])
    │
    ├── Core delta: after[i] - before[i]  →  36 active structural deltas
    │
    └── RC2 Security Deltas (12 features):
          taint_paths_added / removed
          sources_added / removed
          sinks_added / removed
          sanitizers_added / removed
          findings_added / removed
          CWE_added / removed
```

---

## 10. ML Pipeline

```
Delta Feature Vector (60-dim)
    │
    ├── Training: LightGBM Classifier
    │     ├── Dataset: V7 (9,130 pairs, 48 active features)
    │     ├── Validation: 5-fold GroupKFold (group by pair_id)
    │     └── Optimization: Optuna (100 trials)
    │
    └── Inference:
          ├── model_rc2.pkl  (scikit-learn wrapper, Python inference)
          └── model_rc2.onnx (ONNX Runtime, production inference)
```

---

## 11. ONNX Deployment Pipeline

```
model_rc2.pkl
    │
    └── skl2onnx.convert_sklearn()
          │
          └── model_rc2.onnx
                │
                ├── Python: onnxruntime.InferenceSession → run()
                └── Production: Any ONNX Runtime (C++/Java/JS)
```

The ONNX model accepts a float32 input of shape `[1, 48]` and returns class probabilities of shape `[1, 2]`.
