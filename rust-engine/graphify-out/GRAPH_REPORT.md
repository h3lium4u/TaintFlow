# Graph Report - .  (2026-07-01)

## Corpus Check
- 67 files · ~75,359 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 663 nodes · 1530 edges · 66 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Interprocedural Taint Engine|Interprocedural Taint Engine]]
- [[_COMMUNITY_CLI Entrypoint & Analysis Findings|CLI Entrypoint & Analysis Findings]]
- [[_COMMUNITY_Global Symbol Table|Global Symbol Table]]
- [[_COMMUNITY_Intermediate Representation (IR)|Intermediate Representation (IR)]]
- [[_COMMUNITY_Local Taint Propagation|Local Taint Propagation]]
- [[_COMMUNITY_Interprocedural CFG (ICFG)|Interprocedural CFG (ICFG)]]
- [[_COMMUNITY_CLI Validation Harness|CLI Validation Harness]]
- [[_COMMUNITY_Vulnerability Rules Engine|Vulnerability Rules Engine]]
- [[_COMMUNITY_CFG Evaluator|CFG Evaluator]]
- [[_COMMUNITY_Sample Debugging Tool|Sample Debugging Tool]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]

## God Nodes (most connected - your core abstractions)
1. `Program` - 27 edges
2. `String` - 27 edges
3. `GlobalSymbolTable` - 25 edges
4. `InterproceduralTaintEngine<'a>` - 25 edges
5. `String` - 20 edges
6. `InterproceduralTaintEngine` - 20 edges
7. `TaintEngine` - 19 edges
8. `Option` - 18 edges
9. `ModuleId` - 17 edges
10. `RuleEngine` - 15 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Import Cycles
- 1-file cycle: `crates/cfg/src/evaluator.rs -> crates/cfg/src/evaluator.rs`
- 1-file cycle: `crates/cfg/src/icfg.rs -> crates/cfg/src/icfg.rs`
- 1-file cycle: `crates/cli/src/bin/debug_holdout.rs -> crates/cli/src/bin/debug_holdout.rs`
- 1-file cycle: `crates/cli/src/bin/debug_transfer.rs -> crates/cli/src/bin/debug_transfer.rs`
- 1-file cycle: `crates/cli/src/bin/inspect_sample_116.rs -> crates/cli/src/bin/inspect_sample_116.rs`
- 1-file cycle: `crates/cli/src/main.rs -> crates/cli/src/main.rs`
- 1-file cycle: `crates/cli/src/v2_validation.rs -> crates/cli/src/v2_validation.rs`
- 1-file cycle: `crates/taint/src/interproc.rs -> crates/taint/src/interproc.rs`
- 1-file cycle: `crates/features/src/lib.rs -> crates/features/src/lib.rs`
- 1-file cycle: `crates/ir/src/lib.rs -> crates/ir/src/lib.rs`
- 1-file cycle: `crates/normalizer/src/lib.rs -> crates/normalizer/src/lib.rs`
- 1-file cycle: `crates/rules/src/lib.rs -> crates/rules/src/lib.rs`
- 1-file cycle: `crates/semantic_rules/src/lib.rs -> crates/semantic_rules/src/lib.rs`
- 1-file cycle: `crates/symbols/src/lib.rs -> crates/symbols/src/lib.rs`
- 1-file cycle: `crates/taint/src/stubs.rs -> crates/taint/src/stubs.rs`

## Communities (66 total, 0 thin omitted)

### Community 0 - "Interprocedural Taint Engine"
Cohesion: 0.08
Nodes (49): BTreeSet, Cell, CallGraph, CWE, GlobalSymbolTable, HashMap, HashSet, InstructionId (+41 more)

### Community 1 - "CLI Entrypoint & Analysis Findings"
Cohesion: 0.07
Nodes (61): Finding, HashSet, NormalizedNode, Option, Path, RuleEngine, String, SymbolTable (+53 more)

### Community 2 - "Global Symbol Table"
Cohesion: 0.16
Nodes (36): AstNode, HashMap, HashSet, MethodId, Option, Program, Result, Self (+28 more)

### Community 3 - "Intermediate Representation (IR)"
Cohesion: 0.17
Nodes (31): AstNode, HashMap, Option, Result, Self, String, Vec, clean_var_name() (+23 more)

### Community 4 - "Local Taint Propagation"
Cohesion: 0.14
Nodes (19): HashMap, HashSet, NormalizedNode, Option, Self, String, Vec, ChaTable (+11 more)

### Community 5 - "Interprocedural CFG (ICFG)"
Cohesion: 0.18
Nodes (23): ConstantValue, CallGraph, HashMap, HashSet, InstructionId, MethodId, Option, Program (+15 more)

### Community 6 - "CLI Validation Harness"
Cohesion: 0.19
Nodes (27): GlobalSymbolTable, Option, Path, Program, String, Vec, code_defines_symbol(), extract_imported_symbols() (+19 more)

### Community 7 - "Vulnerability Rules Engine"
Cohesion: 0.16
Nodes (16): CWE, HashSet, NormalizedNode, Option, Self, String, TaintEngine, Vec (+8 more)

### Community 8 - "CFG Evaluator"
Cohesion: 0.29
Nodes (13): HashMap, Option, Result, Self, String, Vec, ConstantValue, Evaluator (+5 more)

### Community 9 - "Sample Debugging Tool"
Cohesion: 0.23
Nodes (20): code_defines_symbol(), extract_imported_symbols(), extract_imports_from_code(), fetch_file_from_github(), get_modified_files_from_git(), get_target_filename(), HoldoutEntry, load_mock_helpers() (+12 more)

### Community 10 - "Community 10"
Cohesion: 0.21
Nodes (12): HashMap, Option, Result, Self, String, Vec, Scope, ScopeKind (+4 more)

### Community 11 - "Community 11"
Cohesion: 0.18
Nodes (17): GlobalSymbolTable, HashMap, HashSet, InstructionId, MethodId, Option, Program, Self (+9 more)

### Community 12 - "Community 12"
Cohesion: 0.26
Nodes (9): AstNode, HashMap, Option, Self, String, Span, NormalizedKind, NormalizedNode (+1 more)

### Community 13 - "Community 13"
Cohesion: 0.28
Nodes (10): NormalizedNode, Option, Self, Vec, NodeId, CfgBuilder, CfgEdge, CfgNode (+2 more)

### Community 14 - "Community 14"
Cohesion: 0.29
Nodes (9): HashMap, Option, Self, String, Vec, LibraryStub, MethodStub, StubKind (+1 more)

### Community 16 - "Community 16"
Cohesion: 0.29
Nodes (9): Result, String, Vec, Node, AstNode, NodeKind, preprocess_python(), Span (+1 more)

### Community 18 - "Community 18"
Cohesion: 0.40
Nodes (8): ControlFlowGraph, Finding, SymbolTable, TaintEngine, FeatureExtractor, FeatureVector, get_longest_path(), get_path_count()

### Community 19 - "Community 19"
Cohesion: 0.57
Nodes (6): main(), print_node(), rules_eval_recursive(), NormalizedNode, RuleEngine, TaintEngine

### Community 20 - "Community 20"
Cohesion: 0.47
Nodes (5): main(), Sample, test_version(), Path, String

### Community 22 - "Community 22"
Cohesion: 0.40
Nodes (3): HoldoutEntry, Option, String

### Community 23 - "Community 23"
Cohesion: 0.50
Nodes (4): Program, String, Vec, scan_semantic_violations()

## Knowledge Gaps
- **60 isolated node(s):** `Self`, `HashSet`, `Self`, `Self`, `String` (+55 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `RefCell` connect `Interprocedural Taint Engine` to `CLI Validation Harness`?**
  _High betweenness centrality (0.012) - this node is a cross-community bridge._
- **Why does `InterproceduralCFG` connect `Interprocedural Taint Engine` to `Community 15`?**
  _High betweenness centrality (0.008) - this node is a cross-community bridge._
- **What connects `Self`, `HashSet`, `Self` to the rest of the system?**
  _60 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Interprocedural Taint Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.07875404055245372 - nodes in this community are weakly interconnected._
- **Should `CLI Entrypoint & Analysis Findings` be split into smaller, more focused modules?**
  _Cohesion score 0.0671602326811211 - nodes in this community are weakly interconnected._
- **Should `Local Taint Propagation` be split into smaller, more focused modules?**
  _Cohesion score 0.13588850174216027 - nodes in this community are weakly interconnected._