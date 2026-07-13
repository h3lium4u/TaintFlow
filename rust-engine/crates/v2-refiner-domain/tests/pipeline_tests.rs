use ir::{Program, Method, MethodId, InstructionId, Instruction, InstructionKind};
use symbols::GlobalSymbolTable;
use symbols::call_graph::CallGraph;
use cfg::icfg::InterproceduralCFG;
use taint::interproc::{InterproceduralTaintEngine, TaintFlow};
use v2_export_adapter::Exporter;
use v2_refiner_domain::{PathRefiner, FeasibilityStatus};

#[test]
fn test_end_to_end_validation_pipeline() {
    let mut program = Program::new();

    // ─── Set up Method 1: Feasible Path ───
    let mut method1 = Method {
        id: MethodId(1),
        name: "feasible_method".to_string(),
        parent_type_id: None,
        parameters: Vec::new(),
        body: Vec::new(),
    };
    let inst_id_num1 = InstructionId(10);
    let inst_num1 = Instruction {
        id: inst_id_num1,
        kind: InstructionKind::Assign {
            dest: "num".to_string(),
            src: "106".to_string(),
        },
        file_line: 5,
    };
    program.instructions.insert(inst_id_num1, inst_num1);
    method1.body.push(inst_id_num1);

    let inst_id_branch1 = InstructionId(1);
    let inst_branch1 = Instruction {
        id: inst_id_branch1,
        kind: InstructionKind::Branch {
            cond: "7 * 18 + num > 200".to_string(),
            then_block: vec![InstructionId(20)],
            else_block: None,
        },
        file_line: 10,
    };
    program.instructions.insert(inst_id_branch1, inst_branch1);
    method1.body.push(inst_id_branch1);

    let inst_id_assign1 = InstructionId(20);
    let inst_assign1 = Instruction {
        id: inst_id_assign1,
        kind: InstructionKind::Assign {
            dest: "bar".to_string(),
            src: "param".to_string(),
        },
        file_line: 11,
    };
    program.instructions.insert(inst_id_assign1, inst_assign1);

    let inst_id_sink1 = InstructionId(2);
    let inst_sink1 = Instruction {
        id: inst_id_sink1,
        kind: InstructionKind::Sink {
            name: "feasible_sink".to_string(),
        },
        file_line: 12,
    };
    program.instructions.insert(inst_id_sink1, inst_sink1);
    method1.body.push(inst_id_sink1);
    program.methods.insert(method1.id, method1);


    // ─── Set up Method 2: Infeasible Path ───
    let mut method2 = Method {
        id: MethodId(2),
        name: "infeasible_method".to_string(),
        parent_type_id: None,
        parameters: Vec::new(),
        body: Vec::new(),
    };
    let inst_id_num2 = InstructionId(30);
    let inst_num2 = Instruction {
        id: inst_id_num2,
        kind: InstructionKind::Assign {
            dest: "num".to_string(),
            src: "86".to_string(),
        },
        file_line: 19,
    };
    program.instructions.insert(inst_id_num2, inst_num2);
    method2.body.push(inst_id_num2);

    let inst_id_branch2 = InstructionId(3);
    let inst_branch2 = Instruction {
        id: inst_id_branch2,
        kind: InstructionKind::Branch {
            cond: "7 * 42 - num > 200".to_string(),
            then_block: vec![InstructionId(40)],
            else_block: Some(vec![InstructionId(50)]),
        },
        file_line: 20,
    };
    program.instructions.insert(inst_id_branch2, inst_branch2);
    method2.body.push(inst_id_branch2);

    let inst_id_assign2_then = InstructionId(40);
    let inst_assign2_then = Instruction {
        id: inst_id_assign2_then,
        kind: InstructionKind::Assign {
            dest: "bar".to_string(),
            src: "'safe'".to_string(),
        },
        file_line: 21,
    };
    program.instructions.insert(inst_id_assign2_then, inst_assign2_then);

    let inst_id_assign2_else = InstructionId(50);
    let inst_assign2_else = Instruction {
        id: inst_id_assign2_else,
        kind: InstructionKind::Assign {
            dest: "bar".to_string(),
            src: "param".to_string(),
        },
        file_line: 23,
    };
    program.instructions.insert(inst_id_assign2_else, inst_assign2_else);

    let inst_id_sink2 = InstructionId(4);
    let inst_sink2 = Instruction {
        id: inst_id_sink2,
        kind: InstructionKind::Sink {
            name: "infeasible_sink".to_string(),
        },
        file_line: 25,
    };
    program.instructions.insert(inst_id_sink2, inst_sink2);
    method2.body.push(inst_id_sink2);
    program.methods.insert(method2.id, method2);


    // ─── Set up Method 3: Unknown Path ───
    let mut method3 = Method {
        id: MethodId(3),
        name: "unknown_method".to_string(),
        parent_type_id: None,
        parameters: Vec::new(),
        body: Vec::new(),
    };
    let inst_id_assign3 = InstructionId(60);
    let inst_assign3 = Instruction {
        id: inst_id_assign3,
        kind: InstructionKind::Assign {
            dest: "bar".to_string(),
            src: "param".to_string(),
        },
        file_line: 29,
    };
    program.instructions.insert(inst_id_assign3, inst_assign3);
    method3.body.push(inst_id_assign3);

    let inst_id_sink3 = InstructionId(5);
    let inst_sink3 = Instruction {
        id: inst_id_sink3,
        kind: InstructionKind::Sink {
            name: "unknown_sink".to_string(),
        },
        file_line: 30,
    };
    program.instructions.insert(inst_id_sink3, inst_sink3);
    method3.body.push(inst_id_sink3);
    program.methods.insert(method3.id, method3);


    // ─── Run Global Symbol Resolution ───
    let gst = GlobalSymbolTable::new();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    // ─── Initialize Engine and Mock Taint Flows ───
    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    
    let flow1 = TaintFlow {
        source_node_id: 0,
        sink_node_id: 2,
        source_var: "param".to_string(),
        sink_var: "bar".to_string(),
        cwe: taint::CWE::CWE22,
    };
    let flow2 = TaintFlow {
        source_node_id: 0,
        sink_node_id: 4,
        source_var: "param".to_string(),
        sink_var: "bar".to_string(),
        cwe: taint::CWE::CWE22,
    };
    let flow3 = TaintFlow {
        source_node_id: 0,
        sink_node_id: 5,
        source_var: "param".to_string(),
        sink_var: "bar".to_string(),
        cwe: taint::CWE::CWE22,
    };

    engine.flows.insert(flow1);
    engine.flows.insert(flow2);
    engine.flows.insert(flow3);

    // ─── Step 1: Export ProgramFacts ───
    let mut facts = Exporter::export(&engine);
    facts.icfg_to_inst.clear();

    // ─── Step 2: Run PathRefiner ───
    let refinements1 = PathRefiner::refine_paths(&facts);
    let refinements2 = PathRefiner::refine_paths(&facts);

    // ─── Assert Determinism & Immutability ───
    assert_eq!(refinements1.len(), refinements2.len());
    for i in 0..refinements1.len() {
        assert_eq!(refinements1[i].status, refinements2[i].status);
        assert_eq!(refinements1[i].reason, refinements2[i].reason);
    }
    assert_eq!(engine.flows.len(), 3); // Engine unchanged
    assert_eq!(facts.taint_flows.len(), 3); // ProgramFacts unchanged

    // ─── Step 3: Filter & Suppress ───
    let mut feasible_count = 0;


    let mut infeasible_count = 0;
    let mut unknown_count = 0;
    let mut filtered_findings = Vec::new();
    let mut suppressed_flows = Vec::new();

    for refinement in &refinements1 {
        let flow = &facts.taint_flows[refinement.flow_index];
        match refinement.status {
            FeasibilityStatus::Feasible => {
                feasible_count += 1;
                filtered_findings.push(flow.clone());
            }
            FeasibilityStatus::Unknown => {
                unknown_count += 1;
                filtered_findings.push(flow.clone());
            }
            FeasibilityStatus::Infeasible => {
                infeasible_count += 1;
                suppressed_flows.push((flow.clone(), refinement.reason.clone()));
            }
        }
    }

    // ─── Assert Filter Correctness ───
    assert_eq!(feasible_count, 2);
    assert_eq!(infeasible_count, 1);
    assert_eq!(unknown_count, 0);
    assert_eq!(filtered_findings.len(), 2);

    assert_eq!(suppressed_flows.len(), 1);

    // ─── Print Example Comparison Report ───
    println!("\n--------------------------------");
    println!("Original findings : {}", engine.flows.len());
    println!("Feasible          : {}", feasible_count);
    println!("Unknown           : {}", unknown_count);
    println!("Infeasible        : {}", infeasible_count);
    println!("Filtered findings : {}", filtered_findings.len());
    println!("--------------------------------");

    for (flow, reason) in &suppressed_flows {
        println!("\nSuppressed Flow (Sink Node: {})", flow.sink_node_id);
        println!("Status: Infeasible");
    }
}

#[test]
fn test_refiner_arraylist_end_to_end() {
    let mut program = Program::new();
    let mut method = Method {
        id: MethodId(1),
        name: "test_arraylist_method".to_string(),
        parent_type_id: None,
        parameters: Vec::new(),
        body: Vec::new(),
    };

    // 16. new ArrayList
    let inst_id_16 = InstructionId(16);
    program.instructions.insert(inst_id_16, Instruction {
        id: inst_id_16,
        kind: InstructionKind::Call {
            dest: Some("valuesList".to_string()),
            callee: "new java.util.ArrayList<String>".to_string(),
            args: Vec::new(),
        },
        file_line: 16,
    });
    method.body.push(inst_id_16);

    // 17. valuesList.add("safe")
    let inst_id_17 = InstructionId(17);
    program.instructions.insert(inst_id_17, Instruction {
        id: inst_id_17,
        kind: InstructionKind::Call {
            dest: None,
            callee: "valuesList.add".to_string(),
            args: vec!["\"safe\"".to_string()],
        },
        file_line: 17,
    });
    method.body.push(inst_id_17);

    // 18. valuesList.add(param)
    let inst_id_18 = InstructionId(18);
    program.instructions.insert(inst_id_18, Instruction {
        id: inst_id_18,
        kind: InstructionKind::Call {
            dest: None,
            callee: "valuesList.add".to_string(),
            args: vec!["param".to_string()],
        },
        file_line: 18,
    });
    method.body.push(inst_id_18);

    // 19. valuesList.add("moresafe")
    let inst_id_19 = InstructionId(19);
    program.instructions.insert(inst_id_19, Instruction {
        id: inst_id_19,
        kind: InstructionKind::Call {
            dest: None,
            callee: "valuesList.add".to_string(),
            args: vec!["\"moresafe\"".to_string()],
        },
        file_line: 19,
    });
    method.body.push(inst_id_19);

    // 20. valuesList.remove(0)
    let inst_id_20 = InstructionId(20);
    program.instructions.insert(inst_id_20, Instruction {
        id: inst_id_20,
        kind: InstructionKind::Call {
            dest: None,
            callee: "valuesList.remove".to_string(),
            args: vec!["\"0\"".to_string()],
        },
        file_line: 20,
    });
    method.body.push(inst_id_20);

    // 21. bar = valuesList.get(1)
    let inst_id_21 = InstructionId(21);
    program.instructions.insert(inst_id_21, Instruction {
        id: inst_id_21,
        kind: InstructionKind::Call {
            dest: Some("bar".to_string()),
            callee: "valuesList.get".to_string(),
            args: vec!["\"1\"".to_string()],
        },
        file_line: 21,
    });
    method.body.push(inst_id_21);

    // 22. sink
    let inst_id_22 = InstructionId(22);
    program.instructions.insert(inst_id_22, Instruction {
        id: inst_id_22,
        kind: InstructionKind::Sink {
            name: "sink".to_string(),
        },
        file_line: 22,
    });
    method.body.push(inst_id_22);

    program.methods.insert(method.id, method);

    // ─── Set up Global symbols, callgraph, icfg (mocked) ───
    let gst = GlobalSymbolTable::new();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    let flow = TaintFlow {
        source_node_id: 0,
        sink_node_id: 22,
        source_var: "param".to_string(),
        sink_var: "bar".to_string(),
        cwe: taint::CWE::CWE22,
    };
    engine.flows.insert(flow);

    let mut facts = Exporter::export(&engine);
    facts.icfg_to_inst.clear();
    let refinements = PathRefiner::refine_paths(&facts);
    
    assert_eq!(refinements.len(), 1);
    assert_eq!(refinements[0].status, FeasibilityStatus::Infeasible);
}

#[test]
fn test_refiner_hashmap_end_to_end() {
    let mut program = Program::new();
    
    // ─── Set up Method: test_hashmap_method ───
    let mut method = Method {
        id: MethodId(1),
        name: "test_hashmap_method".to_string(),
        parent_type_id: None,
        parameters: Vec::new(),
        body: Vec::new(),
    };

    // 10. new HashMap
    let inst_id_10 = InstructionId(10);
    program.instructions.insert(inst_id_10, Instruction {
        id: inst_id_10,
        kind: InstructionKind::Call {
            dest: Some("map".to_string()),
            callee: "new java.util.HashMap<String, Object>".to_string(),
            args: Vec::new(),
        },
        file_line: 10,
    });
    method.body.push(inst_id_10);

    // 11. map.put("keyA", "safe")
    let inst_id_11 = InstructionId(11);
    program.instructions.insert(inst_id_11, Instruction {
        id: inst_id_11,
        kind: InstructionKind::Call {
            dest: None,
            callee: "map.put".to_string(),
            args: vec!["\"keyA\"".to_string(), "\"safe\"".to_string()],
        },
        file_line: 11,
    });
    method.body.push(inst_id_11);

    // 12. map.put("keyB", param)
    let inst_id_12 = InstructionId(12);
    program.instructions.insert(inst_id_12, Instruction {
        id: inst_id_12,
        kind: InstructionKind::Call {
            dest: None,
            callee: "map.put".to_string(),
            args: vec!["\"keyB\"".to_string(), "param".to_string()],
        },
        file_line: 12,
    });
    method.body.push(inst_id_12);

    // 13. bar1 = map.get("keyA")
    let inst_id_13 = InstructionId(13);
    program.instructions.insert(inst_id_13, Instruction {
        id: inst_id_13,
        kind: InstructionKind::Call {
            dest: Some("bar1".to_string()),
            callee: "map.get".to_string(),
            args: vec!["\"keyA\"".to_string()],
        },
        file_line: 13,
    });
    method.body.push(inst_id_13);

    // 14. bar2 = map.get("keyB")
    let inst_id_14 = InstructionId(14);
    program.instructions.insert(inst_id_14, Instruction {
        id: inst_id_14,
        kind: InstructionKind::Call {
            dest: Some("bar2".to_string()),
            callee: "map.get".to_string(),
            args: vec!["\"keyB\"".to_string()],
        },
        file_line: 14,
    });
    method.body.push(inst_id_14);

    // 15. sink1
    let inst_id_15 = InstructionId(15);
    program.instructions.insert(inst_id_15, Instruction {
        id: inst_id_15,
        kind: InstructionKind::Sink {
            name: "sink1".to_string(),
        },
        file_line: 15,
    });
    method.body.push(inst_id_15);

    // 16. sink2
    let inst_id_16 = InstructionId(16);
    program.instructions.insert(inst_id_16, Instruction {
        id: inst_id_16,
        kind: InstructionKind::Sink {
            name: "sink2".to_string(),
        },
        file_line: 16,
    });
    method.body.push(inst_id_16);

    program.methods.insert(method.id, method);

    // ─── Set up Global symbols, callgraph, icfg ───
    let gst = GlobalSymbolTable::new();
    let cg = CallGraph::build(&program, &gst);
    let icfg = InterproceduralCFG::build(&program, &cg);

    let mut engine = InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    
    // Flow 1: param -> bar1 (should be suppressed)
    let flow1 = TaintFlow {
        source_node_id: 0,
        sink_node_id: 15,
        source_var: "param".to_string(),
        sink_var: "bar1".to_string(),
        cwe: taint::CWE::CWE22,
    };
    // Flow 2: param -> bar2 (should be preserved)
    let flow2 = TaintFlow {
        source_node_id: 0,
        sink_node_id: 16,
        source_var: "param".to_string(),
        sink_var: "bar2".to_string(),
        cwe: taint::CWE::CWE22,
    };

    engine.flows.insert(flow1);
    engine.flows.insert(flow2);

    let mut facts = Exporter::export(&engine);
    facts.icfg_to_inst.clear();
    let refinements = PathRefiner::refine_paths(&facts);
    
    assert_eq!(refinements.len(), 2);
    
    for refinement in &refinements {
        let flow = &facts.taint_flows[refinement.flow_index];
        if flow.sink_var == "bar1" {
            assert_eq!(refinement.status, FeasibilityStatus::Infeasible);
        } else if flow.sink_var == "bar2" {
            assert_eq!(refinement.status, FeasibilityStatus::Feasible);
        } else {
            panic!("Unexpected flow: {:?}", flow);
        }
    }
}


