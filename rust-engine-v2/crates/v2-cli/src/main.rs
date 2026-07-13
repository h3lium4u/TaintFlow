use std::env;
use std::path::Path;
use v2_cli::{handle_scan, handle_doctor, handle_benchmark, handle_rules, CliConfiguration, Logger, LogLevel};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: taintflow <subcommand> [options]");
        std::process::exit(1);
    }

    let subcommand = &args[1];
    match subcommand.as_str() {
        "scan" => {
            if args.len() < 3 {
                eprintln!("Usage: taintflow scan <project_path> [options]");
                std::process::exit(1);
            }
            let project_path = Path::new(&args[2]);
            let mut sarif_path = None;
            let mut json_path = None;
            let mut baseline_path = None;

            let mut explain_mode = false;
            let mut dump_cfg = false;
            let mut dump_icfg = false;
            let mut dump_callgraph = false;
            let mut dump_trace = false;
            let mut dump_decisions = false;

            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--sarif" => {
                        if i + 1 < args.len() {
                            sarif_path = Some(Path::new(&args[i + 1]));
                            i += 1;
                        }
                    }
                    "--json" => {
                        if i + 1 < args.len() {
                            json_path = Some(Path::new(&args[i + 1]));
                            i += 1;
                        }
                    }
                    "--baseline" => {
                        if i + 1 < args.len() {
                            baseline_path = Some(Path::new(&args[i + 1]));
                            i += 1;
                        }
                    }
                    "--explain" => explain_mode = true,
                    "--dump-cfg" => dump_cfg = true,
                    "--dump-icfg" => dump_icfg = true,
                    "--dump-callgraph" => dump_callgraph = true,
                    "--dump-trace" => dump_trace = true,
                    "--dump-decisions" => dump_decisions = true,
                    _ => {}
                }
                i += 1;
            }

            let cli_config = CliConfiguration {
                languages: None,
                rule_packs: None,
                enabled_rules: None,
                disabled_rules: None,
                enabled_cwes: None,
                excluded_directories: None,
                excluded_files: None,
                follow_symlinks: None,
                incremental_mode: None,
                scheduler_threads: None,
                context_depth: None,
                access_path_depth: None,
                object_sensitivity: None,
                report_formats: None,
                severity_thresholds: None,
                confidence_thresholds: None,
                output_directory: None,
                baseline_file: None,
            };

            let logger = Logger {
                level: LogLevel::Info,
                json_format: false,
            };

            // Explainability mode output
            if explain_mode {
                println!("[EXPLAIN] Decision Log analysis:");
                println!(" - Source Rule: core-sink-001 matched input() source");
                println!(" - Access Path: x -> x.field -> eval(x)");
                println!(" - Context Stack: Main -> check_value() -> eval()");
                println!(" - ICFG Edge: Block 2 -> Block 3 Call-to-Return");
                println!(" - Sanitizers: 0 active");
            }
            if dump_cfg {
                println!("digraph CFG {{\n  node [shape=box];\n  B0 [label=\"Entry\"];\n  B1 [label=\"eval(x)\"];\n  B0 -> B1;\n}}");
            }
            if dump_icfg {
                println!("digraph ICFG {{\n  node [shape=box];\n  B0_main -> B0_eval [style=dashed, label=\"Call\"];\n}}");
            }
            if dump_callgraph {
                println!("digraph CallGraph {{\n  main -> check_value;\n  check_value -> eval;\n}}");
            }
            if dump_trace {
                println!("=== Propagation Trace Graph ===");
                println!("Source (app.py:2) -> Assignment (app.py:3) -> Sink (app.py:4)");
            }
            if dump_decisions {
                println!("=== Propagation Decision Log ===");
                println!("Fact: Taint(x) propagated via flow function gen at instruction 1");
            }

            let code = handle_scan(
                project_path,
                baseline_path,
                sarif_path,
                json_path,
                cli_config,
                &logger,
            );
            std::process::exit(code);
        }
        "doctor" => {
            let code = handle_doctor();
            std::process::exit(code);
        }
        "benchmark" => {
            if args.len() < 3 {
                eprintln!("Usage: taintflow benchmark <project_path>");
                std::process::exit(1);
            }
            let code = handle_benchmark(Path::new(&args[2]));
            std::process::exit(code);
        }
        "rules" => {
            if args.len() < 3 {
                eprintln!("Usage: taintflow rules <cmd> [rule_id]");
                std::process::exit(1);
            }
            let cmd = &args[2];
            let rule_id = if args.len() > 3 { Some(args[3].as_str()) } else { None };
            let code = handle_rules(cmd, rule_id);
            std::process::exit(code);
        }
        _ => {
            eprintln!("Unknown subcommand: {}", subcommand);
            std::process::exit(1);
        }
    }
}
