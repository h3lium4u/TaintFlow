use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Deserialize)]
struct HoldoutEntry {
    before: String,
    after: String,
    language: String,
    repo: Option<String>,
    source: Option<String>,
    cwe: Option<String>,
    commit: Option<String>,
}

struct Sample {
    code: String,
    language: String,
    vulnerable: bool,
    cwe: String,
    repo: String,
    commit: String,
    is_juliet: bool,
}

fn get_target_filename(_repo: &str, _commit: &str, _code: &str) -> String {
    "test.py".to_string()
}

fn repo_name_to_local_folder(repo: &str) -> &str {
    let repo_clean = repo.trim_end_matches(".git");
    let parts: Vec<&str> = repo_clean.split('/').collect();
    if parts.is_empty() {
        return repo_clean;
    }
    parts[parts.len() - 1]
}

fn get_modified_files_from_git(repo_path: &Path, commit: &str) -> Option<Vec<String>> {
    let output = std::process::Command::new("git")
        .args(&["diff-tree", "--no-commit-id", "--name-only", "-r", commit])
        .current_dir(repo_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let files = stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some(files)
}

fn fetch_file_from_github(repo: &str, commit: &str, filepath: &str) -> Option<String> {
    let repo_clean = repo.trim_end_matches(".git");
    let parts: Vec<&str> = repo_clean.split('/').collect();
    if parts.len() < 2 {
        return None;
    }
    let repo_name = parts[parts.len() - 1];
    let owner = parts[parts.len() - 2];

    let local_folder = repo_name_to_local_folder(repo);
    let local_root = Path::new("D:/RepositoryCache").join(local_folder);
    if local_root.exists() {
        let local_candidate = local_root.join(filepath);
        if local_candidate.exists() {
            if let Ok(content) = std::fs::read_to_string(&local_candidate) {
                return Some(content);
            }
        }
        if filepath.ends_with(".py") {
            let src_candidate = local_root.join("src").join(filepath);
            if src_candidate.exists() {
                if let Ok(content) = std::fs::read_to_string(&src_candidate) {
                    return Some(content);
                }
            }
        }
    }

    let cache_dir = Path::new("d:/V2 Backup/scratch/repository_cache")
        .join(owner)
        .join(repo_name)
        .join(commit);
    let cache_file = cache_dir.join(filepath);
    if cache_file.exists() {
        if let Ok(code) = std::fs::read_to_string(&cache_file) {
            return Some(code);
        }
    }
    None
}

fn match_cohort_code_to_path(
    repo: &str,
    commit: &str,
    code: &str,
    modified_files: &[String],
) -> Option<String> {
    for file in modified_files {
        if let Some(content) = fetch_file_from_github(repo, commit, file) {
            if content.trim() == code.trim() {
                return Some(file.clone());
            }
        }
    }
    let parent_commit = format!("{}~1", commit);
    for file in modified_files {
        if let Some(content) = fetch_file_from_github(repo, &parent_commit, file) {
            if content.trim() == code.trim() {
                return Some(file.clone());
            }
        }
    }
    None
}

fn code_defines_symbol(code: &str, symbol: &str) -> bool {
    if symbol.is_empty() {
        return false;
    }
    let def_pattern = format!("def {}", symbol);
    let class_pattern1 = format!("class {}:", symbol);
    let class_pattern2 = format!("class {} (", symbol);
    let class_pattern3 = format!("class {}(", symbol);
    let var_pattern1 = format!("{} = ", symbol);
    let var_pattern2 = format!("{}=", symbol);

    for line in code.lines() {
        let line = line.trim();
        if line.starts_with(&def_pattern)
            || line.starts_with(&class_pattern1)
            || line.starts_with(&class_pattern2)
            || line.starts_with(&class_pattern3)
            || line.starts_with(&var_pattern1)
            || line.starts_with(&var_pattern2)
        {
            return true;
        }
    }
    false
}

fn resolve_sibling_filepath(target_filepath: &str, from_part: &str) -> String {
    let num_dots = from_part.chars().take_while(|&c| c == '.').count();
    if num_dots == 0 {
        return format!("{}.py", from_part.replace('.', "/"));
    }

    let remainder = &from_part[num_dots..];
    let normalized = target_filepath.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 1 {
        if remainder.is_empty() {
            return "sibling.py".to_string();
        } else {
            return format!("{}.py", remainder.replace('.', "/"));
        }
    }

    let parent_parts = &parts[..parts.len() - 1];
    let pop_count = num_dots.saturating_sub(1);

    let keep_parts = if pop_count >= parent_parts.len() {
        if !parent_parts.is_empty() {
            &parent_parts[..1]
        } else {
            &[]
        }
    } else {
        &parent_parts[..parent_parts.len() - pop_count]
    };

    let base_dir = keep_parts.join("/");
    if base_dir.is_empty() {
        if remainder.is_empty() {
            "sibling.py".to_string()
        } else {
            format!("{}.py", remainder.replace('.', "/"))
        }
    } else {
        if remainder.is_empty() {
            format!("{}/sibling.py", base_dir)
        } else {
            format!("{}/{}.py", base_dir, remainder.replace('.', "/"))
        }
    }
}

fn extract_imports_from_code(code: &str) -> Vec<(String, String)> {
    let mut imports = Vec::new();
    for line in code.lines() {
        let line = line.trim();
        if line.starts_with("from ") {
            if let Some(import_idx) = line.find(" import ") {
                let from_part = line["from ".len()..import_idx].trim();
                let import_part = line[import_idx + " import ".len()..].trim();
                let clean_import = import_part.trim_matches(|c| c == '(' || c == ')');
                for part in clean_import.split(',') {
                    let part = part.trim();
                    let symbol = if part.contains(" as ") {
                        part.split(" as ").next().unwrap_or("").trim()
                    } else {
                        part
                    };
                    imports.push((from_part.to_string(), symbol.to_string()));
                }
            }
        } else if line.starts_with("import ") {
            let clean = &line["import ".len()..];
            for part in clean.split(',') {
                let part = part.trim();
                let module_path = if part.contains(" as ") {
                    part.split(" as ").next().unwrap_or("").trim()
                } else {
                    part
                };
                if let Some(last) = module_path.split('.').last() {
                    imports.push((module_path.to_string(), last.to_string()));
                }
            }
        }
    }
    imports
}

fn extract_imported_symbols(code: &str) -> Vec<(String, String)> {
    let mut imports = extract_imports_from_code(code);
    for line in code.lines() {
        let line = line.trim();
        if line.starts_with("import ") {
            let clean = &line["import ".len()..];
            for part in clean.split(',') {
                let part = part.trim();
                let module_path = if part.contains(" as ") {
                    part.split(" as ").next().unwrap_or("").trim()
                } else {
                    part
                };
                if let Some(last) = module_path.split('.').last() {
                    imports.push((module_path.to_string(), last.to_string()));
                }
            }
        }
    }
    imports
}

fn resolve_module_to_filepaths(from_part: &str, symbol: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let s = from_part.replace('.', "/");
    paths.push(format!("{}.py", s));
    paths.push(format!("{}/__init__.py", s));
    paths.push(format!("{}/{}.py", s, symbol.to_lowercase()));
    let parts: Vec<&str> = from_part.split('.').collect();
    if parts.len() > 1 {
        let parent_s = parts[..parts.len() - 1].join("/");
        paths.push(format!("{}.py", parent_s));
        paths.push(format!("{}/__init__.py", parent_s));
        let last = parts[parts.len() - 1].to_lowercase();
        paths.push(format!("{}/{}.py", parent_s, last));
    }
    paths
}

fn load_mock_helpers(
    program: &mut ir::Program,
    gst: &mut symbols::global::GlobalSymbolTable,
    repo: &str,
    commit: &str,
    language: &str,
    base_dir: &Path,
) {
    let mock_helpers_path = base_dir.join("scratch/mock_helpers.json");
    if mock_helpers_path.exists() {
        if let Ok(file) = File::open(&mock_helpers_path) {
            let reader = BufReader::new(file);
            if let Ok(mocks) = serde_json::from_reader::<_, serde_json::Value>(reader) {
                if let Some(mock_list) = mocks.get("mocks") {
                    if let Some(arr) = mock_list.as_array() {
                        for mock in arr {
                            if mock.get("repo").and_then(|v| v.as_str()) == Some(repo)
                                && mock.get("commit").and_then(|v| v.as_str()) == Some(commit)
                            {
                                if let Some(files) = mock.get("files").and_then(|v| v.as_array()) {
                                    for file in files {
                                        if let (Some(path), Some(code)) = (
                                            file.get("path").and_then(|v| v.as_str()),
                                            file.get("code").and_then(|v| v.as_str()),
                                        ) {
                                            let _ = gst.load_file(
                                                program,
                                                code,
                                                &path.to_string(),
                                                language,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let holdout_path = base_dir.join("datasets/processed/external_holdout.jsonl");

    let mut github_samples = Vec::new();
    if holdout_path.exists() {
        let file = File::open(&holdout_path).unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line_str) = line {
                if let Ok(entry) = serde_json::from_str::<HoldoutEntry>(&line_str) {
                    let is_juliet = entry.repo.as_deref() == Some("Juliet")
                        || entry.source.as_deref() == Some("Juliet");
                    let cwe = entry.cwe.unwrap_or_else(|| "unknown".to_string());
                    let repo = entry.repo.unwrap_or_else(|| "unknown".to_string());
                    let commit = entry.commit.unwrap_or_default();

                    let s_before = Sample {
                        code: entry.before,
                        language: entry.language.clone(),
                        vulnerable: true,
                        cwe: cwe.clone(),
                        repo: repo.clone(),
                        commit: commit.clone(),
                        is_juliet,
                    };
                    let s_after = Sample {
                        code: entry.after,
                        language: entry.language,
                        vulnerable: false,
                        cwe,
                        repo,
                        commit,
                        is_juliet,
                    };

                    if !is_juliet {
                        github_samples.push(s_before);
                        github_samples.push(s_after);
                    }
                }
            }
        }
    }

    let skip_pgadmin = std::env::var("SKIP_PGADMIN").is_ok();
    let skip_datachain = std::env::var("SKIP_DATACHAIN").is_ok();
    let skip_ray = std::env::var("SKIP_RAY").is_ok();

    let mut raw_index = 0;
    let mut target_sample = None;
    for sample in &github_samples {
        let skipped_by_standard = (skip_pgadmin && sample.repo.contains("pgadmin"))
            || (skip_datachain && sample.repo.contains("datachain"))
            || (skip_ray && sample.repo.contains("ray"));
        if skipped_by_standard {
            continue;
        }
        let idx = raw_index;
        raw_index += 1;
        if idx == 116 {
            target_sample = Some(sample);
            break;
        }
    }

    let sample = target_sample.expect("Could not find sample at index 116 after skips");
    println!("=== INSPECTING SAMPLE 116 ===");
    println!("Repo: {}", sample.repo);
    println!("Commit: {}", sample.commit);
    println!("Expected CWE: {}", sample.cwe);
    println!("Vulnerable: {}", sample.vulnerable);

    let mut cohort_codes = vec![sample.code.clone()];
    for other in &github_samples {
        if other.repo == sample.repo
            && other.commit == sample.commit
            && other.vulnerable == sample.vulnerable
            && other.code != sample.code
        {
            cohort_codes.push(other.code.clone());
        }
    }

    let repo_name = sample
        .repo
        .split('/')
        .last()
        .unwrap_or("")
        .trim_end_matches(".git");
    let repo_normalized = repo_name.replace('-', "_").to_lowercase();

    let mut import_roots = std::collections::HashSet::new();
    for code in &cohort_codes {
        for (from_part, _) in extract_imported_symbols(code) {
            if !from_part.starts_with('.') {
                if let Some(first) = from_part.split('.').next() {
                    import_roots.insert(first.to_string());
                }
            }
        }
    }

    let mut package_root = repo_normalized.clone();
    for root in &import_roots {
        let root_lower = root.to_lowercase();
        let is_match = root_lower == repo_normalized
            || repo_normalized.starts_with(&root_lower)
            || repo_normalized.ends_with(&root_lower)
            || root_lower.starts_with(&repo_normalized)
            || root_lower.ends_with(&repo_normalized)
            || repo_normalized.split('_').any(|part| part == root_lower)
            || root_lower.split('_').any(|part| part == repo_normalized);
        if is_match {
            package_root = root.clone();
            break;
        }
    }

    let mut resolved_paths = std::collections::HashMap::new();
    let mut git_resolved = false;
    let local_folder = repo_name_to_local_folder(&sample.repo);
    let local_root = Path::new("D:/RepositoryCache").join(local_folder);
    if local_root.exists() {
        if let Some(modified_files) = get_modified_files_from_git(&local_root, &sample.commit) {
            for (i, code) in cohort_codes.iter().enumerate() {
                if let Some(path) =
                    match_cohort_code_to_path(&sample.repo, &sample.commit, code, &modified_files)
                {
                    resolved_paths.insert(i, path);
                }
            }
            if resolved_paths.len() == cohort_codes.len() {
                git_resolved = true;
            }
        }
    }

    if !git_resolved {
        resolved_paths.clear();
        for (i, code) in cohort_codes.iter().enumerate() {
            for (j, other_code) in cohort_codes.iter().enumerate() {
                if i == j {
                    continue;
                }
                for (from_part, symbol) in extract_imported_symbols(other_code) {
                    if !from_part.starts_with('.') && from_part.starts_with(&package_root) {
                        if code_defines_symbol(code, &symbol) {
                            resolved_paths.insert(i, format!("{}.py", from_part.replace('.', "/")));
                            break;
                        }
                    }
                }
                if resolved_paths.contains_key(&i) {
                    break;
                }
            }
        }
    }

    if !resolved_paths.contains_key(&0) {
        let mut max_dots = 1;
        for (from_part, _) in extract_imported_symbols(&sample.code) {
            if from_part.starts_with('.') {
                let dots = from_part.chars().take_while(|&c| c == '.').count();
                if dots > max_dots {
                    max_dots = dots;
                }
            }
        }

        let mut path = package_root.clone();
        for depth in 1..max_dots {
            path = format!("{}/sub{}", path, depth);
        }
        path = format!("{}/target.py", path);
        resolved_paths.insert(0, path);
    }

    let mut resolved_any = true;
    while resolved_any {
        resolved_any = false;
        for i in 1..cohort_codes.len() {
            if resolved_paths.contains_key(&i) {
                continue;
            }
            let code = &cohort_codes[i];
            let mut resolved_path = None;

            for (&j, path_j) in &resolved_paths {
                let other_code = &cohort_codes[j];
                for (from_part, symbol) in extract_imported_symbols(other_code) {
                    if code_defines_symbol(code, &symbol) {
                        if from_part.starts_with('.') {
                            resolved_path = Some(resolve_sibling_filepath(&path_j, &from_part));
                        } else {
                            resolved_path = Some(format!("{}.py", from_part.replace('.', "/")));
                        }
                        break;
                    }
                }
                if resolved_path.is_some() {
                    break;
                }
            }

            if resolved_path.is_none() {
                for (&j, path_j) in &resolved_paths {
                    let other_code = &cohort_codes[j];
                    for (from_part, symbol) in extract_imported_symbols(code) {
                        if code_defines_symbol(other_code, &symbol) {
                            if from_part.starts_with('.') {
                                let num_dots = from_part.chars().take_while(|&c| c == '.').count();
                                let normalized = path_j.replace('\\', "/");
                                let parts: Vec<&str> =
                                    normalized.split('/').filter(|s| !s.is_empty()).collect();
                                if parts.len() > 1 {
                                    let parent_parts = &parts[..parts.len() - 1];
                                    let pop_count = num_dots.saturating_sub(1);
                                    let keep_parts = if pop_count >= parent_parts.len() {
                                        &[]
                                    } else {
                                        &parent_parts[..parent_parts.len() - pop_count]
                                    };
                                    let base_dir = keep_parts.join("/");
                                    if base_dir.is_empty() {
                                        resolved_path = Some(format!("sibling_{}.py", i));
                                    } else {
                                        resolved_path =
                                            Some(format!("{}/sibling_{}.py", base_dir, i));
                                    }
                                }
                            } else {
                                resolved_path = Some(format!("{}.py", from_part.replace('.', "/")));
                            }
                            break;
                        }
                    }
                    if resolved_path.is_some() {
                        break;
                    }
                }
            }

            if let Some(path) = resolved_path {
                resolved_paths.insert(i, path);
                resolved_any = true;
            }
        }
    }

    let mut siblings = Vec::new();
    for i in 1..cohort_codes.len() {
        if !resolved_paths.contains_key(&i) {
            let path = format!("{}/sibling_{}.py", package_root, i);
            resolved_paths.insert(i, path);
        }
    }

    let target_path_str = resolved_paths.get(&0).cloned().unwrap();
    for i in 1..cohort_codes.len() {
        let code = cohort_codes[i].clone();
        let path = resolved_paths.get(&i).unwrap().clone();
        siblings.push((code, path));
    }

    let mut paths = vec![target_path_str.clone()];
    for (_, path) in &siblings {
        paths.push(path.clone());
    }

    // Include dynamically fetched dependencies
    let mut pending_files = vec![(sample.code.clone(), target_path_str.clone())];
    for (code, path) in &siblings {
        pending_files.push((code.clone(), path.clone()));
    }
    let mut analyzed_paths = std::collections::HashSet::new();
    for (_, path) in &pending_files {
        analyzed_paths.insert(path.clone());
    }
    let mut idx = 0;
    while idx < pending_files.len() {
        let (code, _) = pending_files[idx].clone();
        idx += 1;
        for (from_part, symbol) in extract_imported_symbols(&code) {
            if !from_part.starts_with('.') && from_part.starts_with(&package_root) {
                let possible_paths = resolve_module_to_filepaths(&from_part, &symbol);
                let mut already_resolved = false;
                for p in &possible_paths {
                    if analyzed_paths.contains(p) {
                        already_resolved = true;
                        break;
                    }
                }
                if already_resolved {
                    continue;
                }
                for p in possible_paths {
                    if analyzed_paths.contains(&p) {
                        break;
                    }
                    if let Some(content) = fetch_file_from_github(&sample.repo, &sample.commit, &p)
                    {
                        analyzed_paths.insert(p.clone());
                        pending_files.push((content.clone(), p.clone()));
                        siblings.push((content, p));
                        break;
                    }
                }
            }
        }
    }

    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    program
        .source_files
        .insert(target_path_str.clone(), sample.code.clone());
    for (sib_code, sib_filename) in &siblings {
        program
            .source_files
            .insert(sib_filename.clone(), sib_code.clone());
    }

    let _ = gst.load_file(
        &mut program,
        &sample.code,
        &target_path_str,
        &sample.language,
    );
    for (sib_code, sib_filename) in &siblings {
        let _ = gst.load_file(&mut program, sib_code, sib_filename, &sample.language);
    }
    load_mock_helpers(
        &mut program,
        &mut gst,
        &sample.repo,
        &sample.commit,
        &sample.language,
        base_dir,
    );
    gst.resolve_inheritance_hierarchy();
    let cg = symbols::call_graph::CallGraph::build(&program, &gst);
    let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

    println!("\nCall Graph Edges from test_pub_ret_traversal:");
    let mut found_edge = false;
    for edge in &cg.edges {
        if let Some(caller_method) = program.methods.get(&edge.caller) {
            if caller_method.name == "test_pub_ret_traversal" {
                if let Some(callee_method) = program.methods.get(&edge.callee) {
                    println!(
                        "  Caller: '{}' -> Callee: '{}'",
                        caller_method.name, callee_method.name
                    );
                    found_edge = true;
                }
            }
        }
    }
    if !found_edge {
        println!("  (None found)");
    }

    // Run once with the current guard (refinement)
    println!("\n--- RUNNING ANALYSIS WITH GUARD ENABLED (FINAL FIX) ---");
    let mut engine_with_guard = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
    engine_with_guard.target_file = Some(target_path_str.clone());
    let mut set = std::collections::HashSet::new();
    for p in &paths {
        set.insert(p.to_lowercase().replace('\\', "/"));
    }
    engine_with_guard.target_and_siblings = set.clone();
    engine_with_guard.seed_sources(None);
    engine_with_guard.run();

    println!(
        "Detected flows (Final Fix): {}",
        engine_with_guard.flows.len()
    );
    #[cfg(feature = "solver_diagnostics")]
    {
        for flow in &engine_with_guard.flows {
            println!(
                "  Flow: CWE={:?}, sink_node={}, sink_var={}",
                flow.cwe, flow.sink_node_id, flow.sink_var
            );
            let matching_facts = engine_with_guard
                .tainted_facts
                .iter()
                .filter(|f| f.node_id == flow.sink_node_id && f.var == flow.sink_var);
            for fact in matching_facts {
                let mut curr = fact;
                let mut path = vec![curr];
                while let Some(parent) = engine_with_guard.parent_map.get(curr) {
                    path.push(parent);
                    curr = parent;
                }
                path.reverse();
                println!("  Path length: {}", path.len());
                for (step_idx, step) in path.iter().enumerate() {
                    let step_node = icfg.nodes.get(&step.node_id).unwrap();
                    let step_method = program.methods.get(&step_node.method_id).unwrap();
                    let step_inst = step_node
                        .instruction_id
                        .and_then(|id| program.instructions.get(&id));
                    println!(
                        "    [{}] node={} context={} method='{}' var='{}' inst={:?}",
                        step_idx,
                        step.node_id,
                        step.context,
                        step_method.name,
                        step.var,
                        step_inst.map(|i| &i.kind)
                    );
                }
            }
        }
    }

    println!("\nTainted facts in program:");
    for fact in &engine_with_guard.tainted_facts {
        let step_node = icfg.nodes.get(&fact.node_id).unwrap();
        let step_method = program.methods.get(&step_node.method_id).unwrap();
        println!(
            "  node={} context={} method='{}' var='{}'",
            fact.node_id, fact.context, step_method.name, fact.var
        );
    }
}
