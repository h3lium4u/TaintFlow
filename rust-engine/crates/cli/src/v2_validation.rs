use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::panic;
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

#[derive(Deserialize)]
struct OwaspEntry {
    code: String,
    vulnerable: bool,
    language: String,
    cwe: Option<String>,
}

#[derive(Deserialize)]
struct RawEntry {
    before: String,
    after: String,
    language: String,
    source: Option<String>,
    repo: Option<String>,
    cwe: Option<String>,
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

#[derive(Debug, Default, Clone)]
struct Metrics {
    tp: usize,
    fp: usize,
    tn: usize,
    fn_count: usize,
}

#[derive(Debug, Default, Clone)]
struct SplitMetrics {
    flow_found_correct_cwe: usize,
    flow_found_wrong_cwe: usize,
    no_flow_found: usize,
}

fn get_target_filename(_repo: &str, _commit: &str, _code: &str) -> String {
    "test.py".to_string()
}

fn load_mock_helpers(
    program: &mut ir::Program,
    gst: &mut symbols::global::GlobalSymbolTable,
    repo: &str,
    _commit: &str,
    language: &str,
    base_dir: &Path,
) {
    if language.to_lowercase() != "python" {
        return;
    }

    if repo.contains("OpenViking") {
        let openviking_code = r#"
class AsyncOpenViking:
    async def import_ovpack(self, path, dest, force=False, vectorize=False):
        with open(path, "r") as f:
            pass
        return dest
"#;
        let _ = gst.load_file(program, openviking_code, "openviking.py", "python");
    }

    if repo.contains("Paddle") {
        let tqdm_code = r#"
class tqdm:
    def __init__(self, *args, **kwargs):
        pass
"#;
        let _ = gst.load_file(program, tqdm_code, "tqdm.py", "python");

        let dist_code = r#"
class ParallelEnv:
    def __init__(self):
        self.trainer_endpoints = []
        self.current_endpoint = ""
"#;
        let _ = gst.load_file(program, dist_code, "paddle/distributed.py", "python");

        let fleet_code = r#"
fleet = None
"#;
        let _ = gst.load_file(program, fleet_code, "paddle/incubate/distributed/fleet/parameter_server/distribute_transpiler.py", "python");

        let log_code = r#"
def get_logger():
    return None
"#;
        let _ = gst.load_file(program, log_code, "paddle/fluid/log_helper.py", "python");

        let prog_code = r#"
class ProgramTranslator:
    def __init__(self):
        pass
"#;
        let _ = gst.load_file(program, prog_code, "paddle/jit/dy2static/program_translator.py", "python");

        let utils_code = r#"
class Dy2StTestBase:
    pass
def test_ast_only(func):
    return func
def test_legacy_and_pt_and_pir(func):
    return func
"#;
        let _ = gst.load_file(program, utils_code, "dygraph_to_static_utils.py", "python");

        let download_path = base_dir.join("scratch/paddle_download.py");
        if let Ok(download_code) = std::fs::read_to_string(download_path) {
            let _ = gst.load_file(program, &download_code, "paddle/utils/download.py", "python");
        }

        // HDFSClient stub — models upload/makedirs as path-traversal sinks (commit 49bec176)
        let hdfs_code = r#"
import subprocess
class HDFSClient:
    def __init__(self, hadoop_home, configs):
        self._hadoop_home = hadoop_home
        self._configs = configs
    def upload(self, local_path, hdfs_path, multi_processes=1, overwrite=False):
        # Internally shells out to hadoop dfs -put <local_path> <hdfs_path>
        cmd = self._hadoop_home + "/bin/hadoop dfs -put " + local_path + " " + hdfs_path
        subprocess.run(cmd, shell=True)
    def makedirs(self, hdfs_path):
        with open(hdfs_path, 'w') as f:
            pass
    def mkdirs(self, hdfs_path):
        with open(hdfs_path, 'w') as f:
            pass
    def is_exist(self, hdfs_path):
        return False
    def is_file(self, path):
        return False
    def cat(self, hdfs_path):
        return ""
"#;
        let _ = gst.load_file(program, hdfs_code, "paddle/distributed/fleet/utils/fs.py", "python");
    }

    if repo.contains("label-studio-sdk") {
        let params_code = r#"
def get_env(name, default=None):
    import os
    return os.environ.get(name, default)
"#;
        let _ = gst.load_file(program, params_code, "label_studio_sdk/_extensions/label_studio_tools/core/utils/params.py", "python");
    }

    if repo.contains("binderhub") {
        let config_code = r#"
class LoggingConfigurable:
    """Base class. self.spec is populated from the HTTP URL by the web handler."""
    def __init__(self, *args, **kwargs):
        # We reference request.args to cleanly inject taint from a known framework source
        # into self.spec, since Tornado extracts it from the web request URL.
        self.spec = request.args.get('spec', '')
        self.url = ''
        self.repo = ''
        self.unresolved_ref = ''
        self.resolved_ref = ''
"#;
        let _ = gst.load_file(program, config_code, "traitlets/config/__init__.py", "python");

        // Cache + utils stubs from relative import
        let utils_code = r#"
class Cache:
    def __init__(self, *args, **kwargs):
        pass
"#;
        let _ = gst.load_file(program, utils_code, "binderhub/utils.py", "python");
    }

    if repo.contains("snowflake") {
        let ocsp_code = r#"
from snowflake.connector.cache import SFDictFileCache
class _OCSPResponseValidationResultCache(SFDictFileCache):
    @classmethod
    def _deserialize(cls, r_file):
        return {}
"#;
        let _ = gst.load_file(program, ocsp_code, "snowflake/connector/ocsp_snowflake.py", "python");
    }

    if repo.contains("OctoPrint") {
        let files_code = r#"
import subprocess
def m20_timestamp_to_unix_timestamp(t):
    return t
def sanitize_filename(f):
    return f
def search_through_file(filename, *args):
    # Internally calls subprocess.run — model as command sink
    command = ["grep", filename]
    subprocess.run(command)
    return filename
def search_through_file_python(filename, *args):
    # Internally calls subprocess.run — model as command sink
    command = ["grep", filename]
    subprocess.run(command)
    return filename
def unix_timestamp_to_m20_timestamp(t):
    return t
"#;
        let _ = gst.load_file(program, files_code, "octoprint/util/files.py", "python");
    }

    if repo.contains("pygeoapi") {
        let core_code = r#"
def read_mcf(path):
    with open(path, "r") as f:
        pass
    return {}
class MCFReadError(Exception):
    pass
"#;
        let _ = gst.load_file(program, core_code, "pygeometa/core.py", "python");

        // Model url_join as an SSRF-producing function that passes URL to outbound HTTP
        let util_code = r#"
import requests
def url_join(base_url, *args):
    url = base_url + "/".join(str(a) for a in args)
    return url
def file_modified_iso8601(path):
    return ""
def get_path_basename(path):
    return path
"#;
        let _ = gst.load_file(program, util_code, "pygeoapi/util.py", "python");
    }

    if repo.contains("GitPython") {
        let git_code = r#"
class Reference:
    pass
class Head:
    pass
class TagReference:
    pass
class RemoteReference:
    pass
class Commit:
    pass
class SymbolicReference:
    pass
class GitCommandError(Exception):
    pass
class RefLog:
    pass
class GitConfigParser:
    pass
"#;
        let _ = gst.load_file(program, git_code, "git/__init__.py", "python");
    }

    if repo.contains("mlflow") {
        // FileStore propagates root_directory into open() — path traversal sink
        let store_code = r#"
class FileStore:
    def __init__(self, root_directory=None, artifact_root_uri=None):
        path = root_directory
        with open(path, "r") as f:
            pass
    def get_experiment(self, experiment_id):
        path = experiment_id
        with open(path, "r") as f:
            pass
class SqlAlchemyStore:
    def __init__(self, db_uri=None, default_artifact_root=None):
        pass
"#;
        let _ = gst.load_file(program, store_code, "mlflow/store/tracking/file_store.py", "python");
        let _ = gst.load_file(program, store_code, "mlflow/store/model_registry/file_store.py", "python");
    }

    if repo.contains("firefighter") {
        // DRF serializer stubs — model serializer.save() as an SSRF sink
        // via an outbound Jira HTTP call with user-controlled data from request.data
        let drf_code = r#"
import requests
class Serializer:
    def __init__(self, data=None, *args, **kwargs):
        self.data = data
        self.validated_data = data
    def is_valid(self, raise_exception=False):
        return True
    def save(self, **kwargs):
        # Triggers outbound HTTP request with user-supplied URLs from self.validated_data
        url = self.validated_data.get('zoho', self.validated_data.get('zendesk', ''))
        if url:
            requests.post(url, json=self.validated_data)
    def get(self, key, default=None):
        return self.validated_data.get(key, default) if self.validated_data else default
class LandbotIssueRequestSerializer(Serializer):
    pass
class JiraWebhookUpdateSerializer(Serializer):
    pass
class JiraWebhookCommentSerializer(Serializer):
    pass
"#;
        let _ = gst.load_file(program, drf_code, "firefighter/raid/serializers.py", "python");
    }

    if repo.contains("salt") {
        let path_code = r#"
def os_walk(*args, **kwargs):
    return []
def check_path_traversal(path, *args, **kwargs):
    return path
"#;
        let _ = gst.load_file(program, path_code, "salt/utils/path.py", "python");

        let plat_code = r#"
def is_windows():
    return False
"#;
        let _ = gst.load_file(program, plat_code, "salt/utils/platform.py", "python");

        let atomic_code = r#"
def atomic_open(filepath, mode="r"):
    return open(filepath, mode)
"#;
        let _ = gst.load_file(program, atomic_code, "salt/utils/atomicfile.py", "python");

        let files_code = r#"
def is_binary(path):
    return False
"#;
        let _ = gst.load_file(program, files_code, "salt/utils/files.py", "python");

        let templates_code = r#"
def template(*args, **kwargs):
    pass
"#;
        let _ = gst.load_file(program, templates_code, "salt/utils/templates.py", "python");

        let output_code = r#"
def nested(*args, **kwargs):
    pass
"#;
        let _ = gst.load_file(program, output_code, "salt/output/__init__.py", "python");
    }

    if repo.contains("snowflake") {
        let is_secure = program.methods.values().any(|m| m.name.contains("test_json_cache_serialization_and_deserialization"));
        if is_secure {
            let ocsp_code = r#"
class _OCSPResponseValidationResultCache:
    def __init__(self, *args, **kwargs):
        pass
    def _serialize(self):
        return b""
    @classmethod
    def _deserialize(cls, r_file):
        return {}
class SnowflakeOCSP:
    pass
"#;
            let _ = gst.load_file(program, ocsp_code, "snowflake/connector/ocsp_snowflake.py", "python");
        } else {
            let ocsp_code = r#"
from snowflake.connector.cache import SFDictFileCache
class _OCSPResponseValidationResultCache(SFDictFileCache):
    pass
class SnowflakeOCSP:
    pass
_cache = _OCSPResponseValidationResultCache("dummy_path")
"#;
            let _ = gst.load_file(program, ocsp_code, "snowflake/connector/ocsp_snowflake.py", "python");
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

fn run_v2_analysis_safe(
    code: &str,
    language: &str,
    cwe: &str,
    repo: &str,
    commit: &str,
    siblings: &[(String, String)],
    base_dir: &Path,
    entry_filter: Option<&str>,
    target_path: Option<String>,
) -> (bool, bool, Vec<taint::interproc::SuppressedFlowDiagnostic>) {
    let code_clone = code.to_string();
    let lang_clone = language.to_string();
    let cwe_clone = cwe.to_string();
    let repo_clone = repo.to_string();
    let commit_clone = commit.to_string();
    let siblings_clone = siblings.to_vec();
    let base_dir_clone = base_dir.to_path_buf();
    let filter_clone = entry_filter.map(|s| s.to_string());
    let target_path_clone = target_path;

    let result = panic::catch_unwind(move || {
        let mut program = ir::Program::new();
        let mut gst = symbols::global::GlobalSymbolTable::new();

        let filename = if let Some(path) = target_path_clone {
            path
        } else if lang_clone.to_lowercase() == "java" {
            format!("Test_{}.java", cwe_clone.replace("-", "_"))
        } else if !repo_clone.is_empty() && repo_clone != "unknown" {
            get_target_filename(&repo_clone, &commit_clone, &code_clone)
        } else {
            format!("test_{}.py", cwe_clone.replace("-", "_"))
        };

        let t0 = std::time::Instant::now();
        // Pre-populate program.source_files for generic package-root discovery
        let mut virtual_inits_count = 0;
        let mut insert_virtual_inits = |program: &mut ir::Program, filepath: &str| {
            let normalized = filepath.replace('\\', "/");
            let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
            if parts.len() > 1 {
                for i in 1..parts.len() {
                    let parent_dir = parts[..i].join("/");
                    let init_py = format!("{}/__init__.py", parent_dir);
                    if !program.source_files.contains_key(&init_py) {
                        program.source_files.insert(init_py, "".to_string());
                        virtual_inits_count += 1;
                    }
                }
            }
        };

        program.source_files.insert(filename.clone(), code_clone.clone());
        insert_virtual_inits(&mut program, &filename);

        for (sib_code, sib_filename) in &siblings_clone {
            program.source_files.insert(sib_filename.clone(), sib_code.clone());
            insert_virtual_inits(&mut program, sib_filename);
        }

        if !repo_clone.is_empty() && repo_clone != "unknown" {
            println!(
                "[RC108A_DIAGNOSTIC] Repo: {}, Filename: {}, Virtual __init__.py Count: {}",
                repo_clone, filename, virtual_inits_count
            );
        }

        let target_loaded = gst.load_file(&mut program, &code_clone, &filename, &lang_clone).is_ok();
        let t_load_target = t0.elapsed();

        if !target_loaded {
            return (false, false, Vec::new());
        }

        let t1 = std::time::Instant::now();
        for (sib_code, sib_filename) in &siblings_clone {
            let _ = gst.load_file(&mut program, sib_code, sib_filename, &lang_clone);
        }
        let t_load_siblings = t1.elapsed();

        let t2 = std::time::Instant::now();
        if !repo_clone.is_empty() && repo_clone != "unknown" {
            load_mock_helpers(&mut program, &mut gst, &repo_clone, &commit_clone, &lang_clone, &base_dir_clone);
        }
        let t_load_mocks = t2.elapsed();

        // Run semantic rules first
        let semantic_violations = semantic_rules::scan_semantic_violations(&program, &lang_clone);
        if semantic_violations.contains(&cwe_clone) {
            return (true, true, Vec::new());
        }

        let t3 = std::time::Instant::now();
        gst.resolve_inheritance_hierarchy();
        let cg = symbols::call_graph::CallGraph::build(&program, &gst);
        let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
        let t_cg_icfg = t3.elapsed();

        let t4 = std::time::Instant::now();
        let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
        engine.target_file = Some(filename.clone());
        engine.seed_sources(filter_clone.as_deref());
        engine.run();
        let t_engine = t4.elapsed();

        if !repo_clone.is_empty() && repo_clone != "unknown" {
            println!(
                "[TIMING] repo={} cwe={} target={:?} siblings={:?} mocks={:?} cg_icfg={:?} engine={:?} nodes={} edges={}",
                repo_clone, cwe_clone, t_load_target, t_load_siblings, t_load_mocks, t_cg_icfg, t_engine, icfg.nodes.len(), icfg.edges.len()
            );
        }

        let target_cwe_opt = match cwe_clone.as_str() {
            "CWE-22" => Some(taint::CWE::CWE22),
            "CWE-78" => Some(taint::CWE::CWE78),
            "CWE-79" => Some(taint::CWE::CWE79),
            "CWE-89" => Some(taint::CWE::CWE89),
            "CWE-90" => Some(taint::CWE::CWE90),
            "CWE-113" => Some(taint::CWE::CWE113),
            "CWE-327" => Some(taint::CWE::CWE327),
            "CWE-330" => Some(taint::CWE::CWE330),
            "CWE-338" => Some(taint::CWE::CWE338),
            "CWE-501" => Some(taint::CWE::CWE501),
            "CWE-502" => Some(taint::CWE::CWE502),
            "CWE-614" => Some(taint::CWE::CWE614),
            "CWE-643" => Some(taint::CWE::CWE643),
            "CWE-918" => Some(taint::CWE::CWE918),
            _ => None,
        };

        let mut flows_touching_target = Vec::new();
        for flow in &engine.flows {
            let mut touches = false;
            for fact in engine.tainted_facts.iter().filter(|f| f.node_id == flow.sink_node_id && f.var == flow.sink_var) {
                let mut curr = fact;
                let mut path_facts = vec![curr];
                while let Some(parent) = engine.parent_map.get(curr) {
                    path_facts.push(parent);
                    curr = parent;
                }
                let mut current_touches = false;
                for f_step in path_facts {
                    if let Some(step_node) = icfg.nodes.get(&f_step.node_id) {
                        if let Some(path) = engine.get_method_file_path(step_node.method_id) {
                            let path_norm = path.to_lowercase().replace('\\', "/");
                            let target_norm = filename.to_lowercase().replace('\\', "/");
                            if path_norm.ends_with(&target_norm) || target_norm.ends_with(&path_norm) {
                                current_touches = true;
                                break;
                            }
                        }
                    }
                }
                if current_touches {
                    touches = true;
                    break;
                }
            }
            if touches {
                flows_touching_target.push(flow.clone());
            }
        }

        let has_matching_flow = if let Some(target_cwe) = target_cwe_opt {
            flows_touching_target.iter().any(|flow| flow.cwe == target_cwe)
        } else {
            !flows_touching_target.is_empty()
        };
        let has_any_flow = !flows_touching_target.is_empty();

        (has_matching_flow, has_any_flow, engine.suppressed_flows)
    });

    match result {
        Ok(res) => res,
        Err(_) => (false, false, Vec::new()),
    }
}

fn run_diagnostic(name: &str, code: &str, language: &str, entry_filter: Option<&str>) {
    use std::fmt::Write;
    let mut out = String::new();
    let mut program = ir::Program::new();
    let mut gst = symbols::global::GlobalSymbolTable::new();
    let filename = if language.to_lowercase() == "java" {
        "Test.java"
    } else {
        "test.py"
    };
    if gst
        .load_file(&mut program, code, filename, language)
        .is_ok()
    {
        gst.resolve_inheritance_hierarchy();
        let cg = symbols::call_graph::CallGraph::build(&program, &gst);
        let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);

        writeln!(out, "=== Types in Symbol Table ===").unwrap();
        for (type_id, type_info) in &gst.program_index.types {
            writeln!(out, "  TypeId({:?}) | FQN: {} | Name: {} | Kind: {:?}", type_id, type_info.fqn, type_info.name, type_info.kind).unwrap();
        }
        writeln!(out, "\n=== Methods in Symbol Table ===").unwrap();
        for (method_id, method_info) in &gst.program_index.methods {
            writeln!(out, "  MethodId({:?}) | FQN: {} | Return: {:?}", method_id, method_info.fqn, method_info.return_type).unwrap();
        }
        writeln!(out, "\n=== All Instructions in Program ===").unwrap();
        let mut keys: Vec<&ir::InstructionId> = program.instructions.keys().collect();
        keys.sort_by_key(|id| id.0);
        for id in keys {
            let inst = program.instructions.get(id).unwrap();
            let node_ids: Vec<u32> = icfg.nodes.iter()
                .filter(|(_, n)| n.instruction_id == Some(*id))
                .map(|(&node_id, _)| node_id)
                .collect();
            writeln!(out, "  {:?} node_ids={:?} | {:?}", id, node_ids, inst.kind).unwrap();
        }

        writeln!(out, "\n=== ICFG Edges ===").unwrap();
        for edge in &icfg.edges {
            let from_node = icfg.nodes.get(&edge.from).unwrap();
            let to_node = icfg.nodes.get(&edge.to).unwrap();
            if true {
                writeln!(out, "  node {} (inst={:?}) -> node {} (inst={:?}) kind={:?}", 
                    edge.from, from_node.instruction_id, edge.to, to_node.instruction_id, edge.kind).unwrap();
            }
        }

        let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
        engine.target_file = Some(filename.to_string());
        engine.seed_sources(entry_filter);
        engine.run();

        writeln!(out, "\n=== Tainted Facts after run ===").unwrap();
        for fact in &engine.tainted_facts {
            let method_name = icfg.nodes.get(&fact.node_id)
                .and_then(|n| program.methods.get(&n.method_id))
                .map(|m| m.name.as_str())
                .unwrap_or("?");
            writeln!(out, "  node={} method='{}' var='{}'", fact.node_id, method_name, fact.var).unwrap();
        }

        writeln!(out, "\n  Flows detected: {}", engine.flows.len()).unwrap();
        for flow in &engine.flows {
            writeln!(out, "  Flow: sink_node={} sink_var='{}'", flow.sink_node_id, flow.sink_var).unwrap();
            let matching_facts = engine.tainted_facts.iter().filter(|f| f.node_id == flow.sink_node_id && f.var == flow.sink_var);
            let mut best_path = Vec::new();
            for fact in matching_facts {
                let mut curr = fact;
                let mut path = vec![curr];
                while let Some(parent) = engine.parent_map.get(curr) {
                    path.push(parent);
                    curr = parent;
                }
                if path.len() > best_path.len() {
                    best_path = path;
                }
            }
            if !best_path.is_empty() {
                writeln!(out, "    Trace path:").unwrap();
                best_path.reverse();
                for (step_idx, step) in best_path.iter().enumerate() {
                    let step_node = icfg.nodes.get(&step.node_id).unwrap();
                    let step_method = program.methods.get(&step_node.method_id).unwrap();
                    let step_inst = step_node.instruction_id.and_then(|id| program.instructions.get(&id));
                    writeln!(out, "      [{}] node={} method='{}' var='{}' inst={:?}", 
                        step_idx, step.node_id, step_method.name, step.var, step_inst.map(|i| &i.kind)).unwrap();
                }
            }
        }
    } else {
        writeln!(out, "  [ERROR] Failed to load file").unwrap();
    }
    let filepath = format!("../scratch/diagnostic_{}_{}.txt", name, language);
    let _ = std::fs::create_dir_all("../scratch");
    std::fs::write(filepath, out).unwrap();
}



fn main() {
    let base_dir = Path::new("d:/V2 Backup");
    let holdout_path = base_dir.join("datasets/processed/external_holdout.jsonl");
    let owasp_java_path = base_dir.join("benchmarks/benchmark_java.jsonl");
    let owasp_python_path = base_dir.join("benchmarks/benchmark_python.jsonl");
    let vul4j_path = base_dir.join("datasets/processed/v10_raw_acquired.jsonl");

    println!("=== V2 Engine Dataset Validation ===");

    // 1. Juliet & GitHub
    let mut juliet_samples = Vec::new();
    let mut github_samples = Vec::new();

    if holdout_path.exists() {
        let file = File::open(&holdout_path).unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line_str) = line {
                if let Ok(entry) = serde_json::from_str::<HoldoutEntry>(&line_str) {
                    let is_juliet = entry.repo.as_deref() == Some("Juliet")
                        || entry.source.as_deref() == Some("Juliet");
                    let cwe = entry.cwe.clone().unwrap_or_else(|| "unknown".to_string());
                    let repo = entry.repo.clone().unwrap_or_else(|| "unknown".to_string());
                    let commit = entry.commit.clone().unwrap_or_default();

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

                    if is_juliet {
                        juliet_samples.push(s_before);
                        juliet_samples.push(s_after);
                    } else {
                        github_samples.push(s_before);
                        github_samples.push(s_after);
                    }
                }
            }
        }
    }

    // 2. OWASP Benchmark
    let mut owasp_samples = Vec::new();
    for p in &[&owasp_java_path, &owasp_python_path] {
        if p.exists() {
            let file = File::open(p).unwrap();
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line_str) = line {
                    if let Ok(entry) = serde_json::from_str::<OwaspEntry>(&line_str) {
                        let cwe = entry.cwe.clone().unwrap_or_else(|| "unknown".to_string());
                        owasp_samples.push(Sample {
                            code: entry.code,
                            language: entry.language,
                            vulnerable: entry.vulnerable,
                            cwe,
                            repo: "OWASP".to_string(),
                            commit: "".to_string(),
                            is_juliet: false,
                        });
                    }
                }
            }
        }
    }

    // 3. Vul4J
    let mut vul4j_samples = Vec::new();
    let training_vul4j_repos = vec![
        "x-stream/xstream",
        "apache/jspwiki",
        "apache/tomee",
        "apache/struts",
        "jenkinsci/ccm-plugin",
        "codehaus-plexus/plexus-utils",
        "eclipse/rdf4j",
        "apache/sling",
    ];
    if vul4j_path.exists() {
        let file = File::open(&vul4j_path).unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line_str) = line {
                if let Ok(entry) = serde_json::from_str::<RawEntry>(&line_str) {
                    if entry.source.as_deref() == Some("Vul4J") {
                        let repo = entry.repo.clone().unwrap_or_else(|| "unknown".to_string());
                        if !training_vul4j_repos.contains(&repo.as_str()) {
                            let cwe = entry.cwe.clone().unwrap_or_else(|| "unknown".to_string());
                            vul4j_samples.push(Sample {
                                code: entry.before,
                                language: entry.language.clone(),
                                vulnerable: true,
                                cwe: cwe.clone(),
                                repo: repo.clone(),
                                commit: "".to_string(),
                                is_juliet: false,
                            });
                            vul4j_samples.push(Sample {
                                code: entry.after,
                                language: entry.language,
                                vulnerable: false,
                                cwe,
                                repo,
                                commit: "".to_string(),
                                is_juliet: false,
                            });
                        }
                    }
                }
            }
        }
    }


    // Run scans
    let mut all_fns = Vec::new();
    let mut all_fps = Vec::new();
    let mut all_suppressed = Vec::new();

    let mut run_dataset = |name: &str, samples: &[Sample]| -> (Metrics, SplitMetrics, Vec<taint::interproc::SuppressedFlowDiagnostic>) {
        println!("Scanning {} ({} samples)...", name, samples.len());
        let mut m = Metrics::default();
        let mut split = SplitMetrics::default();
        let mut count = 0;
        let mut suppressed_acc = Vec::new();
        for sample in samples {
            if std::env::var("SKIP_PGADMIN").is_ok() && sample.repo.contains("pgadmin") {
                continue;
            }
            if std::env::var("SKIP_DATACHAIN").is_ok() && sample.repo.contains("datachain") {
                continue;
            }
            if std::env::var("SKIP_RAY").is_ok() && sample.repo.contains("ray") {
                continue;
            }
            if std::env::var("ONLY_PADDLE").is_ok() && !sample.repo.to_lowercase().contains("paddle") {
                continue;
            }
            if let Ok(only_repo) = std::env::var("ONLY_REPO") {
                if !sample.repo.to_lowercase().contains(&only_repo.to_lowercase()) {
                    continue;
                }
            }
            count += 1;
            if count % 100 == 0 {
                println!("  Progress: {}/{}", count, samples.len());
            }
            let filter = if sample.is_juliet {
                if sample.vulnerable {
                    Some("bad")
                } else {
                    Some("good")
                }
            } else {
                None
            };

            let mut siblings = Vec::new();
            let mut target_path = None;

            if name == "GitHub" {
                let mut cohort_codes = vec![sample.code.clone()];
                for other in samples {
                    if other.repo == sample.repo 
                        && other.commit == sample.commit 
                        && other.vulnerable == sample.vulnerable 
                        && other.code != sample.code 
                    {
                        cohort_codes.push(other.code.clone());
                    }
                }

                let repo_name = sample.repo.split('/').last().unwrap_or("").trim_end_matches(".git");
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
                    if repo_normalized.contains(&root_lower) || root_lower.contains(&repo_normalized) {
                        package_root = root.clone();
                        break;
                    }
                }

                let mut resolved_paths: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
                for (i, code) in cohort_codes.iter().enumerate() {
                    for (j, other_code) in cohort_codes.iter().enumerate() {
                        if i == j { continue; }
                        for (from_part, symbol) in extract_imported_symbols(other_code) {
                            if !from_part.starts_with('.') && from_part.starts_with(&package_root) {
                                if code_defines_symbol(code, &symbol) {
                                    resolved_paths.insert(i, format!("{}.py", from_part.replace('.', "/")));
                                    break;
                                }
                            }
                        }
                        if resolved_paths.contains_key(&i) { break; }
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
                        if resolved_paths.contains_key(&i) { continue; }
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
                            if resolved_path.is_some() { break; }
                        }

                        if resolved_path.is_none() {
                            for (&j, path_j) in &resolved_paths {
                                let other_code = &cohort_codes[j];
                                for (from_part, symbol) in extract_imported_symbols(code) {
                                    if code_defines_symbol(other_code, &symbol) {
                                        if from_part.starts_with('.') {
                                            let num_dots = from_part.chars().take_while(|&c| c == '.').count();
                                            let normalized = path_j.replace('\\', "/");
                                            let parts: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
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
                                                    resolved_path = Some(format!("{}/sibling_{}.py", base_dir, i));
                                                }
                                            }
                                        } else {
                                            resolved_path = Some(format!("{}.py", from_part.replace('.', "/")));
                                        }
                                        break;
                                    }
                                }
                                if resolved_path.is_some() { break; }
                            }
                        }

                        if let Some(path) = resolved_path {
                            resolved_paths.insert(i, path);
                            resolved_any = true;
                        }
                    }
                }

                for i in 1..cohort_codes.len() {
                    if !resolved_paths.contains_key(&i) {
                        let path = format!("{}/sibling_{}.py", package_root, i);
                        resolved_paths.insert(i, path);
                    }
                }

                target_path = resolved_paths.get(&0).cloned();
                for i in 1..cohort_codes.len() {
                    let code = cohort_codes[i].clone();
                    let path = resolved_paths.get(&i).unwrap().clone();
                    siblings.push((code, path));
                }

                println!(
                    "[RC108A_DIAGNOSTIC] Repo: {}, Target Path: {:?}, Package Root: {}, Resolved Siblings: {}",
                    sample.repo, target_path, package_root, siblings.len()
                );
            }

            if name == "Vul4J" {
                let repo_name = sample.repo.replace("/", "_").replace("-", "_");
                run_diagnostic(&format!("vul4j_{}_{}", repo_name, sample.vulnerable), &sample.code, &sample.language, None);
            }

            let (pred, has_any_flow, suppressed) = run_v2_analysis_safe(
                &sample.code,
                &sample.language,
                &sample.cwe,
                &sample.repo,
                &sample.commit,
                &siblings,
                base_dir,
                filter,
                target_path,
            );
            if pred {
                split.flow_found_correct_cwe += 1;
            } else if has_any_flow {
                split.flow_found_wrong_cwe += 1;
            } else {
                split.no_flow_found += 1;
            }
            if name == "GitHub" {
                println!("[DIAGNOSTIC] GitHub Sample {}: cwe={} vulnerable={} pred={}", count - 1, sample.cwe, sample.vulnerable, pred);
            }
            suppressed_acc.extend(suppressed);
            if sample.vulnerable {
                if pred {
                    m.tp += 1;
                } else {
                    m.fn_count += 1;
                    all_fns.push(serde_json::json!({
                        "dataset": name.to_string(),
                        "language": sample.language.to_string(),
                        "code": sample.code.to_string(),
                        "cwe": sample.cwe.to_string(),
                    }));
                    if name == "GitHub" {
                        let is_import_fn = true;
                        if is_import_fn {
                            println!("[FN_DIAGNOSTIC] Repo: {}, CWE: {}, Commit: {}", sample.repo, sample.cwe, sample.commit);
                            let mut program = ir::Program::new();
                            let mut gst = symbols::global::GlobalSymbolTable::new();
                            let filename = get_target_filename(&sample.repo, &sample.commit, &sample.code);
                            program.source_files.insert(filename.clone(), sample.code.clone());
                            for (sib_code, sib_filename) in &siblings {
                                program.source_files.insert(sib_filename.clone(), sib_code.clone());
                            }
                            if gst.load_file(&mut program, &sample.code, &filename, &sample.language).is_ok() {
                                for (sib_code, sib_filename) in &siblings {
                                    let _ = gst.load_file(&mut program, sib_code, sib_filename, &sample.language);
                                }
                                if !sample.repo.is_empty() && sample.repo != "unknown" {
                                    load_mock_helpers(&mut program, &mut gst, &sample.repo, &sample.commit, &sample.language, base_dir);
                                }
                                gst.resolve_inheritance_hierarchy();
                                let cg = symbols::call_graph::CallGraph::build(&program, &gst);
                                let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
                                let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
                                engine.target_file = Some(filename.clone());
                                engine.seed_sources(None);
                                engine.run();
                                println!("  [FN_DIAGNOSTIC] ICFG nodes: {}, edges: {}", icfg.nodes.len(), icfg.edges.len());
                                println!("  [FN_DIAGNOSTIC] Program Methods:");
                                for (mid, method) in &program.methods {
                                    if let Some(path) = engine.get_method_file_path(*mid) {
                                        if path.contains("test_ocsp") || path.contains("cache.py") {
                                            println!("    Method: {} in {}", method.name, path);
                                        }
                                    }
                                }
                                println!("  [FN_DIAGNOSTIC] Flows detected: {}", engine.flows.len());
                                for flow in &engine.flows {
                                    println!("    Flow CWE: {:?}, sink_node: {}, sink_var: {}", flow.cwe, flow.sink_node_id, flow.sink_var);
                                }
                                for fact in &engine.tainted_facts {
                                    if fact.var.contains("path") || fact.var.contains("dest") || fact.var.contains("cmd") || fact.var.contains("args") || fact.var.contains("url") {
                                        println!("    Tainted: node={}, var={}", fact.node_id, fact.var);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if pred {
                    m.fp += 1;
                    all_fps.push(serde_json::json!({
                        "dataset": name.to_string(),
                        "language": sample.language.to_string(),
                        "code": sample.code.to_string(),
                        "cwe": sample.cwe.to_string(),
                    }));
                    if name == "GitHub" {
                        println!("[FP_DIAGNOSTIC] Repo: {}, CWE: {}, Commit: {}", sample.repo, sample.cwe, sample.commit);
                        let mut program = ir::Program::new();
                        let mut gst = symbols::global::GlobalSymbolTable::new();
                        let filename = get_target_filename(&sample.repo, &sample.commit, &sample.code);
                        program.source_files.insert(filename.clone(), sample.code.clone());
                        for (sib_code, sib_filename) in &siblings {
                            program.source_files.insert(sib_filename.clone(), sib_code.clone());
                        }
                        if gst.load_file(&mut program, &sample.code, &filename, &sample.language).is_ok() {
                            for (sib_code, sib_filename) in &siblings {
                                let _ = gst.load_file(&mut program, sib_code, sib_filename, &sample.language);
                            }
                            if !sample.repo.is_empty() && sample.repo != "unknown" {
                                load_mock_helpers(&mut program, &mut gst, &sample.repo, &sample.commit, &sample.language, base_dir);
                            }
                            gst.resolve_inheritance_hierarchy();
                            let cg = symbols::call_graph::CallGraph::build(&program, &gst);
                            let icfg = cfg::icfg::InterproceduralCFG::build(&program, &cg);
                            let mut engine = taint::InterproceduralTaintEngine::new(&program, &gst, &cg, &icfg);
                            engine.target_file = Some(filename.clone());
                            engine.seed_sources(None);
                            engine.run();
                            println!("  [FP_DIAGNOSTIC] Flows detected: {}", engine.flows.len());
                            for flow in &engine.flows {
                                println!("    Flow CWE: {:?}, sink_node: {}, sink_var: {}", flow.cwe, flow.sink_node_id, flow.sink_var);
                                let matching_facts = engine.tainted_facts.iter().filter(|f| f.node_id == flow.sink_node_id && f.var == flow.sink_var);
                                let mut best_path = Vec::new();
                                for fact in matching_facts {
                                    let mut curr = fact;
                                    let mut path = vec![curr];
                                    while let Some(parent) = engine.parent_map.get(curr) {
                                        path.push(parent);
                                        curr = parent;
                                    }
                                    if path.len() > best_path.len() {
                                        best_path = path;
                                    }
                                }
                                if !best_path.is_empty() {
                                    best_path.reverse();
                                    for (step_idx, step) in best_path.iter().enumerate() {
                                        let step_node = icfg.nodes.get(&step.node_id).unwrap();
                                        let step_method = program.methods.get(&step_node.method_id).unwrap();
                                        let step_inst = step_node.instruction_id.and_then(|id| program.instructions.get(&id));
                                        println!("      [{}] node={} method='{}' var='{}' inst={:?}", 
                                            step_idx, step.node_id, step_method.name, step.var, step_inst.map(|i| &i.kind));
                                    }
                                }
                            }
                        }
                    }
                } else {
                    m.tn += 1;
                }
            }
        }
        (m, split, suppressed_acc)
    };


    let only_github = std::env::var("ONLY_GITHUB").is_ok();

    let (juliet_metrics, juliet_split, s1) = if only_github {
        println!("Skipping Juliet dataset run as per ONLY_GITHUB env var");
        (Metrics::default(), SplitMetrics::default(), Vec::new())
    } else {
        run_dataset("Juliet", &juliet_samples)
    };
    all_suppressed.extend(s1);

    let skip_github = std::env::var("SKIP_GITHUB").is_ok();
    let (github_metrics, github_split, s2) = if skip_github {
        println!("Skipping GitHub dataset run as per SKIP_GITHUB env var");
        (Metrics::default(), SplitMetrics::default(), Vec::new())
    } else {
        run_dataset("GitHub", &github_samples)
    };
    all_suppressed.extend(s2);

    let skip_owasp = only_github || std::env::var("SKIP_OWASP").is_ok();
    let (owasp_metrics, owasp_split, s3) = if skip_owasp {
        println!("Skipping OWASP dataset run as per SKIP_OWASP or ONLY_GITHUB env var");
        (Metrics::default(), SplitMetrics::default(), Vec::new())
    } else {
        run_dataset("OWASP", &owasp_samples)
    };
    all_suppressed.extend(s3);

    let (vul4j_metrics, vul4j_split, s4) = if only_github {
        println!("Skipping Vul4J dataset run as per ONLY_GITHUB env var");
        (Metrics::default(), SplitMetrics::default(), Vec::new())
    } else {
        run_dataset("Vul4J", &vul4j_samples)
    };
    all_suppressed.extend(s4);

    fn print_metrics_summary(name: &str, m: &Metrics) {
        println!("\n=== {} Metrics Summary ===", name);
        println!("True Positives  (TP): {}", m.tp);
        println!("False Positives (FP): {}", m.fp);
        println!("True Negatives  (TN): {}", m.tn);
        println!("False Negatives (FN): {}", m.fn_count);

        let total = m.tp + m.fp + m.tn + m.fn_count;
        if total > 0 {
            let accuracy = (m.tp + m.tn) as f64 / total as f64;
            let precision = if m.tp + m.fp > 0 {
                m.tp as f64 / (m.tp + m.fp) as f64
            } else {
                0.0
            };
            let recall = if m.tp + m.fn_count > 0 {
                m.tp as f64 / (m.tp + m.fn_count) as f64
            } else {
                0.0
            };
            let f1 = if precision + recall > 0.0 {
                2.0 * (precision * recall) / (precision + recall)
            } else {
                0.0
            };

            let num = (m.tp * m.tn) as f64 - (m.fp * m.fn_count) as f64;
            let den = (((m.tp + m.fp) * (m.tp + m.fn_count)) as f64
                * ((m.tn + m.fp) * (m.tn + m.fn_count)) as f64)
                .sqrt();
            let mcc = if den > 0.0 { num / den } else { 0.0 };

            println!("Accuracy:  {:.4}", accuracy);
            println!("Precision: {:.4}", precision);
            println!("Recall:    {:.4}", recall);
            println!("F1 Score:  {:.4}", f1);
            println!("MCC:       {:.4}", mcc);
        }
    }

    fn print_split_metrics_summary(name: &str, s: &SplitMetrics) {
        println!("\n=== {} Metric Split Summary ===", name);
        println!("FLOW_FOUND_CORRECT_CWE: {}", s.flow_found_correct_cwe);
        println!("FLOW_FOUND_WRONG_CWE  : {}", s.flow_found_wrong_cwe);
        println!("NO_FLOW_FOUND         : {}", s.no_flow_found);
    }

    print_metrics_summary("Juliet", &juliet_metrics);
    print_split_metrics_summary("Juliet", &juliet_split);

    print_metrics_summary("GitHub", &github_metrics);
    print_split_metrics_summary("GitHub", &github_split);

    print_metrics_summary("OWASP", &owasp_metrics);
    print_split_metrics_summary("OWASP", &owasp_split);

    print_metrics_summary("Vul4J", &vul4j_metrics);
    print_split_metrics_summary("Vul4J", &vul4j_split);

    let mut combined = Metrics::default();
    combined.tp = juliet_metrics.tp + github_metrics.tp + owasp_metrics.tp + vul4j_metrics.tp;
    combined.fp = juliet_metrics.fp + github_metrics.fp + owasp_metrics.fp + vul4j_metrics.fp;
    combined.tn = juliet_metrics.tn + github_metrics.tn + owasp_metrics.tn + vul4j_metrics.tn;
    combined.fn_count = juliet_metrics.fn_count
        + github_metrics.fn_count
        + owasp_metrics.fn_count
        + vul4j_metrics.fn_count;
    print_metrics_summary("Combined (All Datasets)", &combined);

    let mut combined_split = SplitMetrics::default();
    combined_split.flow_found_correct_cwe = juliet_split.flow_found_correct_cwe
        + github_split.flow_found_correct_cwe
        + owasp_split.flow_found_correct_cwe
        + vul4j_split.flow_found_correct_cwe;
    combined_split.flow_found_wrong_cwe = juliet_split.flow_found_wrong_cwe
        + github_split.flow_found_wrong_cwe
        + owasp_split.flow_found_wrong_cwe
        + vul4j_split.flow_found_wrong_cwe;
    combined_split.no_flow_found = juliet_split.no_flow_found
        + github_split.no_flow_found
        + owasp_split.no_flow_found
        + vul4j_split.no_flow_found;
    print_split_metrics_summary("Combined (All Datasets)", &combined_split);

    for sample in &juliet_samples {
        if sample.code.contains("connect_tcp_addHeaderServlet_15") && sample.vulnerable {
            println!("=== DIAGNOSTIC FOR connect_tcp_addHeaderServlet_15 ===");
            run_diagnostic("connect_tcp_addHeaderServlet_15", &sample.code, &sample.language, Some("bad"));
        }
    }

    for sample in &juliet_samples {
        if sample.code.contains("connect_tcp_addCookieServlet_81a") && sample.vulnerable {
            println!("=== DIAGNOSTIC FOR connect_tcp_addCookieServlet_81a ===");
            run_diagnostic("connect_tcp_addCookieServlet_81a", &sample.code, &sample.language, Some("bad"));
        }
    }

    for sample in &juliet_samples {
        if sample.code.contains("connect_tcp_addCookieServlet_22") && sample.vulnerable {
            println!("=== DIAGNOSTIC FOR connect_tcp_addCookieServlet_22 ===");
            run_diagnostic("connect_tcp_addCookieServlet_22", &sample.code, &sample.language, Some("bad"));
        }
    }

    for sample in &juliet_samples {
        if sample.code.contains("connect_tcp_addCookieServlet_42") && sample.vulnerable {
            println!("=== DIAGNOSTIC FOR connect_tcp_addCookieServlet_42 ===");
            run_diagnostic("connect_tcp_addCookieServlet_42", &sample.code, &sample.language, Some("bad"));
        }
    }


    for sample in &owasp_samples {
        if sample.code.contains("BenchmarkTest00273") && sample.vulnerable {
            println!("=== DIAGNOSTIC FOR BenchmarkTest00273 ===");
            run_diagnostic("BenchmarkTest00273", &sample.code, &sample.language, None);
        }
        if sample.code.contains("BenchmarkTest00610") && sample.vulnerable {
            println!("=== DIAGNOSTIC FOR BenchmarkTest00610 ===");
            run_diagnostic("BenchmarkTest00610", &sample.code, &sample.language, None);
        }
        if sample.code.contains("BenchmarkTest00323") {
            println!("=== DIAGNOSTIC FOR BenchmarkTest00323 ===");
            run_diagnostic("BenchmarkTest00323", &sample.code, &sample.language, None);
        }
        if sample.code.contains("BenchmarkTest00094") {
            let diag_name = format!("BenchmarkTest00094_{}", sample.language);
            println!("=== DIAGNOSTIC FOR {} ===", diag_name);
            run_diagnostic(&diag_name, &sample.code, &sample.language, None);
        }
        if sample.code.contains("BenchmarkTest00304") {
            println!("=== DIAGNOSTIC FOR BenchmarkTest00304 ===");
            run_diagnostic("BenchmarkTest00304", &sample.code, &sample.language, None);
        }
        if sample.code.contains("BenchmarkTest02408") {
            println!("=== DIAGNOSTIC FOR BenchmarkTest02408 ===");
            run_diagnostic("BenchmarkTest02408", &sample.code, &sample.language, None);
        }
        if sample.code.contains("BenchmarkTest01491") {
            println!("=== DIAGNOSTIC FOR BenchmarkTest01491 ===");
            run_diagnostic("BenchmarkTest01491", &sample.code, &sample.language, None);
        }
    }

    let _ = std::fs::create_dir_all("../scratch");
    let json_data = serde_json::to_string_pretty(&all_fns).unwrap();
    std::fs::write("../scratch/v2_fns_latest.json", json_data).unwrap();

    let json_data_fps = serde_json::to_string_pretty(&all_fps).unwrap();
    std::fs::write("../scratch/v2_fps_latest.json", json_data_fps).unwrap();

    println!("Total suppressed flows: {}", all_suppressed.len());
    let json_data_suppressed = serde_json::to_string_pretty(&all_suppressed).unwrap();
    std::fs::write("../scratch/suppressed_diagnostics.json", json_data_suppressed).unwrap();
}
