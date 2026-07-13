use ir::Program;
use symbols::{GlobalSymbolTable, TypeKind};

#[test]
fn test_java_extraction_and_resolution() {
    let java_file_1 = r#"
        package org.example.service;
        
        import org.example.model.User;
        import org.example.repo.*;
        
        @Service
        public class UserService extends BaseService implements IUserService {
            @Autowired
            private UserRepository userRepo;
            
            @Override
            public User getUser(String id) {
                return userRepo.find(id);
            }
        }
    "#;

    let java_file_2 = r#"
        package org.example.service;
        
        public class BaseService {
            public void log(String msg) {
                // log
            }
        }
    "#;

    let java_file_3 = r#"
        package org.example.repo;
        
        public class UserRepository {
            public Object find(String id) {
                return null;
            }
        }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    let m1 = gst
        .load_file(&mut program, java_file_1, "src/UserService.java", "java")
        .unwrap();
    let _m2 = gst
        .load_file(&mut program, java_file_2, "src/BaseService.java", "java")
        .unwrap();
    let _m3 = gst
        .load_file(&mut program, java_file_3, "src/UserRepository.java", "java")
        .unwrap();

    // Resolve hierarchy
    gst.resolve_inheritance_hierarchy();

    println!("MODULES: {:?}", gst.program_index.modules);
    println!("TYPES: {:?}", gst.type_index.fqn_to_id);

    // Verify Modules
    assert_eq!(gst.program_index.modules.len(), 3);

    // Verify Package Name
    let mod1 = gst.program_index.modules.get(&m1).unwrap();
    assert_eq!(mod1.package_name.as_deref(), Some("org.example.service"));

    // Verify Type Extraction
    let user_service_id = gst
        .resolve_type(m1, "UserService")
        .expect("Should resolve UserService");
    let user_service_info = gst.program_index.types.get(&user_service_id).unwrap();
    assert_eq!(user_service_info.fqn, "org.example.service.UserService");
    assert_eq!(user_service_info.kind, TypeKind::Class);
    assert!(user_service_info
        .annotations
        .contains(&"@Service".to_string()));

    // Verify Import Resolution
    let user_fqn = gst.resolve_import(m1, "User");
    assert_eq!(user_fqn.as_deref(), Some("org.example.model.User"));

    // Verify Type Resolution (Wildcard)
    let repo_id = gst
        .resolve_type(m1, "UserRepository")
        .expect("Should resolve UserRepository via wildcard");
    let repo_info = gst.program_index.types.get(&repo_id).unwrap();
    assert_eq!(repo_info.fqn, "org.example.repo.UserRepository");

    // Verify Field Extraction
    // TypeInfo contains a fields mapping name -> FieldId
    // Wait, TypeInfo in global.rs has id, name, fqn, kind, module_id, annotations.
    // Fields are registered in program_index.fields. Let's look up the field in program_index.fields.
    let field_info = gst
        .program_index
        .fields
        .values()
        .find(|f| f.parent_type_id == user_service_id && f.name == "userRepo")
        .expect("Should have userRepo field");
    assert_eq!(field_info.fqn, "org.example.service.UserService.userRepo");
    assert!(field_info.annotations.contains(&"@Autowired".to_string()));

    // Verify Inheritance Hierarchy Resolution
    // UserService extends BaseService
    let parent_id = gst.resolve_type(m1, "BaseService").unwrap();
    let children = gst
        .parent_to_children
        .get(&parent_id)
        .expect("Should have children");
    assert!(children.contains(&user_service_id));

    // UserService implements IUserService (raw unresolved fallback)
    let implementors = gst
        .interface_to_implementors
        .get("IUserService")
        .expect("Should have implementors for IUserService");
    assert!(implementors.contains(&user_service_id));

    // Verify Method Resolution (Inherited)
    // UserService inherits log() from BaseService
    let log_method_id = gst
        .resolve_method(user_service_id, "log")
        .expect("Should resolve inherited log() method");
    let log_method_info = gst.program_index.methods.get(&log_method_id).unwrap();
    assert_eq!(log_method_info.fqn, "org.example.service.BaseService.log");
}

#[test]
fn test_python_extraction_and_resolution() {
    let python_file_1 = r#"
        from base import BaseView
        
        @route("/api")
        class MyView(BaseView):
            @login_required
            def get(self, user_id):
                return "user"
    "#;

    let python_file_2 = r#"
        class BaseView:
            def dispatch(self):
                pass
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    let m1 = gst
        .load_file(&mut program, python_file_1, "views.py", "python")
        .unwrap();
    let m2 = gst
        .load_file(&mut program, python_file_2, "base.py", "python")
        .unwrap();

    gst.resolve_inheritance_hierarchy();

    // Verify Modules
    assert_eq!(gst.program_index.modules.len(), 2);

    // Verify Type Extraction
    let my_view_id = gst
        .resolve_type(m1, "MyView")
        .expect("Should resolve MyView");
    let my_view_info = gst.program_index.types.get(&my_view_id).unwrap();
    assert_eq!(my_view_info.fqn, "views.MyView");
    assert!(my_view_info
        .annotations
        .contains(&"@route(\"/api\")".to_string()));

    // Verify Method and Decorators
    let get_method_id = gst
        .resolve_method(my_view_id, "get")
        .expect("Should resolve get method");
    let get_method_info = gst.program_index.methods.get(&get_method_id).unwrap();
    assert_eq!(get_method_info.fqn, "views.MyView.get");
    assert!(get_method_info
        .annotations
        .contains(&"@login_required".to_string()));

    // Verify Inheritance Model
    let base_view_id = gst
        .resolve_type(m2, "BaseView")
        .expect("Should resolve BaseView");
    let base_view_info = gst.program_index.types.get(&base_view_id).unwrap();
    assert_eq!(base_view_info.fqn, "base.BaseView");

    // MyView inherits dispatch from BaseView
    let dispatch_method_id = gst
        .resolve_method(my_view_id, "dispatch")
        .expect("Should resolve inherited dispatch method");
    let dispatch_method_info = gst.program_index.methods.get(&dispatch_method_id).unwrap();
    assert_eq!(dispatch_method_info.fqn, "base.BaseView.dispatch");
}

#[test]
fn test_call_graph_resolution() {
    use ir::MethodId;
    use symbols::{CallGraph, EdgeType};

    let controller_code = r#"
        package org.example.controller;
        import org.example.service.UserService;

        @RestController
        public class UserController {
            @Autowired
            private UserService userService;

            @GetMapping("/users")
            public Object getUser(String id) {
                return userService.getUser(id);
            }
        }
    "#;

    let service_code = r#"
        package org.example.service;
        import org.example.repo.UserRepository;

        @Service
        public class UserService {
            @Autowired
            private UserRepository userRepo;

            public Object getUser(String id) {
                return userRepo.find(id);
            }
        }
    "#;

    let repo_code = r#"
        package org.example.repo;

        @Repository
        public class UserRepository {
            public Object find(String id) {
                return null;
            }
        }
    "#;

    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    let m1 = gst
        .load_file(&mut program, controller_code, "UserController.java", "java")
        .unwrap();
    let m2 = gst
        .load_file(&mut program, service_code, "UserService.java", "java")
        .unwrap();
    let m3 = gst
        .load_file(&mut program, repo_code, "UserRepository.java", "java")
        .unwrap();

    gst.resolve_inheritance_hierarchy();

    // Build the Call Graph
    let cg = CallGraph::build(&program, &gst);

    // Verify nodes contain UserController.getUser, UserService.getUser, UserRepository.find
    let user_controller_get = gst
        .resolve_method(gst.resolve_type(m1, "UserController").unwrap(), "getUser")
        .unwrap();

    let user_service_get = gst
        .resolve_method(gst.resolve_type(m2, "UserService").unwrap(), "getUser")
        .unwrap();

    let user_repo_find = gst
        .resolve_method(gst.resolve_type(m3, "UserRepository").unwrap(), "find")
        .unwrap();

    // Verify HTTP entrypoint FrameworkCall -> UserController.getUser
    let http_entry = MethodId(0);
    let http_edges = cg
        .caller_to_edges
        .get(&http_entry)
        .expect("Should have framework entrypoint calls");
    assert!(http_edges
        .iter()
        .any(|e| e.callee == user_controller_get && e.edge_type == EdgeType::FrameworkCall));

    // Verify UserController.getUser -> UserService.getUser via @Autowired field
    let controller_edges = cg
        .caller_to_edges
        .get(&user_controller_get)
        .expect("Should have controller call edges");
    assert!(controller_edges
        .iter()
        .any(|e| e.callee == user_service_get));

    // Verify UserService.getUser -> UserRepository.find via @Autowired field
    let service_edges = cg
        .caller_to_edges
        .get(&user_service_get)
        .expect("Should have service call edges");
    assert!(service_edges.iter().any(|e| e.callee == user_repo_find));

    // Test Python call graph
    let python_code = r#"
        from services import UserService
        @app.route("/users")
        def get_user(id):
            service = UserService()
            return service.get(id)
    "#;

    let python_service_code = r#"
        class UserService:
            def get(self, id):
                return "data"
    "#;

    let mut py_program = Program::new();
    let mut py_gst = GlobalSymbolTable::new();

    let _pm1 = py_gst
        .load_file(&mut py_program, python_code, "app.py", "python")
        .unwrap();
    let _pm2 = py_gst
        .load_file(
            &mut py_program,
            python_service_code,
            "services.py",
            "python",
        )
        .unwrap();

    py_gst.resolve_inheritance_hierarchy();
    let py_cg = CallGraph::build(&py_program, &py_gst);

    // Verify Python route method is resolved from HTTP entrypoint
    let py_get_user = py_gst
        .method_index
        .fqn_to_id
        .get("app.get_user")
        .copied()
        .expect("Should find get_user");

    let py_http_edges = py_cg
        .caller_to_edges
        .get(&http_entry)
        .expect("Should have Python HTTP entry calls");
    assert!(py_http_edges
        .iter()
        .any(|e| e.callee == py_get_user && e.edge_type == EdgeType::FrameworkCall));

    // Verify Python call: get_user -> UserService.get
    let py_service_get = py_gst
        .method_index
        .fqn_to_id
        .get("services.UserService.get")
        .copied()
        .expect("Should find UserService.get");
    let py_caller_edges = py_cg
        .caller_to_edges
        .get(&py_get_user)
        .expect("Should have caller edges from Python get_user");
    assert!(py_caller_edges.iter().any(|e| e.callee == py_service_get));
}

#[test]
fn test_python_tier_b_import_resolver() {
    use symbols::CallGraph;
    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    // 1. pkg/utils.py
    let utils_code = r#"
def helper():
    return 42
"#;

    // 2. pkg/subpkg/__init__.py (re-exports helper from sibling module)
    let init_code = r#"
from .module import my_func
"#;

    // 3. pkg/subpkg/module.py (defines my_func and imports helper relatively from parent)
    let module_code = r#"
from ..utils import helper

def my_func():
    return helper()
"#;

    // 4. app.py (imports my_func from subpkg package module, which goes through re-export)
    let app_code = r#"
from pkg.subpkg import my_func

def main_flow():
    return my_func()
"#;

    // Load files with their package path layout
    let m_utils = gst
        .load_file(&mut program, utils_code, "pkg/utils.py", "python")
        .unwrap();
    let m_init = gst
        .load_file(&mut program, init_code, "pkg/subpkg/__init__.py", "python")
        .unwrap();
    let m_module = gst
        .load_file(&mut program, module_code, "pkg/subpkg/module.py", "python")
        .unwrap();
    let m_app = gst
        .load_file(&mut program, app_code, "app.py", "python")
        .unwrap();

    // Verify module names are dot-separated packages
    assert_eq!(program.modules.get(&m_utils).unwrap().name, "pkg.utils");
    assert_eq!(program.modules.get(&m_init).unwrap().name, "pkg.subpkg");
    assert_eq!(
        program.modules.get(&m_module).unwrap().name,
        "pkg.subpkg.module"
    );
    assert_eq!(program.modules.get(&m_app).unwrap().name, "app");

    // Verify relative import resolution in pkg/subpkg/module.py
    // "helper" should resolve to "pkg.utils.helper"
    let resolved_helper = gst.resolve_import(m_module, "helper").unwrap();
    assert_eq!(resolved_helper, "pkg.utils.helper");

    // Verify re-export chain resolution:
    // in pkg/subpkg/__init__.py: "my_func" -> "pkg.subpkg.module.my_func"
    // in app.py: "my_func" -> "pkg.subpkg.my_func" which recursively resolves to "pkg.subpkg.module.my_func"
    let resolved_my_func_init = gst.resolve_import(m_init, "my_func").unwrap();
    assert_eq!(resolved_my_func_init, "pkg.subpkg.module.my_func");

    let resolved_my_func_app = gst.resolve_import(m_app, "my_func").unwrap();
    assert_eq!(resolved_my_func_app, "pkg.subpkg.module.my_func");

    // Build call graph and verify cross-file method resolution
    gst.resolve_inheritance_hierarchy();
    let cg = CallGraph::build(&program, &gst);

    let main_flow_id = gst
        .method_index
        .fqn_to_id
        .get("app.main_flow")
        .copied()
        .unwrap();
    let my_func_id = gst
        .method_index
        .fqn_to_id
        .get("pkg.subpkg.module.my_func")
        .copied()
        .unwrap();
    let helper_id = gst
        .method_index
        .fqn_to_id
        .get("pkg.utils.helper")
        .copied()
        .unwrap();

    // app.main_flow should call pkg.subpkg.module.my_func
    let app_edges = cg.caller_to_edges.get(&main_flow_id).unwrap();
    assert!(app_edges.iter().any(|e| e.callee == my_func_id));

    // pkg.subpkg.module.my_func should call pkg.utils.helper
    let module_edges = cg.caller_to_edges.get(&my_func_id).unwrap();
    assert!(module_edges.iter().any(|e| e.callee == helper_id));
}

#[test]
fn test_recursive_python_import_stubs() {
    let mut program = Program::new();
    let mut gst = GlobalSymbolTable::new();

    let app_code = r#"
from pkg.client import Client

def process():
    cli = Client()
    proj = cli.get_project()
    det = proj.get_details()
    det.run()
"#;

    let m_app = gst
        .load_file(&mut program, app_code, "app.py", "python")
        .unwrap();

    // Verify app module is registered
    assert_eq!(program.modules.get(&m_app).unwrap().name, "app");

    // "Client" is imported directly
    assert!(gst.type_index.fqn_to_id.contains_key("pkg.client.Client"));

    // We should have synthesized:
    // 1. pkg.client.Client.get_project method
    assert!(gst
        .method_index
        .fqn_to_id
        .contains_key("pkg.client.Client.get_project"));

    // 2. pkg.client.Client.get_project_Ret type
    assert!(gst
        .type_index
        .fqn_to_id
        .contains_key("pkg.client.Client.get_project_Ret"));

    // 3. pkg.client.Client.get_project_Ret.get_details method
    assert!(gst
        .method_index
        .fqn_to_id
        .contains_key("pkg.client.Client.get_project_Ret.get_details"));

    // 4. pkg.client.Client.get_project_Ret.get_details_Ret type
    assert!(gst
        .type_index
        .fqn_to_id
        .contains_key("pkg.client.Client.get_project_Ret.get_details_Ret"));

    // 5. pkg.client.Client.get_project_Ret.get_details_Ret.run method
    assert!(gst
        .method_index
        .fqn_to_id
        .contains_key("pkg.client.Client.get_project_Ret.get_details_Ret.run"));
}
