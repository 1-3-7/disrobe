#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::{Duration, Instant};

use disrobe_pass_nuitka::{
    BodyLift, CCodeObject, CFunctionWiring, CImplBody, CModuleStructure, ConstantsPool, PythonExpr,
    PythonStmt, SurfaceModule, build_surface, lift_body_detailed, parse_c_module,
};

fn contains_call(stmts: &[PythonStmt]) -> bool {
    stmts.iter().any(|s: &PythonStmt| match s {
        PythonStmt::Return(e) | PythonStmt::Expr(e) | PythonStmt::Assign { value: e, .. } => {
            matches!(e, PythonExpr::Call { .. })
        }
        _ => false,
    })
}

#[test]
fn older_era_pack_threads_pre_pos_args_call_idiom() {
    let body: &str = r"{
PyObject *par_x = python_pars[0];
tmp_cmp = RICH_COMPARE_LT_NBOOL_OBJECT_LONG(par_x, mod_consts.const_int_0);
tmp_return_value = CALL_FUNCTION_WITH_ARGS1(called, par_x);
goto frame_return_exit_1;
}";
    let pool: ConstantsPool = ConstantsPool::default();
    let lift: BodyLift = lift_body_detailed(body, &[], &pool);
    assert!(
        contains_call(&lift.stmts),
        "older-era CALL_FUNCTION_WITH_ARGS1 must lift to a Call via the threaded era pack, got: {:?}",
        lift.stmts
    );
}

#[test]
fn modern_era_pos_args_call_still_lifts() {
    let body: &str = r"{
PyObject *par_x = python_pars[0];
tmp_called = MAKE_ITERATOR_INFALLIBLE(tstate, par_x);
tmp_return_value = CALL_FUNCTION_WITH_POS_ARGS1(tstate, called, par_x);
goto frame_return_exit_1;
}";
    let pool: ConstantsPool = ConstantsPool::default();
    let lift: BodyLift = lift_body_detailed(body, &[], &pool);
    assert!(
        contains_call(&lift.stmts),
        "modern CALL_FUNCTION_WITH_POS_ARGS1 must still lift to a Call, got: {:?}",
        lift.stmts
    );
}

#[test]
fn deeply_nested_call_expression_is_bounded() {
    let prefix: &str = "CALL_FUNCTION_WITH_POS_ARGS1(tstate, callee, ";
    let mut rhs: String = String::with_capacity(prefix.len() * 50_000usize + 5usize + 50_000usize);
    for _ in 0..50_000 {
        rhs.push_str(prefix);
    }
    rhs.push_str("par_x");
    for _ in 0..50_000 {
        rhs.push(')');
    }
    let body: String = format!(
        "{{\nPyObject *par_x = python_pars[0];\ntmp_return_value = {rhs};\ngoto frame_return_exit_1;\n}}"
    );
    let pool: ConstantsPool = ConstantsPool::default();
    let start: Instant = Instant::now();
    let lift: BodyLift = lift_body_detailed(&body, &[], &pool);
    let elapsed: Duration = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "deeply nested expression lift took {elapsed:?}, expected bounded time"
    );
    assert!(
        !lift.stmts.is_empty(),
        "lifter must produce a bounded statement rather than overflowing"
    );
}

#[test]
fn surface_arg_count_overflow_does_not_panic() {
    let code_object: CCodeObject = CCodeObject {
        symbol: "code_objects_f".to_owned(),
        name: "f".to_owned(),
        line: 1,
        arg_names_const: None,
        arg_count: u32::MAX,
        kw_only_count: u32::MAX,
        pos_only_count: 0,
        has_varargs: true,
        has_kwargs: true,
    };
    let impl_body: CImplBody = CImplBody {
        function_name: "f".to_owned(),
        source_index: 0,
        params: vec!["a".to_owned(), "b".to_owned()],
        parent_names: Vec::new(),
        impl_symbol: "impl_m$$$function__0_f".to_owned(),
        code_object_symbol: Some("code_objects_f".to_owned()),
    };
    let wiring: CFunctionWiring = CFunctionWiring {
        function_name: "f".to_owned(),
        source_index: Some(0),
        annotations_dict_const: None,
        defaults_const: None,
        kw_defaults_const: None,
        doc_const: None,
        parent_names: Vec::new(),
    };
    let cmod: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        python_abi: None,
        code_objects: vec![code_object],
        impl_bodies: vec![impl_body],
        const_returns: Vec::new(),
        wirings: vec![wiring],
        has_main_guard: false,
        notes: Vec::new(),
    };
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule =
        build_surface(&cmod, &pool, None).expect("build_surface must not panic on huge arg counts");
    assert_eq!(surface.functions.len(), 1);
}

#[test]
fn valid_module_still_builds_surface() {
    let code_object: CCodeObject = CCodeObject {
        symbol: "code_objects_add".to_owned(),
        name: "add".to_owned(),
        line: 1,
        arg_names_const: None,
        arg_count: 2,
        kw_only_count: 0,
        pos_only_count: 0,
        has_varargs: false,
        has_kwargs: false,
    };
    let impl_body: CImplBody = CImplBody {
        function_name: "add".to_owned(),
        source_index: 0,
        params: vec!["a".to_owned(), "b".to_owned()],
        parent_names: Vec::new(),
        impl_symbol: "impl_m$$$function__0_add".to_owned(),
        code_object_symbol: Some("code_objects_add".to_owned()),
    };
    let cmod: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        python_abi: None,
        code_objects: vec![code_object],
        impl_bodies: vec![impl_body],
        const_returns: Vec::new(),
        wirings: Vec::new(),
        has_main_guard: false,
        notes: Vec::new(),
    };
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&cmod, &pool, None).expect("valid module builds");
    assert_eq!(surface.functions.len(), 1);
    assert_eq!(surface.functions[0].name, "add");
}

#[test]
fn ignored_c_regions_cannot_bind_a_factory_to_a_forged_code_object() {
    let source: &str = r"
PyObject *module_m;
/*
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 99, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_forged_tuple, NULL, 1, 0, 0);
*/
#if 0
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 98, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_disabled_tuple, NULL, 1, 0, 0);
#elif 0
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 97, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_elif_disabled_tuple, NULL, 1, 0, 0);
#endif
#if 1
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 7, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_actual_tuple, NULL, 1, 0, 0);
#else
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 96, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_else_disabled_tuple, NULL, 1, 0, 0);
#endif
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
tmp_f = MAKE_FUNCTION_m$$$function__1_f(tstate, NULL);
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse C module");
    assert_eq!(c_module.code_objects.len(), 1);
    let code_object: &CCodeObject = &c_module.code_objects[0];
    assert_eq!(code_object.symbol, "code_objects_f");
    assert_eq!(code_object.line, 7);
    assert_eq!(
        code_object.arg_names_const.as_deref(),
        Some("const_tuple_str_plain_actual_tuple")
    );
}

#[test]
fn constant_returns_keep_redefinitions_and_exact_signatures() {
    let source: &str = r"
PyObject *module_m;
code_objects_first = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_alpha_tuple, NULL, 1, 0, 0);
code_objects_second = MAKE_CODE_OBJECT(module_filename_obj, 2, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_beta_tuple, NULL, 1, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_first, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_true);
    return (PyObject *)result;
}
static PyObject *MAKE_FUNCTION_m$$$function__2_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_second, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_false);
    return (PyObject *)result;
}
tmp_first = MAKE_FUNCTION_m$$$function__1_f(tstate, NULL);
tmp_second = MAKE_FUNCTION_m$$$function__2_f(tstate, NULL);
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse constant returns");
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert_eq!(surface.functions.len(), 2);
    assert_eq!(
        surface
            .functions
            .iter()
            .map(|function| function.source_index)
            .collect::<Vec<u32>>(),
        vec![1, 2]
    );
    assert_eq!(
        surface.functions[0]
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<Vec<&str>>(),
        vec!["alpha"]
    );
    assert_eq!(
        surface.functions[1]
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<Vec<&str>>(),
        vec!["beta"]
    );
    assert_eq!(
        surface.functions[0].body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("True".to_owned()))]
    );
    assert_eq!(
        surface.functions[1].body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("False".to_owned()))]
    );
}

#[test]
fn unresolved_constant_return_is_not_marked_as_a_recovered_body() {
    let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_frozenset_future);
    return (PyObject *)result;
}
tmp_f = MAKE_FUNCTION_m$$$function__1_f(tstate, NULL);
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse constant return");
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert_eq!(surface.functions.len(), 1);
    let function = &surface.functions[0];
    assert!(!function.body_recovered);
    assert!(function.body_stmts.is_empty());
    assert!(
        function
            .unrecognized_c_lines
            .iter()
            .any(|line: &String| { line.contains("const_frozenset_future") })
    );
    assert!(
        !surface
            .python_source
            .contains("return const_frozenset_future")
    );
}

#[test]
fn malformed_numeric_constant_return_is_not_marked_as_a_recovered_body() {
    let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_int_pos_not_a_number);
    return (PyObject *)result;
}
tmp_f = MAKE_FUNCTION_m$$$function__1_f(tstate, NULL);
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse malformed constant");
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert_eq!(surface.functions.len(), 1);
    let function = &surface.functions[0];
    assert!(!function.body_recovered);
    assert!(function.body_stmts.is_empty());
    assert!(!surface.python_source.contains("return not_a_number"));
}

#[test]
fn prior_populated_module_json_keeps_unambiguous_wiring() {
    let prior: &str = r#"{
        "module_name": "m",
        "code_objects": [{
            "name": "f",
            "line": 17,
            "arg_names_const": null,
            "arg_count": 0,
            "kw_only_count": 0,
            "pos_only_count": 0,
            "has_varargs": false,
            "has_kwargs": false
        }],
        "impl_bodies": [{
            "function_name": "f",
            "source_index": 7,
            "params": [],
            "parent_names": [],
            "impl_symbol": "impl_m$$$function__7_f"
        }],
        "wirings": [{
            "function_name": "f",
            "annotations_dict_const": null,
            "defaults_const": null,
            "doc_const": null,
            "parent_names": []
        }],
        "has_main_guard": false,
        "notes": []
    }"#;
    let c_module: CModuleStructure = serde_json::from_str(prior).expect("deserialize legacy");
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert_eq!(surface.functions.len(), 1);
    assert_eq!(surface.functions[0].source_line, Some(17));
    assert!(
        !surface
            .notes
            .iter()
            .any(|note: &String| note.contains("no wiring record"))
    );
}

#[test]
fn ambiguous_legacy_wiring_is_not_assigned_to_redefinitions() {
    let code_objects: Vec<CCodeObject> = vec![
        CCodeObject {
            symbol: "code_objects_first".to_owned(),
            name: "f".to_owned(),
            line: 1,
            arg_names_const: None,
            arg_count: 0,
            kw_only_count: 0,
            pos_only_count: 0,
            has_varargs: false,
            has_kwargs: false,
        },
        CCodeObject {
            symbol: "code_objects_second".to_owned(),
            name: "f".to_owned(),
            line: 2,
            arg_names_const: None,
            arg_count: 0,
            kw_only_count: 0,
            pos_only_count: 0,
            has_varargs: false,
            has_kwargs: false,
        },
    ];
    let impl_bodies: Vec<CImplBody> = vec![
        CImplBody {
            function_name: "f".to_owned(),
            source_index: 1,
            params: Vec::new(),
            parent_names: Vec::new(),
            impl_symbol: "impl_m$$$function__1_f".to_owned(),
            code_object_symbol: Some("code_objects_first".to_owned()),
        },
        CImplBody {
            function_name: "f".to_owned(),
            source_index: 2,
            params: Vec::new(),
            parent_names: Vec::new(),
            impl_symbol: "impl_m$$$function__2_f".to_owned(),
            code_object_symbol: Some("code_objects_second".to_owned()),
        },
    ];
    let c_module: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        python_abi: None,
        code_objects,
        impl_bodies,
        const_returns: Vec::new(),
        wirings: vec![CFunctionWiring {
            function_name: "f".to_owned(),
            source_index: None,
            annotations_dict_const: None,
            defaults_const: None,
            kw_defaults_const: None,
            doc_const: None,
            parent_names: Vec::new(),
        }],
        has_main_guard: false,
        notes: Vec::new(),
    };
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    let unresolved_wirings: usize = surface
        .notes
        .iter()
        .filter(|note: &&String| note.contains("no wiring record"))
        .count();
    assert_eq!(unresolved_wirings, 2);
}

#[test]
fn implementation_redefinitions_keep_exact_code_object_metadata() {
    let source: &str = r"
PyObject *module_m;
code_objects_first = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_a_tuple, NULL, 1, 0, 0);
code_objects_second = MAKE_CODE_OBJECT(module_filename_obj, 2, CO_VARARGS, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_args_tuple, NULL, 0, 0, 0);
static PyObject *impl_m$$$function__1_f(PyThreadState *tstate, PyObject *const *python_pars) {
    PyObject *par_a = python_pars[0];
    return par_a;
}
static PyObject *impl_m$$$function__2_f(PyThreadState *tstate, PyObject *const *python_pars) {
    PyObject *par_args = python_pars[0];
    return par_args;
}
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(impl_m$$$function__1_f, mod_consts.const_str_plain_f, NULL, code_objects_first, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
static PyObject *MAKE_FUNCTION_m$$$function__2_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(impl_m$$$function__2_f, mod_consts.const_str_plain_f, NULL, code_objects_second, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
tmp_first = MAKE_FUNCTION_m$$$function__1_f(tstate, NULL);
tmp_second = MAKE_FUNCTION_m$$$function__2_f(tstate, NULL);
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse implementations");
    assert_eq!(c_module.impl_bodies.len(), 2);
    assert_eq!(
        c_module.impl_bodies[0].code_object_symbol.as_deref(),
        Some("code_objects_first")
    );
    assert_eq!(
        c_module.impl_bodies[1].code_object_symbol.as_deref(),
        Some("code_objects_second")
    );
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule =
        build_surface(&c_module, &pool, Some(source)).expect("build surface");
    assert_eq!(surface.functions.len(), 2);
    assert_eq!(surface.functions[0].source_line, Some(1));
    assert_eq!(surface.functions[1].source_line, Some(2));
    assert_eq!(surface.functions[0].params[0].name, "a");
    assert_eq!(surface.functions[1].params[0].name, "args");
    assert!(surface.python_source.contains("def f(a):"));
    assert!(surface.python_source.contains("def f(*args):"));
}

#[test]
fn parenthesized_false_preprocessor_branch_cannot_supply_recovery_metadata() {
    let source: &str = r"
PyObject *module_m;
#if (0)
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
#endif
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse guarded source");
    assert!(c_module.code_objects.is_empty());
    assert!(c_module.const_returns.is_empty());
}

#[test]
fn constant_return_rejects_mismatched_conditional_and_nonstatic_factories() {
    let source: &str = r"
PyObject *module_m;
code_objects_wrong = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_other, mod_consts.const_str_plain_other, NULL, NULL, 0, 0, 0);
code_objects_conditional = MAKE_CODE_OBJECT(module_filename_obj, 2, 0, mod_consts.const_str_plain_conditional, mod_consts.const_str_plain_conditional, NULL, NULL, 0, 0, 0);
code_objects_nonstatic = MAKE_CODE_OBJECT(module_filename_obj, 3, 0, mod_consts.const_str_plain_nonstatic, mod_consts.const_str_plain_nonstatic, NULL, NULL, 0, 0, 0);
code_objects_unbraced = MAKE_CODE_OBJECT(module_filename_obj, 4, 0, mod_consts.const_str_plain_unbraced, mod_consts.const_str_plain_unbraced, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_wrong, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
static PyObject *MAKE_FUNCTION_m$$$function__2_conditional(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_conditional, NULL, code_objects_conditional, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    if (enabled) {
        Nuitka_Function_EnableConstReturnTrue(result);
    }
    return (PyObject *)result;
}
static PyObject *MAKE_FUNCTION_m$$$function__3_nonstatic(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(impl_m$$$function__3_nonstatic, mod_consts.const_str_plain_nonstatic, NULL, code_objects_nonstatic, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
static PyObject *MAKE_FUNCTION_m$$$function__4_unbraced(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_unbraced, NULL, code_objects_unbraced, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    if (enabled) Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse factory variants");
    assert!(c_module.const_returns.is_empty());
}

#[test]
fn digest_named_factory_requires_the_matching_code_object_name_token() {
    let source: &str = r"
PyObject *module_m;
code_objects_digest = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_digest_code_object_name, mod_consts.const_str_digest_code_object_name, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_digest_factory_name, NULL, code_objects_digest, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse digest mismatch");
    assert!(c_module.const_returns.is_empty());
    assert!(c_module.impl_bodies.is_empty());
}

#[test]
fn constant_return_defaults_and_parameter_kinds_follow_code_object_metadata() {
    let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_a_str_plain_b_str_plain_c_tuple, NULL, 2, 1, 1);
code_objects_g = MAKE_CODE_OBJECT(module_filename_obj, 2, CO_VARARGS | CO_VARKEYWORDS, mod_consts.const_str_plain_g, mod_consts.const_str_plain_g, mod_consts.const_tuple_str_plain_a_str_plain_c_str_plain_args_str_plain_kwargs_tuple, NULL, 1, 1, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, defaults, NULL, annotations, module_m, mod_consts.const_str_plain_f_doc, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
static PyObject *MAKE_FUNCTION_m$$$function__2_g(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_g, NULL, code_objects_g, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnFalse(result);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    {
        tmp_f = MAKE_FUNCTION_m$$$function__1_f(tstate, mod_consts.const_tuple_int_pos_7_tuple, NULL);
        tmp_g = MAKE_FUNCTION_m$$$function__2_g(tstate, NULL);
    }
}
";
    let c_module: CModuleStructure = parse_c_module(source).expect("parse signature source");
    let f_wiring: &CFunctionWiring = c_module
        .wirings
        .iter()
        .find(|wiring: &&CFunctionWiring| wiring.function_name == "f")
        .expect("f wiring");
    assert_eq!(
        f_wiring.defaults_const.as_deref(),
        Some("const_tuple_int_pos_7_tuple")
    );
    assert_eq!(f_wiring.doc_const.as_deref(), Some("const_str_plain_f_doc"));
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert!(surface.python_source.contains("def f(a, /, b=7, *, c):"));
    assert!(
        surface
            .python_source
            .contains("def g(a, *args, c, **kwargs):")
    );
}

#[test]
fn conflicting_exact_wirings_are_not_assigned() {
    let c_module: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        python_abi: None,
        code_objects: vec![CCodeObject {
            symbol: "code_objects_f".to_owned(),
            name: "f".to_owned(),
            line: 1,
            arg_names_const: None,
            arg_count: 0,
            kw_only_count: 0,
            pos_only_count: 0,
            has_varargs: false,
            has_kwargs: false,
        }],
        impl_bodies: vec![CImplBody {
            function_name: "f".to_owned(),
            source_index: 1,
            params: Vec::new(),
            parent_names: Vec::new(),
            impl_symbol: "impl_m$$$function__1_f".to_owned(),
            code_object_symbol: Some("code_objects_f".to_owned()),
        }],
        const_returns: Vec::new(),
        wirings: vec![
            CFunctionWiring {
                function_name: "f".to_owned(),
                source_index: Some(1),
                annotations_dict_const: None,
                defaults_const: Some("const_tuple_int_pos_1_tuple".to_owned()),
                kw_defaults_const: None,
                doc_const: None,
                parent_names: Vec::new(),
            },
            CFunctionWiring {
                function_name: "f".to_owned(),
                source_index: Some(1),
                annotations_dict_const: None,
                defaults_const: Some("const_tuple_int_pos_2_tuple".to_owned()),
                kw_defaults_const: None,
                doc_const: None,
                parent_names: Vec::new(),
            },
        ],
        has_main_guard: false,
        notes: Vec::new(),
    };
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert!(
        surface
            .notes
            .iter()
            .any(|note: &String| note.contains("function 'f' has no wiring record"))
    );
}

#[test]
fn duplicate_exact_wirings_are_not_assigned() {
    let wiring: CFunctionWiring = CFunctionWiring {
        function_name: "f".to_owned(),
        source_index: Some(1),
        annotations_dict_const: None,
        defaults_const: None,
        kw_defaults_const: None,
        doc_const: None,
        parent_names: Vec::new(),
    };
    let c_module: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        python_abi: None,
        code_objects: vec![CCodeObject {
            symbol: "code_objects_f".to_owned(),
            name: "f".to_owned(),
            line: 1,
            arg_names_const: None,
            arg_count: 0,
            kw_only_count: 0,
            pos_only_count: 0,
            has_varargs: false,
            has_kwargs: false,
        }],
        impl_bodies: vec![CImplBody {
            function_name: "f".to_owned(),
            source_index: 1,
            params: Vec::new(),
            parent_names: Vec::new(),
            impl_symbol: "impl_m$$$function__1_f".to_owned(),
            code_object_symbol: Some("code_objects_f".to_owned()),
        }],
        const_returns: Vec::new(),
        wirings: vec![wiring.clone(), wiring],
        has_main_guard: false,
        notes: Vec::new(),
    };
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&c_module, &pool, None).expect("build surface");
    assert!(
        surface
            .notes
            .iter()
            .any(|note: &String| note.contains("function 'f' has no wiring record"))
    );
}
