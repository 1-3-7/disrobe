#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::{Duration, Instant};

use disrobe_pass_nuitka::{
    BodyLift, CCodeObject, CFunctionWiring, CImplBody, CModuleStructure, ConstantsPool, PythonExpr,
    PythonStmt, SurfaceModule, build_surface, lift_body_detailed,
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
    let mut rhs: String = String::from("par_x");
    for _ in 0..50_000 {
        rhs = format!("CALL_FUNCTION_WITH_POS_ARGS1(tstate, callee, {rhs})");
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
    };
    let wiring: CFunctionWiring = CFunctionWiring {
        function_name: "f".to_owned(),
        annotations_dict_const: None,
        defaults_const: None,
        doc_const: None,
        parent_names: Vec::new(),
    };
    let cmod: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        code_objects: vec![code_object],
        impl_bodies: vec![impl_body],
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
    };
    let cmod: CModuleStructure = CModuleStructure {
        module_name: "m".to_owned(),
        code_objects: vec![code_object],
        impl_bodies: vec![impl_body],
        wirings: Vec::new(),
        has_main_guard: false,
        notes: Vec::new(),
    };
    let pool: ConstantsPool = ConstantsPool::default();
    let surface: SurfaceModule = build_surface(&cmod, &pool, None).expect("valid module builds");
    assert_eq!(surface.functions.len(), 1);
    assert_eq!(surface.functions[0].name, "add");
}
