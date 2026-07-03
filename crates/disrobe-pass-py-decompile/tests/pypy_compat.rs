#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use disrobe_pass_py_decompile::ast::node::{Expr, ExprCtx, Keyword};
use disrobe_pass_py_decompile::bytecode::opcode::pypy_extras::{
    pypy_build_list_from_arg, pypy_jump_if_not_debug_preserves_assert, pypy_load_revdb_var,
    pypy_method_call, pypy_method_call_kw,
};
use disrobe_pass_py_decompile::bytecode::opcode::{CanonicalOp, OpcodeMap, map_for};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::pass::{AltRuntime, DecompilePass, RuntimeRoute, detect_runtime};

const PYPY_LOOKUP_METHOD: u8 = 201;
const PYPY_CALL_METHOD: u8 = 202;
const PYPY_BUILD_LIST_FROM_ARG: u8 = 203;
const PYPY_JUMP_IF_NOT_DEBUG: u8 = 204;
const PYPY_LOAD_REVDB_VAR: u8 = 205;
const PYPY_CALL_METHOD_KW: u8 = 206;

const PYPY_MAGIC_310_MARKER: u32 = 0xA1B2_0000 | 0x0000_0D6Fu32;

fn pypy_map() -> Box<dyn OpcodeMap> {
    map_for(PyVersion::PyPy(Box::new(PyVersion::V3_10)))
}

#[test]
fn pypy3_lookup_call_method_decomp() {
    let map: Box<dyn OpcodeMap> = pypy_map();
    let lookup: CanonicalOp = map.decode(PYPY_LOOKUP_METHOD, 7);
    let call: CanonicalOp = map.decode(PYPY_CALL_METHOD, 2);
    assert!(matches!(lookup, CanonicalOp::LoadAttr(7)));
    assert!(matches!(call, CanonicalOp::CallFunction(2)));

    let receiver: Expr = Expr::Name {
        id: "self".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    let arg_a: Expr = Expr::Name {
        id: "a".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    let arg_b: Expr = Expr::Name {
        id: "b".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    let call_expr: Expr = pypy_method_call(receiver, "method".to_owned(), vec![arg_a, arg_b]);
    let Expr::Call {
        func,
        args,
        keywords,
    } = call_expr
    else {
        panic!("expected Call");
    };
    assert!(keywords.is_empty());
    assert_eq!(args.len(), 2);
    let Expr::Attribute { value, attr, ctx } = *func else {
        panic!("expected Attribute func");
    };
    assert_eq!(attr, "method");
    assert_eq!(ctx, ExprCtx::Load);
    let Expr::Name { id, .. } = *value else {
        panic!("expected Name receiver");
    };
    assert_eq!(id, "self");
}

#[test]
fn pypy3_build_list_from_arg() {
    let map: Box<dyn OpcodeMap> = pypy_map();
    let decoded: CanonicalOp = map.decode(PYPY_BUILD_LIST_FROM_ARG, 1);
    assert!(matches!(decoded, CanonicalOp::BuildList(1)));

    let iter_expr: Expr = Expr::Name {
        id: "it".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    let built: Expr = pypy_build_list_from_arg(iter_expr);
    let Expr::Call { func, args, .. } = built else {
        panic!("expected Call");
    };
    let Expr::Name { id, .. } = *func else {
        panic!("expected Name func");
    };
    assert_eq!(id, "list");
    assert_eq!(args.len(), 1);
}

#[test]
fn pypy3_jump_if_not_debug() {
    let map: Box<dyn OpcodeMap> = pypy_map();
    let decoded: CanonicalOp = map.decode(PYPY_JUMP_IF_NOT_DEBUG, 4);
    assert!(matches!(decoded, CanonicalOp::JumpForward(4)));
    assert!(
        pypy_jump_if_not_debug_preserves_assert(),
        "PyPy JUMP_IF_NOT_DEBUG must preserve the trailing assert in surface output"
    );
}

#[test]
fn pypy3_method_kw() {
    let map: Box<dyn OpcodeMap> = pypy_map();
    let decoded: CanonicalOp = map.decode(PYPY_CALL_METHOD_KW, 3);
    assert!(matches!(decoded, CanonicalOp::CallFunctionKw(3)));

    let receiver: Expr = Expr::Name {
        id: "obj".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    let kw: Keyword = Keyword {
        arg: Some("key".to_owned()),
        value: Expr::Name {
            id: "val".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        },
    };
    let call_expr: Expr = pypy_method_call_kw(receiver, "do".to_owned(), Vec::new(), vec![kw]);
    let Expr::Call {
        func,
        args,
        keywords,
    } = call_expr
    else {
        panic!("expected Call");
    };
    assert!(args.is_empty());
    assert_eq!(keywords.len(), 1);
    assert_eq!(keywords[0].arg.as_deref(), Some("key"));
    let Expr::Attribute { attr, .. } = *func else {
        panic!("expected Attribute func");
    };
    assert_eq!(attr, "do");
}

#[test]
fn pypy_load_revdb() {
    let map: Box<dyn OpcodeMap> = pypy_map();
    let decoded: CanonicalOp = map.decode(PYPY_LOAD_REVDB_VAR, 5);
    assert!(matches!(decoded, CanonicalOp::LoadName(5)));

    let expr: Expr = pypy_load_revdb_var("var".to_owned());
    let Expr::Attribute { value, attr, ctx } = expr else {
        panic!("expected Attribute");
    };
    assert_eq!(attr, "var");
    assert_eq!(ctx, ExprCtx::Load);
    let Expr::Name { id, .. } = *value else {
        panic!("expected Name receiver");
    };
    assert_eq!(id, "__revdb__");
}

#[test]
fn pypy_magic_dispatch() {
    let parsed: PyVersion =
        PyVersion::from_magic(PYPY_MAGIC_310_MARKER).expect("pypy 3.10 magic parses");
    assert_eq!(parsed, PyVersion::PyPy(Box::new(PyVersion::V3_10)));

    let map: Box<dyn OpcodeMap> = map_for(parsed);
    assert_eq!(map.opname(PYPY_LOOKUP_METHOD), "LOOKUP_METHOD");
    assert_eq!(map.opname(PYPY_CALL_METHOD), "CALL_METHOD");
    assert_eq!(map.opname(PYPY_CALL_METHOD_KW), "CALL_METHOD_KW");

    let cpython_310: Box<dyn OpcodeMap> = map_for(PyVersion::V3_10);
    assert_eq!(map.opname(1), cpython_310.opname(1));

    let runtime: AltRuntime = detect_runtime(PYPY_MAGIC_310_MARKER);
    assert_eq!(runtime, AltRuntime::PyPy);
    assert_eq!(
        DecompilePass::dispatch_runtime(runtime),
        RuntimeRoute::NativeMarshal
    );
}

#[test]
fn pypy_full_pipeline() {
    let map: Box<dyn OpcodeMap> = pypy_map();
    let ops: Vec<CanonicalOp> = vec![
        map.decode(124, 0),
        map.decode(PYPY_LOOKUP_METHOD, 0),
        map.decode(PYPY_CALL_METHOD, 0),
        map.decode(83, 0),
    ];
    assert!(matches!(ops[1], CanonicalOp::LoadAttr(0)));
    assert!(matches!(ops[2], CanonicalOp::CallFunction(0)));
    assert!(matches!(ops[3], CanonicalOp::Return));

    let runtime: AltRuntime = detect_runtime(PYPY_MAGIC_310_MARKER);
    assert_eq!(runtime, AltRuntime::PyPy);
    assert_eq!(
        DecompilePass::dispatch_runtime(runtime),
        RuntimeRoute::NativeMarshal
    );

    let receiver: Expr = Expr::Name {
        id: "self".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    let body_call: Expr = pypy_method_call(receiver, "x".to_owned(), Vec::new());
    let Expr::Call { func, .. } = body_call else {
        panic!("expected Call");
    };
    let Expr::Attribute { attr, .. } = *func else {
        panic!("expected Attribute");
    };
    assert_eq!(attr, "x");
}
