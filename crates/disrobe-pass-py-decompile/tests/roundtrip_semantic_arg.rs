#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

const OP_CACHE: u8 = 0;
const OP_PUSH_NULL: u8 = 34;
const OP_RETURN_VALUE: u8 = 36;
const OP_BINARY_OP: u8 = 45;
const OP_BUILD_TUPLE: u8 = 52;
const OP_CALL: u8 = 53;
const OP_LOAD_FAST: u8 = 85;
const OP_STORE_FAST: u8 = 110;
const OP_UNPACK_SEQUENCE: u8 = 117;
const OP_RESUME: u8 = 149;

const NB_ADD: u8 = 0;
const NB_SUBTRACT: u8 = 10;

fn name_obj(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

fn binary_op_body(selector: u8) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_FAST,
        0,
        OP_LOAD_FAST,
        1,
        OP_BINARY_OP,
        selector,
        OP_CACHE,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    co.varnames = vec![name_obj("a"), name_obj("b")];
    co.qualname = name_obj("binop");
    co
}

#[test]
fn binary_op_add_vs_subtract_is_codediff() {
    let plus: CodeObject = binary_op_body(NB_ADD);
    let minus: CodeObject = binary_op_body(NB_SUBTRACT);
    let verdict: Verdict = semantic_equiv(&plus, &minus, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "BINARY_OP add vs subtract must be CodeDiff, got {verdict:?}"
    );
}

#[test]
fn binary_op_same_selector_is_not_codediff() {
    let one: CodeObject = binary_op_body(NB_ADD);
    let two: CodeObject = binary_op_body(NB_ADD);
    let verdict: Verdict = semantic_equiv(&one, &two, PyVersion::PY313);
    assert!(
        !matches!(verdict, Verdict::CodeDiff(_)),
        "BINARY_OP with identical selector must not be CodeDiff, got {verdict:?}"
    );
}

fn call_body(declared_argc: u8) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![
        OP_RESUME,
        0,
        OP_PUSH_NULL,
        0,
        OP_LOAD_FAST,
        0,
        OP_LOAD_FAST,
        1,
        OP_CALL,
        declared_argc,
        OP_CACHE,
        0,
        OP_CACHE,
        0,
        OP_CACHE,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    co.varnames = vec![name_obj("f"), name_obj("a")];
    co.qualname = name_obj("caller");
    co
}

#[test]
fn call_arity_one_vs_three_is_codediff() {
    let one_arg: CodeObject = call_body(1);
    let three_args: CodeObject = call_body(3);
    let verdict: Verdict = semantic_equiv(&one_arg, &three_args, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "CALL declared-arity 1 vs 3 (identical opcode count) must be CodeDiff, got {verdict:?}"
    );
}

#[test]
fn call_same_arity_is_not_codediff() {
    let one: CodeObject = call_body(2);
    let two: CodeObject = call_body(2);
    let verdict: Verdict = semantic_equiv(&one, &two, PyVersion::PY313);
    assert!(
        !matches!(verdict, Verdict::CodeDiff(_)),
        "CALL with identical arity must not be CodeDiff, got {verdict:?}"
    );
}

fn build_tuple_body(declared_count: u8) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_FAST,
        0,
        OP_LOAD_FAST,
        1,
        OP_BUILD_TUPLE,
        declared_count,
        OP_RETURN_VALUE,
        0,
    ];
    co.varnames = vec![name_obj("a"), name_obj("b")];
    co.qualname = name_obj("tup");
    co
}

#[test]
fn build_tuple_two_vs_five_is_codediff() {
    let two: CodeObject = build_tuple_body(2);
    let five: CodeObject = build_tuple_body(5);
    let verdict: Verdict = semantic_equiv(&two, &five, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "BUILD_TUPLE declared 2 vs 5 (identical opcode count) must be CodeDiff, got {verdict:?}"
    );
}

fn unpack_body(declared_count: u8) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_FAST,
        0,
        OP_UNPACK_SEQUENCE,
        declared_count,
        OP_CACHE,
        0,
        OP_STORE_FAST,
        1,
        OP_STORE_FAST,
        2,
        OP_RETURN_VALUE,
        0,
    ];
    co.varnames = vec![name_obj("s"), name_obj("a"), name_obj("b")];
    co.qualname = name_obj("unpack");
    co
}

#[test]
fn unpack_sequence_two_vs_three_is_codediff() {
    let two: CodeObject = unpack_body(2);
    let three: CodeObject = unpack_body(3);
    let verdict: Verdict = semantic_equiv(&two, &three, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "UNPACK_SEQUENCE declared 2 vs 3 (identical opcode count) must be CodeDiff, got {verdict:?}"
    );
}
