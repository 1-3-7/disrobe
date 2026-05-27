#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]

use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

const OP_RESUME: u8 = 149;
const OP_LOAD_CONST: u8 = 83;
const OP_RETURN_VALUE: u8 = 36;
const OP_RETURN_CONST: u8 = 103;
const OP_POP_TOP: u8 = 32;
const OP_CLEANUP_THROW: u8 = 8;
const OP_JUMP_BACKWARD_NO_INTERRUPT: u8 = 78;

fn name_obj(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

#[test]
fn jretleaf_shared_vs_duplicated_yields_semantic() {
    let mut shared: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    shared.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    shared.consts = vec![Object::None];
    shared.qualname = name_obj("leaf");

    let mut duplicated: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    duplicated.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_CONST,
        0,
        OP_RETURN_VALUE,
        0,
        OP_LOAD_CONST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    duplicated.consts = vec![Object::None];
    duplicated.qualname = name_obj("leaf");

    let verdict: Verdict = semantic_equiv(&shared, &duplicated, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Semantic),
        "jretleaf shared vs duplicated must be Semantic, got {verdict:?}"
    );
}

#[test]
fn duplicate_return_const_with_different_values_is_codediff() {
    let mut a: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    a.code = vec![OP_RESUME, 0, OP_RETURN_CONST, 0, OP_RETURN_CONST, 1];
    a.consts = vec![Object::Int(1), Object::Int(2)];
    a.qualname = name_obj("ret");

    let mut b: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    b.code = vec![OP_RESUME, 0, OP_RETURN_CONST, 0, OP_RETURN_CONST, 1];
    b.consts = vec![Object::Int(1), Object::Int(99)];
    b.qualname = name_obj("ret");

    let verdict: Verdict = semantic_equiv(&a, &b, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "different return-const values must be CodeDiff, got {verdict:?}"
    );
}

#[test]
fn async_cold_handler_pair_strip_yields_semantic() {
    let mut without_handler: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    without_handler.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    without_handler.consts = vec![Object::None];
    without_handler.qualname = name_obj("async_fn");

    let mut with_handler: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    with_handler.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_CONST,
        0,
        OP_RETURN_VALUE,
        0,
        OP_CLEANUP_THROW,
        0,
        OP_JUMP_BACKWARD_NO_INTERRUPT,
        0,
    ];
    with_handler.consts = vec![Object::None];
    with_handler.qualname = name_obj("async_fn");

    let verdict: Verdict = semantic_equiv(&without_handler, &with_handler, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Semantic),
        "async cold-handler pair must be stripped to Semantic, got {verdict:?}"
    );
}

#[test]
fn generator_entry_yield_pop_strip_yields_semantic() {
    let mut without_entry: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    without_entry.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    without_entry.consts = vec![Object::None];
    without_entry.qualname = name_obj("gen");

    const OP_YIELD_VALUE: u8 = 118;
    let mut with_entry: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    with_entry.code = vec![
        OP_YIELD_VALUE,
        0,
        OP_POP_TOP,
        0,
        OP_RESUME,
        0,
        OP_LOAD_CONST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    with_entry.consts = vec![Object::None];
    with_entry.qualname = name_obj("gen");

    let verdict: Verdict = semantic_equiv(&without_entry, &with_entry, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Semantic),
        "generator-entry yield/pop must be stripped to Semantic, got {verdict:?}"
    );
}
