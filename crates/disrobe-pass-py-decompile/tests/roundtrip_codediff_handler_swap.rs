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
const OP_STORE_FAST: u8 = 110;
const OP_LOAD_FAST: u8 = 85;

fn name_obj(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

fn str_const(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

fn build_handlers(swap: bool) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let (first, second): (u8, u8) = if swap { (1, 0) } else { (0, 1) };
    co.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_CONST,
        first,
        OP_STORE_FAST,
        0,
        OP_LOAD_CONST,
        second,
        OP_STORE_FAST,
        1,
        OP_LOAD_FAST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    co.consts = vec![str_const("ValueError-body"), str_const("KeyError-body")];
    co.varnames = vec![name_obj("ve"), name_obj("ke")];
    co.qualname = name_obj("handler");
    co
}

#[test]
fn swapped_except_handlers_yield_codediff_with_qualname() {
    let canonical: CodeObject = build_handlers(false);
    let swapped: CodeObject = build_handlers(true);
    let verdict: Verdict = semantic_equiv(&canonical, &swapped, PyVersion::PY313);
    match verdict {
        Verdict::CodeDiff(detail) => {
            assert_eq!(
                detail.qualname, "handler",
                "qualname must surface in DiffDetail"
            );
            assert!(
                detail.note.contains("const value differs") || detail.note.contains("differs"),
                "note must describe the divergence, got: {}",
                detail.note
            );
        }
        other => panic!("expected CodeDiff got {other:?}"),
    }
}
