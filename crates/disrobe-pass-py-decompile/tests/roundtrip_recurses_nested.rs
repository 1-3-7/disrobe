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

fn name_obj(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

fn build_innermost(payload: i32) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    co.consts = vec![Object::Int(payload)];
    co.qualname = name_obj("Outer.Inner.deep_fn");
    co.name = name_obj("deep_fn");
    co
}

fn build_inner_class(inner_payload: i32) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let nested: CodeObject = build_innermost(inner_payload);
    co.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    co.consts = vec![Object::Code(Box::new(nested))];
    co.qualname = name_obj("Outer.Inner");
    co.name = name_obj("Inner");
    co
}

fn build_module(inner_payload: i32) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let nested: CodeObject = build_inner_class(inner_payload);
    co.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    co.consts = vec![Object::Code(Box::new(nested))];
    co.qualname = name_obj("<module>");
    co.name = name_obj("<module>");
    co
}

#[test]
fn identical_nested_yields_perfect() {
    let a: CodeObject = build_module(42);
    let b: CodeObject = build_module(42);
    let verdict: Verdict = semantic_equiv(&a, &b, PyVersion::PY313);
    assert!(matches!(verdict, Verdict::Perfect), "got {verdict:?}");
}

#[test]
fn diff_in_deeply_nested_code_surfaces_with_innermost_qualname() {
    let a: CodeObject = build_module(42);
    let b: CodeObject = build_module(43);
    let verdict: Verdict = semantic_equiv(&a, &b, PyVersion::PY313);
    match verdict {
        Verdict::CodeDiff(detail) => {
            assert_eq!(
                detail.qualname, "Outer.Inner.deep_fn",
                "diff must surface qualname of the deepest divergent code object"
            );
        }
        other => panic!("expected CodeDiff got {other:?}"),
    }
}
