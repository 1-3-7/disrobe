#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements,
    clippy::identity_op,
    clippy::erasing_op
)]

use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

const OP_RESUME: u8 = 149;
const OP_LOAD_FAST: u8 = 85;
const OP_LOAD_FAST_LOAD_FAST: u8 = 88;
const OP_RETURN_VALUE: u8 = 36;
const OP_POP_TOP: u8 = 32;

fn name_obj(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

fn build_unfused() -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_FAST,
        0,
        OP_LOAD_FAST,
        1,
        OP_POP_TOP,
        0,
        OP_POP_TOP,
        0,
        OP_LOAD_FAST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    co.varnames = vec![name_obj("a"), name_obj("b")];
    co.qualname = name_obj("f");
    co
}

fn build_fused() -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let fused_arg: u8 = (0u8 << 4) | 1u8;
    co.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_FAST_LOAD_FAST,
        fused_arg,
        OP_POP_TOP,
        0,
        OP_POP_TOP,
        0,
        OP_LOAD_FAST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    co.varnames = vec![name_obj("a"), name_obj("b")];
    co.qualname = name_obj("f");
    co
}

#[test]
fn super_instruction_fused_vs_unfused_yields_semantic() {
    let unfused: CodeObject = build_unfused();
    let fused: CodeObject = build_fused();
    let verdict: Verdict = semantic_equiv(&unfused, &fused, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Semantic),
        "expected Semantic got {verdict:?}"
    );
}

#[test]
fn super_instruction_swapped_operands_is_codediff() {
    let mut fused_normal: CodeObject = build_fused();
    fused_normal.code[3] = (0u8 << 4) | 1u8;
    let mut fused_swapped: CodeObject = build_fused();
    fused_swapped.code[3] = (1u8 << 4) | 0u8;
    let verdict: Verdict = semantic_equiv(&fused_normal, &fused_swapped, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "swapped fused operands must be CodeDiff, got {verdict:?}"
    );
}
