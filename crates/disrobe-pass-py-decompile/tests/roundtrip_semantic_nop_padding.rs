use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

const OP_NOP: u8 = 30;
const OP_RESUME: u8 = 149;
const OP_LOAD_CONST: u8 = 83;
const OP_RETURN_VALUE: u8 = 36;

fn build_unpadded() -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    co.consts = vec![Object::None];
    co.qualname = Object::String {
        value: "m".to_owned(),
        interned: true,
    };
    co
}

fn build_padded() -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![
        OP_RESUME,
        0,
        OP_NOP,
        0,
        OP_NOP,
        0,
        OP_LOAD_CONST,
        0,
        OP_NOP,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    co.consts = vec![Object::None];
    co.qualname = Object::String {
        value: "m".to_owned(),
        interned: true,
    };
    co
}

#[test]
fn nop_padding_yields_semantic_not_perfect_or_diff() {
    let a: CodeObject = build_unpadded();
    let b: CodeObject = build_padded();
    let verdict: Verdict = semantic_equiv(&a, &b, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Semantic),
        "expected Semantic got {verdict:?}"
    );
}

#[test]
fn extended_arg_padding_yields_semantic() {
    let mut padded: CodeObject = build_unpadded();
    let extended_arg: u8 = 71;
    padded.code = vec![
        OP_RESUME,
        0,
        extended_arg,
        0,
        OP_LOAD_CONST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    let unpadded: CodeObject = build_unpadded();
    let verdict: Verdict = semantic_equiv(&unpadded, &padded, PyVersion::PY313);
    assert!(matches!(verdict, Verdict::Semantic), "got {verdict:?}");
}
