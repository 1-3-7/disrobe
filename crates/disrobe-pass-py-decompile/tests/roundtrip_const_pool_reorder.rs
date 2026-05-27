use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

const OP_RESUME: u8 = 149;
const OP_LOAD_CONST: u8 = 83;
const OP_RETURN_VALUE: u8 = 36;
const OP_POP_TOP: u8 = 32;

fn name_obj(s: &str) -> Object {
    Object::String {
        value: s.to_owned(),
        interned: true,
    }
}

#[test]
fn same_consts_different_pool_order_yield_semantic_equivalence() {
    let mut canonical: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    canonical.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_CONST,
        0,
        OP_POP_TOP,
        0,
        OP_LOAD_CONST,
        1,
        OP_RETURN_VALUE,
        0,
    ];
    canonical.consts = vec![Object::Int(7), Object::Int(11)];
    canonical.qualname = name_obj("reorder");

    let mut reordered: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    reordered.code = vec![
        OP_RESUME,
        0,
        OP_LOAD_CONST,
        1,
        OP_POP_TOP,
        0,
        OP_LOAD_CONST,
        0,
        OP_RETURN_VALUE,
        0,
    ];
    reordered.consts = vec![Object::Int(11), Object::Int(7)];
    reordered.qualname = name_obj("reorder");

    let verdict: Verdict = semantic_equiv(&canonical, &reordered, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Semantic),
        "pool reorder with identical values must be Semantic (compared by value), got {verdict:?}"
    );
}

#[test]
fn pool_reorder_with_different_values_is_codediff() {
    let mut canonical: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    canonical.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    canonical.consts = vec![Object::Int(7)];
    canonical.qualname = name_obj("differ");

    let mut other: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    other.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    other.consts = vec![Object::Int(99)];
    other.qualname = name_obj("differ");

    let verdict: Verdict = semantic_equiv(&canonical, &other, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::CodeDiff(_)),
        "differing const value at same pool index must be CodeDiff, got {verdict:?}"
    );
}
