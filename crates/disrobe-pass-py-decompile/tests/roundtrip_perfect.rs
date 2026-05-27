use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion};

const OP_RESUME: u8 = 149;
const OP_LOAD_CONST: u8 = 83;
const OP_RETURN_VALUE: u8 = 36;

fn build_simple_code() -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    co.code = vec![OP_RESUME, 0, OP_LOAD_CONST, 0, OP_RETURN_VALUE, 0];
    co.consts = vec![Object::None];
    co.qualname = Object::String {
        value: "module".to_owned(),
        interned: true,
    };
    co.name = Object::String {
        value: "module".to_owned(),
        interned: true,
    };
    co
}

#[test]
fn identical_code_objects_yield_perfect() {
    let a: CodeObject = build_simple_code();
    let b: CodeObject = build_simple_code();
    let verdict: Verdict = semantic_equiv(&a, &b, PyVersion::PY313);
    assert!(
        matches!(verdict, Verdict::Perfect),
        "expected Perfect got {verdict:?}"
    );
}

#[test]
fn empty_code_objects_yield_perfect() {
    let a: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let b: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let verdict: Verdict = semantic_equiv(&a, &b, PyVersion::PY313);
    assert!(matches!(verdict, Verdict::Perfect));
}
