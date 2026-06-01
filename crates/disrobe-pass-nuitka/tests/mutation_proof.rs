#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_nuitka::{
    CModuleStructure, build_surface, decode_const_file, emit_python, parse_c_module,
};

const C_SRC: &str = include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");

#[test]
fn mutation_proof_add_to_sub_changes_body() {
    let pool = decode_const_file(CONST, "module.hello.const", "hello").expect("decode");

    // Original lift
    let cmod_orig: CModuleStructure = parse_c_module(C_SRC).expect("parse orig");
    let surf_orig = build_surface(&cmod_orig, &pool, Some(C_SRC)).expect("surface orig");
    let py_orig: String = emit_python(&surf_orig);

    // Mutated: replace the ADD helper call token with SUB
    let mutated_c: String = C_SRC.replace(
        "BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(",
        "BINARY_OPERATION_SUB_OBJECT_OBJECT_OBJECT(",
    );
    assert_ne!(
        mutated_c, C_SRC,
        "mutation should have changed the C source"
    );

    let cmod_mut: CModuleStructure = parse_c_module(&mutated_c).expect("parse mutated");
    let surf_mut = build_surface(&cmod_mut, &pool, Some(&mutated_c)).expect("surface mutated");
    let py_mut: String = emit_python(&surf_mut);

    // The recovered bodies MUST differ
    assert_ne!(
        py_orig, py_mut,
        "mutation proof failed: bodies identical even after replacing ADD token with SUB"
    );

    // Specifically: original has , mutated does not
    assert!(
        py_orig.contains("a + b"),
        "original must contain  from real ADD call; got:
{py_orig}"
    );
    assert!(
        !py_mut.contains("a + b"),
        "mutated must NOT contain  (ADD token removed); got:
{py_mut}"
    );
}
