#![allow(clippy::expect_used, clippy::panic)]

use disrobe_pass_py_disasm::alt_runtimes::micropython::{
    MpyBytecodeModule, MpyObject, parse_bytecode,
};

const FLOAT_REFERENCE: &[u8] = include_bytes!(
    "../../../corpus/python/alt_runtimes/micropython/float_reference/float_constant.mpy"
);
const AUTHORED_SOURCE: &str = include_str!(
    "../../../corpus/python/alt_runtimes/micropython/float_reference/float_constant.py"
);

fn authored_float_literal() -> &'static str {
    let [assignment]: [&str; 1] = AUTHORED_SOURCE
        .lines()
        .collect::<Vec<&str>>()
        .try_into()
        .expect("one authored float assignment");
    assignment
        .strip_prefix("float_reference = ")
        .expect("authored float assignment")
}

fn validate_compiler_float(module: &MpyBytecodeModule, expected: &str) -> Result<(), String> {
    let floats: Vec<&String> = module
        .typed_objects
        .iter()
        .filter_map(|object: &MpyObject| match object {
            MpyObject::Float(value) => Some(value),
            _ => None,
        })
        .collect();
    let [actual]: [&String; 1] = floats
        .try_into()
        .map_err(|values: Vec<&String>| format!("expected one float object, found {values:?}"))?;
    (actual == expected).then_some(()).ok_or_else(|| {
        format!("compiler float object {actual:?} differs from authored source {expected:?}")
    })
}

#[test]
fn compiler_built_v6_float_constant_matches_authored_source_and_rejects_mutation() {
    let expected: &str = authored_float_literal();
    let module: MpyBytecodeModule =
        parse_bytecode(FLOAT_REFERENCE).expect("official mpy-cross v6 float fixture must parse");
    assert_eq!(module.version, 6, "fixture provenance requires mpy v6");
    validate_compiler_float(&module, expected).expect("fixture must preserve the authored float");

    let mut mutated: Vec<u8> = FLOAT_REFERENCE.to_vec();
    let literal_offsets: Vec<usize> = mutated
        .windows(expected.len())
        .enumerate()
        .filter_map(|(offset, bytes): (usize, &[u8])| {
            (bytes == expected.as_bytes()).then_some(offset)
        })
        .collect();
    let [literal_offset]: [usize; 1] = literal_offsets
        .try_into()
        .expect("the compiler fixture has one encoded float literal");
    mutated[literal_offset] = b'7';
    let mutated_module: MpyBytecodeModule =
        parse_bytecode(&mutated).expect("same-length float mutation must remain parseable");
    assert!(
        validate_compiler_float(&mutated_module, expected).is_err(),
        "the reference check must reject a changed compiler float literal"
    );
}
