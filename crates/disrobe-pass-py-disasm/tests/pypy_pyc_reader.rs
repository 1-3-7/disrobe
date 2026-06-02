#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_py_disasm::alt_runtimes::pypy::{
    OpInsn, PyPyModule, PyPyVariant, detect, is_private_opcode, parse,
};

const PYPY_MAGIC_310_LE: [u8; 4] = [0x11, 0xF5, 0xDE, 0xC0];
const PYPY_MAGIC_311_LE: [u8; 4] = [0x12, 0xF5, 0xDE, 0xC0];
const PYPY_MAGIC_312_LE: [u8; 4] = [0x13, 0xF5, 0xDE, 0xC0];
const PYPY_MAGIC_27_LE: [u8; 4] = [0x17, 0xF5, 0xDE, 0xC0];

const OP_LOOKUP_METHOD: u8 = 201;
const OP_CALL_METHOD: u8 = 202;
const OP_BUILD_LIST_FROM_ARG: u8 = 203;
const OP_JUMP_IF_NOT_DEBUG: u8 = 204;

fn fixture(magic: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(16 + body.len());
    bytes.extend_from_slice(&magic);
    bytes.extend_from_slice(&[0u8; 12]);
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn parses_pypy310_fixture() {
    let body: [u8; 6] = [OP_LOOKUP_METHOD, 0, OP_CALL_METHOD, 1, 100, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_310_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse pypy310");
    assert_eq!(module.variant, PyPyVariant::PyPy37);
    assert_eq!(module.private_opcode_total(), 2);
}

#[test]
fn parses_pypy311_fixture() {
    let body: [u8; 4] = [OP_BUILD_LIST_FROM_ARG, 3, OP_JUMP_IF_NOT_DEBUG, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_311_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse pypy311");
    assert_eq!(module.variant, PyPyVariant::PyPy39);
    assert_eq!(module.private_opcode_total(), 2);
}

#[test]
fn parses_pypy312_fixture() {
    let body: [u8; 2] = [OP_LOOKUP_METHOD, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_312_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse pypy312");
    assert_eq!(module.variant, PyPyVariant::PyPy310);
}

#[test]
fn parses_pypy27_fixture_short_header() {
    let mut bytes: Vec<u8> = Vec::with_capacity(16);
    bytes.extend_from_slice(&PYPY_MAGIC_27_LE);
    bytes.extend_from_slice(&[0u8; 4]);
    bytes.extend_from_slice(&[100u8, 0u8, OP_LOOKUP_METHOD]);
    let module: PyPyModule = parse(&bytes).expect("parse pypy27");
    assert_eq!(module.variant, PyPyVariant::PyPy27);
    assert_eq!(module.header_len, 8);
}

#[test]
fn detect_accepts_all_supported_variants() {
    for magic in [
        PYPY_MAGIC_27_LE,
        PYPY_MAGIC_310_LE,
        PYPY_MAGIC_311_LE,
        PYPY_MAGIC_312_LE,
    ] {
        let bytes: Vec<u8> = fixture(magic, &[]);
        assert!(detect(&bytes), "should detect magic {magic:?}");
    }
}

#[test]
fn detect_rejects_cpython_magic() {
    let cpython_311: [u8; 4] = [0xC7, 0x0D, 0x0D, 0x0A];
    let bytes: Vec<u8> = fixture(cpython_311, &[]);
    assert!(!detect(&bytes));
}

#[test]
fn opcode_iterator_visits_all_pypy_private_ops() {
    let body: [u8; 8] = [
        OP_LOOKUP_METHOD,
        0,
        OP_CALL_METHOD,
        1,
        OP_BUILD_LIST_FROM_ARG,
        2,
        OP_JUMP_IF_NOT_DEBUG,
        0,
    ];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_310_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse");
    let private_count: usize = module
        .opcodes()
        .filter(|i: &OpInsn| -> bool { i.is_private })
        .count();
    assert_eq!(private_count, 4);
}

#[test]
fn private_opcode_classifier_matches() {
    assert!(is_private_opcode(OP_LOOKUP_METHOD));
    assert!(is_private_opcode(OP_CALL_METHOD));
    assert!(is_private_opcode(OP_BUILD_LIST_FROM_ARG));
    assert!(is_private_opcode(OP_JUMP_IF_NOT_DEBUG));
    assert!(!is_private_opcode(100));
}
