#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_py_disasm::alt_runtimes::pypy::{
    OpInsn, PyPyDisasm, PyPyModule, PyPyVariant, detect, is_private_opcode, parse,
};

const PYPY_MAGIC_37_LE: [u8; 4] = [0x11, 0xF5, 0xDE, 0xC0];
const PYPY_MAGIC_39_LE: [u8; 4] = [0x12, 0xF5, 0xDE, 0xC0];
const PYPY_MAGIC_310_LE: [u8; 4] = [0x13, 0xF5, 0xDE, 0xC0];
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
fn parses_pypy37_fixture() {
    let body: [u8; 6] = [OP_LOOKUP_METHOD, 0, OP_CALL_METHOD, 1, 100, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_37_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse pypy37");
    assert_eq!(module.variant, PyPyVariant::PyPy37);
    assert_eq!(module.private_opcode_total(), 2);
}

#[test]
fn parses_pypy39_fixture() {
    let body: [u8; 4] = [OP_BUILD_LIST_FROM_ARG, 3, OP_JUMP_IF_NOT_DEBUG, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_39_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse pypy39");
    assert_eq!(module.variant, PyPyVariant::PyPy39);
    assert_eq!(module.private_opcode_total(), 2);
}

#[test]
fn parses_pypy310_fixture() {
    let body: [u8; 2] = [OP_LOOKUP_METHOD, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_310_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse pypy310");
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
        PYPY_MAGIC_37_LE,
        PYPY_MAGIC_39_LE,
        PYPY_MAGIC_310_LE,
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
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_39_LE, &body);
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

const PYPY39_LEGACY: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/pypy/hello_pypy39_legacy.pypy39.pyc");

#[test]
fn pypy39_legacy_marshal_disassembles_real_bytecode() {
    let module: PyPyModule = parse(PYPY39_LEGACY).expect("parse pypy39");
    assert_eq!(module.variant, PyPyVariant::PyPy39);
    assert_eq!(module.compat_version(), disrobe_py_marshal::PyVersion::PY39);
    let disasm: PyPyDisasm = module.disassemble();
    assert!(
        disasm.marshaled_code,
        "a real pypy3.9 .pyc carries a marshaled code object, not raw interp bytecode"
    );
    assert!(
        disasm.instruction_count >= 14,
        "module + greet must recover at least 14 instructions, got {}",
        disasm.instruction_count
    );
    let module_unit = disasm
        .units
        .iter()
        .find(|u| u.qualified_name == "<module>")
        .expect("module unit");
    let mnemonics: Vec<&str> = module_unit
        .instructions
        .iter()
        .map(|i| i.opname.as_str())
        .collect::<Vec<&str>>();
    assert_eq!(
        mnemonics,
        [
            "LOAD_CONST",
            "LOAD_CONST",
            "MAKE_FUNCTION",
            "STORE_NAME",
            "LOAD_NAME",
            "LOAD_CONST",
            "CALL_FUNCTION",
            "STORE_NAME",
            "LOAD_CONST",
            "RETURN_VALUE",
        ],
        "pypy3.9 module opcodes must match the cpython 3.9 dis ground truth"
    );
    let greet_unit = disasm
        .units
        .iter()
        .find(|u| u.qualified_name.ends_with("greet"))
        .expect("greet unit");
    let greet_ops: Vec<&str> = greet_unit
        .instructions
        .iter()
        .map(|i| i.opname.as_str())
        .collect::<Vec<&str>>();
    assert_eq!(
        greet_ops,
        ["LOAD_CONST", "LOAD_FAST", "BINARY_ADD", "RETURN_VALUE"],
        "nested greet() must disassemble to the cpython 3.9 ground truth"
    );
}

#[test]
fn pypy_render_labels_runtime_and_compat() {
    let module: PyPyModule = parse(PYPY39_LEGACY).expect("parse");
    let disasm: PyPyDisasm = module.disassemble();
    let text: String = PyPyDisasm::render(&disasm);
    assert!(text.contains("pypy 3.9"));
    assert!(text.contains("cpython-compat 3.9"));
    assert!(text.contains("MAKE_FUNCTION"));
}

#[test]
fn pypy_raw_bytecode_falls_back_to_linear_listing() {
    let body: [u8; 6] = [OP_LOOKUP_METHOD, 0, OP_CALL_METHOD, 1, 100, 0];
    let bytes: Vec<u8> = fixture(PYPY_MAGIC_39_LE, &body);
    let module: PyPyModule = parse(&bytes).expect("parse");
    let disasm: PyPyDisasm = module.disassemble();
    assert!(
        !disasm.marshaled_code,
        "an arbitrary opcode blob is not a valid marshal stream and must use the linear listing"
    );
    assert!(
        disasm.instruction_count > 0,
        "linear listing must still enumerate opcodes"
    );
    let text: String = PyPyDisasm::render(&disasm);
    assert!(
        text.contains("LOOKUP_METHOD") && text.contains("CALL_METHOD"),
        "linear listing must name pypy private opcodes: {text}"
    );
}
