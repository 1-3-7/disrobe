#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_py_disasm::alt_runtimes::jython::{
    JvmAnalysis, JythonModule, analyze, detect, parse,
};

const CLASS_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
const MINOR_VERSION: [u8; 2] = [0x00, 0x00];
const MAJOR_VERSION_JSE8: [u8; 2] = [0x00, 0x34];

const TAG_UTF8: u8 = 1;
const TAG_CLASS: u8 = 7;

fn build_jython_class() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    out.extend_from_slice(&CLASS_MAGIC);
    out.extend_from_slice(&MINOR_VERSION);
    out.extend_from_slice(&MAJOR_VERSION_JSE8);
    let constants: &[(u8, &[u8])] = &[
        (TAG_UTF8, b"\x00\x13org/python/hello$py"),
        (TAG_CLASS, &[0x00, 0x01]),
        (TAG_UTF8, b"\x00\x10java/lang/Object"),
        (TAG_CLASS, &[0x00, 0x03]),
        (TAG_UTF8, b"\x00\x16org/python/core/PyCode"),
    ];
    let pool_count: u16 = u16::try_from(constants.len() + 1).unwrap();
    out.extend_from_slice(&pool_count.to_be_bytes());
    for (tag, body) in constants {
        out.push(*tag);
        out.extend_from_slice(body);
    }
    let access_flags: [u8; 2] = [0x00, 0x21];
    out.extend_from_slice(&access_flags);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[test]
fn parses_jython_class_with_marker() {
    let bytes: Vec<u8> = build_jython_class();
    let module: JythonModule = parse(&bytes).expect("parse jython");
    assert!(module.this_class.starts_with("org/python/"));
    assert!(!module.jython_markers.is_empty());
}

#[test]
fn analyze_delegates_to_jvm_and_flags_jython() {
    let bytes: Vec<u8> = build_jython_class();
    let analysis: JvmAnalysis = analyze(&bytes).expect("analyze");
    assert!(analysis.is_jython_generated);
    assert!(analysis.constant_pool_size > 0);
}

#[test]
fn detect_finds_org_python_marker() {
    let bytes: Vec<u8> = build_jython_class();
    assert!(detect(&bytes));
}

#[test]
fn detect_rejects_plain_java_class() {
    const HELLO: &[u8] = include_bytes!("../../disrobe-pass-jvm/corpus/Hello.class");
    assert!(!detect(HELLO));
}

#[test]
fn analyze_on_garbage_returns_delegation_failed() {
    let bytes: [u8; 16] = [0u8; 16];
    let err: disrobe_pass_py_disasm::AltRuntimeError = analyze(&bytes).expect_err("must fail");
    assert!(matches!(
        err,
        disrobe_pass_py_disasm::AltRuntimeError::DelegationFailed { .. }
    ));
}
