#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pypacker::PypackerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};

const OBF: &str = "pypacker";

fn assert_marshal_handoff(slot: &str, expected_compressor: &str) {
    let fixture: Vec<u8> = common::require_real_fixture(OBF, slot);
    let text: &str = std::str::from_utf8(&fixture).expect("utf8");
    assert!(
        text.contains("marshal.loads(")
            && text.contains(&format!("{expected_compressor}.decompress(")),
        "real fixture must be the marshal+{expected_compressor} packer wrapper"
    );
    let detect: DetectReport = PypackerPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::Pypacker);
    assert!(detect.matched, "real fixture must be detected: {detect:?}");

    let peel: PeelOutcome = PypackerPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Partial,
        "marshal code object is a bytecode handoff, not source"
    );
    assert_eq!(
        peel.stages_applied,
        vec![
            expected_compressor.to_owned(),
            "marshal".to_owned(),
            "disassemble".to_owned(),
        ]
    );
    assert_eq!(
        peel.diagnostics.get("compressor").map(String::as_str),
        Some(expected_compressor)
    );
    assert_eq!(
        peel.diagnostics
            .get("entry_code_object")
            .map(String::as_str),
        Some("<module>"),
        "the CPython module-level code object is named <module>"
    );
    assert!(
        peel.recovered_source
            .contains("compiled bytecode, not source"),
        "handoff must state its ceiling"
    );
}

#[test]
fn pypacker_real_hello_zlib_marshal_handoff() {
    assert_marshal_handoff("hello", "zlib");
}

#[test]
fn pypacker_real_sample_lzma_marshal_handoff() {
    assert_marshal_handoff("sample", "lzma");
}

#[test]
fn pypacker_real_bz2_marshal_handoff() {
    assert_marshal_handoff("bz2", "bz2");
}

#[test]
fn pypacker_real_gzip_marshal_handoff() {
    assert_marshal_handoff("gzip", "gzip");
}
