#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::DetectReport;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com::PyobfuscateComPass;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com_xor::PyobfuscateComXorPass;

#[test]
fn pyobfuscate_com_real_hello_fixture_loads_and_detector_runs() {
    let fixture: Vec<u8> = common::require_real_fixture("pyobfuscate_com", "hello");
    assert!(!fixture.is_empty(), "real_hello.py must not be empty");
    let legacy: DetectReport = PyobfuscateComPass.detect(&fixture);
    assert!(
        !legacy.matched,
        "the legacy zlib+base64 dropper pass must not claim the 2026 XOR/lambda variant; that belongs to the dedicated PyobfuscateComXorPass"
    );
    let xor: DetectReport = PyobfuscateComXorPass.detect(&fixture);
    assert!(
        xor.matched,
        "the dedicated XOR/lambda pass must detect the real pyobfuscate.com 2026 hello fixture; markers={:?}",
        xor.markers
    );
}

#[test]
fn pyobfuscate_com_real_sample_fixture_loads() {
    let fixture: Vec<u8> = common::require_real_fixture("pyobfuscate_com", "sample");
    assert!(
        fixture.len() > 1000,
        "real_sample.py is ~3.3KB of XOR/lambda obfuscation"
    );
    let legacy: DetectReport = PyobfuscateComPass.detect(&fixture);
    assert!(
        !legacy.matched,
        "the legacy zlib+base64 dropper pass must not claim the 2026 XOR/lambda sample; markers={:?}",
        legacy.markers
    );
    let xor: DetectReport = PyobfuscateComXorPass.detect(&fixture);
    assert!(
        xor.matched,
        "the dedicated XOR/lambda pass must detect the real pyobfuscate.com 2026 sample; markers={:?}",
        xor.markers
    );
}
