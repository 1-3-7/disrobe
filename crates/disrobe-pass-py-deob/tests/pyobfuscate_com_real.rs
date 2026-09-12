#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::DetectReport;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com::PyobfuscateComPass;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com_xor::PyobfuscateComXorPass;

#[test]
fn pyobfuscate_com_real_hello_fixture_loads_and_detector_runs() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyobfuscate_com", "hello")
    else {
        common::skip_absent_corpus(
            "pyobfuscate_com_real_hello_fixture_loads_and_detector_runs",
            "pyobfuscate_com",
        );
        return;
    };
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
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyobfuscate_com", "sample")
    else {
        common::skip_absent_corpus(
            "pyobfuscate_com_real_sample_fixture_loads",
            "pyobfuscate_com",
        );
        return;
    };
    assert!(
        fixture.len() > 1000,
        "real_sample.py is ~3.3KB of XOR/lambda obfuscation"
    );
    let _ = PyobfuscateComPass.detect(&fixture);
    let _ = PyobfuscateComPass.peel(&fixture);
}
