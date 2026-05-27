#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::DetectReport;
use disrobe_pass_py_deob::obfuscators::pyobfuscate_com::PyobfuscateComPass;

#[test]
fn pyobfuscate_com_real_hello_fixture_loads_and_detector_runs() {
    let fixture: Vec<u8> = common::load_real_fixture("pyobfuscate_com", "hello")
        .expect("real_hello.py captured 2026-05-26 from pyobfuscate.com /tools/ast-obfuscator-pro");
    assert!(!fixture.is_empty(), "real_hello.py must not be empty");
    let detect: DetectReport = PyobfuscateComPass.detect(&fixture);
    let _ = PyobfuscateComPass.peel(&fixture);
    assert!(
        !detect.matched,
        "pyobfuscate.com pivoted in 2026 to an XOR/lambda obfuscator that no longer matches the legacy zlib+base64 dropper signature; this real fixture documents that the detector correctly does NOT match the new format. A new pass should be added when the XOR variant is prioritized."
    );
}

#[test]
fn pyobfuscate_com_real_sample_fixture_loads() {
    let fixture: Vec<u8> = common::load_real_fixture("pyobfuscate_com", "sample")
        .expect("real_sample.py captured 2026-05-26 (recursive+class input)");
    assert!(
        fixture.len() > 1000,
        "real_sample.py is ~3.3KB of XOR/lambda obfuscation"
    );
    let _ = PyobfuscateComPass.detect(&fixture);
    let _ = PyobfuscateComPass.peel(&fixture);
}
