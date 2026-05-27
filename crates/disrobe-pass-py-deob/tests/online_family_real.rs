#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::DetectReport;
use disrobe_pass_py_deob::obfuscators::online_family::OnlineFamilyPass;

#[test]
fn online_family_real_hello_detector_matches_banner() {
    let fixture: Vec<u8> = common::load_real_fixture("online_family", "hello")
        .expect("real_hello.py captured 2026-05-26 from pyobfuscator.com (hello-world input)");
    assert!(!fixture.is_empty());
    let detect: DetectReport = OnlineFamilyPass.detect(&fixture);
    assert!(
        detect.matched,
        "pyobfuscator.com banner must be detected: markers={:?}",
        detect.markers
    );
    assert!(
        detect
            .markers
            .iter()
            .any(|m: &String| m == "pyobfuscator.com")
    );
}

#[test]
fn online_family_real_sample_detector_matches_banner() {
    let fixture: Vec<u8> = common::load_real_fixture("online_family", "sample")
        .expect("real_sample.py captured 2026-05-26 from pyobfuscator.com (recursive+class input)");
    assert!(fixture.len() > 200);
    let detect: DetectReport = OnlineFamilyPass.detect(&fixture);
    assert!(
        detect.matched,
        "real pyobfuscator.com sample must match online-family detector: markers={:?}",
        detect.markers
    );
}
