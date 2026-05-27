#![allow(clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::berserker::BerserkerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome};

const OBF: &str = "berserker";

#[test]
fn berserker_real_hello_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        panic!(
            "missing real fixture: corpus/python/obfuscators/{OBF}/real_hello.py — see corpus/python/obfuscators/MANIFEST.toml for regeneration"
        );
    };
    let detect: DetectReport = BerserkerPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::Berserker);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = BerserkerPass.peel(&fixture);
}

#[test]
fn berserker_real_sample_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "sample") else {
        panic!("missing real fixture: corpus/python/obfuscators/{OBF}/real_sample.py");
    };
    let detect: DetectReport = BerserkerPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::Berserker);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = BerserkerPass.peel(&fixture);
}

#[test]
fn berserker_real_application_loads_without_panic() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "application") else {
        panic!("missing real fixture: corpus/python/obfuscators/{OBF}/real_application.py");
    };
    let detect: DetectReport = BerserkerPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::Berserker);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = BerserkerPass.peel(&fixture);
}

#[test]
fn berserker_real_detector_should_match() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture(OBF, "hello") else {
        return;
    };
    let detect: DetectReport = BerserkerPass.detect(&fixture);
    assert!(
        detect.matched,
        "real Berserker output not yet trained into detector"
    );
}
