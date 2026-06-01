#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::oxyry::OxyryPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome};

#[test]
#[ignore = "online-service-requires-manual-capture: oxyry.com is client-side-only JS with no public API; see corpus/python/obfuscators/oxyry/CAPTURE-MANUAL.md"]
fn oxyry_real_fixture_when_manual_capture_lands() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("oxyry", "hello") else {
        return;
    };
    let _detect: DetectReport = OxyryPass.detect(&fixture);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = OxyryPass.peel(&fixture);
}
