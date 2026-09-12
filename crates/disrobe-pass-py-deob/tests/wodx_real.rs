#![allow(clippy::expect_used)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::wodx::WodxPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome};

#[test]
#[ignore = "upstream-dead-2026-05: github.com/Hattori-A1S/WodX-Obfuscator returns HTTP 404"]
fn wodx_real_fixture_when_upstream_revives() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("wodx", "hello") else {
        return;
    };
    let _detect: DetectReport = WodxPass.detect(&fixture);
    let _peel: disrobe_pass_py_deob::Result<PeelOutcome> = WodxPass.peel(&fixture);
}
