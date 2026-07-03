#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Real obfusheader.h gauntlet. `sample.obfuscated.exe` is a real C++ program obfuscated by the
//! actual ac3ss0r/obfusheader.h header (OBF compile-time string encryption) and compiled to a
//! STRIPPED native PE. The strip-surviving pointer-shuffle constant is the non-circular gate for
//! obfusheader.h detection: disrobe must recognize it on the obfuscated build and NOT on clean.

use disrobe_pass_native::{ObfuscatorFamily, ObfuscatorHit, detect_obfuscators};

const OBF: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/obfusheader/sample.obfuscated.exe");
const CLEAN: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/obfusheader/sample.clean.exe");

#[test]
fn real_obfusheader_stripped_binary_detected() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(OBF);
    assert!(
        hits.iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Obfusheader),
        "real obfusheader.h-obfuscated (stripped) binary must be detected as Obfusheader via the \
         strip-surviving pointer-shuffle constant; got {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn clean_baseline_not_detected_as_obfusheader() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(CLEAN);
    assert!(
        !hits
            .iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Obfusheader),
        "the clean pre-obfuscation baseline carries no obfusheader.h constants and must NOT flag \
         Obfusheader: {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}
