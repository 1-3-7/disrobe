#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_native::{ObfuscatorFamily, ObfuscatorHit, detect_obfuscators};

const OBF: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/rust-obfuscator/sample.obfuscated.exe");
const CLEAN: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/rust-obfuscator/sample.clean.exe");

#[test]
fn real_rust_obfuscator_binary_detected_as_cryptify() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(OBF);
    assert!(
        hits.iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Cryptify),
        "real rust-obfuscator/cryptify binary must be detected as Cryptify (it carries the \
         CRYPTIFY_KEY decrypt signature); got {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn clean_baseline_not_detected_as_cryptify() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(CLEAN);
    assert!(
        !hits
            .iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Cryptify),
        "the clean pre-obfuscation baseline has no cryptify decrypt and must NOT flag Cryptify: \
         {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}
