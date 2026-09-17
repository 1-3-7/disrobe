#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_native::{
    ObfuscatorFamily, ObfuscatorHit, StringDecryptHit, detect_obfuscators, recover_obfuscxx_strings,
};

const OBF: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/obfuscxx/sample.obfuscxx.exe");
const CLEAN: &[u8] = include_bytes!("../../../corpus/native/obfuscators/obfuscxx/sample.clean.exe");

#[test]
fn real_obfuscxx_binary_detected() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(OBF);
    assert!(
        hits.iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Obfuscxx),
        "real obfuscxx-obfuscated binary must be detected as Obfuscxx via the ngu::obfuscxx<> \
         template-instantiation symbol; got {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn clean_baseline_not_detected_as_obfuscxx() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(CLEAN);
    assert!(
        !hits
            .iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Obfuscxx),
        "the clean pre-obfuscation baseline carries no obfuscxx template symbol and must NOT flag \
         Obfuscxx: {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn obfuscxx_encrypts_away_the_plaintext_string() {
    const NEEDLE: &[u8] = b"disrobe sample greeting payload";
    let in_clean: bool = CLEAN.windows(NEEDLE.len()).any(|w: &[u8]| w == NEEDLE);
    let in_obf: bool = OBF.windows(NEEDLE.len()).any(|w: &[u8]| w == NEEDLE);
    assert!(
        in_clean,
        "the clean baseline keeps the source string literal verbatim"
    );
    assert!(
        !in_obf,
        "obfuscxx compile-time XTEA must remove the plaintext string from the obfuscated build"
    );
}

#[test]
fn obfuscxx_xtea_string_recovers_against_clean_baseline() {
    const NEEDLE: &str = "disrobe sample greeting payload";
    let clean_recovered: Vec<StringDecryptHit> = recover_obfuscxx_strings(CLEAN);
    assert!(
        clean_recovered.is_empty(),
        "clean baseline must not emit obfuscxx recovered strings: {clean_recovered:?}"
    );
    let recovered: Vec<StringDecryptHit> = recover_obfuscxx_strings(OBF);
    assert!(
        recovered
            .iter()
            .any(|h: &StringDecryptHit| h.recovered == NEEDLE),
        "obfuscxx static XTEA recovery must reproduce the clean baseline string; got {recovered:?}"
    );
}
