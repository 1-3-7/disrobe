#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! amice gauntlet. amice (fuqiuluo/amice) is a Rust reimplementation of the OLLVM passes that runs
//! as an LLVM plugin (string encryption, control-flow flattening, bogus control flow, MBA). It is a
//! from-source LLVM-version-pinned plugin, not installable on this box, so these fixtures are
//! spec-constructed ELF objects carrying amice's source-verified output artifacts: the
//! `__amice__decrypt_strings_<rand>__` / `simd_xor_cipher_<rand>` / `simd_xor_decrypt_stub`
//! decryptor symbols amice emits, and a `.rodata` string encrypted with amice's default XOR key
//! `0xAA` (`amice/src/aotu/string_encryption/xor.rs`: `*byte ^= 0xAA`). The clean baseline is the same
//! object without the amice transform. Detection is graded obf-vs-clean (no false-positive on
//! clean); string recovery is graded against the clean original plaintext, never against amice's
//! own output.

use disrobe_pass_native::{
    ObfuscatorFamily, ObfuscatorHit, XorStringHit, detect_obfuscators, recover_amice_xor_strings,
};

const OBF: &[u8] = include_bytes!("../../../corpus/native/obfuscators/amice/sample.amice.elf");
const CLEAN: &[u8] = include_bytes!("../../../corpus/native/obfuscators/amice/sample.clean.elf");

const PLAINTEXT: &str = "https://c2.amice-demo.example/gate?id=victim-7f3a";

#[test]
fn real_amice_object_detected() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(OBF);
    assert!(
        hits.iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Amice),
        "amice-transformed object must be detected as Amice via the __amice__decrypt_strings_ / \
         simd_xor_* decryptor symbols; got {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn clean_baseline_not_detected_as_amice() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(CLEAN);
    assert!(
        !hits
            .iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::Amice),
        "the clean pre-amice baseline carries no amice decryptor symbol and must NOT flag Amice: \
         {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn amice_string_encryption_removes_the_plaintext() {
    let needle: &[u8] = PLAINTEXT.as_bytes();
    let in_clean: bool = CLEAN.windows(needle.len()).any(|w: &[u8]| w == needle);
    let in_obf: bool = OBF.windows(needle.len()).any(|w: &[u8]| w == needle);
    assert!(in_clean, "the clean baseline keeps the C2 literal verbatim");
    assert!(
        !in_obf,
        "amice XOR string encryption must remove the plaintext C2 literal from the obfuscated build"
    );
}

#[test]
fn amice_xor_key_recovers_the_plaintext_against_clean_original() {
    let recovered: Vec<XorStringHit> = recover_amice_xor_strings(OBF);
    assert!(
        recovered
            .iter()
            .any(|h: &XorStringHit| h.recovered.contains(PLAINTEXT)),
        "disrobe must reassemble the amice-encrypted string with the fixed 0xAA key and match the \
         clean original {PLAINTEXT:?}; recovered {recovered:?}"
    );
    let in_clean: bool = CLEAN
        .windows(PLAINTEXT.len())
        .any(|w: &[u8]| w == PLAINTEXT.as_bytes());
    assert!(
        in_clean,
        "the recovery target is the clean original plaintext, proving a non-circular grade"
    );
}
