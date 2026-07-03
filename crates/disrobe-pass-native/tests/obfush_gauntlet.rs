#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Real obfus.h gauntlet. `sample.obfush.exe` is a real C program compiled with the actual
//! obfus.h macro library (via TCC, its documented target compiler). These are the
//! authoritative non-circular gate for obfus.h detection: disrobe must recognize the real
//! `.obfh` signature section on the obfuscated build and NOT on the clean baseline. No
//! self-authored fixture stands in for the real bytes.

use disrobe_pass_native::{ObfuscatorFamily, ObfuscatorHit, detect_obfuscators};

const OBFUSH: &[u8] = include_bytes!("../../../corpus/native/obfuscators/obfush/sample.obfush.exe");
const CLEAN: &[u8] = include_bytes!("../../../corpus/native/obfuscators/obfush/sample.clean.exe");

#[test]
fn real_obfush_binary_detected_as_obfush() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(OBFUSH);
    assert!(
        hits.iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::ObfusH),
        "real obfus.h binary must be detected as ObfusH (it carries the .obfh signature \
         section); got {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}

#[test]
fn clean_baseline_not_detected_as_obfush() {
    let hits: Vec<ObfuscatorHit> = detect_obfuscators(CLEAN);
    assert!(
        !hits
            .iter()
            .any(|h: &ObfuscatorHit| h.family == ObfuscatorFamily::ObfusH),
        "the clean pre-obfuscation baseline has no .obfh section and must NOT flag obfus.h: {:?}",
        hits.iter()
            .map(|h: &ObfuscatorHit| h.family)
            .collect::<Vec<_>>()
    );
}
