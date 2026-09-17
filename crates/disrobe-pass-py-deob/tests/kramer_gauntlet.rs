#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::kramer::KramerPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const REAL_OBF: &[u8] =
    include_bytes!("../../../corpus/python/obfuscators/kramer/gauntlet/real_gauntlet_kramer.py");

const CLEAN_ORIGINAL: &str =
    include_str!("../../../corpus/python/obfuscators/kramer/gauntlet/clean_original.py");

#[test]
fn kramer_gauntlet_detects_billythegoat356_output() {
    let det: DetectReport = KramerPass.detect(REAL_OBF);
    assert!(
        det.matched,
        "real Kramer (billythegoat356) class-shape output must be detected; got {det:?}"
    );
    assert!(
        det.confidence >= 0.9,
        "confidence must be >= 0.9 for the upstream `class Kramer():` shape, got {}",
        det.confidence
    );
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m == "kramer-upstream-class-shape"),
        "must flag the upstream class shape marker; markers={:?}",
        det.markers
    );
}

#[test]
fn kramer_gauntlet_obfuscation_hides_the_clean_source() {
    let obf: &str = std::str::from_utf8(REAL_OBF).expect("obfuscated fixture is utf-8");

    for needle in [
        "GREETING",
        "THRESHOLD",
        "Ledger",
        "rotate_string",
        "cached_width",
    ] {
        assert!(
            !obf.contains(needle),
            "obfuscated output must not leak original identifier {needle:?}"
        );
    }
    assert!(
        !obf.contains("hello from disrobe"),
        "obfuscated output must not leak the original string constant"
    );
    assert!(
        obf.contains("class Kramer():") && obf.contains("def __decode__"),
        "fixture must carry the real Kramer decoder class shape"
    );
    assert!(
        obf.contains("_sparkle='''"),
        "fixture must carry the slash-delimited hex `_sparkle` payload"
    );
}

#[test]
fn kramer_gauntlet_recovers_clean_original_byte_exact() {
    let peel: PeelOutcome = KramerPass
        .peel(REAL_OBF)
        .expect("peel must not error on the real Kramer class-shape fixture");

    assert_eq!(
        peel.quality,
        Quality::Full,
        "real Kramer must fully recover; quality={:?}, notes={:?}",
        peel.quality,
        peel.lossy_notes
    );

    assert_eq!(
        peel.recovered_source, CLEAN_ORIGINAL,
        "Kramer's Kyrie+key+hex transform is lossless; recovered source must equal the clean original byte-for-byte"
    );

    println!(
        "kramer recovery: {} chars, stages={:?}, ord_shift={}, tokens={}",
        peel.recovered_source.len(),
        peel.stages_applied,
        peel.diagnostics
            .get("ord_shift")
            .map_or("?", String::as_str),
        peel.diagnostics
            .get("sparkle_token_count")
            .map_or("?", String::as_str)
    );
}

#[test]
fn kramer_gauntlet_recovers_every_structural_element() {
    let peel: PeelOutcome = KramerPass.peel(REAL_OBF).expect("peel must succeed");
    let recovered: &str = &peel.recovered_source;

    for needle in [
        "class Ledger:",
        "def report(self):",
        "def rotate_string(text):",
        "def cached_width(key):",
        "def gather(items):",
        "for item in items:",
        "GREETING = \"hello from disrobe\"",
        "THRESHOLD = 42",
        "if __name__ == \"__main__\":",
    ] {
        assert!(
            recovered.contains(needle),
            "recovered source must contain {needle:?}; recovered[:200]={:?}",
            &recovered.chars().take(200).collect::<String>()
        );
    }
}

#[test]
fn kramer_gauntlet_recovers_per_build_random_key() {
    let peel: PeelOutcome = KramerPass.peel(REAL_OBF).expect("peel must succeed");
    let shift: &str = peel.diagnostics.get("ord_shift").map_or("", String::as_str);
    let parsed: u32 = shift
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("ord_shift diagnostic must be a number, got {shift:?}"));
    assert!(
        parsed >= 3,
        "the per-build random Kramer key (>=3) must be recovered statically, not assumed; got {parsed}"
    );
}
