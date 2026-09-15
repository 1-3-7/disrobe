#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::PyminifierPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const REAL_OBF: &[u8] =
    include_bytes!("../../../corpus/python/obfuscators/pyminifier/real_gauntlet_pyminifier.py");

const CLEAN_ORIGINAL: &str =
    include_str!("../../../corpus/python/obfuscators/pyminifier/gauntlet/clean_original.py");

#[test]
fn pyminifier_gauntlet_detects_python_minifier_3_2_0_output() {
    let det: DetectReport = PyminifierPass.detect(REAL_OBF);
    assert!(
        det.matched,
        "python-minifier 3.2.0 output (pyminifier-style) must be detected; got {det:?}"
    );
    assert!(
        det.confidence >= 0.8,
        "confidence must be >= 0.8 for banner-tagged output, got {}",
        det.confidence
    );
}

#[test]
fn pyminifier_gauntlet_recovers_structure_from_python_minifier_output() {
    let peel: PeelOutcome = PyminifierPass
        .peel(REAL_OBF)
        .expect("peel must not error on well-formed pyminifier-style input");

    assert_eq!(
        peel.quality,
        Quality::Full,
        "token-rename variant must reach Quality::Full; quality={:?}, notes={:?}",
        peel.quality,
        peel.lossy_notes
    );

    let recovered: &str = &peel.recovered_source;

    assert!(
        recovered.contains("print("),
        "builtin alias A=print must be recovered; recovered[:200]={:?}",
        &recovered.chars().take(200).collect::<String>()
    );

    assert!(
        recovered.contains("class Cls_0") || recovered.contains("class E"),
        "class identifier must be canonicalized or preserved; recovered[:300]={:?}",
        &recovered.chars().take(300).collect::<String>()
    );

    assert!(
        recovered.contains("def func_0") || recovered.contains("def F"),
        "function identifier must be canonicalized or preserved"
    );

    assert!(
        recovered.contains("'hello from disrobe'"),
        "string constant 'hello from disrobe' must survive recovery"
    );

    assert!(
        recovered.contains("42"),
        "numeric constant 42 must survive recovery"
    );

    assert!(
        !recovered.contains("A=print"),
        "alias definition line A=print must be stripped by alias-unrename stage"
    );

    assert!(
        !recovered.contains("python-minifier") || !recovered.starts_with("# python-minifier"),
        "banner comment must be stripped from recovered source"
    );

    println!(
        "recovery: {} chars, stages={:?}",
        recovered.len(),
        peel.stages_applied
    );
    println!(
        "diagnostics: aliases={}, tokens={}",
        peel.diagnostics
            .get("aliases_recovered")
            .map_or("?", String::as_str),
        peel.diagnostics
            .get("tokens_canonicalized")
            .map_or("?", String::as_str)
    );
}

#[test]
fn pyminifier_gauntlet_clean_original_is_substantially_different() {
    let peel: PeelOutcome = PyminifierPass.peel(REAL_OBF).expect("peel must succeed");
    let recovered: &str = &peel.recovered_source;

    let orig_has_full_names: bool = CLEAN_ORIGINAL.contains("DataProcessor")
        && CLEAN_ORIGINAL.contains("encode_string")
        && CLEAN_ORIGINAL.contains("cached_encode")
        && CLEAN_ORIGINAL.contains("pipeline");

    assert!(
        orig_has_full_names,
        "clean original must contain full identifiers as ground truth"
    );

    let obf_source: &str = std::str::from_utf8(REAL_OBF).expect("utf8");
    assert!(
        !obf_source.contains("DataProcessor"),
        "obfuscated output must NOT contain original identifier DataProcessor (proves it was renamed)"
    );
    assert!(
        !obf_source.contains("encode_string"),
        "obfuscated output must NOT contain original identifier encode_string"
    );

    assert!(
        recovered.len() > 100,
        "recovered source must be non-trivial (>100 chars), got {} chars",
        recovered.len()
    );

    assert!(
        recovered.contains("'hello from disrobe'") && recovered.contains("42"),
        "recovered source must preserve observable constants from the original"
    );
}
