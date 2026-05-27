#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::PyminifierPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const SLOTS: &[&str] = &[
    "edge_cases_3_6_obfuscate",
    "edge_cases_3_6_obfuscate_builtins",
    "edge_cases_3_6_obfuscate_classes",
    "edge_cases_3_6_obfuscate_functions",
    "edge_cases_3_6_obfuscate_variables",
    "edge_hello_world",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_typing_generic",
];

const VARIANT_SLOTS: &[&str] = &[
    "variant_obfuscate",
    "variant_obfuscate_builtins",
    "variant_obfuscate_classes",
    "variant_obfuscate_functions",
    "variant_obfuscate_variables",
    "variant_obfuscate_import_methods",
    "variant_replacement_length_1",
    "variant_replacement_length_2",
    "variant_replacement_length_3",
    "variant_gzip",
    "variant_lzma",
    "variant_bzip2",
    "variant_obfuscate_gzip",
    "variant_obfuscate_lzma",
    "variant_obfuscate_bzip2",
    "variant_prepend",
    "variant_use_tabs",
    "variant_nominify",
];

#[test]
fn pyminifier_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    let mut full_count: usize = 0;
    for slot in SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", slot) else {
            continue;
        };
        tested += 1;
        let det: DetectReport = PyminifierPass.detect(&fixture);
        assert!(det.matched, "pyminifier slot {slot} not detected: {det:?}");
        let peel: PeelOutcome = PyminifierPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("pyminifier slot {slot} peel: {e:?}"));
        if matches!(peel.quality, Quality::Full) {
            full_count += 1;
        }
    }
    assert!(tested > 0, "no pyminifier real fixtures found");
    assert_eq!(
        full_count, tested,
        "expected ALL {tested} pyminifier real fixtures to reach Quality::Full, got {full_count}"
    );
}

#[test]
fn pyminifier_variant_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    let mut full_count: usize = 0;
    let mut not_full: Vec<String> = Vec::new();
    for slot in VARIANT_SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", slot) else {
            panic!("missing pyminifier variant fixture: {slot}");
        };
        tested += 1;
        let det: DetectReport = PyminifierPass.detect(&fixture);
        assert!(
            det.matched,
            "pyminifier variant {slot} not detected: {det:?}"
        );
        let peel: PeelOutcome = PyminifierPass
            .peel(&fixture)
            .unwrap_or_else(|e| panic!("pyminifier variant {slot} peel: {e:?}"));
        if matches!(peel.quality, Quality::Full) {
            full_count += 1;
        } else {
            not_full.push(format!(
                "{slot}: quality={:?} variant={:?}",
                peel.quality,
                peel.diagnostics.get("variant").cloned().unwrap_or_default()
            ));
        }
    }
    assert!(tested > 0, "no pyminifier variant fixtures found");
    println!("pyminifier variants full/total = {full_count}/{tested}");
    if !not_full.is_empty() {
        println!("not-full variants:");
        for n in &not_full {
            println!("  - {n}");
        }
    }
    assert_eq!(
        full_count, tested,
        "expected ALL {tested} pyminifier variant fixtures to reach Quality::Full, got {full_count}"
    );
}

#[test]
fn pyminifier_gzip_recursively_decompresses() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", "variant_gzip")
    else {
        panic!("missing gzip variant fixture");
    };
    let peel: PeelOutcome = PyminifierPass.peel(&fixture).expect("peel");
    assert_eq!(peel.quality, Quality::Full);
    let depth: &String = peel
        .diagnostics
        .get("recursion_depth")
        .unwrap_or_else(|| panic!("no recursion_depth in diagnostics: {:?}", peel.diagnostics));
    assert_ne!(depth, "0", "gzip should decompress at least once");
    assert!(
        peel.recovered_source.contains("def ") || peel.recovered_source.contains("import "),
        "decompressed source should contain Python keywords, got {} bytes: {}",
        peel.recovered_source.len(),
        &peel.recovered_source[..peel.recovered_source.len().min(200)]
    );
}

#[test]
fn pyminifier_bz2_recursively_decompresses() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", "variant_bzip2")
    else {
        panic!("missing bzip2 variant fixture");
    };
    let peel: PeelOutcome = PyminifierPass.peel(&fixture).expect("peel");
    assert_eq!(peel.quality, Quality::Full);
    let depth: &String = peel
        .diagnostics
        .get("recursion_depth")
        .expect("recursion_depth");
    assert_ne!(depth, "0", "bzip2 should decompress at least once");
}

#[test]
fn pyminifier_lzma_recursively_decompresses() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", "variant_lzma")
    else {
        panic!("missing lzma variant fixture");
    };
    let peel: PeelOutcome = PyminifierPass.peel(&fixture).expect("peel");
    assert_eq!(peel.quality, Quality::Full);
    let depth: &String = peel
        .diagnostics
        .get("recursion_depth")
        .expect("recursion_depth");
    assert_ne!(depth, "0", "lzma should decompress at least once");
}

#[test]
fn pyminifier_prepend_strips_copyright_lines() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", "variant_prepend")
    else {
        panic!("missing prepend variant fixture");
    };
    let peel: PeelOutcome = PyminifierPass.peel(&fixture).expect("peel");
    assert_eq!(peel.quality, Quality::Full);
    let prepend_lines: &String = peel
        .diagnostics
        .get("prepend_lines")
        .expect("prepend_lines");
    assert_ne!(
        prepend_lines, "0",
        "prepend variant should strip at least one prefix line"
    );
}
