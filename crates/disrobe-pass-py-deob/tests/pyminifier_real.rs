#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::PyminifierPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const CREDIT: &str = "github.com/liftoff/pyminifier";

const SLOTS: &[(&str, &str)] = &[
    ("edge_cases_3_6_obfuscate", "class Cls_0"),
    ("edge_cases_3_6_obfuscate_builtins", "class Cls_0"),
    ("edge_cases_3_6_obfuscate_classes", "class Cls_0"),
    ("edge_cases_3_6_obfuscate_functions", "def func_0"),
    ("edge_cases_3_6_obfuscate_variables", "class Cls_0"),
    ("edge_hello_world", "print('hello world')"),
    ("edge_recursive", "return n * n(n - 1)"),
    ("edge_class_decorator", "@func_0"),
    ("edge_async_fn", "await s(0)"),
    ("edge_generator", "yield i"),
    (
        "edge_lambda_in_listcomp",
        "(lambda y: y + 1)(x) for x in range(5)",
    ),
    ("edge_typing_generic", "T = TypeVar('T')"),
];

const VARIANT_SLOTS: &[(&str, &str)] = &[
    ("variant_obfuscate", "func_0"),
    ("variant_obfuscate_builtins", "func_0"),
    ("variant_obfuscate_classes", "func_0"),
    ("variant_obfuscate_functions", "func_0"),
    ("variant_obfuscate_variables", "func_0"),
    ("variant_obfuscate_import_methods", "func_0"),
    ("variant_replacement_length_1", "func_0"),
    ("variant_replacement_length_2", "func_0"),
    ("variant_replacement_length_3", "func_0"),
    ("variant_gzip", "Python 3.6+ edge cases"),
    ("variant_lzma", "Python 3.6+ edge cases"),
    ("variant_bzip2", "Python 3.6+ edge cases"),
    ("variant_obfuscate_gzip", "Python 3.6+ edge cases"),
    ("variant_obfuscate_lzma", "Python 3.6+ edge cases"),
    ("variant_obfuscate_bzip2", "Python 3.6+ edge cases"),
    ("variant_prepend", "Python 3.6+ edge cases"),
    ("variant_use_tabs", "func_0"),
    ("variant_nominify", "func_0"),
];

#[test]
fn pyminifier_real_fixtures_detect_and_peel() {
    let mut tested: usize = 0;
    let mut full_count: usize = 0;
    for (slot, needle) in SLOTS {
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
            assert!(
                peel.recovered_source.contains(needle),
                "pyminifier slot {slot}: recovered source missing {needle:?}; got first 160: {:?}",
                &peel.recovered_source.chars().take(160).collect::<String>()
            );
            assert!(
                !peel.recovered_source.contains(CREDIT),
                "pyminifier slot {slot}: upstream credit line must be stripped from the recovered source"
            );
        }
    }
    if tested == 0 {
        common::skip_absent_corpus("pyminifier_real_fixtures_detect_and_peel", "pyminifier");
        return;
    }
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
    for (slot, needle) in VARIANT_SLOTS {
        let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyminifier", slot) else {
            continue;
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
            assert!(
                peel.recovered_source.contains(needle),
                "pyminifier variant {slot}: recovered source missing {needle:?}; got first 160: {:?}",
                &peel.recovered_source.chars().take(160).collect::<String>()
            );
            assert!(
                !peel.recovered_source.contains(CREDIT),
                "pyminifier variant {slot}: upstream credit line must be stripped from the recovered source"
            );
        } else {
            not_full.push(format!(
                "{slot}: quality={:?} variant={:?}",
                peel.quality,
                peel.diagnostics.get("variant").cloned().unwrap_or_default()
            ));
        }
    }
    if tested == 0 {
        common::skip_absent_corpus("pyminifier_variant_fixtures_detect_and_peel", "pyminifier");
        return;
    }
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
        common::skip_absent_corpus("pyminifier_gzip_recursively_decompresses", "pyminifier");
        return;
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
        common::skip_absent_corpus("pyminifier_bz2_recursively_decompresses", "pyminifier");
        return;
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
        common::skip_absent_corpus("pyminifier_lzma_recursively_decompresses", "pyminifier");
        return;
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
        common::skip_absent_corpus("pyminifier_prepend_strips_copyright_lines", "pyminifier");
        return;
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
