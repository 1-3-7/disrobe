#![allow(clippy::panic)]
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

fn assert_full_recovery(kind: &str, slot: &str, needle: &str) -> PeelOutcome {
    let fixture: Vec<u8> = common::require_real_fixture("pyminifier", slot);
    let det: DetectReport = PyminifierPass.detect(&fixture);
    assert!(
        det.matched,
        "pyminifier {kind} {slot} not detected: {det:?}"
    );
    let peel: PeelOutcome = PyminifierPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("pyminifier {kind} {slot} peel: {e:?}"));
    assert_eq!(
        peel.quality,
        Quality::Full,
        "pyminifier {kind} {slot} must reach Quality::Full; variant={:?}",
        peel.diagnostics.get("variant")
    );
    assert!(
        peel.recovered_source.contains(needle),
        "pyminifier {kind} {slot}: recovered source missing {needle:?}; got first 160: {:?}",
        &peel.recovered_source.chars().take(160).collect::<String>()
    );
    assert!(
        !peel.recovered_source.contains(CREDIT),
        "pyminifier {kind} {slot}: upstream credit line must be stripped from the recovered source"
    );
    peel
}

#[test]
fn pyminifier_real_fixtures_detect_and_peel() {
    for (slot, needle) in SLOTS {
        assert_full_recovery("slot", slot, needle);
    }
}

#[test]
fn pyminifier_variant_fixtures_detect_and_peel() {
    for (slot, needle) in VARIANT_SLOTS {
        assert_full_recovery("variant", slot, needle);
    }
}

fn diagnostic<'a>(peel: &'a PeelOutcome, key: &str) -> &'a str {
    peel.diagnostics
        .get(key)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("no {key} in diagnostics: {:?}", peel.diagnostics))
}

#[test]
fn pyminifier_compressed_variants_decompress_once_to_one_source() {
    let mut recovered: Vec<(&str, String)> = Vec::new();
    for (slot, stage) in [
        ("variant_gzip", "decompress-zlib"),
        ("variant_bzip2", "decompress-bz2"),
        ("variant_lzma", "decompress-lzma"),
    ] {
        let peel: PeelOutcome = assert_full_recovery("variant", slot, "def ");
        assert_eq!(
            diagnostic(&peel, "recursion_depth"),
            "1",
            "{slot} wraps exactly one compression layer"
        );
        assert!(
            peel.stages_applied.iter().any(|s: &String| s == stage),
            "{slot} must record {stage}, got {:?}",
            peel.stages_applied
        );
        recovered.push((slot, peel.recovered_source));
    }
    let (first_slot, first_source): &(&str, String) = &recovered[0];
    for (slot, source) in &recovered[1..] {
        assert_eq!(
            source, first_source,
            "{slot} and {first_slot} compress the same minified module, so they must recover the \
             same source"
        );
    }
}

#[test]
fn pyminifier_prepend_strips_copyright_lines() {
    let peel: PeelOutcome =
        assert_full_recovery("variant", "variant_prepend", "Python 3.6+ edge cases");
    assert_eq!(
        diagnostic(&peel, "prepend_lines"),
        "2",
        "the prepend variant carries exactly two prepended lines"
    );
    assert!(
        peel.stages_applied
            .iter()
            .any(|s: &String| s == "prepend-strip"),
        "prepend variant must record prepend-strip, got {:?}",
        peel.stages_applied
    );
}
