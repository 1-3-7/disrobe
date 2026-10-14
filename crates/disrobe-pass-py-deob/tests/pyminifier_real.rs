#![allow(clippy::panic)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::PyminifierPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};

const CREDIT: &str = "github.com/liftoff/pyminifier";

const SLOTS: &[(&str, &str)] = &[
    ("edge_cases_3_6_obfuscate", "exercise ok"),
    ("edge_cases_3_6_obfuscate_builtins", "exercise ok"),
    ("edge_cases_3_6_obfuscate_classes", "exercise ok"),
    ("edge_cases_3_6_obfuscate_functions", "exercise ok"),
    ("edge_cases_3_6_obfuscate_variables", "exercise ok"),
    ("edge_hello_world", "print('hello world')"),
    ("edge_recursive", "return n * n(n - 1)"),
    ("edge_class_decorator", "decorated = True"),
    ("edge_async_fn", "await s(0)"),
    ("edge_generator", "yield i"),
    (
        "edge_lambda_in_listcomp",
        "(lambda y: y + 1)(x) for x in range(5)",
    ),
    ("edge_typing_generic", "T = TypeVar('T')"),
];

const VARIANT_SLOTS: &[(&str, &str)] = &[
    ("variant_obfuscate", "exercise ok"),
    ("variant_obfuscate_builtins", "exercise ok"),
    ("variant_obfuscate_classes", "exercise ok"),
    ("variant_obfuscate_functions", "exercise ok"),
    ("variant_obfuscate_variables", "exercise ok"),
    ("variant_obfuscate_import_methods", "exercise ok"),
    ("variant_replacement_length_1", "exercise ok"),
    ("variant_replacement_length_2", "exercise ok"),
    ("variant_replacement_length_3", "exercise ok"),
    ("variant_gzip", "Python 3.6+ edge cases"),
    ("variant_lzma", "Python 3.6+ edge cases"),
    ("variant_bzip2", "Python 3.6+ edge cases"),
    ("variant_obfuscate_gzip", "Python 3.6+ edge cases"),
    ("variant_obfuscate_lzma", "Python 3.6+ edge cases"),
    ("variant_obfuscate_bzip2", "Python 3.6+ edge cases"),
    ("variant_prepend", "Python 3.6+ edge cases"),
    ("variant_use_tabs", "exercise ok"),
    ("variant_nominify", "exercise ok"),
];

const RENAMED_BY_TOOL: &[&str] = &[
    "edge_cases_3_6_obfuscate",
    "edge_cases_3_6_obfuscate_builtins",
    "edge_cases_3_6_obfuscate_functions",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "variant_obfuscate",
    "variant_obfuscate_functions",
    "variant_replacement_length_1",
    "variant_replacement_length_2",
    "variant_replacement_length_3",
    "variant_obfuscate_gzip",
    "variant_obfuscate_lzma",
    "variant_obfuscate_bzip2",
];

fn expected_quality(slot: &str) -> Quality {
    if RENAMED_BY_TOOL.contains(&slot) {
        Quality::Partial
    } else {
        Quality::Full
    }
}

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
        expected_quality(slot),
        "pyminifier {kind} {slot}: generated identifiers without a mapping cap recovery at Partial; variant={:?}",
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

#[test]
fn the_generated_name_heuristic_flags_a_pinned_set() {
    let renamed: Vec<&str> = SLOTS
        .iter()
        .chain(VARIANT_SLOTS)
        .map(|(slot, _): &(&str, &str)| *slot)
        .filter(|slot: &&str| {
            let fixture: Vec<u8> = common::require_real_fixture("pyminifier", slot);
            PyminifierPass
                .peel(&fixture)
                .unwrap_or_else(|e| panic!("{slot}: {e:?}"))
                .diagnostics
                .get("identifiers_renamed_by_tool")
                .map(String::as_str)
                == Some("true")
        })
        .collect();
    assert_eq!(renamed, RENAMED_BY_TOOL);
}

fn diagnostic<'a>(peel: &'a PeelOutcome, key: &str) -> &'a str {
    peel.diagnostics.get(key).map_or_else(
        || panic!("no {key} in diagnostics: {:?}", peel.diagnostics),
        String::as_str,
    )
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
