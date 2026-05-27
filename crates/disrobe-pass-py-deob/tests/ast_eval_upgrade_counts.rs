#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]
mod common;

use disrobe_pass_py_deob::ObfuscatorPass;
use disrobe_pass_py_deob::obfuscators::blankobf::BlankObfPass;
use disrobe_pass_py_deob::obfuscators::manglify::ManglifyPass;
use disrobe_pass_py_deob::obfuscators::pyminifier::PyminifierPass;
use disrobe_pass_py_deob::obfuscators::{PeelOutcome, Quality};

const BLANKOBF_SLOTS: &[&str] = &[
    "edge_cases_3_8_r1",
    "edge_cases_3_8_r1_imports",
    "edge_hello_world",
    "edge_recursive",
    "edge_class_decorator",
    "edge_async_fn",
    "edge_generator",
    "edge_lambda_in_listcomp",
    "edge_walrus_operator",
    "edge_match_statement",
    "edge_structural_pattern",
    "edge_typing_generic",
];

const MANGLIFY_SLOTS: &[&str] = &[
    "edge_cases_3_8",
    "edge_hello_world",
    "edge_async_fn",
    "edge_lambda_in_listcomp",
    "edge_typing_generic",
    "edge_walrus_operator",
];

const PYMINIFIER_SLOTS: &[&str] = &[
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
fn report_upgrade_counts() {
    let blankobf: (usize, usize) = count("blankobf", BLANKOBF_SLOTS, |bytes: &[u8]| {
        BlankObfPass.peel(bytes).expect("peel")
    });
    let manglify: (usize, usize) = count("manglify", MANGLIFY_SLOTS, |bytes: &[u8]| {
        ManglifyPass.peel(bytes).expect("peel")
    });
    let pyminifier: (usize, usize) = count("pyminifier", PYMINIFIER_SLOTS, |bytes: &[u8]| {
        PyminifierPass.peel(bytes).expect("peel")
    });
    println!("blankobf full/total = {}/{}", blankobf.0, blankobf.1);
    println!("manglify full/total = {}/{}", manglify.0, manglify.1);
    println!("pyminifier full/total = {}/{}", pyminifier.0, pyminifier.1);
    assert!(blankobf.0 >= 1, "expected >=1 blankobf upgrade");
    assert!(manglify.0 >= 1, "expected >=1 manglify upgrade");
    assert!(pyminifier.0 >= 1, "expected >=1 pyminifier upgrade");
}

fn count<F: Fn(&[u8]) -> PeelOutcome>(name: &str, slots: &[&str], peel: F) -> (usize, usize) {
    let mut full: usize = 0;
    let mut total: usize = 0;
    for slot in slots {
        let Some(bytes): Option<Vec<u8>> = common::load_real_fixture(name, slot) else {
            continue;
        };
        total += 1;
        let outcome: PeelOutcome = peel(&bytes);
        if matches!(outcome.quality, Quality::Full) {
            full += 1;
        }
    }
    (full, total)
}
