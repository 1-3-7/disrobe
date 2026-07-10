#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::{Error, PeelOptions, peel_eval_chain};

const EXPECTED: &[u8] = include_bytes!("fixtures/php_real_chains/EXPECTED.txt");

fn assert_exact_recovery(input: &[u8]) {
    let report: disrobe_pass_php::PeelReport =
        peel_eval_chain(input, PeelOptions::default()).expect("peel octal char-code loader");
    assert_eq!(report.final_source, EXPECTED);
}

#[test]
fn inline_legacy_octal_chr_concat_recovers_exact_source() {
    const INPUT: &[u8] = include_bytes!("fixtures/php_real_chains/c_octal_inline.php");
    assert_exact_recovery(INPUT);
}

#[test]
fn legacy_octal_chr_function_name_recovers_exact_source() {
    const INPUT: &[u8] = include_bytes!("fixtures/php_real_chains/c_octal_loader.php");
    assert_exact_recovery(INPUT);
}

#[test]
fn invalid_octal_chr_literal_is_rejected_without_output() {
    let result: disrobe_pass_php::Result<disrobe_pass_php::PeelReport> =
        peel_eval_chain(b"<?php eval(chr(08));", PeelOptions::default());
    assert!(matches!(result, Err(Error::EvalChainStuck { depth: 0 })));
}

#[test]
fn runtime_chr_concat_term_is_rejected_without_output() {
    let result: disrobe_pass_php::Result<disrobe_pass_php::PeelReport> = peel_eval_chain(
        b"<?php eval(chr(0145).runtime_value().chr(0143));",
        PeelOptions::default(),
    );
    assert!(matches!(result, Err(Error::EvalChainStuck { depth: 0 })));
}
