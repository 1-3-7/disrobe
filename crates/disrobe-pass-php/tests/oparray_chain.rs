#![cfg(feature = "chain")]
#![allow(clippy::expect_used)]

use disrobe_core::chain::{DetectContext, DetectVerdict, Detector, Pass};
use disrobe_core::error::CoreError;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_php::chain_detector::{PHP_PASS, PhpDetectorImpl};
use disrobe_pass_php::{PhpKind, detect_php};

const HELLO_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/hello.dzoa");

const fn context(bytes: &[u8]) -> DetectContext<'_> {
    DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    }
}

#[test]
fn registered_pass_recovers_committed_oparray_to_php_source() {
    assert_eq!(detect_php(HELLO_DZOA).kind, PhpKind::Unknown);
    let verdict: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(HELLO_DZOA))
        .expect("the registered PHP detector must recognize DZOA input");
    assert_eq!(verdict.pass_id, "php.peel");
    assert_eq!(verdict.format_tag, "php-oparray");

    let input: Artifact = Artifact::new(Rung::Raw, HELLO_DZOA.to_vec(), [0x5a; 32]);
    let output: Artifact = PHP_PASS
        .run(&input)
        .expect("the registered pass must recover DZOA");

    assert_eq!(output.rung, Rung::Surface);
    assert_eq!(output.root_hash, input.root_hash);
    assert_eq!(
        std::str::from_utf8(&output.envelope).expect("recovered source must be UTF-8"),
        "<?php\necho 'hello from ioncube container';\n"
    );
}

#[test]
fn registered_pass_rejects_a_truncated_oparray_with_the_parser_code() {
    let bytes: &[u8] = b"DZOA\x02";
    Detector::detect(&PhpDetectorImpl, &context(bytes))
        .expect("the detector must route a truncated DZOA container to its bounded parser");
    let input: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0x3c; 32]);
    let error: CoreError = PHP_PASS
        .run(&input)
        .expect_err("a truncated DZOA container must be refused");

    assert!(
        error.to_string().contains("DR-PHP-0092"),
        "unexpected error: {error}"
    );
}

#[test]
fn chain_detector_requires_exact_leading_magic_and_keeps_container_precedence() {
    let near_miss: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(b"DZOX<?php"))
        .expect("the embedded PHP source remains detectable");
    assert_eq!(near_miss.format_tag, "php-source");
    let verdict: DetectVerdict = Detector::detect(&PhpDetectorImpl, &context(b"DZOA<?php"))
        .expect("leading DZOA must take precedence over an embedded PHP tag");
    assert_eq!(verdict.format_tag, "php-oparray");
    assert!(Detector::detect(&PhpDetectorImpl, &context(b"DZOX payload")).is_none());
}
