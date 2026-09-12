#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

mod common;

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_pass_php::{RecoveryReport, RecoveryStage, recover_php};
use php_toolchain::{PhpRuntime, require_php, residual_decode_primitives, with_open_tag};

const MARKER: &str = "DISROBE-PHP-DIFF-9F3A";

fn marker_payload() -> String {
    format!("echo '{MARKER}';")
}

fn graded_for(label: &str) -> String {
    format!("the {label} loader differential against the real php interpreter")
}

fn assert_runtime_equivalent(label: &str, obfuscated: &[u8], expected_marker: &str) {
    let graded: String = graded_for(label);
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };

    let obf_stdout: Vec<u8> = php.stdout_of(label, obfuscated);
    let obf_text: String = String::from_utf8_lossy(&obf_stdout).into_owned();
    assert!(
        obf_text.contains(expected_marker),
        "{label}: the obfuscated loader itself does not print the ground-truth marker \
         {expected_marker:?} under {}; got {obf_text:?}. Comparing a recovery against an input that \
         never produced the marker would grade nothing.",
        php.banner
    );

    let report: RecoveryReport = recover_php(obfuscated, None)
        .unwrap_or_else(|e: disrobe_pass_php::Error| panic!("{label}: recover failed: {e}"));
    assert_ne!(
        report.stage,
        RecoveryStage::PlainSource,
        "{label}: a real obfuscated loader must not be reported as plain source"
    );
    assert!(
        !report.output.is_empty(),
        "{label}: recovery produced no source to grade"
    );

    let recovered_source: String = with_open_tag(&report.output);
    let recovered_stdout: Vec<u8> = php.stdout_of(label, recovered_source.as_bytes());

    assert_eq!(
        String::from_utf8_lossy(&recovered_stdout),
        String::from_utf8_lossy(&obf_stdout),
        "{label}: the recovered source is not behaviorally equivalent to the obfuscated loader \
         under {}\n--- recovered ---\n{recovered_source}",
        php.banner
    );

    let residual: Vec<&'static str> = residual_decode_primitives(&report.output);
    assert!(
        residual.is_empty(),
        "{label}: the recovered source runs to the same output as the loader but still calls \
         {residual:?}. A loader with one layer left on executes identically to the fully peeled \
         program, so behavioral equality alone must never be read as recovered \
         source.\n--- recovered ---\n{recovered_source}"
    );
}

#[test]
fn base64_gzinflate_eval_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_eval_chain(&marker_payload());
    assert_runtime_equivalent("base64+gzinflate", &blob, MARKER);
}

#[test]
fn base64_only_eval_runtime_equivalent() {
    let blob: Vec<u8> = common::build_b64_only_eval(&marker_payload());
    assert_runtime_equivalent("base64-only", &blob, MARKER);
}

#[test]
fn rot13_interposed_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_rot13_interposed_chain(&marker_payload());
    assert_runtime_equivalent("gzinflate(str_rot13(base64))", &blob, MARKER);
}

#[test]
fn strrev_wrapped_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_b64_wrapping_strrev_chain(&marker_payload());
    assert_runtime_equivalent("base64(strrev)", &blob, MARKER);
}

#[test]
fn split_literal_b64_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_split_literal_b64_chain(&marker_payload());
    assert_runtime_equivalent("base64(concat-literals)", &blob, MARKER);
}

#[test]
fn fopo_loader_runtime_equivalent() {
    let blob: Vec<u8> = common::build_fopo(&marker_payload());
    assert_runtime_equivalent("fopo", &blob, MARKER);
}

#[test]
fn better_php_obf_variable_chain_runtime_equivalent() {
    let blob: Vec<u8> = common::build_better_php_obf(&marker_payload());
    assert_runtime_equivalent("better-php-obfuscator", &blob, MARKER);
}

#[test]
fn str_rot13_base64_loader_runtime_equivalent() {
    let blob: Vec<u8> = common::build_str_rot13_b64(&marker_payload());
    assert_runtime_equivalent("base64(str_rot13)", &blob, MARKER);
}

#[test]
fn array_indexed_function_dispatch_runtime_equivalent() {
    let blob: Vec<u8> = common::build_array_indexed_dispatch(&marker_payload());
    assert_runtime_equivalent("array-indexed dispatch", &blob, MARKER);
}

#[test]
fn strtr_custom_alphabet_base64_runtime_equivalent() {
    let blob: Vec<u8> = common::build_strtr_custom_alphabet_chain(&marker_payload());
    assert_runtime_equivalent("base64(strtr custom alphabet)", &blob, MARKER);
}

#[test]
fn dot_append_base64_payload_builder_runtime_equivalent() {
    let blob: Vec<u8> = common::build_dot_append_b64_chain(&marker_payload());
    assert_runtime_equivalent("dot-append base64", &blob, MARKER);
}

#[test]
fn dot_append_gzinflate_payload_builder_runtime_equivalent() {
    let blob: Vec<u8> = common::build_dot_append_gzinflate_chain(&marker_payload());
    assert_runtime_equivalent("dot-append gzinflate", &blob, MARKER);
}

#[test]
fn xor_keystream_loop_runtime_equivalent() {
    let blob: Vec<u8> = common::build_loop_xor_chain(&marker_payload());
    assert_runtime_equivalent("xor-keystream-loop", &blob, MARKER);
}

#[test]
fn rc4_static_key_loop_runtime_equivalent() {
    let blob: Vec<u8> = common::build_rc4_static_key_chain(&marker_payload());
    assert_runtime_equivalent("rc4-static-key", &blob, MARKER);
}

#[test]
fn runtime_sourced_key_walls_and_recovered_body_is_never_fabricated() {
    let graded: String = graded_for("runtime-keyed eval wall");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let loader: &[u8] =
        b"<?php $k=$_GET['k']; ev\x61l(gzinflate(base64_decode($k . 'cGF5bG9hZA==')));";
    let report: RecoveryReport = recover_php(loader, None).expect("recover runtime-key loader");
    assert!(
        !report.output.contains(MARKER),
        "a $_GET-sourced key is absent from the file; recovery must wall, never fabricate a body; \
         got:\n{}",
        report.output
    );
    let sanity: Vec<u8> = php.stdout_of("wall sanity", b"<?php echo 'wall-pin-ok';");
    assert_eq!(
        String::from_utf8_lossy(&sanity),
        "wall-pin-ok",
        "the php reference this wall is graded beside does not run correctly, so the absence of a \
         fabricated body proves nothing"
    );
}

#[test]
fn the_differential_rejects_a_loader_whose_recovery_keeps_a_decode_layer() {
    let graded: String = graded_for("under-peeled loader rejection");
    let Some(php): Option<PhpRuntime> = require_php(&graded) else {
        return;
    };
    let inner: String = marker_payload();
    let once_wrapped: Vec<u8> = common::build_b64_only_eval(&inner);
    let twice_wrapped: Vec<u8> =
        common::build_b64_only_eval(&String::from_utf8_lossy(&once_wrapped).replace("<?php ", ""));

    let outer_stdout: Vec<u8> = php.stdout_of("twice-wrapped", &twice_wrapped);
    let inner_stdout: Vec<u8> = php.stdout_of("once-wrapped", &once_wrapped);
    assert_eq!(
        outer_stdout, inner_stdout,
        "a loader and the same loader with one more layer print the same thing, which is exactly \
         why behavioral equality alone cannot show a chain was fully peeled"
    );

    let half_peeled: String = String::from_utf8_lossy(&once_wrapped).into_owned();
    let residual: Vec<&'static str> = residual_decode_primitives(&half_peeled);
    assert!(
        residual.contains(&"base64_decode") && residual.contains(&"eval("),
        "the residual check must see the decode call and the sink that are still present in a \
         half-peeled recovery, saw {residual:?}"
    );
    assert!(
        residual_decode_primitives(&inner).is_empty(),
        "the fully peeled payload must carry no decode primitive, so the check does not simply \
         reject everything"
    );
}
