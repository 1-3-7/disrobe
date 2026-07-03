#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use disrobe_pass_php::{
    AuthorizationToken, RecoveryReport, RecoveryStage, build_ioncube_container,
    build_sourceguardian_container, build_zend_guard_obfuscated, recover_php,
};

const HELLO_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/hello.dzoa");
const FUNCS_DZOA: &[u8] = include_bytes!("fixtures/protector_oparray/funcs.dzoa");

const HELLO_SRC: &str = "<?php\necho 'hello from ioncube container';\n";
const FUNCS_SRC: &str = "<?php\nfunction greet($name) {\n    return 'hi ' . $name;\n}\n$msg = greet('world');\necho $msg;\n";

fn auth() -> Option<AuthorizationToken> {
    Some(AuthorizationToken::user_attested())
}

fn php_container_body(
    magic: [u8; 4],
    version: u32,
    flags: u32,
    declared_len: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(24 + payload.len());
    body.extend_from_slice(&magic);
    body.extend_from_slice(&version.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&declared_len.to_le_bytes());
    body.extend_from_slice(&[0u8; 8]);
    body.extend_from_slice(payload);
    body
}

fn ioncube_container_with_declared_len(declared_len: u32, payload: &[u8]) -> Vec<u8> {
    let body: Vec<u8> = php_container_body(*b"ICUB", 9, 0, declared_len, payload);
    let mut out: Vec<u8> = b"<?php ".to_vec();
    out.extend_from_slice(b"//");
    out.extend_from_slice(b"004F\n");
    out.extend_from_slice(B64_STD.encode(body).as_bytes());
    out.push(b'\n');
    out
}

fn sourceguardian_container_with_declared_len(declared_len: u32, payload: &[u8]) -> Vec<u8> {
    let body: Vec<u8> = php_container_body(*b"SGEN", 12, 0, declared_len, payload);
    let mut out: Vec<u8> = b"<?php sg_load('".to_vec();
    out.extend_from_slice(B64_STD.encode(body).as_bytes());
    out.extend_from_slice(b"');\n");
    out
}

#[test]
fn ioncube_container_lifts_real_opcode_stream_to_source() {
    let envelope: Vec<u8> =
        build_ioncube_container(b"<?php //004F", 9, 0, HELLO_DZOA, false).expect("build");
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::OpArrayDecompiled,
        "notes: {:?}",
        report.notes
    );
    assert_eq!(report.encoder.as_deref(), Some("IonCube"));
    assert!(
        report
            .output
            .contains("echo 'hello from ioncube container';"),
        "recovered: {}",
        report.output
    );
}

#[test]
fn ioncube_container_declared_length_mismatch_walls() {
    let envelope: Vec<u8> = ioncube_container_with_declared_len(1, HELLO_DZOA);
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::StructuralOnly,
        "declared container length mismatch must not lift source: {}",
        report.output
    );
    assert!(report.output.is_empty());
}

#[test]
fn ioncube_container_lifts_through_zlib_layer() {
    let envelope: Vec<u8> =
        build_ioncube_container(b"<?php //0080", 10, 1, FUNCS_DZOA, true).expect("build");
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    assert!(
        report.output.contains("function greet("),
        "recovered: {}",
        report.output
    );
    assert!(
        report.output.contains("return 'hi ' . "),
        "recovered: {}",
        report.output
    );
}

#[test]
fn sourceguardian_container_lifts_real_opcode_stream_to_source() {
    let envelope: Vec<u8> =
        build_sourceguardian_container(12, 0, FUNCS_DZOA, false).expect("build");
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::OpArrayDecompiled,
        "notes: {:?}",
        report.notes
    );
    assert_eq!(report.encoder.as_deref(), Some("SourceGuardian"));
    assert!(
        report.output.contains("function greet("),
        "recovered: {}",
        report.output
    );
}

#[test]
fn sourceguardian_container_declared_length_mismatch_walls() {
    let envelope: Vec<u8> = sourceguardian_container_with_declared_len(1, HELLO_DZOA);
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::StructuralOnly,
        "declared container length mismatch must not lift source: {}",
        report.output
    );
    assert!(report.output.is_empty());
}

#[test]
fn sourceguardian_container_lifts_through_zlib_layer() {
    let envelope: Vec<u8> = build_sourceguardian_container(12, 1, HELLO_DZOA, true).expect("build");
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    assert!(
        report
            .output
            .contains("echo 'hello from ioncube container';"),
        "recovered: {}",
        report.output
    );
}

#[test]
fn sourceguardian_container_without_auth_still_recovers_static_opcodes() {
    let envelope: Vec<u8> =
        build_sourceguardian_container(12, 0, HELLO_DZOA, false).expect("build");
    let report: RecoveryReport = recover_php(&envelope, None).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::OpArrayDecompiled,
        "static opcode bytes are present in the file and should lift without a runtime key"
    );
    assert!(
        report
            .output
            .contains("echo 'hello from ioncube container';"),
        "recovered: {}",
        report.output
    );
}

#[test]
fn grade_recovered_statements_against_original_source() {
    let cases: [(&[u8], &str, &[&str]); 2] = [
        (
            HELLO_DZOA,
            HELLO_SRC,
            &["echo 'hello from ioncube container';"],
        ),
        (
            FUNCS_DZOA,
            FUNCS_SRC,
            &[
                "function greet(",
                "return 'hi ' . ",
                "greet('world')",
                "echo ",
            ],
        ),
    ];
    for (dzoa, src, expected_fragments) in cases {
        let envelope: Vec<u8> =
            build_ioncube_container(b"<?php //004F", 9, 0, dzoa, false).expect("build");
        let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
        assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
        let recovered: usize = expected_fragments
            .iter()
            .filter(|frag: &&&str| report.output.contains(*frag))
            .count();
        assert_eq!(
            recovered,
            expected_fragments.len(),
            "original source:\n{src}\nrecovered:\n{}\nmissing fragments from {expected_fragments:?}",
            report.output
        );
    }
}

#[test]
fn wrong_key_corrupted_opcode_body_walls_no_fabrication() {
    let mut corrupted: Vec<u8> = HELLO_DZOA.to_vec();
    let key: [u8; 4] = [0x5a, 0xa5, 0x3c, 0xc3];
    for (i, b) in corrupted.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    let envelope: Vec<u8> =
        build_ioncube_container(b"<?php //004F", 9, 0, &corrupted, false).expect("build");
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::StructuralOnly,
        "a wrongly-keyed opcode body must wall, not fabricate; got: {}",
        report.output
    );
    assert!(
        report.output.is_empty(),
        "no fabricated source for an unrecoverable opcode body"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("cannot be lifted statically")),
        "wall note states the physical reason: {:?}",
        report.notes
    );
}

#[test]
fn zend_optimizer_obfuscation_key_lifts_real_opcode_stream() {
    let key: &[u8] = b"ZENDOPTKEY01";
    let envelope: Vec<u8> = build_zend_guard_obfuscated(b'4', key, FUNCS_DZOA).expect("build");
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::OpArrayDecompiled,
        "notes: {:?}",
        report.notes
    );
    assert_eq!(report.encoder.as_deref(), Some("ZendGuard"));
    assert_eq!(report.key_provenance.as_deref(), Some("StaticEmbedded"));
    assert!(
        report.output.contains("function greet("),
        "recovered: {}",
        report.output
    );
}

#[test]
fn zend_optimizer_wrong_key_walls_no_fabrication() {
    let key: &[u8] = b"RIGHTKEY01";
    let mut envelope: Vec<u8> = build_zend_guard_obfuscated(b'4', key, HELLO_DZOA).expect("build");
    let key_pos: usize = envelope
        .windows(4)
        .position(|w: &[u8]| w == b"ZOBF")
        .expect("zobf tag")
        + 6;
    envelope[key_pos] ^= 0xff;
    let report: RecoveryReport = recover_php(&envelope, auth()).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::StructuralOnly,
        "a tampered obfuscation key must wall, not fabricate: {}",
        report.output
    );
    assert!(report.output.is_empty());
}

#[test]
fn zend_optimizer_empty_key_is_rejected() {
    assert!(build_zend_guard_obfuscated(b'4', &[], HELLO_DZOA).is_err());
}

#[test]
fn ioncube_container_without_auth_still_recovers_static_opcodes() {
    let envelope: Vec<u8> =
        build_ioncube_container(b"<?php //004F", 9, 0, HELLO_DZOA, false).expect("build");
    let report: RecoveryReport = recover_php(&envelope, None).expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::OpArrayDecompiled,
        "static opcode bytes are present in the file and should lift without a runtime key"
    );
    assert!(
        report
            .output
            .contains("echo 'hello from ioncube container';"),
        "recovered: {}",
        report.output
    );
}
