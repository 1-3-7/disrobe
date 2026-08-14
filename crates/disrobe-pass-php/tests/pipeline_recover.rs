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
use base64::engine::general_purpose::STANDARD as B64;
use disrobe_pass_php::decompile::op;
use disrobe_pass_php::{
    Decompilation, OPARRAY_MAGIC, OPARRAY_VERSION, RecoveryReport, RecoveryStage, recover_php,
};

fn build_oparray_echo(literal: &str) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(0);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.push(4);
    body.extend_from_slice(&(literal.len() as u32).to_le_bytes());
    body.extend_from_slice(literal.as_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    push_op(&mut body, op::ECHO, 1, 0, 0, 0, 0, 0, 0, 1);
    push_op(&mut body, op::RETURN, 1, 0, 0, 0, 0, 0, 0, 1);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(OPARRAY_MAGIC);
    out.push(OPARRAY_VERSION);
    out.extend_from_slice(&body);
    out
}

fn build_expression_oparray(missing_definition: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(0);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&3u32.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&7i64.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&2i64.to_le_bytes());
    body.push(4);
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(b" apples");
    body.extend_from_slice(&5u32.to_le_bytes());
    push_op(&mut body, op::ASSIGN, 8, 1, 0, 0, 0, 0, 0, 1);
    push_op(
        &mut body,
        op::ADD,
        if missing_definition { 2 } else { 8 },
        1,
        2,
        if missing_definition { 99 } else { 0 },
        1,
        5,
        0,
        2,
    );
    push_op(&mut body, op::CONCAT, 2, 1, 2, 5, 2, 6, 0, 3);
    push_op(&mut body, op::ASSIGN, 8, 2, 0, 1, 6, 0, 0, 4);
    push_op(
        &mut body,
        op::RETURN,
        if missing_definition { 2 } else { 8 },
        0,
        0,
        if missing_definition { 77 } else { 1 },
        0,
        0,
        0,
        5,
    );
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(OPARRAY_MAGIC);
    out.push(OPARRAY_VERSION);
    out.extend_from_slice(&body);
    out
}

fn build_conditional_definition_oparray() -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(0);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&1i64.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&2i64.to_le_bytes());
    body.extend_from_slice(&3u32.to_le_bytes());
    push_op(&mut body, op::JMPZ, 8, 0, 0, 0, 2, 0, 0, 1);
    push_op(&mut body, op::ADD, 1, 1, 2, 0, 1, 5, 0, 2);
    push_op(&mut body, op::RETURN, 2, 0, 0, 5, 0, 0, 0, 3);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(OPARRAY_MAGIC);
    out.push(OPARRAY_VERSION);
    out.extend_from_slice(&body);
    out
}

fn build_terminal_return_oparray(opcode: u8, extended_value: u32) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(0);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&1i64.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    push_op(&mut body, opcode, 1, 0, 0, 0, 0, 0, extended_value, 1);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(OPARRAY_MAGIC);
    out.push(OPARRAY_VERSION);
    out.extend_from_slice(&body);
    out
}

#[allow(clippy::too_many_arguments)]
fn push_op(
    out: &mut Vec<u8>,
    opcode: u8,
    t1: u8,
    t2: u8,
    tr: u8,
    o1: u32,
    o2: u32,
    r: u32,
    ext: u32,
    line: u32,
) {
    out.push(opcode);
    out.push(t1);
    out.push(t2);
    out.push(tr);
    out.extend_from_slice(&o1.to_le_bytes());
    out.extend_from_slice(&o2.to_le_bytes());
    out.extend_from_slice(&r.to_le_bytes());
    out.extend_from_slice(&ext.to_le_bytes());
    out.extend_from_slice(&line.to_le_bytes());
}

#[test]
fn pipeline_peels_eval_chain_to_source() {
    let payload: &str = "echo 'pipeline recovered';";
    let blob: String = format!("<?php eval(base64_decode('{}'));", B64.encode(payload));
    let report: RecoveryReport = recover_php(blob.as_bytes(), None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::EvalChainPeeled);
    assert!(
        report.output.contains("pipeline recovered"),
        "output: {}",
        report.output
    );
    assert!(report.decompilation.is_none());
}

#[test]
fn pipeline_decompiles_raw_oparray_container_to_skeleton() {
    let bytes: Vec<u8> = build_oparray_echo("from oparray");
    let report: RecoveryReport = recover_php(&bytes, None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    assert!(
        report.output.contains("echo 'from oparray';"),
        "output: {}",
        report.output
    );
    let decomp: Decompilation = report.decompilation.expect("decompilation present");
    assert_eq!(decomp.op_count, 2);
    assert_eq!(decomp.literal_count, 1);
}

#[test]
fn pipeline_reconstructs_assignment_arithmetic_concatenation_and_return() {
    let bytes: Vec<u8> = build_expression_oparray(false);
    let report: RecoveryReport = recover_php(&bytes, None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    assert!(report.output.contains("$v0 = 7;"), "{}", report.output);
    assert!(
        report.output.contains("$v1 = $v0 + 2 . ' apples';"),
        "{}",
        report.output
    );
    assert!(report.output.contains("return $v1;"), "{}", report.output);
    let decomp: Decompilation = report.decompilation.expect("decompilation present");
    assert_eq!(decomp.unrecovered_total, 0);
}

#[test]
fn pipeline_refuses_expression_operands_without_reaching_definitions() {
    let bytes: Vec<u8> = build_expression_oparray(true);
    let report: RecoveryReport = recover_php(&bytes, None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    let decomp: &Decompilation = report
        .decompilation
        .as_ref()
        .expect("decompilation present");
    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry| entry.mnemonic == "ZEND_ADD"
                && entry.reason.contains("reaching definition")),
        "unrecovered: {:?}",
        decomp.unrecovered
    );
    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry| entry.mnemonic == "ZEND_ASSIGN"
                && entry.reason.contains("reaching definition")),
        "unrecovered: {:?}",
        decomp.unrecovered
    );
    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry| entry.mnemonic == "ZEND_RETURN"
                && entry.reason.contains("reaching definition")),
        "unrecovered: {:?}",
        decomp.unrecovered
    );
    assert!(
        !report.output.contains("$tmp99")
            && !report.output.contains("$var99")
            && !report.output.contains("$tmp77"),
        "{}",
        report.output
    );
}

#[test]
fn pipeline_refuses_a_definition_that_exists_on_only_one_conditional_path() {
    let bytes: Vec<u8> = build_conditional_definition_oparray();
    let report: RecoveryReport = recover_php(&bytes, None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    let decomp: &Decompilation = report
        .decompilation
        .as_ref()
        .expect("decompilation present");
    assert!(
        decomp
            .unrecovered
            .iter()
            .any(|entry| entry.mnemonic == "ZEND_RETURN"
                && entry.reason.contains("reaching definition")),
        "unrecovered: {:?}",
        decomp.unrecovered
    );
    assert!(
        !report.output.contains("return 1 + 2;"),
        "{}",
        report.output
    );
}

#[test]
fn pipeline_uses_return_provenance_instead_of_terminal_position() {
    let explicit_bytes: Vec<u8> = build_terminal_return_oparray(op::RETURN, 0);
    let explicit: RecoveryReport = recover_php(&explicit_bytes, None).expect("recover");
    assert!(explicit.output.contains("return 1;"), "{}", explicit.output);
    assert_eq!(
        explicit
            .decompilation
            .as_ref()
            .expect("decompilation present")
            .unrecovered_total,
        0
    );

    let final_bytes: Vec<u8> = build_terminal_return_oparray(op::RETURN, u32::MAX);
    let final_report: RecoveryReport = recover_php(&final_bytes, None).expect("recover");
    assert!(
        !final_report.output.contains("return 1;"),
        "{}",
        final_report.output
    );
    assert_eq!(
        final_report
            .decompilation
            .as_ref()
            .expect("decompilation present")
            .unrecovered_total,
        0
    );

    let by_ref_bytes: Vec<u8> = build_terminal_return_oparray(op::RETURN_BY_REF, u32::MAX);
    let by_ref: RecoveryReport = recover_php(&by_ref_bytes, None).expect("recover");
    assert!(!by_ref.output.contains("return 1;"), "{}", by_ref.output);
    assert_eq!(
        by_ref
            .decompilation
            .as_ref()
            .expect("decompilation present")
            .unrecovered_total,
        0
    );
}

fn build_oparray_with_unmodelled_opcode(literal: &str) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(0);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.push(4);
    body.extend_from_slice(&(literal.len() as u32).to_le_bytes());
    body.extend_from_slice(literal.as_bytes());
    body.extend_from_slice(&3u32.to_le_bytes());
    push_op(&mut body, op::SWITCH_LONG, 0, 0, 0, 0, 2, 0, 0, 1);
    push_op(&mut body, op::ECHO, 1, 0, 0, 0, 0, 0, 0, 2);
    push_op(&mut body, op::RETURN, 1, 0, 0, 0, 0, 0, 0, 3);
    body.extend_from_slice(&0u32.to_le_bytes());

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(OPARRAY_MAGIC);
    out.push(OPARRAY_VERSION);
    out.extend_from_slice(&body);
    out
}

#[test]
fn pipeline_reports_every_opcode_the_lifter_refused() {
    let bytes: Vec<u8> = build_oparray_with_unmodelled_opcode("still echoed");
    let report: RecoveryReport = recover_php(&bytes, None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::OpArrayDecompiled);
    let decomp = report
        .decompilation
        .as_ref()
        .expect("decompilation present");
    assert_eq!(decomp.unrecovered_total, 1);
    assert!(
        report.notes.iter().any(|note: &String| note
            .contains("1 of 3 opcodes were refused rather than guessed")
            && note.contains("switch and match dispatch is not reconstructed")),
        "a caller reading only the report must learn the recovered source is incomplete; notes: \
         {:?}",
        report.notes
    );
    assert!(
        report
            .output
            .contains("// disrobe: unrecovered ZEND_SWITCH_LONG at op 0"),
        "output: {}",
        report.output
    );
}

#[test]
fn pipeline_records_no_refusal_when_every_opcode_is_modelled() {
    let bytes: Vec<u8> = build_oparray_echo("from oparray");
    let report: RecoveryReport = recover_php(&bytes, None).expect("recover");
    let decomp = report
        .decompilation
        .as_ref()
        .expect("decompilation present");
    assert_eq!(decomp.unrecovered_total, 0);
    assert!(
        !report
            .notes
            .iter()
            .any(|note: &String| note.contains("refused")),
        "notes: {:?}",
        report.notes
    );
}

#[test]
fn pipeline_plain_source_is_passthrough() {
    let src: &[u8] = b"<?php function plain() { return 1; }";
    let report: RecoveryReport = recover_php(src, None).expect("recover");
    assert!(matches!(
        report.stage,
        RecoveryStage::PlainSource | RecoveryStage::EvalChainPeeled
    ));
    assert!(report.output.contains("function plain"));
}

#[test]
fn pipeline_corrupt_oparray_container_errors_honestly() {
    let mut bytes: Vec<u8> = OPARRAY_MAGIC.to_vec();
    bytes.push(OPARRAY_VERSION);
    bytes.push(0);
    let err = recover_php(&bytes, None).expect_err("corrupt container must error, not fake source");
    assert!(format!("{err}").contains("DR-PHP-009"), "{err}");
}

#[test]
fn pipeline_ioncube_without_auth_is_structural_only_and_honest() {
    let mut envelope: Vec<u8> = b"<?php //004F\n".to_vec();
    envelope.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\nblob\n");
    envelope.extend_from_slice(&[0x11u8; 128]);
    let report: RecoveryReport = recover_php(&envelope, None).expect("recover");
    assert_eq!(report.stage, RecoveryStage::StructuralOnly);
    assert_eq!(report.encoder.as_deref(), Some("IonCube"));
    assert_eq!(report.key_provenance.as_deref(), Some("LoaderDerivedRsa"));
    assert!(
        report.output.is_empty(),
        "no fabricated source for runtime-keyed encoder"
    );
    assert!(report.notes.iter().any(|n: &String| n.contains("loader")));
}

#[test]
fn pipeline_ioncube_with_auth_walls_to_structural_only_no_fake_recovery() {
    let mut envelope: Vec<u8> = b"<?php //004F\n".to_vec();
    envelope.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\nblob\n");
    envelope.extend_from_slice(&[0x42u8; 192]);

    let report: RecoveryReport = recover_php(
        &envelope,
        Some(disrobe_pass_php::AuthorizationToken::user_attested()),
    )
    .expect("recover");
    assert_eq!(report.stage, RecoveryStage::StructuralOnly);
    assert_eq!(report.encoder.as_deref(), Some("IonCube"));
    assert!(report.residual_ciphertext_len > 0);
    assert!(
        report.output.is_empty(),
        "no fabricated source past the proprietary-VM wall"
    );
}

#[test]
fn pipeline_sourceguardian_with_auth_walls_to_structural_only_no_fake_recovery() {
    let mut envelope: Vec<u8> = b"<?php\n//SGV-banner\n".to_vec();
    envelope.extend_from_slice(&[0x37u8; 192]);

    let report: RecoveryReport = recover_php(
        &envelope,
        Some(disrobe_pass_php::AuthorizationToken::user_attested()),
    )
    .expect("recover");
    assert_eq!(report.stage, RecoveryStage::StructuralOnly);
    assert_eq!(report.encoder.as_deref(), Some("SourceGuardian"));
    assert!(report.residual_ciphertext_len > 0);
    assert!(
        report.output.is_empty(),
        "no fabricated source for proprietary-VM SourceGuardian payload"
    );
}

#[test]
fn pipeline_zend_guard_xor_payload_decrypts_and_decompiles() {
    let key: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let plaintext_oparray: Vec<u8> = build_oparray_echo("zend recovered");
    let cipher: Vec<u8> = plaintext_oparray
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect();

    let mut envelope: Vec<u8> = b"<?php @Zend;\n".to_vec();
    envelope.push(b'3');
    envelope.push(0x00);
    envelope.extend_from_slice(&key);
    envelope.extend_from_slice(&cipher);

    let report: RecoveryReport = recover_php(
        &envelope,
        Some(disrobe_pass_php::AuthorizationToken::user_attested()),
    )
    .expect("recover");
    assert_eq!(
        report.stage,
        RecoveryStage::OpArrayDecompiled,
        "notes: {:?}",
        report.notes
    );
    assert!(
        report.output.contains("echo 'zend recovered';"),
        "output: {}",
        report.output
    );
}
