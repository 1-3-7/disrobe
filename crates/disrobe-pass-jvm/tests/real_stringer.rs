#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::ptr_arg
)]

use disrobe_pass_jvm::{
    ClassFile, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport, parse_classfile,
    stringer_protector,
};

const DIGI: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Digi.class");
const HANDLER: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Handler.class");
const UH: &[u8] = include_bytes!("../../../corpus/jvm/stringer/uh.class");

#[test]
fn real_stringer_digi_caller_is_detect_only_with_self_checksum_reason() {
    let cf: ClassFile = parse_classfile(DIGI).expect("Digi.class parses");
    assert!(
        stringer_protector::has_runtime_key_signature(&cf),
        "Digi carries the (Ljava/lang/Object;I)Ljava/lang/String; stack-trace-reading decrypt shape"
    );
    let report: ProtectorPeelReport =
        stringer_protector::peel(&cf, "pack/tests/basics/accu/Digi", "J");
    assert_eq!(report.family, ProtectorFamilyKind::Stringer);
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "the peel does not yet emit cross-class AES cleartext for Digi (the decrypt lives in a \
         sibling class), so peel stays detect-only without fabricating"
    );
    assert!(report.strings_recovered.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("self-tamper checksum")
                && n.contains("enclosing jar's ZIP directory")
                && n.contains("1738644257434835613")
                && n.contains("information-theoretic wall")),
        "the note must state the self-tamper checksum folds the enclosing jar's ZIP directory at \
         runtime (genuine value 1738644257434835613, absent from the committed few-class \
         artifact), making the cleartext an information-theoretic wall for this sample, got {:?}",
        report.notes
    );
}

#[test]
fn real_stringer_handler_caller_stays_detect_only() {
    let handler: ClassFile = parse_classfile(HANDLER).expect("Handler.class parses");
    assert!(!handler.constant_pool.is_empty());
    let report: ProtectorPeelReport =
        stringer_protector::peel(&handler, "ube/tms/Handler", "openConnection");
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "Handler invokes the cross-class uh.T decryptor; the peel does not yet emit that AES \
         cleartext, so the inline constant stays opaque and nothing is fabricated"
    );
    assert!(report.strings_recovered.is_empty());
}

#[test]
fn real_stringer_uh_decoder_parses_under_tolerant_modified_utf8() {
    let cf: ClassFile = parse_classfile(UH).expect(
        "Stringer's encrypted pool constants carry unpaired surrogates; the tolerant \
         modified-utf8 decoder parses the class instead of rejecting it",
    );
    let report: ProtectorPeelReport = stringer_protector::peel(&cf, "ube/tms/uh", "i");
    assert!(
        report.strings_recovered.is_empty(),
        "uh is the AES decryptor; the peel does not fabricate AES cleartext. Its self-tamper key \
         word folds the enclosing jar's ZIP directory at runtime (genuine 1738644257434835613, \
         verified vs uh.B() under a JVM); only the empty-input decoy fold is statically evaluable, \
         and it does not decrypt the constants"
    );
}
