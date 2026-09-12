#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_jvm::{
    CallerKeyedReport, ClassFile, PeelStatus, ProtectorPeelReport, parse_classfile,
    recover_caller_keyed_strings, stringer_protector, zelix_protector,
};

const STATIC_TABLE: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
const DIGI: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Digi.class");

#[test]
fn static_table_self_contained_decrypt_recovers_known_plaintext() {
    let cf: ClassFile = parse_classfile(STATIC_TABLE).expect("StaticTableCrypt.class parses");
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    let recovered: Vec<String> = report.recovered.values().cloned().collect();
    for want in [
        "jdbc:mysql://10.0.0.5:3306/billing",
        "X-Internal-Auth: 9f8e7d6c",
    ] {
        assert!(
            recovered.iter().any(|s: &String| s == want),
            "the constrained evaluator must run the class's own static-table decrypt (clinit \
             builds the char[] key, getstatic reads it) and recover {want:?}; got {recovered:?}"
        );
    }
}

#[test]
fn static_table_class_peels_via_real_evaluator_not_synthetic_cipher() {
    let cf: ClassFile = parse_classfile(STATIC_TABLE).expect("parses");
    let report: ProtectorPeelReport = zelix_protector::peel(&cf);
    assert_eq!(
        report.status,
        PeelStatus::StubRecovered,
        "the self-contained decrypt is executed in-tree, so peel reports a real recovery"
    );
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    assert!(
        recovered
            .iter()
            .any(|s: &String| s == "jdbc:mysql://10.0.0.5:3306/billing"),
        "zelix peel must surface the evaluator-recovered plaintext, got {recovered:?}"
    );
}

#[test]
fn real_stringer_digi_self_checksum_keyed_stays_detect_only() {
    let cf: ClassFile = parse_classfile(DIGI).expect("real Stringer Digi.class parses");
    assert!(
        stringer_protector::has_runtime_key_signature(&cf),
        "Digi.class carries the Stringer decrypt signature"
    );
    let report: ProtectorPeelReport =
        stringer_protector::peel(&cf, "pack/tests/basics/accu/Digi", "J");
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "Stringer's AES key word is masked by a self-integrity checksum the decryptor computes \
         over its own reflectively-read class bytes, not present in this artifact; the constants \
         stay opaque and nothing is fabricated"
    );
    assert!(report.strings_recovered.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("self-tamper checksum")),
        "the detect-only result must state the concrete self-integrity-checksum reason"
    );
}
