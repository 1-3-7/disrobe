#![allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use disrobe_pass_jvm::{
    ClassFile, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport, detect_protector_family,
    parse_classfile, peel_for_family,
};

const ALLATORI_STRINGS: &[u8] =
    include_bytes!("../../../corpus/jvm/allatori/AllatoriStrings.class");
const ALLATORI_CALLER: &[u8] = include_bytes!("../../../corpus/jvm/allatori/AllatoriCaller.class");

const STRINGS_ORACLE: &[&str] = &[
    "jdbc:postgresql://10.4.2.9:5432/ledger_main",
    "sk-live-7f3a9c1d-2b8e-4f60-a1d2-payments-prod",
    "/opt/disrobe/conf/keystore.p12",
    "s3://disrobe-artifacts/build/release",
    "config-key=disrobe-static-test-marker",
];

#[test]
fn real_allatori_sample_is_detected() {
    let cf: ClassFile = parse_classfile(ALLATORI_STRINGS).expect("real Allatori class parses");
    assert_eq!(
        detect_protector_family(&cf),
        Some(ProtectorFamilyKind::Allatori),
        "the obfuscated class carries the Allatori marker and must route to the Allatori peel"
    );
}

#[test]
fn real_allatori_strings_decrypt_to_authored_plaintext() {
    let cf: ClassFile = parse_classfile(ALLATORI_STRINGS).expect("real Allatori class parses");
    let report: ProtectorPeelReport = peel_for_family(&cf, ProtectorFamilyKind::Allatori);

    assert_eq!(report.family, ProtectorFamilyKind::Allatori);
    assert!(
        matches!(
            report.status,
            PeelStatus::StubRecovered | PeelStatus::CipherRecovered
        ),
        "the injected decrypt method must be executed to recover the cleartext; got {:?}",
        report.status
    );

    let recovered: Vec<&String> = report.strings_recovered.values().collect();
    for want in STRINGS_ORACLE {
        assert!(
            recovered.iter().any(|r: &&String| r.as_str() == *want),
            "the peel must recover the authored literal {want:?}; got {recovered:?}"
        );
    }
}

#[test]
fn real_allatori_local_decryptor_recovers_local_string() {
    let cf: ClassFile = parse_classfile(ALLATORI_CALLER).expect("real Allatori caller parses");
    let report: ProtectorPeelReport = peel_for_family(&cf, ProtectorFamilyKind::Allatori);

    assert!(
        report
            .strings_recovered
            .values()
            .any(|s: &String| s == "kafka://broker.internal:9092/disrobe-events-topic"),
        "the locally-decrypted secret must be recovered; got {:?}",
        report.strings_recovered
    );
}

#[test]
fn char_array_scheme_decryptor_recovers_against_authored_plaintext() {
    let cf: ClassFile = parse_classfile(ALLATORI_STRINGS).expect("parses");
    let report: ProtectorPeelReport =
        disrobe_pass_jvm::allatori_protector::peel(&cf, "com/disrobe/sample/Secret", "decrypt");

    let recovered: Vec<&String> = report.strings_recovered.values().collect();
    for want in STRINGS_ORACLE {
        assert!(
            recovered.iter().any(|r: &&String| r.as_str() == *want),
            "the dedicated Allatori scheme must recover {want:?}; got {recovered:?}"
        );
    }
}
