#![allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use disrobe_pass_jvm::{
    ClassFile, NameKeyedCipher, NameKeyedRecovery, PeelStatus, ProtectorFamilyKind,
    ProtectorPeelReport, allatori_protector, dasho_protector, parse_classfile, recover_name_keyed,
};

const ALLATORI_NAME_KEYED: &[u8] =
    include_bytes!("../../../corpus/jvm/namekeyed/AllatoriNameKeyed.class");
const DASHO_NAME_KEYED: &[u8] =
    include_bytes!("../../../corpus/jvm/namekeyed/DashONameKeyed.class");

const ALLATORI_ORACLE: &[&str] = &[
    "jdbc:mariadb://10.2.0.7:3306/ledger",
    "X-Allatori-Key: 7c3f1a",
    "eu-west-1",
];

const DASHO_ORACLE: &[&str] = &[
    "https://settlement.internal/api/post",
    "Bearer 5f2e9d",
    "/opt/app/conf/keystore.p12",
];

#[test]
fn allatori_name_keyed_recovers_from_shared_decryptor_call_sites() {
    let cf: ClassFile =
        parse_classfile(ALLATORI_NAME_KEYED).expect("real AllatoriNameKeyed.class parses");
    let report: ProtectorPeelReport =
        allatori_protector::peel(&cf, "com/disrobe/bench/AllatoriNameKeyed", "init");

    assert_eq!(report.family, ProtectorFamilyKind::Allatori);
    assert_eq!(
        report.status,
        PeelStatus::CipherRecovered,
        "the decryptor is in a shared class, but the per-class-name key is static, so the cipher \
         is rebuilt and applied; got {:?}",
        report.status
    );
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in ALLATORI_ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the name-keyed fallback must recover {want:?}; got {recovered:?}"
        );
    }
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("per-class-name key")),
        "the recovery note must credit the per-class-name key derivation"
    );
}

#[test]
fn dasho_name_keyed_recovers_from_shared_decryptor_call_sites() {
    let cf: ClassFile =
        parse_classfile(DASHO_NAME_KEYED).expect("real DashONameKeyed.class parses");
    let report: ProtectorPeelReport =
        dasho_protector::peel(&cf, "com/disrobe/bench/DashONameKeyed");

    assert_eq!(report.family, ProtectorFamilyKind::DashO);
    assert_eq!(
        report.status,
        PeelStatus::CipherRecovered,
        "the per-class key is built from this_class metadata, statically present; got {:?}",
        report.status
    );
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in DASHO_ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the name-keyed fallback must recover {want:?}; got {recovered:?}"
        );
    }
}

#[test]
fn allatori_name_keyed_recover_helper_matches_oracle() {
    let cf: ClassFile = parse_classfile(ALLATORI_NAME_KEYED).expect("parses");
    let recovery: NameKeyedRecovery = recover_name_keyed(&cf, NameKeyedCipher::Allatori);
    assert_eq!(
        recovery.call_sites, 3,
        "three dbUrl/apiKey/region call sites hand ciphertext to the shared decryptor"
    );
    assert_eq!(recovery.recovered.len(), ALLATORI_ORACLE.len());
}

#[test]
fn wrong_cipher_family_does_not_decrypt_dasho_ciphertext() {
    let cf: ClassFile = parse_classfile(DASHO_NAME_KEYED).expect("parses");
    let recovery: NameKeyedRecovery = recover_name_keyed(&cf, NameKeyedCipher::Allatori);
    let recovered: Vec<String> = recovery.recovered.values().cloned().collect();
    for want in DASHO_ORACLE {
        assert!(
            !recovered.iter().any(|r: &String| r == want),
            "the Allatori cipher must not reproduce DashO plaintext {want:?}; got {recovered:?}"
        );
    }
}
