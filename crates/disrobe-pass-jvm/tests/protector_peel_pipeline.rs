#![allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use disrobe_pass_jvm::{
    ClassFile, DecompiledDex, DexFile, PeelStatus, PeeledClass, ProtectorFamilyKind,
    ProtectorPeelReport, decompile_dex, detect_protector_family, parse_classfile, parse_dex,
    peel_and_decompile_classfile,
};

const ZKM_STATIC_TABLE: &[u8] =
    include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
const DASHO_STRINGS: &[u8] = include_bytes!("../../../corpus/jvm/dasho/DashOStrings.class");
const DASHO_REFLECT: &[u8] = include_bytes!("../../../corpus/jvm/dasho/DashOReflect.class");
const BASELINE_CLEAN: &[u8] = include_bytes!("../../../corpus/jvm/kotlin/Greeter.class");
const STRINGER_DIGI: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Digi.class");
const DEXGUARD_DEX: &[u8] =
    include_bytes!("../../../corpus/jvm/dexguard/DexGuardReflectStrings.dex");

const DEXGUARD_ORACLE: &[&str] = &[
    "https://api.example.com/v1/auth",
    "X-Api-Key",
    "decryptToken",
    "SELECT * FROM secrets WHERE id = ?",
    "AES/CBC/PKCS5Padding",
    "com.disrobe.sample.Secret",
];

const ZKM_ORACLE: &[&str] = &[
    "jdbc:mysql://10.0.0.5:3306/billing",
    "X-Internal-Auth: 9f8e7d6c",
];

const DASHO_ORACLE: &[&str] = &[
    "jdbc:oracle:thin:@prod-db:1521/ORCL",
    "X-Service-Token: 4b1d9e",
    "https://billing.internal/api/charge",
    "ROLE_SUPERUSER",
    "/etc/app/secrets.properties",
];

#[test]
fn zelix_static_table_plaintext_lands_in_decompiled_source() {
    let cf: ClassFile = parse_classfile(ZKM_STATIC_TABLE).expect("StaticTableCrypt.class parses");
    assert_eq!(
        detect_protector_family(&cf),
        Some(ProtectorFamilyKind::ZelixKlassMaster),
        "the static-table XOR shape must be routed to the Zelix/self-contained peel"
    );
    let peeled: PeeledClass = peel_and_decompile_classfile(&cf)
        .expect("a detected protector class must produce a peeled decompile");
    let report: &ProtectorPeelReport = &peeled.report;
    assert_eq!(report.status, PeelStatus::StubRecovered);

    for want in ZKM_ORACLE {
        assert!(
            report
                .strings_recovered
                .values()
                .any(|s: &String| s == want),
            "peel must recover {want:?} by running the class's own decrypt; got {:?}",
            report.strings_recovered
        );
        assert!(
            peeled.source.contains(want),
            "the recovered plaintext {want:?} must be substituted into the decompiled .java; \
             source was:\n{}",
            peeled.source
        );
    }
    assert!(
        !peeled.source.contains("d9nx04qdw9"),
        "the encrypted ciphertext literal must not survive in the peeled source"
    );
}

#[test]
fn dasho_per_class_keyed_plaintext_lands_in_decompiled_source() {
    let cf: ClassFile = parse_classfile(DASHO_STRINGS).expect("DashOStrings.class parses");
    let peeled: PeeledClass =
        peel_and_decompile_classfile(&cf).expect("DashO class peels and decompiles");
    assert_eq!(peeled.report.family, ProtectorFamilyKind::DashO);
    assert_eq!(peeled.report.status, PeelStatus::StubRecovered);
    for want in DASHO_ORACLE {
        assert!(
            peeled.source.contains(want),
            "the DashO plaintext {want:?} must appear in the substituted decompiled source; \
             got:\n{}",
            peeled.source
        );
    }
}

#[test]
fn dasho_reflection_member_names_land_in_decompiled_source() {
    let cf: ClassFile = parse_classfile(DASHO_REFLECT).expect("DashOReflect.class parses");
    let peeled: PeeledClass =
        peel_and_decompile_classfile(&cf).expect("DashOReflect peels and decompiles");
    for want in ["java.lang.System", "getProperty", "java.version"] {
        assert!(
            peeled.source.contains(want),
            "the decrypted reflective target {want:?} must be substituted into the source; got:\n{}",
            peeled.source
        );
    }
}

#[test]
fn dexguard_dex_recovered_plaintext_lands_in_decompiled_source() {
    let dex: DexFile = parse_dex(DEXGUARD_DEX).expect("committed DexGuard dex parses");
    let decompiled: DecompiledDex = decompile_dex(&dex, DEXGUARD_DEX);
    for want in DEXGUARD_ORACLE {
        assert!(
            decompiled.source.contains(want),
            "the reflection-invoked decrypt plaintext {want:?} must be surfaced in the \
             decompiled dalvik source; got:\n{}",
            decompiled.source
        );
    }
    assert!(
        decompiled
            .source
            .contains("recovered 6 encrypted string(s) by running decrypt()"),
        "the dalvik decompile must credit running the real decrypt routine; got:\n{}",
        decompiled.source
    );
}

#[test]
fn stringer_self_checksum_keyed_class_is_detected_but_walled_honestly() {
    let cf: ClassFile = parse_classfile(STRINGER_DIGI).expect("real Stringer Digi.class parses");
    assert_eq!(
        detect_protector_family(&cf),
        Some(ProtectorFamilyKind::Stringer),
        "the real Stringer decrypt descriptor must be recognised as Stringer"
    );
    let peeled: PeeledClass =
        peel_and_decompile_classfile(&cf).expect("Stringer class still decompiles");
    assert_eq!(
        peeled.report.status,
        PeelStatus::DetectOnly,
        "the Stringer AES key word is masked by a self-integrity checksum over the decryptor's own \
         reflectively-read class bytes; the peel must stay an honest wall and must not fabricate \
         plaintext"
    );
    assert!(
        peeled.report.strings_recovered.is_empty(),
        "no plaintext may be invented for a self-checksum-keyed Stringer class"
    );
    assert!(
        peeled
            .report
            .notes
            .iter()
            .any(|n: &String| n.contains("self-tamper checksum")),
        "the report must explain the self-integrity-checksum wall; got {:?}",
        peeled.report.notes
    );
}

#[test]
fn clean_class_with_no_protector_does_not_peel() {
    let cf: ClassFile = parse_classfile(BASELINE_CLEAN).expect("parse");
    if detect_protector_family(&cf).is_none() {
        assert!(
            peel_and_decompile_classfile(&cf).is_none(),
            "with no protector detected the orchestrator must not fabricate a peel"
        );
    }
}
