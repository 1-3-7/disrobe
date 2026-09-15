#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    ClassFile, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport, StringRecoveryReport,
    parse_classfile, peel_for_family, recover_strings,
};

const SEED_ROTATE: &[u8] = include_bytes!("../../../corpus/jvm/seedrotate/SeedRotateCrypt.class");

const ORACLE: &[&str] = &[
    "jdbc:mysql://10.0.0.5:3306/billing",
    "X-Internal-Auth: 9f8e7d6c",
    "SELECT secret FROM vault WHERE tenant = ?",
    "AES/GCM/NoPadding",
    "feature.kill-switch=enabled",
];

#[test]
fn recovers_per_call_site_seed_rotated_plaintext_from_real_javac_bytecode() {
    let cf: ClassFile = parse_classfile(SEED_ROTATE).expect("real SeedRotateCrypt.class parses");
    let report: StringRecoveryReport = recover_strings(&cf);

    assert_eq!(
        report.decrypt_methods, 1,
        "the private static decode(String, int) is the lone decrypt method"
    );
    assert_eq!(
        report.attempted,
        ORACLE.len(),
        "the seed-aware scanner finds one candidate per call site even with the inline seed push \
         between the ldc and the invokestatic"
    );
    assert!(
        !report.runtime_key_wall,
        "the rotating key set and per-string seed are fully static; no runtime wall here"
    );

    let recovered: Vec<String> = report.recovered.values().cloned().collect();
    for want in ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the seeded-mode evaluator must recover {want:?} from real javac bytecode using the \
             inline call-site seed; got {recovered:?}"
        );
    }
    assert_eq!(
        report.recovered.len(),
        ORACLE.len(),
        "every encrypted constant resolves and nothing extra is fabricated"
    );
}

#[test]
fn wired_protector_peel_recovers_seeded_strings_and_leaves_detect_only_behind() {
    let cf: ClassFile = parse_classfile(SEED_ROTATE).expect("real SeedRotateCrypt.class parses");
    let report: ProtectorPeelReport = peel_for_family(&cf, ProtectorFamilyKind::ZelixKlassMaster);

    assert_eq!(
        report.status,
        PeelStatus::StubRecovered,
        "the seeded mode is now recovered, not detect-only"
    );
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the wired protector peel must surface {want:?} via the seed-aware evaluator; got \
             {recovered:?}"
        );
    }
}
