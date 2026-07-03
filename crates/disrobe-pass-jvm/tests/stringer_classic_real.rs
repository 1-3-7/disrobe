#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::{
    CallerKeyedReport, ClassFile, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport,
    parse_classfile, recover_caller_keyed_strings, stringer_protector,
};

const STRINGER_CLASSIC: &[u8] =
    include_bytes!("../../../corpus/jvm/stringer/StringerClassic.class");

const ORACLE: &[&str] = &[
    "jdbc:sqlserver://10.9.8.7:1433;db=orders",
    "Authorization: Bearer 7c1e0a4d",
    "https://vault.internal/v1/secret/app",
    "ROLE_TENANT_ADMIN",
    "/var/run/secrets/app.key",
];

#[test]
fn recovers_stringer_classic_per_class_keyed_strings_from_real_javac_bytecode() {
    let cf: ClassFile =
        parse_classfile(STRINGER_CLASSIC).expect("real StringerClassic.class parses");
    let report: ProtectorPeelReport =
        stringer_protector::peel(&cf, "com/disrobe/bench/StringerClassic", "decrypt");

    assert_eq!(report.family, ProtectorFamilyKind::Stringer);
    assert_eq!(
        report.status,
        PeelStatus::StubRecovered,
        "the classic non-flow mode keys on the class name folded in <clinit>, fully static, so the \
         evaluator recovers the constants rather than walling"
    );
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the Stringer peel must recover {want:?} by running the class's own per-class-keyed \
             decrypt under the bytecode evaluator; got {recovered:?}"
        );
    }
    assert_eq!(
        report.strings_recovered.len(),
        ORACLE.len(),
        "every encrypted constant resolves and nothing extra is fabricated"
    );
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("bytecode evaluation") || n.contains("decrypt-method")),
        "the recovery note must credit running the real decrypt method, not an invented cipher"
    );
}

#[test]
fn stringer_classic_recovers_via_caller_keyed_evaluator_directly() {
    let cf: ClassFile =
        parse_classfile(STRINGER_CLASSIC).expect("real StringerClassic.class parses");
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    assert!(
        !report.runtime_key_wall,
        "the class-name-derived key is folded in <clinit> and fully present in the artifact; no \
         runtime wall here"
    );
    let recovered: Vec<String> = report.recovered.values().cloned().collect();
    for want in ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the evaluator runs <clinit> to populate the static key then executes the class's own \
             decrypt and must recover {want:?}; got {recovered:?}"
        );
    }
}
