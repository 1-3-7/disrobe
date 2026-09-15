#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_jvm::{
    ClassFile, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport, detect_protector_family,
    parse_classfile, stringer_protector, zelix_protector,
};

const REFLECT_THREAD: &[u8] =
    include_bytes!("../../../corpus/jvm/stock_control/ReflectThreadDemo.class");
const PLAIN_DATA: &[u8] = include_bytes!("../../../corpus/jvm/stock_control/PlainData.class");
const COLLECTIONS: &[u8] =
    include_bytes!("../../../corpus/jvm/stock_control/CollectionsDemo.class");
const REFLECT_INVOKER: &[u8] =
    include_bytes!("../../../corpus/jvm/stock_control/ReflectInvoker.class");

const STOCK_CONTROLS: &[(&str, &[u8])] = &[
    ("ReflectThreadDemo", REFLECT_THREAD),
    ("PlainData", PLAIN_DATA),
    ("CollectionsDemo", COLLECTIONS),
    ("ReflectInvoker", REFLECT_INVOKER),
];

const STATIC_TABLE: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");
const DIGI: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Digi.class");

#[test]
fn stock_unobfuscated_classes_are_never_flagged_as_protected() {
    for (label, bytes) in STOCK_CONTROLS {
        let cf: ClassFile =
            parse_classfile(bytes).unwrap_or_else(|e| panic!("{label} must parse: {e:?}"));
        assert!(
            !stringer_protector::has_runtime_key_signature(&cf),
            "{label} is stock unobfuscated javac output and must not trip the Stringer \
             runtime-key signature; reflection/Thread/Class.forName use is legitimate"
        );
        let family: Option<ProtectorFamilyKind> = detect_protector_family(&cf);
        assert!(
            family.is_none(),
            "{label} is stock unobfuscated javac output and must not be detected as any \
             protector family, got {family:?}"
        );
    }
}

#[test]
fn real_stringer_digi_still_detects_after_tightening() {
    let cf: ClassFile = parse_classfile(DIGI).expect("Digi.class parses");
    assert!(
        stringer_protector::has_runtime_key_signature(&cf),
        "real Stringer Digi.class carries the decrypt-stub descriptor plus encrypted constants \
         and must still trip the runtime-key signature"
    );
    assert_eq!(
        detect_protector_family(&cf),
        Some(ProtectorFamilyKind::Stringer),
        "real Stringer Digi.class must still be classified as Stringer"
    );
    let report: ProtectorPeelReport =
        stringer_protector::peel(&cf, "pack/tests/basics/accu/Digi", "J");
    assert_eq!(report.status, PeelStatus::DetectOnly);
}

#[test]
fn real_zelix_static_table_still_detects_after_tightening() {
    let cf: ClassFile = parse_classfile(STATIC_TABLE).expect("StaticTableCrypt.class parses");
    let report: ProtectorPeelReport = zelix_protector::peel(&cf);
    assert_eq!(
        report.status,
        PeelStatus::StubRecovered,
        "the real Zelix StaticTableCrypt self-contained decrypt must still recover plaintext"
    );
    assert!(
        report
            .strings_recovered
            .values()
            .any(|s: &String| s == "jdbc:mysql://10.0.0.5:3306/billing"),
        "the no-false-negative side must still surface evaluator-recovered plaintext"
    );
}
