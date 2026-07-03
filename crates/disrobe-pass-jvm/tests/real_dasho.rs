#![allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport,
    dasho_protector, parse_classfile,
};

const DASHO_STRINGS: &[u8] = include_bytes!("../../../corpus/jvm/dasho/DashOStrings.class");
const DASHO_REFLECT: &[u8] = include_bytes!("../../../corpus/jvm/dasho/DashOReflect.class");

const STRINGS_ORACLE: &[&str] = &[
    "jdbc:oracle:thin:@prod-db:1521/ORCL",
    "X-Service-Token: 4b1d9e",
    "https://billing.internal/api/charge",
    "ROLE_SUPERUSER",
    "/etc/app/secrets.properties",
];

const REFLECT_ORACLE: &[&str] = &["java.lang.System", "getProperty", "java.version"];

#[test]
fn recovers_dasho_per_class_keyed_strings_from_real_javac_bytecode() {
    let cf: ClassFile = parse_classfile(DASHO_STRINGS).expect("real DashOStrings.class parses");
    let report: ProtectorPeelReport = dasho_protector::peel(&cf, "com/disrobe/bench/DashOStrings");

    assert_eq!(report.family, ProtectorFamilyKind::DashO);
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in STRINGS_ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the DashO peel must recover {want:?} by running the class's own per-class-keyed \
             decrypt under the bytecode evaluator; got {recovered:?}"
        );
    }
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("bytecode evaluation") || n.contains("decrypt-method")),
        "the recovery note must credit running the real decrypt method, not an invented cipher"
    );
}

#[test]
fn recovers_dasho_reflection_member_names_from_real_javac_bytecode() {
    let cf: ClassFile = parse_classfile(DASHO_REFLECT).expect("real DashOReflect.class parses");
    let report: ProtectorPeelReport = dasho_protector::peel(&cf, "com/disrobe/bench/DashOReflect");

    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in REFLECT_ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the reflective target {want:?} must be resolved by decrypting the constant through \
             the class's own decrypt method; got {recovered:?}"
        );
    }
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("reflection hiding")),
        "the report must call out that decrypted constants name reflective members"
    );
}

#[test]
fn dasho_peel_without_reachable_decrypt_is_detect_only() {
    let class_name: &str = "com/preemptive/Demo";
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    let opaque: &[&str] = &[
        "\u{0002}\u{0091}\u{0014}\u{00b2}\u{0007}\u{00fe}\u{0033}",
        "\u{0080}\u{0012}\u{00cd}\u{0005}\u{009f}\u{0061}\u{00d3}\u{0044}",
        "\u{0019}\u{00ee}\u{0002}\u{00b7}\u{0044}\u{0098}\u{0021}\u{00ff}",
    ];
    for s in opaque {
        let u: u16 = u16::try_from(cp.len()).expect("cp index");
        cp.push(ConstantPoolEntry::Utf8((*s).to_owned()));
        cp.push(ConstantPoolEntry::String { utf8_index: u });
    }
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let report: ProtectorPeelReport = dasho_protector::peel(&cf, class_name);
    assert_eq!(report.family, ProtectorFamilyKind::DashO);
    assert_eq!(report.status, PeelStatus::DetectOnly);
    assert!(
        report.strings_recovered.is_empty(),
        "detect-only peel must not fabricate plaintext"
    );
}

#[test]
fn dasho_marker_string_logged_in_notes() {
    let class_name: &str = "com/Cls";
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8(
        "Protected by DashO from PreEmptive Protection".into(),
    ));
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let report: ProtectorPeelReport = dasho_protector::peel(&cf, class_name);
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.to_lowercase().contains("dasho-marker"))
    );
}
