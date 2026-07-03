#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{
    CallerKeyedReport, ClassFile, ConstantPoolEntry, Detection, Protector, StringStrip, detect_all,
    parse_classfile, recover_caller_keyed_strings, strip_encrypted_strings,
};

const STATIC_TABLE: &[u8] = include_bytes!("../../../corpus/jvm/zkmshape/StaticTableCrypt.class");

const STATIC_TABLE_ORACLE: &[&str] = &[
    "jdbc:mysql://10.0.0.5:3306/billing",
    "X-Internal-Auth: 9f8e7d6c",
];

fn synth_class_with_strings(strings: &[&str]) -> ClassFile {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    for s in strings {
        cp.push(ConstantPoolEntry::Utf8((*s).to_string()));
    }
    ClassFile {
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
    }
}

#[test]
fn detects_published_zkm_marker_in_constant_pool() {
    let cf: ClassFile = synth_class_with_strings(&["produced by ZKM 14.0 KlassMaster"]);
    let detections: Vec<Detection> = detect_all(&cf);
    assert!(
        detections
            .iter()
            .any(|d: &Detection| d.protector == Protector::ZelixKlassMaster),
        "this grades the documented ZKM watermark vector as a constant-pool signature match, not a \
         packed sample: a Utf8 carrying the published marker must raise the Zelix detection"
    );
}

#[test]
fn ordinary_constant_pool_strings_do_not_trip_zkm_detection() {
    let cf: ClassFile =
        synth_class_with_strings(&["config.json", "user.home", "GET /health HTTP/1.1"]);
    let detections: Vec<Detection> = detect_all(&cf);
    assert!(
        !detections
            .iter()
            .any(|d: &Detection| d.protector == Protector::ZelixKlassMaster),
        "a clean class with no ZKM marker and no encrypted pool must not be flagged Zelix; the \
         signature check must not fire on ordinary application strings"
    );
}

#[test]
fn strip_on_unobfuscated_class_recovers_nothing_encrypted_and_fabricates_no_plaintext() {
    let plain: &[&str] = &["plain text", "another"];
    let cf: ClassFile = synth_class_with_strings(plain);
    let ss: StringStrip = strip_encrypted_strings(&cf, Protector::ZelixKlassMaster);
    assert_eq!(
        ss.residual_encrypted, 0,
        "an unobfuscated class holds no high-entropy encrypted constants, so the strip flags none \
         as residual ciphertext"
    );
    assert!(
        ss.recovered
            .values()
            .all(|v: &String| plain.contains(&v.as_str())),
        "strip on a clean class is constant-pool mechanics only: it returns the existing plaintext \
         pool entries verbatim and invents no decrypted output; got {:?}",
        ss.recovered
    );
    assert_eq!(
        ss.recovered.len(),
        plain.len(),
        "every plaintext pool entry passes through as a non-encrypted string, none dropped or added"
    );
}

#[test]
fn real_static_table_class_decrypts_to_documented_plaintext_oracle() {
    let cf: ClassFile =
        parse_classfile(STATIC_TABLE).expect("real javac StaticTableCrypt.class parses");
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    let recovered: Vec<String> = report.recovered.values().cloned().collect();
    for want in STATIC_TABLE_ORACLE {
        assert!(
            recovered.iter().any(|s: &String| s == want),
            "the constrained evaluator runs the class's own static-table decrypt (clinit builds the \
             char[] key, getstatic reads it) and must recover the documented plaintext {want:?}; \
             got {recovered:?}"
        );
    }
    assert!(
        !report.runtime_key_wall,
        "the key table is fully static, so this is a real recovery, not a runtime-key wall"
    );
}
