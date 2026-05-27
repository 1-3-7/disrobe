#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::ptr_arg
)]

use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use disrobe_pass_jvm::allatori_protector::{self, AllatoriKey};
use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, ProtectorFamilyKind, ProtectorPeelReport, parse_classfile,
};

fn baseline_jar_path() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    p.push("megafile");
    p.push("EdgeCases-baseline.jar");
    p
}

fn collect_real_string_constants_from_jar(jar: &PathBuf, max: usize) -> Vec<String> {
    let f: fs::File = fs::File::open(jar).expect("open jar");
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip");
    let mut out: Vec<String> = Vec::new();
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if !entry.name().ends_with(".class") {
            continue;
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes).expect("read class");
        let cf: ClassFile = match parse_classfile(&bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for entry_cp in &cf.constant_pool {
            if let ConstantPoolEntry::Utf8(s) = entry_cp
                && !s.is_empty()
                && s.chars().all(|c: char| c.is_ascii_graphic() || c == ' ')
                && s.len() >= 4
                && s.len() <= 80
                && !s.contains('/')
                && !s.contains('(')
                && !s.contains(';')
            {
                out.push(s.clone());
                if out.len() >= max {
                    return out;
                }
            }
        }
    }
    out
}

#[test]
fn real_jar_strings_encrypt_and_decrypt_correctly() {
    let strings: Vec<String> = collect_real_string_constants_from_jar(&baseline_jar_path(), 20);
    assert!(
        strings.len() >= 5,
        "expected to collect at least 5 real strings, got {}",
        strings.len()
    );

    let key: AllatoriKey = allatori_protector::derive_key("com/example/EdgeCases", "decrypt");
    for plain in &strings {
        let cipher_units: Vec<u16> = allatori_protector::allatori_encrypt(plain, key);
        let plain_units: Vec<u16> = allatori_protector::allatori_xor_codeunits(&cipher_units, key);
        let recovered: String = String::from_utf16(&plain_units).expect("valid utf16 roundtrip");
        assert_eq!(&recovered, plain, "roundtrip mismatch");
    }
}

fn cipher_is_lossless_utf16(plain: &str, cipher: &[u16]) -> bool {
    let s: String = match String::from_utf16(cipher) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let re_encoded: Vec<u16> = s.encode_utf16().collect();
    re_encoded == cipher && !plain.is_empty()
}

#[test]
fn allatori_peel_recovers_protected_strings_in_synthetic_class() {
    let key: AllatoriKey = allatori_protector::derive_key("com/example/Service", "init");
    let candidates: &[&str] = &[
        "user-agent",
        "Content-Type: application/json",
        "PRIMARY_DATABASE_URL",
        "auth.token",
        "REQUEST_ID",
        "x-correlation-id",
        "session.cookie.secure",
        "feature.flags.enabled",
        "DEBUG=true",
        "/api/v1/users",
        "INSERT INTO logs",
        "SELECT * FROM events",
    ];
    let mut plaintexts: Vec<&str> = Vec::new();
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    for p in candidates {
        let cipher: Vec<u16> = allatori_protector::allatori_encrypt(p, key);
        if !cipher_is_lossless_utf16(p, &cipher) {
            continue;
        }
        plaintexts.push(*p);
        cp.push(ConstantPoolEntry::Utf8(
            String::from_utf16(&cipher).expect("lossless"),
        ));
    }
    assert!(
        !plaintexts.is_empty(),
        "no candidate produced lossless utf16 cipher"
    );
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
    let report: ProtectorPeelReport = allatori_protector::peel(&cf, "com/example/Service", "init");
    assert_eq!(report.family, ProtectorFamilyKind::Allatori);
    let recovered_values: Vec<String> = report.strings_recovered.values().cloned().collect();
    let matched_count: usize = plaintexts
        .iter()
        .filter(|p: &&&str| recovered_values.iter().any(|s: &String| s == *p))
        .count();
    assert!(
        matched_count >= 1,
        "expected >=1 plaintext recovered, got {matched_count} out of {plain_count}",
        plain_count = plaintexts.len()
    );
}

#[test]
fn allatori_watermark_field_stripped() {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    cp.push(ConstantPoolEntry::Utf8("AllatoriWM_42".into()));
    let cf: ClassFile = ClassFile {
        minor_version: 0,
        major_version: 52,
        constant_pool: cp,
        access_flags: 0,
        this_class: 0,
        super_class: 0,
        interfaces: Vec::new(),
        fields: vec![disrobe_pass_jvm::FieldInfo {
            access_flags: 0,
            name_index: 1,
            descriptor_index: 1,
            attributes: Vec::new(),
        }],
        methods: Vec::new(),
        attributes: Vec::new(),
    };
    let report: ProtectorPeelReport = allatori_protector::peel(&cf, "Cls", "init");
    assert!(
        report
            .watermarks_stripped
            .iter()
            .any(|s: &String| s.contains("AllatoriWM_42"))
    );
}
