#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]

use disrobe_pass_jvm::dasho_protector::{self, DashOKey};
use disrobe_pass_jvm::{ClassFile, ConstantPoolEntry, ProtectorFamilyKind, ProtectorPeelReport};

#[test]
fn dasho_round_trip_recovers_real_url_and_secret_strings() {
    let key: DashOKey = dasho_protector::derive_key("com/example/Cloud");
    let plaintexts: &[&str] = &[
        "https://api.cloud.example/v2/upload",
        "aws_access_key_id",
        "ROLE_ADMIN",
        "license-server.example.net",
    ];
    for p in plaintexts {
        let cipher_units: Vec<u16> = dasho_protector::dasho_encrypt(p, key);
        let back_units: Vec<u16> = dasho_protector::dasho_xor_codeunits(&cipher_units, key);
        let recovered: String = String::from_utf16(&back_units).expect("utf16 roundtrip");
        assert_eq!(&recovered, p);
    }
}

fn cipher_is_lossless_utf16(cipher: &[u16]) -> bool {
    let s: String = match String::from_utf16(cipher) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let re_encoded: Vec<u16> = s.encode_utf16().collect();
    re_encoded == cipher
}

#[test]
fn dasho_peel_recovers_protected_strings_in_synthetic_class() {
    let class_name: &str = "com/preemptive/Demo";
    let key: DashOKey = dasho_protector::derive_key(class_name);
    let candidates: &[&str] = &[
        "secret-token",
        "https://example.com/api",
        "api.key",
        "/health",
        "ROLE_USER",
        "Bearer xyz",
        "redis-host",
        "log-level",
        "x-tenant",
        "v1.endpoint",
    ];
    let mut plaintexts: Vec<&str> = Vec::new();
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    for p in candidates {
        let cipher: Vec<u16> = dasho_protector::dasho_encrypt(p, key);
        if !cipher_is_lossless_utf16(&cipher) {
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
    let report: ProtectorPeelReport = dasho_protector::peel(&cf, class_name);
    assert_eq!(report.family, ProtectorFamilyKind::DashO);
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    let matched: usize = plaintexts
        .iter()
        .filter(|p: &&&str| recovered.iter().any(|s: &String| s == *p))
        .count();
    assert!(
        matched >= 1,
        "expected >=1 plaintext recovered, got {matched} of {len}",
        len = plaintexts.len()
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
