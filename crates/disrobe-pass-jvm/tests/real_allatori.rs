#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
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
    ClassFile, ConstantPoolEntry, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport,
    parse_classfile,
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

fn collect_real_string_constants_from_jar(jar: &PathBuf, max: usize) -> Option<Vec<String>> {
    let f: fs::File = fs::File::open(jar).ok()?;
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
                    return Some(out);
                }
            }
        }
    }
    Some(out)
}

/// Self-consistency (involution) of the synthetic stand-in transform only.
///
/// The string constants are sourced from the UNPROTECTED baseline jar purely to
/// exercise the transform over realistic input shapes; they are encrypted with
/// our OWN reference transform and decrypted with its inverse. This is NOT
/// recovery of Allatori-protected samples and asserts nothing about the
/// proprietary Allatori algorithm.
#[test]
fn synthetic_transform_is_involution_over_baseline_jar_string_shapes() {
    let jar: PathBuf = baseline_jar_path();
    let Some(strings): Option<Vec<String>> = collect_real_string_constants_from_jar(&jar, 20)
    else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            jar.display()
        );
        return;
    };
    assert!(
        strings.len() >= 5,
        "expected to collect at least 5 baseline strings, got {}",
        strings.len()
    );

    let key: AllatoriKey = allatori_protector::derive_key("com/example/EdgeCases", "decrypt");
    for plain in &strings {
        let cipher_units: Vec<u16> = allatori_protector::allatori_encrypt(plain, key);
        let plain_units: Vec<u16> = allatori_protector::allatori_xor_codeunits(&cipher_units, key);
        let recovered: String = String::from_utf16(&plain_units).expect("valid utf16 roundtrip");
        assert_eq!(&recovered, plain, "synthetic transform not an involution");
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

/// Without an embedded decrypt stub, peel must honestly report detect-only and
/// must NOT fabricate plaintext via the synthetic stand-in cipher.
#[test]
fn allatori_peel_without_stub_is_detect_only() {
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
    assert_eq!(report.status, PeelStatus::DetectOnly);
    assert!(
        report.strings_recovered.is_empty(),
        "detect-only peel must not fabricate plaintext"
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
