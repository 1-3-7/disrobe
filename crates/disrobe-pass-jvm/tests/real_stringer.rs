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

use disrobe_pass_jvm::stringer_protector::{self, StringerKey, class_key};
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

fn read_real_strings(max: usize) -> Option<Vec<String>> {
    let f: fs::File = fs::File::open(baseline_jar_path()).ok()?;
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip");
    let mut out: Vec<String> = Vec::new();
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if !entry.name().ends_with(".class") {
            continue;
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes).expect("read");
        let cf: ClassFile = match parse_classfile(&bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for cp_entry in &cf.constant_pool {
            if let ConstantPoolEntry::Utf8(s) = cp_entry
                && (4..=100).contains(&s.len())
                && s.chars().all(|c: char| c.is_ascii_graphic() || c == ' ')
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

/// Self-consistency (involution) of the synthetic stand-in transform only; not real Stringer recovery.
#[test]
fn synthetic_transform_is_involution_over_baseline_jar_string_shapes() {
    let Some(strings): Option<Vec<String>> = read_real_strings(15) else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            baseline_jar_path().display()
        );
        return;
    };
    assert!(strings.len() >= 5);

    let key: StringerKey = StringerKey::new(class_key("com/example/EdgeCases"), class_key("init"));
    for plain in &strings {
        let cipher_units: Vec<u16> = stringer_protector::stringer_encrypt(plain, key);
        let back_units: Vec<u16> = stringer_protector::stringer_xor_codeunits(&cipher_units, key);
        let recovered: String = String::from_utf16(&back_units).expect("utf16 roundtrip");
        assert_eq!(&recovered, plain);
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

/// Without an embedded decrypt stub, peel must honestly report detect-only.
#[test]
fn stringer_peel_without_stub_is_detect_only() {
    let key: StringerKey = StringerKey::new(class_key("com/Foo"), class_key("decrypt"));
    let candidates: &[&str] = &[
        "env.SECRET_KEY",
        "redis://localhost:6379",
        "loglevel=DEBUG",
        "api.key",
        "service.id",
        "DB_HOST",
        "/health/check",
        "X-Request-Id",
        "auth.bearer",
        "feature.flag",
    ];
    let mut plaintexts: Vec<&str> = Vec::new();
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    for p in candidates {
        let cipher: Vec<u16> = stringer_protector::stringer_encrypt(p, key);
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
    let report: ProtectorPeelReport = stringer_protector::peel(&cf, "com/Foo", "decrypt");
    assert_eq!(report.family, ProtectorFamilyKind::Stringer);
    assert_eq!(report.status, PeelStatus::DetectOnly);
    assert!(
        report.strings_recovered.is_empty(),
        "detect-only peel must not fabricate plaintext"
    );
}
