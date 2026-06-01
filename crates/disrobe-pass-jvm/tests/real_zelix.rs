#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
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

use disrobe_pass_jvm::zelix_protector::{self, ZelixKey};
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

fn read_first_classfile_from_jar(jar_path: &PathBuf) -> Option<Vec<u8>> {
    let f: fs::File = fs::File::open(jar_path).ok()?;
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip read");
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if entry.name().ends_with(".class") {
            let mut out: Vec<u8> = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut out).expect("read class");
            return Some(out);
        }
    }
    panic!("no class file in jar");
}

fn cipher_is_lossless_utf16(cipher: &[u16]) -> bool {
    let s: String = match String::from_utf16(cipher) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let re_encoded: Vec<u16> = s.encode_utf16().collect();
    re_encoded == cipher
}

fn synth_zelix_protected_class(seed: ZelixKey, candidates: &[&str]) -> (ClassFile, Vec<String>) {
    let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
    let mut accepted: Vec<String> = Vec::new();
    for s in candidates {
        let cipher: Vec<u16> = zelix_protector::zelix_encrypt_chars(s, seed);
        if !cipher_is_lossless_utf16(&cipher) {
            continue;
        }
        cp.push(ConstantPoolEntry::Utf8(
            String::from_utf16(&cipher).expect("lossless"),
        ));
        accepted.push((*s).to_string());
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
    (cf, accepted)
}

#[test]
fn real_baseline_jar_classfile_parses_for_protector_input() {
    let jar: PathBuf = baseline_jar_path();
    let Some(bytes): Option<Vec<u8>> = read_first_classfile_from_jar(&jar) else {
        eprintln!(
            "skip: EdgeCases-baseline.jar fixture absent at {}",
            jar.display()
        );
        return;
    };
    let cf: ClassFile = parse_classfile(&bytes).expect("parse classfile");
    assert_eq!(cf.major_version, 69);
    assert!(!cf.constant_pool.is_empty());
}

/// Self-consistency (involution) of the synthetic stand-in cipher only.
///
/// This encrypts plaintext with our OWN reference transform and decrypts it with
/// the inverse of that same transform. It is NOT recovery of a real
/// Zelix-protected sample: without the protector's embedded decrypt stub the real
/// algorithm is opaque, so `peel` honestly reports detect-only (asserted below).
#[test]
fn synthetic_zelix_cipher_is_self_consistent_and_peel_is_detect_only() {
    let key: ZelixKey = ZelixKey::new(0x1234_5678, 0xABCD, 7);
    let candidates: &[&str] = &[
        "INSERT INTO users VALUES (?, ?, ?)",
        "https://api.internal/v1/auth",
        "Authorization: Bearer ${TOKEN}",
        "config.database.password",
        "user.id",
        "session.token",
        "api.endpoint",
        "DB_HOST",
        "ROLE_ADMIN",
        "/v1/login",
    ];
    let (cf, accepted): (ClassFile, Vec<String>) = synth_zelix_protected_class(key, candidates);
    assert!(!accepted.is_empty(), "no lossless cipher accepted");
    for plain in &accepted {
        let cipher: Vec<u16> = zelix_protector::zelix_encrypt_chars(plain, key);
        let back: String = zelix_protector::zelix_decrypt_chars(&cipher, key);
        assert_eq!(&back, plain, "synthetic cipher not an involution");
    }
    let report: ProtectorPeelReport = zelix_protector::peel(&cf, key);
    assert_eq!(report.family, ProtectorFamilyKind::ZelixKlassMaster);
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "no embedded stub present, peel must not claim recovery"
    );
    assert!(
        report.strings_recovered.is_empty(),
        "detect-only peel must not fabricate plaintext"
    );
}
