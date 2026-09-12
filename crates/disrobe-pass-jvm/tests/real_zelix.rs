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

use disrobe_pass_jvm::protectors::unflatten::{self, CffReport};
use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, PeelStatus, ProtectorFamilyKind, ProtectorPeelReport,
    parse_classfile, zelix_protector,
};

fn corpus_jar(rel: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("jvm");
    for seg in rel {
        p.push(seg);
    }
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

#[test]
fn real_baseline_jar_classfile_parses_for_protector_input() {
    let jar: PathBuf = corpus_jar(&["megafile", "EdgeCases-baseline.jar"]);
    let bytes: Vec<u8> = read_first_classfile_from_jar(&jar)
        .expect("EdgeCases-baseline.jar fixture must be committed and contain a .class");
    let cf: ClassFile = parse_classfile(&bytes).expect("parse classfile");
    assert_eq!(cf.major_version, 69);
    assert!(!cf.constant_pool.is_empty());
    let utf8_symbols: Vec<&str> = cf
        .constant_pool
        .iter()
        .filter_map(|e: &ConstantPoolEntry| match e {
            ConstantPoolEntry::Utf8(s) => Some(s.as_str()),
            _ => None,
        })
        .collect();
    for expected in ["<init>", "java/util/function/Supplier", "java/lang/Object"] {
        assert!(
            utf8_symbols.contains(&expected),
            "expected javac-emitted constant-pool symbol {expected:?}, got {utf8_symbols:?}"
        );
    }
}

#[test]
fn unobfuscated_class_peels_detect_only_without_fabricating() {
    let jar: PathBuf = corpus_jar(&["megafile", "EdgeCases-baseline.jar"]);
    let bytes: Vec<u8> = read_first_classfile_from_jar(&jar).expect("baseline jar class");
    let cf: ClassFile = parse_classfile(&bytes).expect("parse");
    let report: ProtectorPeelReport = zelix_protector::peel(&cf);
    assert_eq!(report.family, ProtectorFamilyKind::ZelixKlassMaster);
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "a clean javac class carries no decrypt stub; peel must not fabricate plaintext"
    );
    assert!(report.strings_recovered.is_empty());
}

#[test]
fn real_r8_jar_classes_are_not_flagged_flattened_and_structure_cleanly() {
    let jar: PathBuf = corpus_jar(&["r8", "EdgeCases-r8.jar"]);
    let Ok(f): Result<fs::File, _> = fs::File::open(&jar) else {
        eprintln!("skip: r8 fixture absent at {}", jar.display());
        return;
    };
    let mut z: zip::ZipArchive<fs::File> = zip::ZipArchive::new(f).expect("zip");
    let mut classes_checked: usize = 0;
    let mut residual_switch_regions: u32 = 0;
    let mut methods_scanned: u32 = 0;
    for i in 0..z.len() {
        let mut entry: zip::read::ZipFile<'_> = z.by_index(i).expect("entry");
        if !entry.name().ends_with(".class") {
            continue;
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes).expect("read");
        let Ok(cf): Result<ClassFile, _> = parse_classfile(&bytes) else {
            continue;
        };
        let cff: CffReport = unflatten::unflatten_class(&cf);
        residual_switch_regions += cff.residual_switch_regions;
        methods_scanned += cff.methods_scanned;
        classes_checked += 1;
    }
    assert!(
        classes_checked >= 1 && methods_scanned >= 1,
        "the r8 jar must contain parseable classes with method bodies"
    );
    assert_eq!(
        residual_switch_regions, 0,
        "every method the un-flattener touched in the real r8 jar must re-structure to fully \
         reducible control flow with no leftover dispatcher switch"
    );
}
