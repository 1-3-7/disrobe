#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Read;
use std::path::PathBuf;

use disrobe_pass_jvm::classfile::{ClassFile, ConstantPoolEntry};
use disrobe_pass_jvm::obfuscators::UpstreamStatus;
use disrobe_pass_jvm::{Detection, Protector, detect_all, parse_classfile, upstream_status};

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

fn first_baseline_class() -> ClassFile {
    let bytes: Vec<u8> =
        std::fs::read(corpus(&["jvm", "megafile", "EdgeCases-baseline.jar"])).expect("read jar");
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(cursor).expect("open jar");
    for i in 0..zip.len() {
        let mut f: zip::read::ZipFile<'_> = zip.by_index(i).expect("entry");
        if f.name() == "EdgeCases$Circle.class" {
            let mut buf: Vec<u8> = Vec::new();
            f.read_to_end(&mut buf).expect("read");
            return parse_classfile(&buf).expect("parse class");
        }
    }
    panic!("EdgeCases$Circle.class not found in baseline jar");
}

fn with_marker(marker: &str) -> ClassFile {
    let mut cf: ClassFile = first_baseline_class();
    cf.constant_pool
        .push(ConstantPoolEntry::Utf8(marker.to_string()));
    cf
}

#[test]
fn clean_baseline_class_does_not_flag_dead_protectors() {
    let cf: ClassFile = first_baseline_class();
    let detections: Vec<Detection> = detect_all(&cf);
    for d in &detections {
        assert!(
            !matches!(
                d.protector,
                Protector::YGuard | Protector::SkidSuite2 | Protector::Jbco
            ),
            "clean baseline class falsely flagged dead protector {:?}",
            d.protector
        );
    }
}

#[test]
fn yguard_marker_detected() {
    let cf: ClassFile = with_marker("yGuard 4.0 obfuscation map");
    let detections: Vec<Detection> = detect_all(&cf);
    assert!(
        detections
            .iter()
            .any(|d: &Detection| d.protector == Protector::YGuard),
        "yGuard marker must be detected, got {detections:?}"
    );
}

#[test]
fn skidsuite2_marker_detected() {
    let cf: ClassFile = with_marker("me/lpk/skidsuite2/transform/StringEncrypt");
    let detections: Vec<Detection> = detect_all(&cf);
    assert!(
        detections
            .iter()
            .any(|d: &Detection| d.protector == Protector::SkidSuite2),
        "SkidSuite2 marker must be detected, got {detections:?}"
    );
}

#[test]
fn jbco_marker_detected() {
    let cf: ClassFile = with_marker("soot.jbco.IJbcoTransform");
    let detections: Vec<Detection> = detect_all(&cf);
    assert!(
        detections
            .iter()
            .any(|d: &Detection| d.protector == Protector::Jbco),
        "JBCO marker must be detected, got {detections:?}"
    );
}

#[test]
fn dead_protectors_marked_dead_active_marked_active() {
    assert_eq!(upstream_status(Protector::YGuard), UpstreamStatus::Dead);
    assert_eq!(upstream_status(Protector::SkidSuite2), UpstreamStatus::Dead);
    assert_eq!(upstream_status(Protector::Jbco), UpstreamStatus::Dead);
    assert_eq!(upstream_status(Protector::DexGuard), UpstreamStatus::Active);
    assert_eq!(
        upstream_status(Protector::ProguardR8),
        UpstreamStatus::Active
    );
    assert_eq!(upstream_status(Protector::DashO), UpstreamStatus::Archived);
}
