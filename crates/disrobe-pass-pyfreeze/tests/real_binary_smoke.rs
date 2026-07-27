#![allow(clippy::expect_used, clippy::unwrap_used, clippy::unreadable_literal)]
use std::path::PathBuf;

use disrobe_pass_pyfreeze::{Detection, FreezerKind, detect_bytes};

#[test]
fn detect_synthetic_shiv_via_shebang_and_bootstrap_marker() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"#!/usr/bin/env python3\n");
    let zip_start: usize = buf.len();
    buf.extend_from_slice(b"_bootstrap/environment.json");
    buf.extend_from_slice(b"\x00".repeat(64).as_slice());
    let body_len: usize = buf.len() - zip_start;
    let mut eocd: Vec<u8> = vec![0u8; 22];
    eocd[0..4].copy_from_slice(&0x06054b50u32.to_le_bytes());
    eocd[12..16].copy_from_slice(&u32::try_from(body_len).expect("fits").to_le_bytes());
    eocd[16..20].copy_from_slice(&u32::try_from(zip_start).expect("fits").to_le_bytes());
    buf.extend_from_slice(&eocd);
    let det: Detection = detect_bytes(&buf, Some(&PathBuf::from("synthetic-shiv.pyz")));
    assert_eq!(det.kind, FreezerKind::Shiv, "got: {det:?}");
    assert!(det.confidence > 0.5);
}

#[test]
fn detect_synthetic_pex_via_shebang_and_pex_info_marker() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"#!/usr/bin/env python3.11\n");
    let zip_start: usize = buf.len();
    buf.extend_from_slice(b"PEX-INFO\x00\x00\x00\x00");
    buf.extend_from_slice(b"{\"entry_point\":\"app:main\"}");
    buf.extend_from_slice(b"\x00".repeat(64).as_slice());
    let body_len: usize = buf.len() - zip_start;
    let mut eocd: Vec<u8> = vec![0u8; 22];
    eocd[0..4].copy_from_slice(&0x06054b50u32.to_le_bytes());
    eocd[12..16].copy_from_slice(&u32::try_from(body_len).expect("fits").to_le_bytes());
    eocd[16..20].copy_from_slice(&u32::try_from(zip_start).expect("fits").to_le_bytes());
    buf.extend_from_slice(&eocd);
    let det: Detection = detect_bytes(&buf, Some(&PathBuf::from("synthetic-pex.pex")));
    assert_eq!(det.kind, FreezerKind::Pex, "got: {det:?}");
    assert!(det.confidence > 0.5);
}

#[test]
fn detect_synthetic_py2exe_via_pe_and_pythonscript_marker() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"MZ");
    buf.extend_from_slice(&[0u8; 0x3C - 2]);
    buf.extend_from_slice(&0x40u32.to_le_bytes());
    buf.extend_from_slice(b"PE\0\0");
    buf.extend_from_slice(&[0u8; 256]);
    buf.extend_from_slice(b"PYTHONSCRIPT\0");
    buf.extend_from_slice(&[0u8; 128]);
    let det: Detection = detect_bytes(&buf, Some(&PathBuf::from("synthetic.exe")));
    assert_eq!(det.kind, FreezerKind::Py2exe, "got: {det:?}");
    assert!(det.confidence > 0.5);
}

#[test]
fn detect_unknown_when_no_signature_present() {
    let buf: Vec<u8> = b"not a pe, not a zip, just bytes".to_vec();
    let det: Detection = detect_bytes(&buf, Some(&PathBuf::from("random.bin")));
    assert_eq!(det.kind, FreezerKind::Unknown);
}

#[test]
fn detect_synthetic_pyoxidizer_via_runtime_markers() {
    let mut buf: Vec<u8> = vec![0u8; 256];
    buf.extend_from_slice(b"pyembed");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(b"python-stdlib");
    buf.extend_from_slice(&[0u8; 32]);
    buf.extend_from_slice(b"python312.dll");
    let det: Detection = detect_bytes(&buf, Some(&PathBuf::from("pyox-app.exe")));
    assert_eq!(det.kind, FreezerKind::PyOxidizer, "got: {det:?}");
    assert!(det.confidence > 0.5);
}

#[test]
fn detect_synthetic_briefcase_via_sibling_layout() {
    let purpose: String = format!(
        "disrobe-briefcase-detect-{}-{}",
        std::process::id(),
        rand_suffix()
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let tmp: PathBuf = scratch.path().to_path_buf();
    let bin: PathBuf = tmp.join("hello.exe");
    std::fs::write(&bin, b"fake").expect("write bin");
    std::fs::create_dir_all(tmp.join("app_packages")).expect("mkdir app_packages");
    let buf: Vec<u8> = std::fs::read(&bin).expect("read");
    let det: Detection = detect_bytes(&buf, Some(&bin));
    assert_eq!(det.kind, FreezerKind::Briefcase, "got: {det:?}");
    assert!(det.confidence > 0.5);
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xc0ffee);
    N.fetch_add(1, Ordering::Relaxed)
}
