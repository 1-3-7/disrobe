#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::io::{Cursor, Write};
use std::path::PathBuf;

use disrobe_pass_pyfreeze::{
    Detection, FreezerKind, PyfreezeOutput, RecoveredModule, RoundtripGrade, detect_bytes, extract,
};
use zip::write::SimpleFileOptions;

const KNOWN_PYC: &[u8] = include_bytes!("../../../corpus/python/freezers/zipapp_pyc/known_mod.pyc");
const KNOWN_SOURCE: &str = include_str!("../../../corpus/python/freezers/zipapp_pyc/known_mod.py");

const PYTHON_SHEBANG: &[u8] = b"#!/usr/bin/env python3\n";

fn build_container(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip_buf: Vec<u8> = Vec::new();
    {
        let mut writer: zip::ZipWriter<Cursor<&mut Vec<u8>>> =
            zip::ZipWriter::new(Cursor::new(&mut zip_buf));
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, body) in members {
            writer.start_file(*name, opts).expect("start zip member");
            writer.write_all(body).expect("write zip member");
        }
        writer.finish().expect("finish zip");
    }
    let mut out: Vec<u8> = Vec::with_capacity(PYTHON_SHEBANG.len() + zip_buf.len());
    out.extend_from_slice(PYTHON_SHEBANG);
    out.extend_from_slice(&zip_buf);
    out
}

fn out_dir(tag: &str) -> PathBuf {
    let mut p: PathBuf = std::env::temp_dir();
    p.push(format!(
        "disrobe-pex-shiv-pyc-{tag}-{pid}-{nonce}",
        pid = std::process::id(),
        nonce = next_nonce()
    ));
    p
}

fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xC0FF_EE00);
    N.fetch_add(1, Ordering::Relaxed)
}

fn assert_known_module_recovered(module: &RecoveredModule) {
    assert!(
        module.recovered_directly,
        "known_mod.pyc must decompile to real source, not a fallback; reason={:?}\nsource:\n{}",
        module.fallback_reason, module.source
    );
    assert!(
        module.source.contains("def add") && module.source.contains("def main"),
        "recovered source must carry both known functions from {KNOWN_SOURCE:?}; got:\n{}",
        module.source
    );
    match &module.roundtrip {
        RoundtripGrade::Perfect | RoundtripGrade::Semantic => {}
        RoundtripGrade::NoInterpreter(hint) => {
            eprintln!(
                "[pex_shiv_pyc_recovery] HONEST-PARTIAL: source recovered for `{}` but recompile \
                 oracle unavailable ({hint}); bytecode equivalence not graded",
                module.name
            );
        }
        other => panic!(
            "recovered `{}` must recompile to equivalent bytecode; got {other:?}\nsource:\n{}",
            module.name, module.source
        ),
    }
}

#[test]
fn pex_container_with_pyc_populates_recovery_field() {
    let pex_info: &[u8] =
        br#"{"entry_point":"known_mod:main","interpreter_constraints":["CPython>=3.14"]}"#;
    let container: Vec<u8> = build_container(&[
        ("PEX-INFO", pex_info),
        ("__main__.py", b"import known_mod\n"),
        ("known_mod.pyc", KNOWN_PYC),
    ]);

    let dir: PathBuf = out_dir("pex");
    std::fs::create_dir_all(&dir).expect("create out dir");
    let input: PathBuf = dir.join("hello.pex");
    std::fs::write(&input, &container).expect("write pex");

    let det: Detection = detect_bytes(&container, Some(&input));
    assert_eq!(
        det.kind,
        FreezerKind::Pex,
        "synthetic pex container must detect as Pex; got {det:?}"
    );

    let out: PyfreezeOutput = extract(&input, &dir.join("extracted")).expect("pex extract");
    assert!(
        !out.recovery.is_empty(),
        "pex recovery field must not be empty when a .pyc member is present"
    );
    let module: &RecoveredModule = out
        .recovery
        .modules
        .iter()
        .find(|m: &&RecoveredModule| m.name.ends_with("known_mod.pyc"))
        .unwrap_or_else(|| {
            panic!(
                "known_mod.pyc must be recovered from the pex; recovered={:?}",
                out.recovery
                    .modules
                    .iter()
                    .map(|m| m.name.clone())
                    .collect::<Vec<String>>()
            )
        });
    assert_known_module_recovered(module);

    eprintln!(
        "[pex_shiv_pyc_recovery] OK pex: recovered {} module(s), known_mod grade={}",
        out.recovery.modules.len(),
        module.roundtrip.label()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shiv_container_with_pyc_populates_recovery_field() {
    let environment: &[u8] =
        br#"{"entry_point":"known_mod:main","shiv_version":"1.0.4","build_id":"gate"}"#;
    let container: Vec<u8> = build_container(&[
        ("_bootstrap/__init__.py", b"# shiv bootstrap\n"),
        ("_bootstrap/environment.json", environment),
        ("site-packages/known_mod.pyc", KNOWN_PYC),
    ]);

    let dir: PathBuf = out_dir("shiv");
    std::fs::create_dir_all(&dir).expect("create out dir");
    let input: PathBuf = dir.join("hello.pyz");
    std::fs::write(&input, &container).expect("write pyz");

    let det: Detection = detect_bytes(&container, Some(&input));
    assert_eq!(
        det.kind,
        FreezerKind::Shiv,
        "synthetic shiv container must detect as Shiv; got {det:?}"
    );

    let out: PyfreezeOutput = extract(&input, &dir.join("extracted")).expect("shiv extract");
    assert!(
        !out.recovery.is_empty(),
        "shiv recovery field must not be empty when a .pyc member is present"
    );
    let module: &RecoveredModule = out
        .recovery
        .modules
        .iter()
        .find(|m: &&RecoveredModule| m.name.ends_with("known_mod.pyc"))
        .unwrap_or_else(|| {
            panic!(
                "known_mod.pyc must be recovered from the shiv; recovered={:?}",
                out.recovery
                    .modules
                    .iter()
                    .map(|m| m.name.clone())
                    .collect::<Vec<String>>()
            )
        });
    assert_known_module_recovered(module);

    eprintln!(
        "[pex_shiv_pyc_recovery] OK shiv: recovered {} module(s), known_mod grade={}",
        out.recovery.modules.len(),
        module.roundtrip.label()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn raw_pyc_file_populates_recovery_field() {
    let dir: PathBuf = out_dir("raw-pyc");
    std::fs::create_dir_all(&dir).expect("create out dir");
    let input: PathBuf = dir.join("known_mod.pyc");
    std::fs::write(&input, KNOWN_PYC).expect("write pyc");

    let det: Detection = detect_bytes(KNOWN_PYC, Some(&input));
    assert_eq!(
        det.kind,
        FreezerKind::Pyc,
        "raw pyc must detect as Pyc; got {det:?}"
    );

    let out: PyfreezeOutput = extract(&input, &dir.join("extracted")).expect("pyc extract");
    assert_eq!(out.detection.kind, FreezerKind::Pyc);
    assert!(
        !out.recovery.is_empty(),
        "raw pyc recovery field must not be empty"
    );
    let module: &RecoveredModule = out
        .recovery
        .modules
        .iter()
        .find(|m: &&RecoveredModule| m.name.ends_with("known_mod.pyc"))
        .unwrap_or_else(|| {
            panic!(
                "known_mod.pyc must be recovered from raw pyc input; recovered={:?}",
                out.recovery
                    .modules
                    .iter()
                    .map(|m| m.name.clone())
                    .collect::<Vec<String>>()
            )
        });
    assert_known_module_recovered(module);
    let _ = std::fs::remove_dir_all(&dir);
}
