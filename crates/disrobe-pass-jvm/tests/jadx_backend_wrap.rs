#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_jvm::android_backend::{
    AndroidDecompileOutput, AndroidDecompiler, BackendPreference,
};
use disrobe_pass_jvm::{android_decompile_dex, run_jadx_on_bytes};

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

fn jadx_on_path() -> bool {
    let Some(path_var): Option<std::ffi::OsString> = std::env::var_os("PATH") else {
        return false;
    };
    let exts: &[&str] = if cfg!(windows) {
        &["", ".bat", ".exe"]
    } else {
        &[""]
    };
    std::env::split_paths(&path_var).any(|dir: PathBuf| {
        exts.iter()
            .any(|ext: &&str| dir.join(format!("jadx{ext}")).is_file())
    })
}

#[test]
fn in_house_is_the_default_engine() {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "Hello.dex"])).expect("dex");
    let out: AndroidDecompileOutput =
        android_decompile_dex(&dex_bytes, BackendPreference::PreferInHouse).expect("decompile");
    assert_eq!(
        out.engine,
        AndroidDecompiler::InHouseDalvik,
        "default backend must be the in-house Dalvik decompiler"
    );
    assert!(out.class_count > 0, "in-house engine must produce classes");
    assert!(!out.sources.is_empty(), "in-house engine must emit source");
}

#[test]
fn prefer_jadx_falls_back_to_in_house_when_absent() {
    if jadx_on_path() {
        eprintln!("SKIP-fallback: jadx IS on PATH; fallback path not exercised here");
        return;
    }
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "Hello.dex"])).expect("dex");
    let out: AndroidDecompileOutput =
        android_decompile_dex(&dex_bytes, BackendPreference::PreferJadxIfAvailable)
            .expect("must fall back, not error");
    assert_eq!(
        out.engine,
        AndroidDecompiler::InHouseDalvik,
        "with jadx absent, PreferJadxIfAvailable must fall back to in-house"
    );
}

#[test]
fn force_jadx_reports_missing_tool_when_absent() {
    if jadx_on_path() {
        eprintln!("SKIP-missing: jadx IS on PATH; cannot assert MissingTool");
        return;
    }
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "Hello.dex"])).expect("dex");
    let err = android_decompile_dex(&dex_bytes, BackendPreference::ForceJadx)
        .expect_err("force jadx with no jadx must error");
    assert!(
        matches!(err, disrobe_pass_jvm::Error::MissingTool(_)),
        "ForceJadx without jadx must yield MissingTool, got {err:?}"
    );
}

#[test]
fn jadx_backend_decompiles_real_dex_when_available() {
    if !jadx_on_path() {
        eprintln!("SKIP: jadx not on PATH - external backend wrap unverified (honest MissingTool)");
        return;
    }
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let out: AndroidDecompileOutput = run_jadx_on_bytes(&dex_bytes, "input.dex").expect("jadx run");
    assert_eq!(out.engine, AndroidDecompiler::Jadx);
    assert!(out.class_count >= 1, "jadx must emit at least one .java");
    let all_src: String = out.sources.values().cloned().collect::<Vec<_>>().join("\n");
    assert!(
        all_src.contains("class EdgeCases") || all_src.contains("EdgeCases"),
        "jadx output must mention EdgeCases"
    );
    assert!(out.method_count > 0, "jadx output must contain methods");
}
