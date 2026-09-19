#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_jvm::android_backend::{
    AndroidDecompileOutput, AndroidDecompiler, BackendPreference, JadxCapturedOutcome,
    run_jadx_on_bytes_captured,
};
use disrobe_pass_jvm::{Error, android_decompile_dex, run_jadx_on_bytes};

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
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "Hello.dex"])).expect("dex");
    let out: AndroidDecompileOutput = run_jadx_on_bytes(&dex_bytes, "input.dex").expect("jadx run");
    assert_eq!(out.engine, AndroidDecompiler::Jadx);
    assert_eq!(out.class_count, 2, "jadx must emit Hello and Greeter");
    let hello: &String = out
        .sources
        .get("defpackage/Hello.java")
        .expect("jadx must emit defpackage/Hello.java");
    assert!(
        hello.contains("class Hello"),
        "Hello.java must declare Hello"
    );
    assert!(
        hello.contains("bumpCounter"),
        "Hello.java must retain bumpCounter"
    );
    assert!(
        hello.contains("describe"),
        "Hello.java must retain describe"
    );
    let greeter: &String = out
        .sources
        .get("defpackage/Greeter.java")
        .expect("jadx must emit defpackage/Greeter.java");
    assert!(
        greeter.contains("class Greeter"),
        "Greeter.java must declare Greeter"
    );
    assert!(greeter.contains("greet"), "Greeter.java must retain greet");
    assert!(
        out.method_count >= 5,
        "jadx output must contain Hello and Greeter methods"
    );
    verify_edgecases_producer_outcome().expect("JADX retains the EdgeCases producer outcome");
}

fn verify_edgecases_producer_outcome() -> Result<(), Error> {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let outcome: JadxCapturedOutcome =
        run_jadx_on_bytes_captured(&dex_bytes, "input.dex").expect("jadx invocation");
    match outcome {
        JadxCapturedOutcome::Recovered(output) => {
            assert_eq!(output.engine, AndroidDecompiler::Jadx);
            let edgecases: &String = output
                .sources
                .get("defpackage/EdgeCases.java")
                .expect("successful JADX recovery must emit defpackage/EdgeCases.java");
            assert!(
                edgecases.contains("class EdgeCases"),
                "EdgeCases.java must declare EdgeCases"
            );
            assert!(
                edgecases.contains("shapeFacts"),
                "EdgeCases.java must retain shapeFacts"
            );
            assert!(
                output.method_count > 0,
                "successful JADX recovery must emit methods"
            );
        }
        JadxCapturedOutcome::ProducerFailed {
            tool,
            status,
            stdout,
            stderr,
            output,
            emitted_methods,
            ..
        } => {
            assert_eq!(tool, "jadx");
            assert_ne!(
                status, 0,
                "producer failures must retain a nonzero exit status"
            );
            let diagnostics: String = format!("{stdout}\n{stderr}");
            assert!(
                diagnostics.contains("finished with errors"),
                "the captured JADX diagnostics must report a failed producer run: {diagnostics}"
            );
            assert_eq!(output.engine, AndroidDecompiler::Jadx);
            assert_eq!(
                output.class_count, 2,
                "JADX 1.5.5 emits two partial sources"
            );
            assert_eq!(
                output.sources.len(),
                2,
                "JADX 1.5.5 emits two partial sources"
            );
            let edgecases: &String = output
                .sources
                .get("defpackage/EdgeCases.java")
                .expect("partial JADX output must retain defpackage/EdgeCases.java");
            assert!(
                edgecases.contains("RegionMakerVisitor"),
                "partial EdgeCases.java must retain the RegionMakerVisitor diagnostic"
            );
            assert!(
                edgecases.contains("shapeFacts"),
                "partial EdgeCases.java must retain shapeFacts"
            );
            assert!(
                output
                    .sources
                    .contains_key("com/android/tools/r8/RecordTag.java"),
                "partial JADX output must retain RecordTag.java"
            );
            assert_eq!(output.method_count, emitted_methods);
            assert!(
                emitted_methods > 0,
                "partial JADX output must retain methods"
            );
        }
        JadxCapturedOutcome::Refused(refusal) => {
            return Err(Error::BackendFailed {
                tool: "jadx".to_owned(),
                status: -1,
                stderr: format!(
                    "real EdgeCases input must not be refused by the JADX wrapper: {refusal}"
                ),
            });
        }
        _ => {
            return Err(Error::BackendFailed {
                tool: "jadx".to_owned(),
                status: -1,
                stderr: "real EdgeCases input produced an unsupported JADX outcome".to_owned(),
            });
        }
    }
    Ok(())
}
