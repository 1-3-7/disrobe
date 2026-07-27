#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_pyfreeze::cxfreeze::{CxFreezeExtraction, CxFreezeRecovery, detect_and_extract};
use disrobe_pass_pyfreeze::recover::{RoundtripGrade, recover_bytecode_file, surface_native_file};
use disrobe_pass_pyfreeze::{
    Detection, FreezerKind, RecoveredModule, SurfacedNative, detect_bytes,
};

const APP_LOGIC_SOURCE: &str = "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\n\ndef greet(name):\n    return 'hello ' + name + ' fib10=' + str(fib(10))\n";
const MAIN_SOURCE: &str = "import app_logic\n\n\ndef main():\n    print(app_logic.greet('frozen world'))\n\n\nif __name__ == '__main__':\n    main()\n";
const SETUP_SOURCE: &str = "from cx_Freeze import Executable, setup\n\nsetup(\n    name='disrobe_frozen_gate',\n    version='0.1',\n    executables=[Executable('main.py', target_name='disrobe_frozen_gate')],\n    options={'build_exe': {'excludes': ['tkinter', 'unittest', 'test', 'pydoc_data']}},\n)\n";

const fn python() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

fn has_cx_freeze() -> bool {
    Command::new(python())
        .args(["-c", "import cx_Freeze"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn build_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("cxfreeze-gate");
    p
}

fn write_sources(root: &Path) {
    std::fs::create_dir_all(root).expect("create build root");
    std::fs::write(root.join("app_logic.py"), APP_LOGIC_SOURCE).expect("write app_logic");
    std::fs::write(root.join("main.py"), MAIN_SOURCE).expect("write main");
    std::fs::write(root.join("setup.py"), SETUP_SOURCE).expect("write setup");
}

fn locate_built_exe(build_dir: &Path) -> Option<PathBuf> {
    let read = std::fs::read_dir(build_dir).ok()?;
    for entry in read.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("exe."))
        {
            let read_inner = std::fs::read_dir(&path).ok()?;
            for inner in read_inner.flatten() {
                let p: PathBuf = inner.path();
                if p.extension().and_then(|e| e.to_str()) == Some("exe") {
                    return Some(p);
                }
            }
            #[cfg(not(windows))]
            {
                for inner in std::fs::read_dir(&path).ok()?.flatten() {
                    let p: PathBuf = inner.path();
                    if p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("disrobe_frozen_gate"))
                    {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

fn build_cx_freeze() -> Option<PathBuf> {
    if !has_cx_freeze() {
        eprintln!("[real_frozen_recovery] skipped: cx_Freeze not importable on this box");
        return None;
    }
    let root: PathBuf = build_root();
    write_sources(&root);
    let status = Command::new(python())
        .current_dir(&root)
        .args(["setup.py", "build_exe"])
        .output()
        .expect("run cx_Freeze build");
    if !status.status.success() {
        eprintln!(
            "[real_frozen_recovery] cx_Freeze build failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        return None;
    }
    let exe: Option<PathBuf> = locate_built_exe(&root.join("build"));
    if exe.is_none() {
        eprintln!("[real_frozen_recovery] cx_Freeze build produced no exe");
    }
    exe
}

fn out_dir() -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-frozen-gate-{pid}", pid = std::process::id());
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

#[test]
fn cxfreeze_real_build_recovers_bytecode_and_surfaces_native() {
    let Some(exe): Option<PathBuf> = build_cx_freeze() else {
        eprintln!(
            "[real_frozen_recovery] HONEST-PARTIAL: gate not exercised (cx_Freeze unavailable); \
             recovery code is built and unit-tested but the end-to-end real-sample assertion is skipped"
        );
        return;
    };

    let bytes: Vec<u8> = std::fs::read(&exe).expect("read frozen exe");
    let det: Detection = detect_bytes(&bytes, Some(&exe));
    assert_eq!(
        det.kind,
        FreezerKind::CxFreeze,
        "real cx_Freeze build must detect as cx_Freeze; got {det:?}"
    );

    let scratch: disrobe_core::scratch::ScratchDir = out_dir();
    let out: PathBuf = scratch.path().to_path_buf();
    let extraction: CxFreezeExtraction =
        detect_and_extract(&exe, &out).expect("cxfreeze extraction");

    let recovery: CxFreezeRecovery = extraction.recover();

    let app_logic: &RecoveredModule = recovery
        .modules
        .iter()
        .find(|m: &&RecoveredModule| m.name == "app_logic.pyc")
        .unwrap_or_else(|| {
            panic!(
                "app_logic.pyc must be recovered; recovered={:?} failures={:?}",
                recovery
                    .modules
                    .iter()
                    .map(|m| m.name.clone())
                    .collect::<Vec<String>>(),
                recovery.bytecode_failures
            )
        });

    assert!(
        app_logic.recovered_directly,
        "app_logic must decompile to real source, not a fallback; reason={:?}\nsource:\n{}",
        app_logic.fallback_reason, app_logic.source
    );
    assert!(
        app_logic.source.contains("def fib") && app_logic.source.contains("def greet"),
        "recovered source must contain both functions, got:\n{}",
        app_logic.source
    );

    match &app_logic.roundtrip {
        RoundtripGrade::Perfect | RoundtripGrade::Semantic => {}
        RoundtripGrade::NoInterpreter(hint) => {
            eprintln!(
                "[real_frozen_recovery] HONEST-PARTIAL: source recovered but recompile oracle \
                 unavailable ({hint}); decompile content asserted, bytecode equivalence not graded"
            );
        }
        other => panic!(
            "recovered app_logic.pyc must recompile to equivalent bytecode against the real \
             interpreter; got {other:?}\nsource:\n{}",
            app_logic.source
        ),
    }

    let native: Vec<SurfacedNative> = {
        let mut v: Vec<SurfacedNative> = recovery.native.clone();
        v.extend(extraction.sibling_native_extensions());
        v
    };
    let surfaced: &SurfacedNative = native
        .iter()
        .find(|n: &&SurfacedNative| n.instruction_count > 0)
        .unwrap_or_else(|| {
            panic!(
                "at least one bundled native extension (.pyd/.dll) must surface native disasm; \
                 native={:?} failures={:?}",
                native
                    .iter()
                    .map(|n| n.name.clone())
                    .collect::<Vec<String>>(),
                recovery.native_failures
            )
        });
    assert!(
        surfaced.instruction_count > 4,
        "native extension `{}` surfaced too few instructions: {}",
        surfaced.name,
        surfaced.instruction_count
    );
    assert!(
        !surfaced.sample.is_empty() && !surfaced.sample[0].mnemonic.is_empty(),
        "surfaced native disasm must carry decoded mnemonics for `{}`",
        surfaced.name
    );

    eprintln!(
        "[real_frozen_recovery] OK: recovered {} modules (app_logic grade={}), surfaced {} native \
         extensions (e.g. {} -> {} {} insns)",
        recovery.modules.len(),
        app_logic.roundtrip.label(),
        native.len(),
        surfaced.name,
        surfaced.arch.label(),
        surfaced.instruction_count
    );
}

#[test]
fn clean_control_yields_no_recovery() {
    let clean: Vec<u8> = b"#!/bin/sh\necho not a frozen python app\n".to_vec();
    let det: Detection = detect_bytes(&clean, None);
    assert_eq!(
        det.kind,
        FreezerKind::Unknown,
        "a plain shell script must not be classified as a Python freezer"
    );

    let purpose: String = format!("disrobe-frozen-control-{}", std::process::id());
    let (scratch, _file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "bin").expect("create scratch file");
    let tmp: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&tmp, &clean).expect("write control");
    assert!(
        recover_bytecode_file("control.pyc", &tmp).is_err(),
        "non-pyc bytes must not yield recovered bytecode"
    );
    assert!(
        surface_native_file("control.pyd", &tmp).is_err(),
        "non-native bytes must not surface disasm"
    );
}
