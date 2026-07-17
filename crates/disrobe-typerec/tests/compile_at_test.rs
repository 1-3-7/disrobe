#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_typerec::dwarf_gt::{self, DebugImage};
use disrobe_typerec::grade::{self, GradeReport};

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|out: std::process::Output| out.status.success())
}

fn source_path() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("types_corpus.c");
    path
}

fn run(command: &mut Command) -> bool {
    command
        .status()
        .is_ok_and(|status: std::process::ExitStatus| status.success())
}

#[test]
fn recompiled_corpus_reproduces_measured_floors() {
    if !tool_available("gcc") || !tool_available("objcopy") {
        eprintln!("skipping: gcc and objcopy are required for the compile-at-test-time path");
        return;
    }

    let work: PathBuf =
        std::env::temp_dir().join(format!("disrobe_typerec_{}", std::process::id()));
    if std::fs::create_dir_all(&work).is_err() {
        eprintln!("skipping: could not create a working directory");
        return;
    }
    let unstripped: PathBuf = work.join("corpus.unstripped.exe");
    let stripped: PathBuf = work.join("corpus.stripped.exe");

    let built: bool = run(Command::new("gcc")
        .args([
            "-g",
            "-O0",
            "-gdwarf-4",
            "-fno-asynchronous-unwind-tables",
            "-nostdlib",
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&unstripped)
        .arg(source_path()));
    if !built {
        cleanup(&work);
        eprintln!("skipping: gcc could not build the freestanding corpus on this host");
        return;
    }
    let object_stripped: bool = run(Command::new("objcopy")
        .arg("--strip-debug")
        .arg(&unstripped)
        .arg(&stripped));
    if !object_stripped {
        cleanup(&work);
        eprintln!("skipping: objcopy could not strip debug info on this host");
        return;
    }

    let Some(ground_truth): Option<DebugImage> = std::fs::read(&unstripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load(&bytes).ok())
    else {
        cleanup(&work);
        panic!("freshly built unstripped binary must carry readable DWARF");
    };
    let Some((base, text)): Option<(u64, Vec<u8>)> = std::fs::read(&stripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load_text(&bytes).ok())
    else {
        cleanup(&work);
        panic!("freshly stripped binary must expose a .text section");
    };

    let input: DebugImage = DebugImage {
        text_base: base,
        text,
        functions: ground_truth.functions,
    };
    let report: GradeReport = grade::grade_image(&input);
    cleanup(&work);

    assert!(
        report.total_vars > 0,
        "recompiled corpus must expose variables"
    );
    assert_eq!(
        report.mapped_vars, report.total_vars,
        "every recompiled DWARF variable must map to a recovered slot",
    );
    assert!(
        report.width_mismatches.is_empty(),
        "recompiled width must never be wrong: {:?}",
        report.width_mismatches,
    );
    assert!((report.width.recall() - 1.0).abs() < f64::EPSILON);
    assert!(
        report.sign_mismatches.is_empty(),
        "recompiled signedness must never be wrong: {:?}",
        report.sign_mismatches,
    );
    assert!((report.sign.precision() - 1.0).abs() < f64::EPSILON);
    assert!(report.sign.correct >= 1, "some signs must be recoverable");
}

fn cleanup(work: &Path) {
    let _ = std::fs::remove_dir_all(work);
}
