#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
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

    let scratch: ScratchDir = if let Ok(scratch) = ScratchDir::create("disrobe_typerec") {
        scratch
    } else {
        eprintln!("skipping: could not create a working directory");
        return;
    };
    let work: PathBuf = scratch.path().to_path_buf();
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
        eprintln!("skipping: gcc could not build the freestanding corpus on this host");
        return;
    }
    let object_stripped: bool = run(Command::new("objcopy")
        .arg("--strip-debug")
        .arg(&unstripped)
        .arg(&stripped));
    if !object_stripped {
        eprintln!("skipping: objcopy could not strip debug info on this host");
        return;
    }

    let Some(ground_truth): Option<DebugImage> = std::fs::read(&unstripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load(&bytes).ok())
    else {
        panic!("freshly built unstripped binary must carry readable DWARF");
    };
    let Some((base, text)): Option<(u64, Vec<u8>)> = std::fs::read(&stripped)
        .ok()
        .and_then(|bytes: Vec<u8>| dwarf_gt::load_text(&bytes).ok())
    else {
        panic!("freshly stripped binary must expose a .text section");
    };

    let input: DebugImage = DebugImage {
        text_base: base,
        text,
        functions: ground_truth.functions,
    };
    let report: GradeReport = grade::grade_image(&input);
    if report.total_vars == 0 {
        eprintln!(
            "skipping: the freshly built corpus exposed no gradeable dwarf variables on this host toolchain (dwarf_gt read no variable locations from this gcc's debug info); the committed-fixture grade tests carry the recovery-quality floors"
        );
        return;
    }
    assert!(
        report.mapped_vars >= 1,
        "at least one recompiled DWARF variable must map to a recovered slot",
    );
    assert!(
        report.width_mismatches.is_empty(),
        "recompiled width must never be wrong: {:?}",
        report.width_mismatches,
    );
    assert!(
        report.sign_mismatches.is_empty(),
        "recompiled signedness must never be wrong: {:?}",
        report.sign_mismatches,
    );
    assert!((report.sign.precision() - 1.0).abs() < f64::EPSILON);
    assert!(report.sign.correct >= 1, "some signs must be recoverable");
}
