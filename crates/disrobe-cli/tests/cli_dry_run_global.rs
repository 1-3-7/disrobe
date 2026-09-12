#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_path, write_bytes};

#[test]
fn pyarmor_unpack_dry_run_exits_zero_with_no_file_output() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("dryrun-pyarmor", "py");
    write_bytes(
        &src,
        b"# pyarmor wrapper stub\nfrom pyarmor_runtime import __pyarmor__\n",
    );
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("dryrun-pyarmor-out", "dir");
    let _: std::io::Result<()> = std::fs::remove_dir_all(&out);

    let r: Run = run_disrobe(&[
        "--dry-run",
        "pyarmor",
        "unpack",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "--dry-run must exit 0. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("DRY-RUN") || r.stderr.contains("DRY-RUN"),
        "must announce DRY-RUN. stdout={} stderr={}",
        r.stdout,
        r.stderr
    );
    assert!(
        !out.exists(),
        "--dry-run must NOT create output dir: {}",
        out.display()
    );
}

#[test]
fn pyinstaller_extract_dry_run_exits_zero_with_no_file_output() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("dryrun-pyinst", "bin");
    write_bytes(&src, b"not a real pyinstaller archive\n");
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("dryrun-pyinst-out", "dir");
    let _: std::io::Result<()> = std::fs::remove_dir_all(&out);

    let r: Run = run_disrobe(&[
        "--dry-run",
        "pyinstaller",
        "extract",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "--dry-run must exit 0 even on garbage input. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        !out.exists(),
        "--dry-run must NOT create output dir: {}",
        out.display()
    );
}
