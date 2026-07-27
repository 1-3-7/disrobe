#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_path, write_bytes};

#[test]
fn threads_one_succeeds() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("threads-1", "py");
    write_bytes(&src, b"a = 1\n");
    let r: Run = run_disrobe(&["--threads", "1", "py", "deob", src.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
}

#[test]
fn threads_four_succeeds() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("threads-4", "py");
    write_bytes(&src, b"b = 2\n");
    let r: Run = run_disrobe(&["-j", "4", "py", "deob", src.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
}

#[test]
fn threads_zero_is_clamped_or_rejected() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("threads-0", "py");
    write_bytes(&src, b"c = 3\n");
    let r: Run = run_disrobe(&["--threads", "0", "py", "deob", src.to_str().unwrap()]);
    assert_eq!(
        r.code, 0,
        "threads=0 must be clamped to >=1 internally and still succeed. stdout={} stderr={}",
        r.stdout, r.stderr
    );
}
