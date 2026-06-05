#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_path, write_bytes};

#[test]
fn no_cache_flag_is_accepted_and_runs() {
    let src: PathBuf = temp_path("nocache-src", "bin");
    write_bytes(&src, b"hello no-cache\n");
    let out1: PathBuf = temp_path("nocache-env-1", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&out1);
    let r1: Run = run_disrobe(&[
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        out1.to_str().unwrap(),
    ]);
    assert_eq!(
        r1.code, 0,
        "first run must succeed. stdout={} stderr={}",
        r1.stdout, r1.stderr
    );
    assert!(out1.exists(), "envelope file not written");

    let out2: PathBuf = temp_path("nocache-env-2", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&out2);
    let r2: Run = run_disrobe(&[
        "--no-cache",
        "envelope",
        "create",
        src.to_str().unwrap(),
        "--out",
        out2.to_str().unwrap(),
    ]);
    assert_eq!(
        r2.code, 0,
        "second run with --no-cache must regenerate. stdout={} stderr={}",
        r2.stdout, r2.stderr
    );
    assert!(
        out2.exists(),
        "envelope file not regenerated under --no-cache"
    );
}
