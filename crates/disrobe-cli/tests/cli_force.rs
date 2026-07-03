#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_dir, temp_path, write_bytes};

#[test]
fn rerunning_into_populated_out_dir_without_force_errors() {
    let src: PathBuf = temp_path("force-src", "py");
    write_bytes(&src, b"z = 3\n");
    let out: PathBuf = temp_dir("force-out");
    write_bytes(&out.join("preexisting.txt"), b"already here\n");

    let r: Run = run_disrobe(&[
        "py",
        "deob",
        "--out",
        out.join("z.deob.py").to_str().unwrap(),
        src.to_str().unwrap(),
    ]);
    let target: PathBuf = out.join("z.deob.py");
    write_bytes(&target, b"existing\n");

    let r2: Run = run_disrobe(&[
        "py",
        "deob",
        "--out",
        target.to_str().unwrap(),
        src.to_str().unwrap(),
    ]);
    assert_ne!(
        r2.code, 0,
        "second run without --force MUST fail with existing target. stdout={} stderr={}",
        r2.stdout, r2.stderr
    );
    assert!(
        r2.stderr.contains("already exists") || r2.stdout.contains("already exists"),
        "must mention 'already exists': stdout={} stderr={}",
        r2.stdout,
        r2.stderr
    );

    let r3: Run = run_disrobe(&[
        "--force",
        "py",
        "deob",
        "--out",
        target.to_str().unwrap(),
        src.to_str().unwrap(),
    ]);
    assert_eq!(
        r3.code, 0,
        "rerun with --force MUST succeed. stdout={} stderr={}",
        r3.stdout, r3.stderr
    );
    let _: Run = r;
}
