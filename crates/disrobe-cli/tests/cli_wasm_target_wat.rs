#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, minimal_wasm, run_disrobe, temp_path, write_bytes};

#[test]
fn wasm_decompile_target_wat_smoke() {
    let src: PathBuf = temp_path("wasm-wat", "wasm");
    write_bytes(&src, &minimal_wasm());
    let out: PathBuf = temp_path("wasm-wat-out", "wat");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "wat",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(
        out.exists(),
        "wat output file not written at {}",
        out.display()
    );
    let txt: String = std::fs::read_to_string(&out).expect("read");
    assert!(
        txt.contains("disrobe wasm lift target=wat"),
        "missing wat banner in {txt}"
    );
}
