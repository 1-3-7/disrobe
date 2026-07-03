#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, minimal_wasm, run_disrobe, temp_path, write_bytes};

#[test]
fn wasm_decompile_target_c_smoke() {
    let src: PathBuf = temp_path("wasm-c", "wasm");
    write_bytes(&src, &minimal_wasm());
    let out: PathBuf = temp_path("wasm-c-out", "c");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "c",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(
        out.exists(),
        "c output file not written at {}",
        out.display()
    );
    let txt: String = std::fs::read_to_string(&out).expect("read");
    assert!(
        txt.contains("disrobe wasm lift target=c"),
        "missing c banner in {txt}"
    );
}
