#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, minimal_wasm, run_disrobe, temp_path, write_bytes};

#[test]
fn wasm_decompile_target_ts_smoke() {
    let src: PathBuf = temp_path("wasm-ts", "wasm");
    write_bytes(&src, &minimal_wasm());
    let out: PathBuf = temp_path("wasm-ts-out", "ts");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "ts",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(
        out.exists(),
        "ts output file not written at {}",
        out.display()
    );
    let txt: String = std::fs::read_to_string(&out).expect("read");
    assert!(
        txt.contains("disrobe wasm lift target=typescript"),
        "missing typescript banner in {txt}"
    );
}
