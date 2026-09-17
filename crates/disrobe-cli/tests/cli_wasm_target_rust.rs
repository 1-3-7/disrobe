#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, minimal_wasm, run_disrobe, temp_path, write_bytes};

#[test]
fn wasm_decompile_target_rust_smoke() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-rust", "wasm");
    write_bytes(&src, &minimal_wasm());
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-rust-out", "rs");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "rust",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(
        out.exists(),
        "rust output file not written at {}",
        out.display()
    );
    let txt: String = std::fs::read_to_string(&out).expect("read");
    assert!(
        txt.contains("disrobe wasm lift target=rust"),
        "missing rust banner in {txt}"
    );
}

#[test]
fn wasm_decompile_target_rust_rejects_unsafe_atomic_state() {
    let module: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 2 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    )
    .expect("wat");
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-rust-unsafe-atomic", "wasm");
    write_bytes(&src, &module);
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-rust-unsafe-atomic-out", "rs");
    let r: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "rust",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_ne!(r.code, 0, "stdout={} stderr={}", r.stdout, r.stderr);
    assert!(
        r.stderr.contains("DR-WASMDEOB-0003"),
        "unsafe atomic state returned the wrong diagnostic: {}",
        r.stderr
    );
    assert!(
        !out.exists(),
        "unsafe atomic state wrote a lifted stub at {}",
        out.display()
    );
}
