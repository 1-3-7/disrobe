#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, minimal_wasm, run_disrobe, temp_path, write_bytes};

#[test]
fn wasm_decompile_target_ts_smoke() {
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-ts", "wasm");
    write_bytes(&src, &minimal_wasm());
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-ts-out", "ts");
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

#[test]
fn wasm_decompile_target_ts_routes_shared_atomics_to_an_instance_factory() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
  (memory (export "memory") 1 1 shared)
  (func (export "increment") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.atomic.rmw.add align=4))"#,
    )
    .expect("shared atomic fixture must assemble");
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-ts-atomic", "wasm");
    write_bytes(&src, &bytes);
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-ts-atomic-out", "ts");
    let run: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "ts",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    let source: String = std::fs::read_to_string(&out).expect("read atomic TypeScript output");
    assert!(source.contains("export const instantiate"), "{source}");
    assert!(source.contains("Atomics.add"), "{source}");
    assert!(!source.contains("workerData?.wasmMemory"), "{source}");
}

#[test]
fn wasm_decompile_target_ts_refuses_fence_before_writing_output() {
    let bytes: Vec<u8> = wat::parse_str(r#"(module (func (export "fence") atomic.fence))"#)
        .expect("fence fixture must assemble");
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-ts-fence", "wasm");
    write_bytes(&src, &bytes);
    let (_out_scratch, out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("wasm-ts-fence-out", "ts");
    let run: Run = run_disrobe(&[
        "wasm",
        "decompile",
        src.to_str().unwrap(),
        "--target",
        "ts",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    assert!(run.stderr.contains("atomic.fence"), "{}", run.stderr);
    assert!(!out.exists(), "refusal created {}", out.display());
}
