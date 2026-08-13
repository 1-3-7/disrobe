#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_wasm_deob::{
    AtomicMemoryRefusal, Error, LiftResult, LiftTarget, c_runtime_prelude, rust_runtime_prelude,
    try_lift_function_from_module,
};

const FENCE_WAT: &str = r#"(module (func (export "fence") atomic.fence))"#;

fn fence_module() -> Vec<u8> {
    wat::parse_str(FENCE_WAT).expect("fence module must assemble")
}

fn tool(name: &str) -> Option<PathBuf> {
    let finder: &str = if cfg!(windows) { "where" } else { "which" };
    let output: Output = Command::new(finder).arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout.lines().next().map(PathBuf::from)
}

fn compile_rust(source: &str, directory: &Path) {
    let source_path: PathBuf = directory.join("fence.rs");
    std::fs::write(&source_path, source).expect("write Rust lift");
    let rustc: PathBuf = tool("rustc").expect("rustc is required for the fence lift gate");
    let output: Output = Command::new(rustc)
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--emit=metadata",
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(directory.join("fence.rmeta"))
        .output()
        .expect("run rustc");
    assert!(
        output.status.success(),
        "rustc rejected the atomic fence lift: {}\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn compile_c(source: &str, directory: &Path) {
    let source_path: PathBuf = directory.join("fence.c");
    std::fs::write(&source_path, source).expect("write C lift");
    let compiler: PathBuf = ["clang", "cc", "gcc"]
        .into_iter()
        .find_map(tool)
        .expect("a C compiler is required for the fence lift gate");
    let output: Output = Command::new(compiler)
        .args(["-std=c11", "-Werror", "-c"])
        .arg(&source_path)
        .arg("-o")
        .arg(directory.join("fence.o"))
        .output()
        .expect("run clang");
    assert!(
        output.status.success(),
        "the C compiler rejected the atomic fence lift: {}\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn public_module_lift_emits_real_seqcst_fences_and_refuses_typescript() {
    let bytes: Vec<u8> = fence_module();
    let rust: LiftResult = try_lift_function_from_module(&bytes, 0, LiftTarget::Rust)
        .expect("Rust fence lift must succeed");
    let c: LiftResult =
        try_lift_function_from_module(&bytes, 0, LiftTarget::C).expect("C fence lift must succeed");
    assert!(rust.pseudo_source.contains("wasm_atomic_fence();"));
    assert!(c.pseudo_source.contains("wasm_atomic_fence();"));
    assert!(
        rust_runtime_prelude()
            .contains("std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst)")
    );
    assert!(c_runtime_prelude().contains("atomic_thread_fence(memory_order_seq_cst)"));

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("wasm-atomic-fence").expect("create scratch");
    compile_rust(
        &format!("{}\n{}", rust_runtime_prelude(), rust.pseudo_source),
        scratch.path(),
    );
    compile_c(
        &format!("{}\n{}", c_runtime_prelude(), c.pseudo_source),
        scratch.path(),
    );

    let error: Error = try_lift_function_from_module(&bytes, 0, LiftTarget::TypeScript)
        .expect_err("TypeScript must refuse a standalone fence it cannot express");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::UnsupportedTarget {
            target: "typescript",
            operation: "atomic.fence"
        })
    ));
}
