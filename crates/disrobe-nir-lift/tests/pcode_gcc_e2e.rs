#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_nir::{
    SurfaceFunction, basic_blocks, emit_pseudo_source, structurize_function, surfacify_function,
};
use disrobe_nir_lift::lower_x86_64;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn compile_text(name: &str, source: &str, extra: &[&str]) -> Vec<u8> {
    let sequence: u64 = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory: PathBuf =
        std::env::temp_dir().join(format!("disrobe-pcode-{}-{sequence}", std::process::id()));
    fs::create_dir_all(&directory).expect("create gcc test directory");
    let source_path: PathBuf = directory.join(format!("{name}.c"));
    let object_path: PathBuf = directory.join(format!("{name}.o"));
    let binary_path: PathBuf = directory.join(format!("{name}.bin"));
    fs::write(&source_path, source).expect("write gcc source");
    let mut compiler: Command = Command::new("gcc");
    compiler.args([
        "-c",
        "-m64",
        "-O1",
        "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-ident",
    ]);
    compiler.args(extra);
    compiler.arg(&source_path).arg("-o").arg(&object_path);
    let compile_status: std::process::ExitStatus = compiler.status().expect("execute real gcc");
    assert!(compile_status.success(), "gcc failed for {name}");
    let extract_status: std::process::ExitStatus = Command::new("objcopy")
        .args(["-j", ".text", "-O", "binary"])
        .arg(&object_path)
        .arg(&binary_path)
        .status()
        .expect("execute real objcopy");
    assert!(extract_status.success(), "objcopy failed for {name}");
    let mut bytes: Vec<u8> = fs::read(&binary_path).expect("read extracted text");
    while bytes.last() == Some(&0x90) {
        bytes.pop();
    }
    remove_directory(&directory);
    assert!(!bytes.is_empty(), "gcc emitted no text for {name}");
    bytes
}

fn remove_directory(directory: &Path) {
    fs::remove_dir_all(directory).expect("remove gcc test directory");
}

fn command_version_contains(command: &str, expected: &[u8]) -> bool {
    let result: std::io::Result<Output> = Command::new(command).arg("--version").output();
    let output: Output = match result {
        Ok(value) => value,
        Err(_error) => return false,
    };
    output.status.success()
        && output
            .stdout
            .windows(expected.len())
            .any(|window: &[u8]| window == expected)
}

fn gnu_toolchain_available() -> bool {
    command_version_contains("gcc", b"Free Software Foundation")
        && command_version_contains("objcopy", b"GNU objcopy")
        && gcc_targets_x86_64()
}

fn gcc_targets_x86_64() -> bool {
    let result: std::io::Result<Output> = Command::new("gcc").arg("-dumpmachine").output();
    let output: Output = match result {
        Ok(value) => value,
        Err(_error) => return false,
    };
    output.status.success()
        && (output.stdout.starts_with(b"x86_64")
            || output
                .stdout
                .windows(b"amd64".len())
                .any(|window: &[u8]| window == b"amd64"))
}

fn decompile(name: &str, source: &str, extra: &[&str]) -> Option<(SurfaceFunction, String)> {
    if !gnu_toolchain_available() {
        eprintln!("skipping GCC x86-64 check: GNU GCC and objcopy are unavailable");
        return None;
    }
    let bytes: Vec<u8> = compile_text(name, source, extra);
    let nir: disrobe_nir::NirFunction =
        lower_x86_64(&bytes, 0x1000, name).expect("lower gcc x86 p-code");
    assert!(!basic_blocks(&nir).is_empty(), "missing CFG blocks");
    let hir: disrobe_nir::HirFunction = structurize_function(&nir);
    let surface: SurfaceFunction = surfacify_function(&hir);
    let emitted: String = emit_pseudo_source(&surface).expect("emit pseudo source");
    Some((surface, emitted))
}

#[test]
fn real_gcc_arithmetic_leaf_reaches_structured_surface() {
    let result: Option<(SurfaceFunction, String)> = decompile(
        "arithmetic",
        "int arithmetic(int a, int b) { return (a + b) * 3 - 7; }",
        &[],
    );
    let Some((surface, emitted)): Option<(SurfaceFunction, String)> = result else {
        return;
    };
    assert!(
        surface.structured,
        "arithmetic was not structured:\n{emitted}"
    );
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains('+'), "addition missing:\n{emitted}");
    assert!(emitted.contains('*'), "multiplication missing:\n{emitted}");
    assert!(emitted.contains('-') || emitted.contains("0xfffffffffffffff9"));
    assert!(!emitted.contains("auto cf;"), "dead carry flag:\n{emitted}");
    assert!(
        !emitted.contains("auto af;"),
        "dead adjust flag:\n{emitted}"
    );
    assert!(
        !emitted.contains("auto pf;"),
        "dead parity flag:\n{emitted}"
    );
    assert!(
        emitted.contains("return rax"),
        "return value missing:\n{emitted}"
    );
    assert!(
        emitted.matches('+').count() >= 2,
        "dataflow missing:\n{emitted}"
    );
}

#[test]
fn real_gcc_if_reaches_structured_surface() {
    let result: Option<(SurfaceFunction, String)> = decompile(
        "choose",
        "int choose(int x) { if (x > 5) return x - 2; return x + 4; }",
        &["-fno-if-conversion", "-fno-if-conversion2"],
    );
    let Some((surface, emitted)): Option<(SurfaceFunction, String)> = result else {
        return;
    };
    assert!(
        surface.structured,
        "if function was not structured:\n{emitted}"
    );
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains("if ("), "if missing:\n{emitted}");
    assert!(
        emitted.contains('+') && emitted.contains('-'),
        "if arms missing:\n{emitted}"
    );
    assert_eq!(emitted.matches("return rax;").count(), 2);
    assert!(
        emitted.contains("bool_negate"),
        "comparison missing:\n{emitted}"
    );
}

#[test]
fn real_gcc_loop_reaches_structured_surface() {
    let result: Option<(SurfaceFunction, String)> = decompile(
        "sum_loop",
        "int sum_loop(int n) { int s = 0; for (int i = 0; i < n; ++i) s += i; return s; }",
        &[],
    );
    let Some((surface, emitted)): Option<(SurfaceFunction, String)> = result else {
        return;
    };
    assert!(surface.structured, "loop was not structured:\n{emitted}");
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains("while (true)"), "loop missing:\n{emitted}");
    assert_eq!(
        emitted.matches("while (true)").count(),
        1,
        "spurious loop present:\n{emitted}"
    );
    assert!(emitted.contains("break;"), "loop exit missing:\n{emitted}");
    assert!(emitted.contains('+'), "loop arithmetic missing:\n{emitted}");
    assert!(
        emitted.contains("continue;"),
        "loop latch missing:\n{emitted}"
    );
    assert!(
        emitted.contains("return rax;"),
        "loop return missing:\n{emitted}"
    );
}
