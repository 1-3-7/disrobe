#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_nir::{
    NirFunction, SurfaceFunction, ValueId, basic_blocks, def_use, emit_pseudo_source,
    structurize_function, surfacify_function,
};
use disrobe_nir_lift::lower_aarch64;

fn assemble(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word: &u32| word.to_le_bytes())
        .collect()
}

fn decompile_bytes(name: &str, bytes: &[u8]) -> (NirFunction, SurfaceFunction, String) {
    let nir: NirFunction = lower_aarch64(bytes, 0x1000, name).expect("lower aarch64 leaf");
    assert!(!basic_blocks(&nir).is_empty(), "missing CFG blocks");
    let hir: disrobe_nir::HirFunction = structurize_function(&nir);
    let surface: SurfaceFunction = surfacify_function(&hir);
    let emitted: String = emit_pseudo_source(&surface).expect("emit pseudo source");
    (nir, surface, emitted)
}

fn assert_no_arch_flags(nir: &NirFunction, emitted: &str) {
    for instruction in &nir.instructions {
        let flow: disrobe_nir::DefUse = def_use(instruction);
        for value in flow.defs.iter().chain(flow.uses.iter()) {
            if let ValueId::Register(name) = value {
                assert!(
                    !matches!(name.as_str(), "ng" | "zr" | "cy" | "ov"),
                    "nzcv flag {name} reached the recovered nir"
                );
            }
        }
    }
    for token in
        emitted.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
    {
        assert!(
            !matches!(token, "ng" | "zr" | "cy" | "ov" | "nzcv"),
            "arch flag concept `{token}` reached the emitted output:\n{emitted}"
        );
    }
}

#[test]
fn committed_arithmetic_leaf_reaches_structured_surface() {
    let bytes: Vec<u8> = assemble(&[0x8b01_0000, 0xd65f_03c0]);
    let (nir, surface, emitted): (NirFunction, SurfaceFunction, String) =
        decompile_bytes("arith", &bytes);
    assert!(surface.structured, "not structured:\n{emitted}");
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains('+'), "addition missing:\n{emitted}");
    assert!(
        emitted.contains("return x0"),
        "return value missing:\n{emitted}"
    );
    assert_no_arch_flags(&nir, &emitted);
}

#[test]
fn committed_if_leaf_reaches_structured_surface() {
    let bytes: Vec<u8> = assemble(&[
        0xb400_0060,
        0x9100_0400,
        0x1400_0002,
        0xd100_0400,
        0xd65f_03c0,
    ]);
    let (nir, surface, emitted): (NirFunction, SurfaceFunction, String) =
        decompile_bytes("choose", &bytes);
    assert!(surface.structured, "not structured:\n{emitted}");
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains("if ("), "if missing:\n{emitted}");
    assert!(
        emitted.contains('+') && emitted.contains('-'),
        "if arms missing:\n{emitted}"
    );
    assert!(
        emitted.contains("int_equal"),
        "comparison missing:\n{emitted}"
    );
    assert!(emitted.contains("return x0"), "return missing:\n{emitted}");
    assert_no_arch_flags(&nir, &emitted);
}

#[test]
fn committed_loop_leaf_reaches_structured_surface() {
    let bytes: Vec<u8> = assemble(&[0xb400_0060, 0xd100_0400, 0x17ff_fffe, 0xd65f_03c0]);
    let (nir, surface, emitted): (NirFunction, SurfaceFunction, String) =
        decompile_bytes("countdown", &bytes);
    assert!(surface.structured, "not structured:\n{emitted}");
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains("while (true)"), "loop missing:\n{emitted}");
    assert_eq!(
        emitted.matches("while (true)").count(),
        1,
        "spurious loop:\n{emitted}"
    );
    assert!(emitted.contains("break;"), "loop exit missing:\n{emitted}");
    assert!(emitted.contains('-'), "loop arithmetic missing:\n{emitted}");
    assert!(
        emitted.contains("return x0"),
        "loop return missing:\n{emitted}"
    );
    assert_no_arch_flags(&nir, &emitted);
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

fn cross_toolchain() -> Option<(String, String)> {
    for (gcc, objcopy) in [
        ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-objcopy"),
        (
            "aarch64-none-linux-gnu-gcc",
            "aarch64-none-linux-gnu-objcopy",
        ),
        ("aarch64-linux-android-gcc", "aarch64-linux-android-objcopy"),
    ] {
        if command_version_contains(gcc, b"Free Software Foundation")
            && command_version_contains(objcopy, b"GNU objcopy")
        {
            return Some((gcc.to_owned(), objcopy.to_owned()));
        }
    }
    None
}

fn cross_compile(gcc: &str, objcopy: &str, name: &str, source: &str) -> Vec<u8> {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-aarch64").expect("create scratch directory");
    let directory: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = directory.join(format!("{name}.c"));
    let object_path: PathBuf = directory.join(format!("{name}.o"));
    let binary_path: PathBuf = directory.join(format!("{name}.bin"));
    fs::write(&source_path, source).expect("write cross source");
    let compile_status: std::process::ExitStatus = Command::new(gcc)
        .args([
            "-c",
            "-O1",
            "-fno-asynchronous-unwind-tables",
            "-fno-stack-protector",
            "-fno-ident",
            "-fno-if-conversion",
            "-fno-if-conversion2",
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(&object_path)
        .status()
        .expect("execute cross gcc");
    assert!(compile_status.success(), "cross gcc failed for {name}");
    let extract_status: std::process::ExitStatus = Command::new(objcopy)
        .args(["-j", ".text", "-O", "binary"])
        .arg(&object_path)
        .arg(&binary_path)
        .status()
        .expect("execute cross objcopy");
    assert!(extract_status.success(), "cross objcopy failed for {name}");
    let mut bytes: Vec<u8> = fs::read(&binary_path).expect("read extracted text");
    let nop: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];
    while bytes.len() >= 4 && bytes.ends_with(&nop) {
        bytes.truncate(bytes.len().saturating_sub(4));
    }
    assert!(!bytes.is_empty(), "cross gcc emitted no text for {name}");
    bytes
}

#[test]
fn cross_compiled_if_reaches_structured_surface() {
    let Some((gcc, objcopy)): Option<(String, String)> = cross_toolchain() else {
        eprintln!("skipping cross aarch64 check: no aarch64 GNU toolchain on PATH");
        return;
    };
    let bytes: Vec<u8> = cross_compile(
        &gcc,
        &objcopy,
        "choose",
        "long choose(long x) { if (x == 0) return x + 1; return x - 1; }",
    );
    let (_nir, surface, emitted): (NirFunction, SurfaceFunction, String) =
        decompile_bytes("choose", &bytes);
    assert!(surface.structured, "cross if not structured:\n{emitted}");
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains("if ("), "if missing:\n{emitted}");
}

#[test]
fn cross_compiled_loop_reaches_structured_surface() {
    let Some((gcc, objcopy)): Option<(String, String)> = cross_toolchain() else {
        eprintln!("skipping cross aarch64 check: no aarch64 GNU toolchain on PATH");
        return;
    };
    let bytes: Vec<u8> = cross_compile(
        &gcc,
        &objcopy,
        "countdown",
        "long countdown(long n) { while (n != 0) n = n - 1; return n; }",
    );
    let (_nir, surface, emitted): (NirFunction, SurfaceFunction, String) =
        decompile_bytes("countdown", &bytes);
    assert!(surface.structured, "cross loop not structured:\n{emitted}");
    assert!(!emitted.contains("goto"), "spaghetti output:\n{emitted}");
    assert!(emitted.contains("while (true)"), "loop missing:\n{emitted}");
}
