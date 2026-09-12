#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use std::path::PathBuf;

pub fn corpus_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push(rel);
    p
}

pub fn fixture_or_skip(rel: &str) -> Option<Vec<u8>> {
    let p: PathBuf = corpus_path(rel);
    let bytes: Option<Vec<u8>> = std::fs::read(&p).ok();
    if bytes.is_none() {
        eprintln!(
            "FIXTURE PENDING: {} missing; regenerate via corpus/native/regen.ps1",
            p.display()
        );
    }
    bytes
}

pub fn fixture_or_fail(rel: &str) -> Vec<u8> {
    let p: PathBuf = corpus_path(rel);
    match std::fs::read(&p) {
        Ok(bytes) => bytes,
        Err(error) => panic!(
            "committed fixture {} is the graded reference for this suite and could not be read \
             ({error}); restore it from git rather than skipping the measurement",
            p.display()
        ),
    }
}

pub const REQUIRE_TOOLCHAIN_VAR: &str = "DISROBE_REQUIRE_NATIVE_TOOLCHAIN";

pub fn tool_or_unmeasured(candidates: &[&'static str], graded: &str) -> Option<String> {
    for candidate in candidates {
        let runs: bool = std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|output: std::process::Output| output.status.success());
        if runs {
            return Some((*candidate).to_owned());
        }
    }
    let names: String = candidates
        .iter()
        .map(|c: &&'static str| format!("`{c}`"))
        .collect::<Vec<String>>()
        .join(", ");
    assert!(
        std::env::var_os(REQUIRE_TOOLCHAIN_VAR).is_none(),
        "{REQUIRE_TOOLCHAIN_VAR} makes an external toolchain mandatory, so {graded} cannot be \
         measured and must not report success: none of {names} is callable on PATH"
    );
    println!(
        "\nNOT MEASURED: {graded} was skipped because none of {names} is callable on PATH. Set \
         {REQUIRE_TOOLCHAIN_VAR}=1 to fail instead of skipping.\n"
    );
    None
}

pub fn crate_fixture_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(rel);
    p
}

pub fn crate_fixture_or_fail(rel: &str) -> Vec<u8> {
    let p: PathBuf = crate_fixture_path(rel);
    match std::fs::read(&p) {
        Ok(bytes) => bytes,
        Err(error) => panic!(
            "committed fixture {} is the graded reference for this suite and could not be read \
             ({error}); restore it from git rather than skipping the measurement",
            p.display()
        ),
    }
}

pub const ZIG_ELF: &str = "zig/hello.zig.elf";
pub const ZIG_RELEASEFAST_ELF: &str = "zig_modes/arith_releasefast_x86_64_linux.elf";
pub const ZIG_RELEASEFAST_PE: &str = "zig_modes/arith_releasefast_x86_64_windows.exe";
pub const ZIG_RELEASEFAST_MACHO: &str = "zig_modes/arith_releasefast_x86_64_macos.macho";
pub const ZIG_MODES_SOURCE: &str = "zig_modes/arith.zig";
pub const NIM_ELF: &str = "nim/hello.nim.elf";
pub const CRYSTAL_PE: &str = "crystal/hello.cr.exe";
pub const D_OBJ_ELF: &str = "d/hello.d.o.elf";
pub const D_PE: &str = "d/hello.d.exe";
pub const D_CLEAN_CONTROL: &str = "d/clean_control.exe";
