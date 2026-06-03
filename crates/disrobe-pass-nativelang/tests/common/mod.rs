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

pub const ZIG_ELF: &str = "zig/hello.zig.elf";
pub const NIM_ELF: &str = "nim/hello.nim.elf";
pub const CRYSTAL_PE: &str = "crystal/hello.cr.exe";
