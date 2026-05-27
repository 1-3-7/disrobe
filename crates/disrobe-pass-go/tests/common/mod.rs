#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use std::path::PathBuf;

pub fn fixture_path(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

pub fn fixture(name: &str) -> Vec<u8> {
    let p: PathBuf = fixture_path(name);
    match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) => panic!(
            "missing fixture {}: {e}; regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1",
            p.display()
        ),
    }
}

pub fn fixture_or_skip(name: &str) -> Option<Vec<u8>> {
    let p: PathBuf = fixture_path(name);
    let bytes: Option<Vec<u8>> = std::fs::read(&p).ok();
    if bytes.is_none() {
        eprintln!(
            "FIXTURE PENDING: {} missing; regenerate via crates/disrobe-pass-go/tests/fixtures/regen.ps1",
            p.display()
        );
    }
    bytes
}

pub const HELLO_NORMAL: &str = "hello_normal.exe";
pub const HELLO_STRIPPED: &str = "hello_stripped.exe";
pub const HELLO_GARBLE: &str = "hello_garble.exe";
