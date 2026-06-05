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
            "\n========================================================================\n\
             SKIPPED: fixture `{name}` absent at {}.\n\
             This assertion did NOT run and is NOT CI-enforced. A green result here is\n\
             a SKIP, not a measured pass. Regenerate the fixtures (Go toolchain required):\n\
             pwsh crates/disrobe-pass-go/tests/fixtures/regen.ps1\n\
             ========================================================================\n",
            p.display()
        );
    }
    bytes
}

pub const HELLO_NORMAL: &str = "hello_normal.exe";
pub const HELLO_STRIPPED: &str = "hello_stripped.exe";
pub const HELLO_GARBLE: &str = "hello_garble.exe";
pub const HELLO_EMBED: &str = "hello_embed.exe";
pub const HELLO_GENERICS: &str = "hello_generics.exe";
pub const HELLO_GENERICS_STRIPPED: &str = "hello_generics_stripped.exe";

const PCLNTAB_MAGICS: [[u8; 4]; 4] = [
    [0xfb, 0xff, 0xff, 0xff],
    [0xfa, 0xff, 0xff, 0xff],
    [0xf0, 0xff, 0xff, 0xff],
    [0xf1, 0xff, 0xff, 0xff],
];

pub fn find_pclntab_offset(bytes: &[u8]) -> Option<usize> {
    let mut i: usize = 0;
    while i + 16 <= bytes.len() {
        for magic in &PCLNTAB_MAGICS {
            if &bytes[i..i + 4] == magic
                && bytes[i + 4] == 0
                && bytes[i + 5] == 0
                && matches!(bytes[i + 6], 1 | 2 | 4)
                && matches!(bytes[i + 7], 4 | 8)
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub fn fixture_with_patched_pclntab(name: &str, patch: impl Fn(&mut [u8])) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = fixture_or_skip(name)?;
    let off: usize = find_pclntab_offset(&bytes)?;
    let end: usize = (off + 128).min(bytes.len());
    patch(&mut bytes[off..end]);
    Some(bytes)
}
