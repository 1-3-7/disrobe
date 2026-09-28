#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_nativelang::{FunctionStart, FunctionStartSource, NativeImage};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mobile/macho-mac/SwiftHello.original")
}

fn llvm_objdump_function_starts(path: &PathBuf) -> BTreeSet<u64> {
    let output: Output = Command::new("llvm-objdump")
        .arg("--macho")
        .arg("--function-starts")
        .arg(path)
        .output()
        .unwrap_or_else(|error| {
            panic!("llvm-objdump (LLVM 19, on PATH per AGENTS.md) is required: {error}")
        });
    assert!(
        output.status.success(),
        "llvm-objdump failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("llvm-objdump prints ascii")
        .lines()
        .filter_map(|line: &str| u64::from_str_radix(line.trim(), 16).ok())
        .collect()
}

#[test]
fn arm64_macho_function_starts_match_llvm_objdump() {
    let path: PathBuf = fixture();
    let bytes: Vec<u8> = std::fs::read(&path).expect("read the committed arm64 Mach-O");
    let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse the Mach-O");
    let recovered: BTreeSet<u64> = image
        .function_starts
        .iter()
        .filter(|start: &&FunctionStart| start.source == FunctionStartSource::MachOFunctionStarts)
        .map(|start: &FunctionStart| start.address)
        .collect();
    let reference: BTreeSet<u64> = llvm_objdump_function_starts(&path);
    assert!(
        !reference.is_empty(),
        "the fixture carries LC_FUNCTION_STARTS"
    );
    assert_eq!(recovered, reference);
}
