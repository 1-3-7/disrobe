#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_nativelang::{FunctionStart, FunctionStartSource, NativeImage};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/mobile/macho-mac/SwiftHello.original")
}

const OBJDUMP_CANDIDATES: [&str; 6] = [
    "llvm-objdump",
    "llvm-objdump-20",
    "llvm-objdump-19",
    "llvm-objdump-18",
    "llvm-objdump-17",
    "objdump",
];

fn llvm_objdump() -> &'static str {
    OBJDUMP_CANDIDATES
        .into_iter()
        .find(|candidate: &&str| {
            Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output: Output| {
                    output.status.success()
                        && String::from_utf8_lossy(&output.stdout).contains("LLVM")
                })
        })
        .unwrap_or_else(|| {
            panic!(
                "an LLVM objdump is required as the function-starts reference; none of {OBJDUMP_CANDIDATES:?} reports LLVM"
            )
        })
}

fn llvm_objdump_function_starts(path: &PathBuf) -> BTreeSet<u64> {
    let tool: &str = llvm_objdump();
    let output: Output = Command::new(tool)
        .arg("--macho")
        .arg("--function-starts")
        .arg(path)
        .output()
        .unwrap_or_else(|error| panic!("running {tool}: {error}"));
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
