#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::{ExtractionResult, extract_to};

fn temp_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-legacy-{tag}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn expected(format_dir: &str, rel: &str) -> Vec<u8> {
    let path: PathBuf = common::corpus_binfmt_root()
        .join(format_dir)
        .join("expected")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("read {format_dir}/expected/{rel}"))
}

fn run(format_dir: &str, fixture: &str, kind: ContainerKind, member: &str) {
    let bytes: Vec<u8> = common::load_fixture(format_dir, fixture)
        .unwrap_or_else(|| panic!("missing fixture corpus/binfmt/{format_dir}/{fixture}"));
    assert_eq!(
        detect_container(&bytes),
        Some(kind),
        "{format_dir}/{fixture} must detect as {kind:?}"
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir(format_dir);
    let out: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(kind, &bytes, &out).unwrap_or_else(|e| panic!("extract {format_dir}: {e}"));
    assert_eq!(result.kind, kind);
    let want: Vec<u8> = expected(format_dir, member);
    let got: Vec<u8> = std::fs::read(out.join(member)).unwrap_or_else(|_| {
        panic!(
            "member {member} not recovered from {fixture}; violations: {:?}",
            result.integrity_violations
        )
    });
    assert_eq!(
        got, want,
        "{member} from {format_dir} must be byte-identical to the source"
    );
}

#[test]
fn arj_stored_member_byte_exact() {
    run("arj", "hello.arj", ContainerKind::Arj, "HELLO.TXT");
}

#[test]
fn arc_stored_member_byte_exact() {
    run("arc", "hello.arc", ContainerKind::Arc, "README.TXT");
}

#[test]
fn lzh_lh0_member_byte_exact() {
    run("lzh", "hello.lzh", ContainerKind::Lzh, "HELLO.TXT");
}

#[test]
fn lzop_stored_member_byte_exact() {
    run("lzop", "hello.lzo", ContainerKind::Lzo, "payload.txt");
}

#[test]
fn ar_short_named_member_byte_exact() {
    run("ar", "hello.a", ContainerKind::Ar, "short.o");
}

#[test]
fn ar_gnu_long_named_member_byte_exact() {
    run(
        "ar",
        "hello.a",
        ContainerKind::Ar,
        "a_very_long_member_name_that_exceeds_sixteen_chars.o",
    );
}
