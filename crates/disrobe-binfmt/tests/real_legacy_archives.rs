#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::{arc_entry_bytes, parse_arc};
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
    run("arj", "method0.arj", ContainerKind::Arj, "hello.txt");
}

#[test]
fn arc_stored_member_byte_exact() {
    run("arc", "hello.arc", ContainerKind::Arc, "README.TXT");
}

#[test]
fn arc_fixed_lzw_methods_are_byte_exact() {
    for member in ["METHOD5.BIN", "METHOD6.BIN", "METHOD7.BIN"] {
        run("arc", "methods.arc", ContainerKind::Arc, member);
    }
}

#[test]
fn historical_arc_method6_member_is_byte_exact() {
    run("arc", "dosamatc.arc", ContainerKind::Arc, "COMPAQ.BAT");
}

#[test]
fn arc_dynamic_lzw_methods_are_byte_exact() {
    for (fixture, member) in [
        ("method8-rle.arc", "DreamAlone"),
        ("method9.arc", "crystals.669"),
    ] {
        run("arc", fixture, ContainerKind::Arc, member);
    }
}

#[test]
fn arc_dynamic_lzw_real_wires_reject_framing_and_body_mutations() {
    let method8: Vec<u8> =
        common::load_fixture("arc", "method8-rle.arc").expect("load method 8 fixture");
    let method8_archive: disrobe_binfmt::containers::ArcArchive =
        parse_arc(&method8).expect("parse method 8 fixture");
    let mut wrong_width: Vec<u8> = method8;
    wrong_width[method8_archive.entries[0].data_offset] = 11;
    let wrong_width_archive: disrobe_binfmt::containers::ArcArchive =
        parse_arc(&wrong_width).expect("parse wrong-width fixture");
    assert!(arc_entry_bytes(&wrong_width, &wrong_width_archive.entries[0], 1 << 20).is_err());

    let mut method9: Vec<u8> =
        common::load_fixture("arc", "method9.arc").expect("load method 9 fixture");
    let archive: disrobe_binfmt::containers::ArcArchive =
        parse_arc(&method9).expect("parse method 9 fixture");
    let entry: &disrobe_binfmt::containers::ArcEntry = &archive.entries[0];
    let data_end: usize = entry.data_offset + entry.compressed_size as usize;
    method9.insert(data_end, 0);
    method9[15..19].copy_from_slice(&(entry.compressed_size + 1).to_le_bytes());
    let appended_archive: disrobe_binfmt::containers::ArcArchive =
        parse_arc(&method9).expect("parse appended method 9 fixture");
    assert!(arc_entry_bytes(&method9, &appended_archive.entries[0], 1 << 20).is_err());

    let mut changed_body: Vec<u8> =
        common::load_fixture("arc", "method9.arc").expect("reload method 9 fixture");
    changed_body[entry.data_offset + 17] ^= 0x40;
    let changed_archive: disrobe_binfmt::containers::ArcArchive =
        parse_arc(&changed_body).expect("parse changed method 9 fixture");
    assert!(arc_entry_bytes(&changed_body, &changed_archive.entries[0], 1 << 20).is_err());
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
