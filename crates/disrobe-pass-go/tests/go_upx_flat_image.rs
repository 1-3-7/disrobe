#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use object::Object as _;
use object::ObjectSection as _;
use object::read::File as ObjFile;

use disrobe_pass_go::{Error, analyze};

fn carve_in_memory_image(pe_bytes: &[u8]) -> Vec<u8> {
    let file: ObjFile<'_, &[u8]> = ObjFile::parse(pe_bytes).expect("parse reference pe");
    let mut min_addr: u64 = u64::MAX;
    let mut max_end: u64 = 0;
    for sec in file.sections() {
        let addr: u64 = sec.address();
        let data: &[u8] = sec.data().unwrap_or(b"");
        if data.is_empty() || addr == 0 {
            continue;
        }
        min_addr = min_addr.min(addr);
        max_end = max_end.max(addr + data.len() as u64);
    }
    assert!(max_end > min_addr, "reference pe has no mapped sections");
    let span: usize = usize::try_from(max_end - min_addr).expect("span fits usize");
    let mut flat: Vec<u8> = vec![0u8; span];
    for sec in file.sections() {
        let addr: u64 = sec.address();
        let data: &[u8] = sec.data().unwrap_or(b"");
        if data.is_empty() || addr < min_addr {
            continue;
        }
        let off: usize = usize::try_from(addr - min_addr).expect("offset fits usize");
        let end: usize = off + data.len();
        if end <= flat.len() {
            flat[off..end].copy_from_slice(data);
        }
    }
    flat
}

fn assert_headerless_refusal(bytes: &[u8]) {
    let error: Error = analyze(bytes).expect_err("headerless bytes must not enter Go recovery");
    assert!(matches!(error, Error::HeaderlessEpochUnproven));
}

#[test]
fn flat_image_is_not_a_recognized_container() {
    let pe: Vec<u8> = common::fixture(common::HELLO_EMBED);
    let flat: Vec<u8> = carve_in_memory_image(&pe);
    assert!(
        object::read::FileKind::parse(flat.as_slice()).is_err(),
        "the carved image must not retain a native container header",
    );
}

#[test]
fn headerless_unpacked_image_refuses_pointer_recovery() {
    let pe: Vec<u8> = common::fixture(common::HELLO_EMBED);
    let flat: Vec<u8> = carve_in_memory_image(&pe);
    assert_headerless_refusal(&flat);
}

#[test]
fn headerless_386_image_refuses_before_symbol_recovery() {
    let pe: Vec<u8> = common::fixture(common::HELLO_386);
    let flat: Vec<u8> = carve_in_memory_image(&pe);
    assert_headerless_refusal(&flat);
}

#[test]
fn headerless_garble_image_refuses_before_literal_recovery() {
    let pe: Vec<u8> = common::fixture(common::HELLO_GARBLE);
    let flat: Vec<u8> = carve_in_memory_image(&pe);
    assert_headerless_refusal(&flat);
}

#[test]
fn headerless_garble_literal_image_refuses_before_literal_recovery() {
    let pe: Vec<u8> = common::fixture(common::GARBLE_LITERALS_INDIRECT);
    let flat: Vec<u8> = carve_in_memory_image(&pe);
    assert_headerless_refusal(&flat);
}

#[test]
fn unrecognized_bytes_do_not_claim_headerless_go_provenance() {
    let blob: Vec<u8> = vec![0x42u8; 4096];
    let error: Error = analyze(&blob).expect_err("opaque bytes must not analyze as Go");
    assert!(matches!(error, Error::UnrecognizedContainer));
}
