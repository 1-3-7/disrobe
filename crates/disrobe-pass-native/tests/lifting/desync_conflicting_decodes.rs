#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use std::path::PathBuf;

use disrobe_pass_native::pass::analyze_deobf_report;
use disrobe_pass_native::{Bitness, ByteRange, DesyncReport, resolve_desync};

const BASE: u64 = 0x1000;

fn corpus(relative: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(relative);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} is tracked in git and this grade needs it: {error}",
            path.display()
        )
    })
}

#[test]
fn an_entry_ret_section_reports_unreached_bytes_and_no_junk() {
    let mut section: Vec<u8> = vec![0xC3];
    section.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]);
    section.extend_from_slice(b"an ordinary string table\0");
    let report: DesyncReport =
        resolve_desync(Bitness::Bits64, BASE, &section, &[BASE]).expect("resolve");
    assert!(
        report.junk_ranges.is_empty() && report.evidence().is_none(),
        "`entry: ret` leaves the rest of the section unreached, and no second decode disagrees \
         with the one instruction the walk reached: {report:?}"
    );
    assert_eq!(
        report.unreached_ranges,
        vec![ByteRange {
            start: BASE + 1,
            end: BASE + section.len() as u64,
        }],
        "the bytes the walk never reached are reported as unreached"
    );
    assert!(
        !report.cleaned_listing().contains("junk bytes elided"),
        "{}",
        report.cleaned_listing()
    );
}

#[test]
fn a_jump_over_a_junk_call_opcode_is_a_conflicting_decode() {
    let code: [u8; 12] = [
        0xEB, 0x01, 0xE8, 0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3, 0xCC,
    ];
    let report: DesyncReport =
        resolve_desync(Bitness::Bits64, BASE, &code, &[BASE]).expect("resolve");
    assert_eq!(
        report.junk_ranges,
        vec![ByteRange {
            start: BASE + 2,
            end: BASE + 3,
        }],
        "a linear sweep reads the E8 as call rel32 across the real push rbp; mov rbp,rsp, so the \
         two decodes disagree on exactly that byte: {report:?}"
    );
    assert!(report.evidence().is_some());
}

#[test]
fn ordinary_unpacked_pe_images_report_no_anti_disassembly() {
    for relative in [
        "native/packers/aspack/AccessEnum.original.exe",
        "native/packers/upx/hello.unpacked.exe",
    ] {
        let bytes: Vec<u8> = corpus(relative);
        let report = analyze_deobf_report(&bytes)
            .unwrap_or_else(|| panic!("{relative} has a decodable code section"));
        assert!(
            report.cleaned_listing.is_some(),
            "{relative}: the control needs a decoded section"
        );
        assert_eq!(
            report.anti_disassembly, None,
            "{relative} is compiler output with no anti-disassembly; unreached bytes are not junk"
        );
    }
}
