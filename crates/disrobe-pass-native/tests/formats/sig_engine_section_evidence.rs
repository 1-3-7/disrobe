#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use std::path::PathBuf;

use disrobe_pass_native::analyze_signatures;
use disrobe_pass_native::sig_engine::{SigMatch, SigReport, StructFamily, StructFinding};

const PE_OFFSET: usize = 0x80;
const OPTIONAL_HEADER_SIZE: usize = 0xE0;
const SECTION_TABLE: usize = PE_OFFSET + 4 + 20 + OPTIONAL_HEADER_SIZE;
const FILE_ALIGNMENT: usize = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;

struct Section<'a> {
    name: &'a [u8],
    data: Vec<u8>,
}

fn pe32(sections: &[Section<'_>], entry_section: usize) -> Vec<u8> {
    let headers: usize = 0x400;
    let mut buf: Vec<u8> = vec![0u8; headers];
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3C..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
    buf[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
    let coff: usize = PE_OFFSET + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014C_u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(OPTIONAL_HEADER_SIZE as u16).to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102_u16.to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010B_u16.to_le_bytes());
    let entry_rva: u32 = SECTION_ALIGNMENT * (entry_section as u32 + 1);
    buf[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
    buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000_u32.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
    let image_size: u32 = SECTION_ALIGNMENT * (sections.len() as u32 + 1);
    buf[opt + 56..opt + 60].copy_from_slice(&image_size.to_le_bytes());
    buf[opt + 60..opt + 64].copy_from_slice(&(headers as u32).to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&2_u16.to_le_bytes());
    buf[opt + 92..opt + 96].copy_from_slice(&16_u32.to_le_bytes());
    for (index, section) in sections.iter().enumerate() {
        let raw_pointer: usize = buf.len();
        let raw_size: usize = section.data.len().div_ceil(FILE_ALIGNMENT) * FILE_ALIGNMENT;
        buf.extend_from_slice(&section.data);
        buf.resize(raw_pointer + raw_size, 0);
        let entry: usize = SECTION_TABLE + index * 40;
        buf[entry..entry + section.name.len()].copy_from_slice(section.name);
        let virtual_address: u32 = SECTION_ALIGNMENT * (index as u32 + 1);
        buf[entry + 8..entry + 12].copy_from_slice(&(section.data.len() as u32).to_le_bytes());
        buf[entry + 12..entry + 16].copy_from_slice(&virtual_address.to_le_bytes());
        buf[entry + 16..entry + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        buf[entry + 20..entry + 24].copy_from_slice(&(raw_pointer as u32).to_le_bytes());
        buf[entry + 36..entry + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    }
    buf
}

fn vb6_entry() -> Vec<u8> {
    let mut code: Vec<u8> = vec![
        0x68, 0x40, 0x12, 0x40, 0x00, 0xE8, 0xEE, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0x00, 0x00,
        0x00, 0x30, 0x00, 0x00, 0x00,
    ];
    code.resize(0x400, 0xCC);
    code
}

fn vmprotect_families(report: &SigReport) -> Vec<String> {
    let mut out: Vec<String> = report
        .structured
        .iter()
        .filter(|f: &&StructFinding| f.family == StructFamily::VmProtect)
        .map(|f: &StructFinding| f.locus.clone())
        .collect();
    out.extend(
        report
            .matches
            .iter()
            .filter(|m: &&SigMatch| m.family == "vmprotect")
            .map(|m: &SigMatch| m.marker.to_owned()),
    );
    out
}

#[test]
fn a_vb6_entry_with_an_ordinary_section_table_is_not_vmprotect() {
    let bytes: Vec<u8> = pe32(
        &[
            Section {
                name: b".text",
                data: vb6_entry(),
            },
            Section {
                name: b".data",
                data: vec![0u8; 0x200],
            },
            Section {
                name: b".rsrc",
                data: vec![0u8; 0x200],
            },
        ],
        0,
    );
    let report: SigReport = analyze_signatures(&bytes);
    let hits: Vec<String> = vmprotect_families(&report);
    assert!(
        hits.is_empty(),
        "push VBHeader; call ThunRTMain is the VB5/6 runtime entry, and without a .vmp section it \
         is no VMProtect evidence: {hits:?}"
    );
}

#[test]
fn the_same_entry_behind_a_vmp_section_table_is_vmprotect() {
    let bytes: Vec<u8> = pe32(
        &[
            Section {
                name: b".text",
                data: vec![0xC3; 0x200],
            },
            Section {
                name: b".vmp0",
                data: vec![0u8; 0x200],
            },
            Section {
                name: b".vmp1",
                data: vb6_entry(),
            },
        ],
        2,
    );
    let report: SigReport = analyze_signatures(&bytes);
    assert!(
        report.structured.iter().any(|f: &StructFinding| {
            f.family == StructFamily::VmProtect && f.locus.starts_with("entry point")
        }),
        "the vm-entry template must still fire when the section table names .vmp sections: {:?}",
        report.structured
    );
}

#[test]
fn a_section_name_match_reports_the_section_header_file_offset() {
    let bytes: Vec<u8> = pe32(
        &[
            Section {
                name: b".text",
                data: vec![0xC3; 0x200],
            },
            Section {
                name: b".data",
                data: vec![0u8; 0x200],
            },
            Section {
                name: b".vmp0",
                data: vec![0u8; 0x200],
            },
        ],
        0,
    );
    let report: SigReport = analyze_signatures(&bytes);
    let vmp: &SigMatch = report
        .matches
        .iter()
        .find(|m: &&SigMatch| m.marker == ".vmp0 section name")
        .expect(".vmp0 in the section table must match");
    let header_offset: u64 = (SECTION_TABLE + 2 * 40) as u64;
    assert_eq!(
        vmp.matched_offset, header_offset,
        "matched_offset is a file offset: the third section header sits at {header_offset:#x}, \
         not at section index 2"
    );
    assert_eq!(
        &bytes[header_offset as usize..header_offset as usize + 5],
        b".vmp0"
    );
}

#[test]
fn section_name_signatures_never_fall_back_to_a_byte_search() {
    let mut text: Vec<u8> = vec![0xC3; 0x400];
    text[0x100..0x105].copy_from_slice(b".vmp0");
    text[0x200..0x204].copy_from_slice(b"MEWT");
    let bytes: Vec<u8> = pe32(
        &[Section {
            name: b".text",
            data: text,
        }],
        0,
    );
    let report: SigReport = analyze_signatures(&bytes);
    let named: Vec<&SigMatch> = report
        .matches
        .iter()
        .filter(|m: &&SigMatch| m.family == "vmprotect" || m.family == "mew")
        .collect();
    assert!(
        named.is_empty(),
        "section names in section data are not section-table evidence: {named:?}"
    );
}

#[test]
fn mew_does_not_match_mewt_in_a_committed_mingw_build() {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/native/packers/upx/git.original.exe");
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("{} is tracked in git: {error}", path.display()));
    assert!(
        bytes.windows(4).any(|w: &[u8]| w == b"MEWT"),
        "the control needs the MEWT byte run this grade is about"
    );
    let report: SigReport = analyze_signatures(&bytes);
    let mew: Vec<&SigMatch> = report
        .matches
        .iter()
        .filter(|m: &&SigMatch| m.family == "mew")
        .collect();
    assert!(
        mew.is_empty(),
        "git.exe is an unpacked MinGW build whose section table has no MEW section: {mew:?}"
    );
}
