#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_binfmt::{
    Arch, Endian, Error as BinfmtError, NativeFile, ParsedNativeFormat, classify_input,
    parse_native,
};
use disrobe_pass_native::fixtures::minimal_lx;
use disrobe_pass_native::{
    DetectedFormat, FileIdReport, NativeFormat, detect_format, identify_file,
};

const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
const REAL_OS2_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_os2_ne.exe");
const REAL_LX: &[u8] = include_bytes!("../../../corpus/native/formats/hello_lx.exe");

#[test]
fn validated_ne_fixture_classified() {
    let d = detect_format(REAL_NE).expect("ne");
    assert_eq!(d.kind, NativeFormat::Ne);
}

#[test]
fn lx_fixture_classified() {
    let d = detect_format(&minimal_lx()).expect("lx");
    assert_eq!(d.kind, NativeFormat::Lx);
}

fn new_header_sig(image: &[u8]) -> [u8; 2] {
    let lfanew: usize =
        u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    [image[lfanew], image[lfanew + 1]]
}

#[test]
fn real_legacy_binary_walk() {
    assert_eq!(
        &new_header_sig(REAL_NE),
        b"NE",
        "the real OpenWatcom build must carry a Win16 NE new-header signature"
    );
    let ne: DetectedFormat = detect_format(REAL_NE).expect("detect real NE");
    assert_eq!(
        ne.kind,
        NativeFormat::Ne,
        "a real Win16 NE executable must classify as Ne; notes={:?}",
        ne.notes
    );
    assert_eq!(ne.subsystem.as_deref(), Some("windows"));

    assert_eq!(
        &new_header_sig(REAL_LX),
        b"LX",
        "the real OpenWatcom build must carry an OS/2 LX new-header signature"
    );
    let lx: DetectedFormat = detect_format(REAL_LX).expect("detect real LX");
    assert_eq!(
        lx.kind,
        NativeFormat::Lx,
        "a real OS/2 LX executable must classify as Lx; notes={:?}",
        lx.notes
    );

    assert!(
        REAL_NE.len() < 256 * 1024 && REAL_LX.len() < 256 * 1024,
        "fixtures under 256KB budget"
    );
}

#[test]
fn real_ne_structure_reaches_the_shared_native_model() {
    let parsed: NativeFile = parse_native(REAL_NE).expect("parse real NE");
    assert_eq!(parsed.format, ParsedNativeFormat::NeWindows);
    assert_eq!(parsed.arch, Arch::X86);
    assert_eq!(parsed.bits, 16);
    assert_eq!(parsed.endian, Endian::Little);
    assert_eq!(parsed.segments.len(), 2);
    assert_eq!(parsed.sections.len(), 2);
    assert_eq!(parsed.imports.len(), 81);
    assert!(parsed.exports.is_empty());
    assert_eq!(
        parsed
            .symbols
            .iter()
            .map(|symbol: &disrobe_binfmt::SymbolInfo| { (symbol.name.as_str(), symbol.address) })
            .collect::<Vec<_>>(),
        vec![("entry", 0x0001_006c)]
    );
    assert_eq!(
        parsed
            .segments
            .iter()
            .map(|segment: &disrobe_binfmt::SegmentInfo| (segment.address, segment.size))
            .collect::<Vec<_>>(),
        vec![(0x0001_0000, 0x6a8c), (0x0002_0000, 0x09c0)]
    );
    let libraries: std::collections::BTreeSet<&str> = parsed
        .imports
        .iter()
        .map(|import: &disrobe_binfmt::ImportInfo| import.library.as_str())
        .collect();
    assert_eq!(
        libraries,
        std::collections::BTreeSet::from([
            "COMMDLG", "GDI", "KERNEL", "KEYBOARD", "USER", "WIN87EM"
        ])
    );
}

#[test]
fn detect_classification_names_ne_and_retains_its_parsed_model() {
    let classification: disrobe_binfmt::InputClassification =
        classify_input(std::path::Path::new("hello_ne.exe"), REAL_NE);
    assert!(classification.reason.contains("native Ne"));
    let parsed: NativeFile = classification.native.expect("parsed NE classification");
    assert_eq!(parsed.format, ParsedNativeFormat::NeWindows);
    assert_eq!(parsed.imports.len(), 81);
}

#[test]
fn identify_reports_the_ne_format_target_and_bitness() {
    let report: FileIdReport = identify_file(REAL_NE);
    assert_eq!(report.format, "ne");
    assert_eq!(report.bits, 16);
    assert_eq!(report.subsystem.as_deref(), Some("windows"));
}

fn ne_header_offset(image: &[u8]) -> usize {
    u32::from_le_bytes([image[0x3c], image[0x3d], image[0x3e], image[0x3f]]) as usize
}

fn assert_ne_error(image: &[u8]) {
    let error: BinfmtError = parse_native(image).expect_err("malformed NE must fail");
    assert!(matches!(error, BinfmtError::Ne(_)), "{error:?}");
}

#[test]
fn ne_parser_rejects_truncated_tables_zero_counts_overlaps_and_cycles() {
    let base: usize = ne_header_offset(REAL_NE);
    assert_ne_error(&REAL_NE[..base + 0x3f]);

    let mut zero_segments: Vec<u8> = REAL_NE.to_vec();
    zero_segments[base + 0x1c..base + 0x1e].copy_from_slice(&0u16.to_le_bytes());
    assert_ne_error(&zero_segments);

    let mut invalid_table: Vec<u8> = REAL_NE.to_vec();
    invalid_table[base + 0x22..base + 0x24].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_ne_error(&invalid_table);

    let segment_table: usize = base + 0x40;
    let mut overlapping: Vec<u8> = REAL_NE.to_vec();
    let first_sector: [u8; 2] = [overlapping[segment_table], overlapping[segment_table + 1]];
    overlapping[segment_table + 8..segment_table + 10].copy_from_slice(&first_sector);
    assert_ne_error(&overlapping);

    let mut cyclic_relocation: Vec<u8> = REAL_NE.to_vec();
    let first_segment_file_offset: usize = 0x0124;
    let first_source_offset: u16 = 0x311f;
    let first_source_index: usize = usize::from(first_source_offset);
    cyclic_relocation[first_segment_file_offset + first_source_index
        ..first_segment_file_offset + first_source_index + 2]
        .copy_from_slice(&first_source_offset.to_le_bytes());
    assert_ne_error(&cyclic_relocation);
}

#[test]
fn ne_parser_accepts_windows_and_os2_target_values() {
    let base: usize = ne_header_offset(REAL_NE);
    let mut os2: Vec<u8> = REAL_NE.to_vec();
    os2[base + 0x36] = 1;
    let parsed: NativeFile = parse_native(&os2).expect("OS/2 NE shares the parsed container");
    assert_eq!(parsed.format, ParsedNativeFormat::NeOs2);
    let detected: DetectedFormat = detect_format(&os2).expect("detect OS/2 NE");
    assert_eq!(detected.subsystem.as_deref(), Some("os2"));
}

#[test]
fn real_os2_ne_structure_reaches_the_shared_native_model() {
    let parsed: NativeFile = parse_native(REAL_OS2_NE).expect("parse real OS/2 NE");
    assert_eq!(parsed.format, ParsedNativeFormat::NeOs2);
    assert_eq!(parsed.arch, Arch::X86);
    assert_eq!(parsed.bits, 16);
    assert_eq!(parsed.endian, Endian::Little);
    assert_eq!(parsed.sections.len(), 2);
    assert_eq!(parsed.imports.len(), 6);
    assert!(parsed.exports.is_empty());
    assert_eq!(
        parsed
            .symbols
            .iter()
            .map(|symbol: &disrobe_binfmt::SymbolInfo| { (symbol.name.as_str(), symbol.address) })
            .collect::<Vec<_>>(),
        vec![("entry", 0x0001_0040)]
    );
    assert_eq!(
        parsed
            .segments
            .iter()
            .map(|segment: &disrobe_binfmt::SegmentInfo| (segment.address, segment.size))
            .collect::<Vec<_>>(),
        vec![(0x0001_0000, 0x0384), (0x0002_0000, 0x0060)]
    );
    let detected: DetectedFormat = detect_format(REAL_OS2_NE).expect("detect real OS/2 NE");
    assert_eq!(detected.subsystem.as_deref(), Some("os2"));
}
