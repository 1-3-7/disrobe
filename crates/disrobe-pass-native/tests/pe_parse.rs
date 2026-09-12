#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::{FileIdReport, NativeFormat, detect_format, identify_file, minimal_pe32};

const REAL_PE64: &[u8] = include_bytes!("../../../corpus/native/formats/hello.pe64.exe");

#[test]
fn baked_pe32_fixture_classified() {
    let bytes: Vec<u8> = minimal_pe32();
    let d = detect_format(&bytes).expect("pe");
    assert!(matches!(d.kind, NativeFormat::Pe32 | NativeFormat::EfiPe));
}

#[test]
fn real_pe64_executable_classified() {
    let d = detect_format(REAL_PE64).expect("detect real pe64");
    assert_eq!(
        d.kind,
        NativeFormat::Pe64,
        "a real linked PE32+ executable must classify as Pe64; notes={:?}",
        d.notes
    );
    assert_eq!(d.bits, 64);
}

#[test]
fn real_pe64_directory_and_sections_parse() {
    let image: PeImage = parse_pe_image(REAL_PE64).expect("parse real PE image");
    assert!(
        !image.sections.is_empty(),
        "a real compiled PE must expose its section table"
    );
    let has_text: bool = image.sections.iter().any(|s| s.name_trimmed() == b".text");
    assert!(
        has_text,
        "the executable code section .text must be present in a real PE"
    );

    let report: FileIdReport = identify_file(REAL_PE64);
    assert_eq!(report.format, "pe64");
    assert_eq!(report.bits, 64);
    assert!(REAL_PE64.len() < 256 * 1024, "fixture under 256KB budget");
}
