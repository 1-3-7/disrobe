#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::minimal_macho_fat;
use disrobe_pass_native::{
    FileIdReport, NativeFormat, detect_format, identify_file, minimal_macho64,
};

const REAL_MACHO64: &[u8] = include_bytes!("../../../corpus/native/formats/hello.macho64.o");

#[test]
fn baked_macho64_fixture_classified() {
    let d = detect_format(&minimal_macho64()).expect("macho");
    assert_eq!(d.kind, NativeFormat::MachO64);
}

#[test]
fn baked_macho_fat_fixture_classified() {
    let d = detect_format(&minimal_macho_fat()).expect("fat");
    assert_eq!(d.kind, NativeFormat::MachOFat);
}

#[test]
fn real_macho64_object_classified() {
    let d = detect_format(REAL_MACHO64).expect("detect real macho64");
    assert_eq!(
        d.kind,
        NativeFormat::MachO64,
        "a real x86-64 Mach-O object must classify as MachO64; notes={:?}",
        d.notes
    );
    let magic: u32 = u32::from_le_bytes([
        REAL_MACHO64[0],
        REAL_MACHO64[1],
        REAL_MACHO64[2],
        REAL_MACHO64[3],
    ]);
    assert_eq!(
        magic, 0xFEED_FACF,
        "little-endian 64-bit Mach-O magic MH_MAGIC_64 must be present"
    );
}

#[test]
fn real_macho64_identify_reports_macho_format() {
    let report: FileIdReport = identify_file(REAL_MACHO64);
    assert_eq!(report.format, "macho64");
    assert!(
        REAL_MACHO64.len() < 256 * 1024,
        "fixture under 256KB budget"
    );
}
