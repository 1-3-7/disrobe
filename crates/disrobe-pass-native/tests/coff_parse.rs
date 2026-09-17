#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{NativeFormat, detect_format, tiny_coff_x64};

const REAL_COFF: &[u8] = include_bytes!("../../../corpus/native/formats/hello.coff.x64.o");

#[test]
fn coff_x64_fixture_classified() {
    let d = detect_format(&tiny_coff_x64()).expect("coff");
    assert_eq!(d.kind, NativeFormat::Coff);
}

#[test]
fn real_msvc_coff_object_classified() {
    let d = detect_format(REAL_COFF).expect("detect real coff");
    assert_eq!(
        d.kind,
        NativeFormat::Coff,
        "a real x86-64 COFF object from the msvc target must classify as Coff; notes={:?}",
        d.notes
    );
    let machine: u16 = u16::from_le_bytes([REAL_COFF[0], REAL_COFF[1]]);
    assert_eq!(
        machine, 0x8664,
        "COFF header machine field must be IMAGE_FILE_MACHINE_AMD64 (0x8664)"
    );
    let number_of_sections: u16 = u16::from_le_bytes([REAL_COFF[2], REAL_COFF[3]]);
    assert!(
        number_of_sections > 0,
        "a real compiled object must carry at least one section"
    );
    assert!(REAL_COFF.len() < 256 * 1024, "fixture under 256KB budget");
}
