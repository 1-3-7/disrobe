#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::minimal_efi_pe;
use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::{NativeFormat, detect_format};

const REAL_EFI: &[u8] = include_bytes!("../../../corpus/native/formats/hello.efi");

#[test]
fn efi_pe_fixture_classified() {
    let d = detect_format(&minimal_efi_pe()).expect("efi");
    assert_eq!(d.kind, NativeFormat::EfiPe);
    assert_eq!(d.subsystem.as_deref(), Some("efi-application"));
}

#[test]
fn real_efi_uefi_binary_classified() {
    let d = detect_format(REAL_EFI).expect("detect real efi");
    assert_eq!(
        d.kind,
        NativeFormat::EfiPe,
        "a real x86_64-unknown-uefi PE32+ must classify as EfiPe; notes={:?}",
        d.notes
    );
    assert_eq!(
        d.subsystem.as_deref(),
        Some("efi-application"),
        "PE subsystem field 10 must be read as efi-application"
    );
}

#[test]
fn real_efi_pe_image_parses_sections() {
    let image: PeImage = parse_pe_image(REAL_EFI).expect("parse real EFI PE");
    assert!(
        image.is_pe32_plus,
        "a UEFI image is always PE32+ (optional-header magic 0x20b)"
    );
    assert!(
        !image.sections.is_empty(),
        "a real EFI binary must expose its section table"
    );
    assert!(
        image.sections.iter().any(|s| s.name_trimmed() == b".text"),
        "the EFI entry code section must be present"
    );
    assert!(REAL_EFI.len() < 256 * 1024, "fixture under 256KB budget");
}
