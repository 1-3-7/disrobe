#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::minimal_efi_pe;
use disrobe_pass_native::{NativeFormat, detect_format};

#[test]
fn efi_pe_fixture_classified() {
    let d = detect_format(&minimal_efi_pe()).expect("efi");
    assert_eq!(d.kind, NativeFormat::EfiPe);
    assert_eq!(d.subsystem.as_deref(), Some("efi-application"));
}

#[test]
#[ignore = "FIXTURE PENDING: real UEFI .efi binary required for relocation + protocol-GUID parse"]
fn real_efi_uefi_binary_parse() {}
