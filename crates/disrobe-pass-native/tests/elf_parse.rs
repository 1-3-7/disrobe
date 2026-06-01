#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{NativeFormat, detect_format, minimal_elf64};

#[test]
fn baked_elf64_fixture_classified() {
    let bytes: Vec<u8> = minimal_elf64();
    let d = detect_format(&bytes).expect("elf");
    assert_eq!(d.kind, NativeFormat::Elf64);
}

#[test]
#[ignore = "FIXTURE PENDING: real stripped ELF64 binary required for full segments/symbols sweep"]
fn real_elf64_full_parse() {}
