#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{NativeFormat, detect_format, minimal_pe32};

#[test]
fn baked_pe32_fixture_classified() {
    let bytes: Vec<u8> = minimal_pe32();
    let d = detect_format(&bytes).expect("pe");
    assert!(matches!(d.kind, NativeFormat::Pe32 | NativeFormat::EfiPe));
}

#[test]
#[ignore = "FIXTURE PENDING: real signed PE32+ binary required to exercise full directory parsing"]
fn real_pe_signed_directory_parse() {}
