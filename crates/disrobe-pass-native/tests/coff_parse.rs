#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{NativeFormat, detect_format, tiny_coff_x64};

#[test]
fn coff_x64_fixture_classified() {
    let d = detect_format(&tiny_coff_x64()).expect("coff");
    assert_eq!(d.kind, NativeFormat::Coff);
}

#[test]
#[ignore = "FIXTURE PENDING: real COFF object from MSVC toolchain needed for relocation parse"]
fn real_msvc_coff_object_relocation_parse() {}
