#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::{minimal_lx, minimal_ne};
use disrobe_pass_native::{NativeFormat, detect_format};

#[test]
fn ne_fixture_classified() {
    let d = detect_format(&minimal_ne()).expect("ne");
    assert_eq!(d.kind, NativeFormat::Ne);
}

#[test]
fn lx_fixture_classified() {
    let d = detect_format(&minimal_lx()).expect("lx");
    assert_eq!(d.kind, NativeFormat::Lx);
}

#[test]
#[ignore = "FIXTURE PENDING: real Win16/OS2 NE/LE/LX binaries needed for resource-table sweep"]
fn real_legacy_binary_walk() {}
