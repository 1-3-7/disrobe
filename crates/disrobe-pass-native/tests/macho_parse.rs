#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::minimal_macho_fat;
use disrobe_pass_native::{NativeFormat, detect_format, minimal_macho64};

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
#[ignore = "FIXTURE PENDING: real universal Mach-O binary needed for slice-walking proof"]
fn real_universal_macho_walk() {}
