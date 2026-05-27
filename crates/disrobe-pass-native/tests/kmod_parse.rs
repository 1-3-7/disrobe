#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::minimal_elf_relocatable_kmod;
use disrobe_pass_native::{NativeFormat, detect_format};

#[test]
fn kmod_relocatable_elf_fixture_classified() {
    let d = detect_format(&minimal_elf_relocatable_kmod()).expect("ko");
    assert_eq!(d.kind, NativeFormat::KernelModule);
}

#[test]
#[ignore = "FIXTURE PENDING: real Linux .ko with .modinfo + signing trailer required"]
fn real_linux_ko_with_modinfo_parse() {}
