#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::fixtures::minimal_elf_relocatable_kmod;
use disrobe_pass_native::{NativeFormat, detect_format};

const REAL_RELOC_ELF: &[u8] = include_bytes!("../../../corpus/native/formats/hello_reloc.ko.o");

#[test]
fn kmod_relocatable_elf_fixture_classified() {
    let d = detect_format(&minimal_elf_relocatable_kmod()).expect("ko");
    assert_eq!(d.kind, NativeFormat::KernelModule);
}

#[test]
fn real_relocatable_elf64_classifies_as_kernel_module_shape() {
    let d = detect_format(REAL_RELOC_ELF).expect("detect real relocatable elf");
    assert_eq!(
        d.kind,
        NativeFormat::KernelModule,
        "a real ET_REL relocatable ELF64 object carries the kernel-module format shape; notes={:?}",
        d.notes
    );
    assert_eq!(d.bits, 64);
    assert!(
        d.notes.iter().any(|n: &String| n == "relocatable"),
        "e_type=ET_REL must be recorded as relocatable; got {:?}",
        d.notes
    );
    assert!(
        REAL_RELOC_ELF.starts_with(b"\x7FELF"),
        "fixture must be a real ELF object"
    );
    assert!(
        REAL_RELOC_ELF.len() < 256 * 1024,
        "fixture under 256KB budget"
    );
}
