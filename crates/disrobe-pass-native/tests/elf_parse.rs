#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    FileIdReport, NativeFormat, detect_format, identify_file, minimal_elf64,
};

const REAL_ELF64: &[u8] = include_bytes!("../../../corpus/native/formats/hello.elf64");

#[test]
fn baked_elf64_fixture_classified() {
    let bytes: Vec<u8> = minimal_elf64();
    let d = detect_format(&bytes).expect("elf");
    assert_eq!(d.kind, NativeFormat::Elf64);
}

#[test]
fn real_elf64_executable_classified() {
    let d = detect_format(REAL_ELF64).expect("detect real elf64");
    assert_eq!(
        d.kind,
        NativeFormat::Elf64,
        "a linked ELF64 executable (e_type=ET_EXEC) must classify as Elf64, notes={:?}",
        d.notes
    );
    assert_eq!(d.bits, 64);
    assert!(
        d.notes.iter().any(|n: &String| n == "executable"),
        "e_type=2 must be recorded as executable; got {:?}",
        d.notes
    );
}

#[test]
fn real_elf64_identify_reports_elf_format() {
    let report: FileIdReport = identify_file(REAL_ELF64);
    assert_eq!(report.format, "elf64");
    assert_eq!(report.bits, 64);
    assert!(
        REAL_ELF64.len() < 256 * 1024,
        "fixture must stay under the 256KB corpus budget"
    );
}
