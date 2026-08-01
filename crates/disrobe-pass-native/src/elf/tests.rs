use std::path::{Path, PathBuf};

use super::*;

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .join("corpus")
}

fn read_corpus(rel: &str) -> Option<Vec<u8>> {
    std::fs::read(corpus_root().join(rel)).ok()
}

#[test]
fn dynamic_fixture_matches_readelf_d_ground_truth() {
    let Some(bytes): Option<Vec<u8>> = read_corpus("binfmt/elf-dynamic/sample.elf") else {
        eprintln!("skip: corpus/binfmt/elf-dynamic/sample.elf absent");
        return;
    };
    let report: ElfDynamicReport = analyze(&bytes).expect("parse dynamic elf");

    assert_eq!(report.class, ElfClass::Elf64);
    assert_eq!(report.data, ElfData::Little);

    assert_eq!(
        report.needed,
        vec!["libc.so.6".to_owned(), "libm.so.6".to_owned()],
        "DT_NEEDED order and contents must equal readelf -d",
    );
    assert_eq!(report.soname.as_deref(), Some("libsample.so.1"));
    assert_eq!(report.rpath.as_deref(), Some("/opt/legacy/lib"));
    assert_eq!(
        report.runpath.as_deref(),
        Some("$ORIGIN/../lib:/usr/local/sample/lib"),
    );

    assert_eq!(
        report.dynamic_entry_count, 8,
        "readelf -d reports 8 dynamic entries including the terminating NULL",
    );

    let dynamic_segment: bool = report
        .segments
        .iter()
        .any(|s: &SegmentMapping| s.kind == "dynamic" && s.virtual_addr == 0x1110);
    assert!(dynamic_segment, "PT_DYNAMIC at vaddr 0x1110 must be mapped");

    let load_segment: &SegmentMapping = report
        .segments
        .iter()
        .find(|s: &&SegmentMapping| s.kind == "load")
        .expect("PT_LOAD present");
    assert_eq!(load_segment.virtual_addr, 0x1000);
    assert!(load_segment.readable && load_segment.executable && !load_segment.writable);
}

#[test]
fn pyarmor_runtime_so_recovers_needed_symbols_and_relocs_like_readelf() {
    let Some(bytes): Option<Vec<u8>> =
        read_corpus("python/pyarmor/v9/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so")
    else {
        eprintln!("skip: pyarmor_runtime.so absent");
        return;
    };
    let report: ElfDynamicReport = analyze(&bytes).expect("parse pyarmor runtime so");

    assert_eq!(report.class, ElfClass::Elf64);
    assert_eq!(
        report.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libdl.so.2".to_owned(),
            "libc.so.6".to_owned(),
        ],
        "NEEDED list must match readelf -d output exactly",
    );

    assert_eq!(
        report.init,
        Some(0x96d0),
        "DT_INIT must equal readelf 0x96d0"
    );
    assert_eq!(
        report.fini,
        Some(0xa52a8),
        "DT_FINI must equal readelf 0xa52a8"
    );

    assert_eq!(
        report.symbol_count_source,
        Some(SymbolCountSource::GnuHash),
        "the .gnu.hash chain drives the symbol count",
    );
    assert_eq!(
        report.symbols.len(),
        321,
        "readelf --dyn-syms reports 321 .dynsym entries; gnu.hash chain count must equal it",
    );

    let exported: &DynamicSymbol = report
        .symbols
        .iter()
        .find(|s: &&DynamicSymbol| s.name == "PyInit_pyarmor_runtime")
        .expect("the one exported init function nm -D reports as T");
    assert!(
        exported.defined,
        "PyInit_pyarmor_runtime is a defined export"
    );
    assert_eq!(
        exported.value, 0x10600,
        "nm -D address of PyInit_pyarmor_runtime is 0x10600",
    );
    assert_eq!(exported.sym_type, SymbolType::Func);
    assert_eq!(exported.bind, SymbolBind::Global);

    let imported: &DynamicSymbol = report
        .symbols
        .iter()
        .find(|s: &&DynamicSymbol| s.name == "PyUnicode_FromFormat")
        .expect("nm -D lists PyUnicode_FromFormat as U");
    assert!(
        !imported.defined,
        "PyUnicode_FromFormat is an undefined import"
    );

    let undefined: usize = report
        .symbols
        .iter()
        .filter(|s: &&DynamicSymbol| {
            !s.defined
                && matches!(s.bind, SymbolBind::Global | SymbolBind::Weak)
                && !s.name.is_empty()
        })
        .count();
    assert!(
        undefined >= 300,
        "nm -D lists 310 undefined imports; recovered {undefined} should be in that ballpark",
    );

    assert!(
        !report.relocations.is_empty(),
        "RELA + JMPREL relocations are present in this PIE and must be read",
    );
    let named_reloc: bool = report
        .relocations
        .iter()
        .any(|r: &Relocation| r.symbol_name.as_deref() == Some("PyUnicode_FromFormat"));
    assert!(
        named_reloc,
        "at least one relocation must resolve to the PyUnicode_FromFormat import symbol",
    );
}

#[test]
fn truncated_and_non_elf_inputs_yield_none_not_panic() {
    assert!(analyze(&[]).is_none());
    assert!(analyze(b"\x7FELF").is_none());
    assert!(analyze(b"MZ\x90\x00").is_none());
    let mut header_only: Vec<u8> = vec![0u8; 64];
    header_only[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    header_only[4] = 2;
    header_only[5] = 1;
    let report: ElfDynamicReport = analyze(&header_only).expect("bare elf header parses");
    assert!(report.needed.is_empty());
    assert!(report.symbols.is_empty());
}

#[test]
fn extended_program_header_count_reads_section_zero_info() {
    let section_offset: usize = 64;
    let section_offset_u64: u64 = 64;
    let mut bytes: Vec<u8> = vec![0u8; section_offset + 64];
    bytes[section_offset + 44..section_offset + 48]
        .copy_from_slice(&u32::from(PN_XNUM).to_le_bytes());
    let count: Option<SectionTableValidation> = validate_section_table(
        &bytes,
        ElfClass::Elf64,
        Endian { little: true },
        section_offset_u64,
        64,
        1,
        0,
        PN_XNUM,
    );
    assert!(matches!(
        count,
        Some(SectionTableValidation::ExtendedProgramCount(value)) if value == usize::from(PN_XNUM)
    ));
    bytes[section_offset + 44..section_offset + 48]
        .copy_from_slice(&(u32::from(PN_XNUM) - 1).to_le_bytes());
    let malformed: Option<SectionTableValidation> = validate_section_table(
        &bytes,
        ElfClass::Elf64,
        Endian { little: true },
        section_offset_u64,
        64,
        1,
        0,
        PN_XNUM,
    );
    assert_eq!(malformed, None);
}

#[test]
fn extended_section_name_index_uses_section_zero_link() {
    const SECTION_OFFSET: usize = 64;
    const SECTION_ENTRY_SIZE: usize = 64;
    const SECTION_COUNT: usize = 0xff01;
    let mut bytes: Vec<u8> = vec![0u8; SECTION_OFFSET + SECTION_ENTRY_SIZE * SECTION_COUNT];
    bytes[SECTION_OFFSET + 32..SECTION_OFFSET + 40]
        .copy_from_slice(&(SECTION_COUNT as u64).to_le_bytes());
    bytes[SECTION_OFFSET + 40..SECTION_OFFSET + 44]
        .copy_from_slice(&u32::from(SHN_LORESERVE).to_le_bytes());
    let valid: Option<SectionTableValidation> = validate_section_table(
        &bytes,
        ElfClass::Elf64,
        Endian { little: true },
        SECTION_OFFSET as u64,
        64,
        0,
        SHN_XINDEX,
        1,
    );
    assert!(matches!(
        valid,
        Some(SectionTableValidation::NoExtendedProgramCount)
    ));
    bytes[SECTION_OFFSET + 40..SECTION_OFFSET + 44].copy_from_slice(&0xffu32.to_le_bytes());
    let malformed: Option<SectionTableValidation> = validate_section_table(
        &bytes,
        ElfClass::Elf64,
        Endian { little: true },
        SECTION_OFFSET as u64,
        64,
        0,
        SHN_XINDEX,
        1,
    );
    assert_eq!(malformed, None);
}

#[test]
fn fuzz_truncations_never_panic() {
    let Some(full): Option<Vec<u8>> =
        read_corpus("python/pyarmor/v9/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so")
    else {
        eprintln!("skip: pyarmor_runtime.so absent");
        return;
    };
    for cut in (0..full.len()).step_by(4099) {
        let _ = analyze(&full[..cut]);
    }
    let mut corrupted: Vec<u8> = full;
    for i in (0..corrupted.len()).step_by(257) {
        corrupted[i] = corrupted[i].wrapping_add(0x5A);
    }
    let _ = analyze(&corrupted);
}
