#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_typerec::import_map::{ImportFormat, ImportMap, ImportRef, ImportSource};
use object::elf::{R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT};
use object::{File, Object, ObjectSymbol, ObjectSymbolTable, RelocationFlags, RelocationTarget};

fn fixture(name: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn low(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_lowercase()
}

fn pe_named_set(map: &ImportMap) -> BTreeSet<(String, String)> {
    map.by_slot_va
        .values()
        .filter(|entry: &&ImportRef| matches!(entry.source, ImportSource::PeImport))
        .filter_map(|entry: &ImportRef| {
            entry.name().map(|name: &str| {
                (
                    entry.library.to_ascii_lowercase(),
                    name.to_ascii_lowercase(),
                )
            })
        })
        .collect()
}

#[test]
fn pe_import_set_matches_object_high_level() {
    let bytes: Vec<u8> = fixture("imports_pe.exe");
    let map: ImportMap = ImportMap::from_image(&bytes);
    assert_eq!(map.format, ImportFormat::Pe);
    assert_eq!(map.image_base, 0x1_4000_0000);

    let mine: BTreeSet<(String, String)> = pe_named_set(&map);

    let file: File<'_> = File::parse(&*bytes).expect("object parse pe");
    let theirs: BTreeSet<(String, String)> = file
        .imports()
        .expect("object imports")
        .iter()
        .map(|imp: &object::Import<'_>| (low(imp.library()), low(imp.name())))
        .collect();

    eprintln!(
        "pe differential: typerec={} object={} slots={}",
        mine.len(),
        theirs.len(),
        map.by_slot_va.len()
    );
    for entry in &mine {
        eprintln!("  {}!{}", entry.0, entry.1);
    }

    assert!(!theirs.is_empty(), "fixture must import named symbols");
    assert_eq!(mine, theirs, "typerec import set must match object");
    assert!(theirs.contains(&("kernel32.dll".to_owned(), "getmodulehandlea".to_owned())));
    assert!(theirs.contains(&("kernel32.dll".to_owned(), "exitprocess".to_owned())));

    for (&slot_va, entry) in &map.by_slot_va {
        assert_eq!(map.resolve(slot_va), Some(entry));
    }
}

#[test]
fn elf_dynamic_relocations_match_object_high_level() {
    let bytes: Vec<u8> = fixture("imports_elf.so");
    let map: ImportMap = ImportMap::from_image(&bytes);
    assert_eq!(map.format, ImportFormat::Elf);

    let mine: BTreeMap<u64, String> = map
        .by_slot_va
        .iter()
        .filter(|(_, entry): &(&u64, &ImportRef)| {
            matches!(
                entry.source,
                ImportSource::ElfJumpSlot | ImportSource::ElfGlobData
            )
        })
        .filter_map(|(&slot_va, entry): (&u64, &ImportRef)| {
            entry.name().map(|name: &str| (slot_va, name.to_owned()))
        })
        .collect();

    let file: File<'_> = File::parse(&*bytes).expect("object parse elf");
    let dynsym: Option<object::SymbolTable<'_, '_>> = file.dynamic_symbol_table();
    let mut theirs: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(relocations) = file.dynamic_relocations() {
        for (addr, reloc) in relocations {
            let RelocationFlags::Elf { r_type } = reloc.flags() else {
                continue;
            };
            if r_type != R_X86_64_JUMP_SLOT && r_type != R_X86_64_GLOB_DAT {
                continue;
            }
            let RelocationTarget::Symbol(index): RelocationTarget = reloc.target() else {
                continue;
            };
            let Some(table): &Option<object::SymbolTable<'_, '_>> = &dynsym else {
                continue;
            };
            let symbol: object::Symbol<'_, '_> =
                table.symbol_by_index(index).expect("dynamic symbol");
            let name: &str = symbol.name().expect("symbol name");
            theirs.insert(addr, name.to_owned());
        }
    }

    eprintln!(
        "elf differential: typerec={} object={}",
        mine.len(),
        theirs.len()
    );
    for (slot_va, name) in &theirs {
        eprintln!("  {slot_va:#x} {name}");
    }

    assert!(!theirs.is_empty(), "fixture must have dynamic imports");
    assert_eq!(mine, theirs, "typerec slot map must match object");

    let names: BTreeSet<&str> = theirs.values().map(String::as_str).collect();
    for expected in [
        "printf",
        "malloc",
        "free",
        "puts",
        "strlen",
        "atoi",
        "external_counter",
    ] {
        assert!(names.contains(expected), "missing import {expected}");
    }

    for (&slot_va, name) in &theirs {
        assert_eq!(
            map.resolve(slot_va).and_then(ImportRef::name),
            Some(name.as_str())
        );
    }
}

fn assert_bounded(bytes: &[u8]) {
    let map: ImportMap = ImportMap::from_image(bytes);
    assert!(
        map.len() < 100_000,
        "map must stay bounded on malformed input"
    );
}

#[test]
fn malformed_input_stays_bounded_without_panicking() {
    let pe: Vec<u8> = fixture("imports_pe.exe");
    let elf: Vec<u8> = fixture("imports_elf.so");

    let mut length: usize = 0;
    while length < pe.len() {
        assert_bounded(&pe[..length]);
        length += 13;
    }
    length = 0;
    while length < elf.len() {
        assert_bounded(&elf[..length]);
        length += 13;
    }

    assert_bounded(&[]);
    assert_bounded(&vec![0u8; 8192]);
    assert_bounded(&vec![0xFFu8; 8192]);

    let mut mz_garbage: Vec<u8> = vec![0u8; 4096];
    mz_garbage[0] = b'M';
    mz_garbage[1] = b'Z';
    mz_garbage[0x3c] = 0x80;
    assert_bounded(&mz_garbage);

    let mut elf_garbage: Vec<u8> = vec![0x41u8; 4096];
    elf_garbage[..4].copy_from_slice(b"\x7fELF");
    elf_garbage[4] = 2;
    elf_garbage[5] = 1;
    assert_bounded(&elf_garbage);
}

#[test]
fn corrupt_pe_import_directory_abstains() {
    let mut bytes: Vec<u8> = fixture("imports_pe.exe");
    let e_lfanew: usize =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let optional: usize = e_lfanew + 4 + 20;
    let import_dir: usize = optional + 112 + 8;
    bytes[import_dir..import_dir + 4].copy_from_slice(&0x7FFF_F000u32.to_le_bytes());

    let map: ImportMap = ImportMap::from_image(&bytes);
    assert_eq!(map.format, ImportFormat::Pe);
    assert!(
        pe_named_set(&map).is_empty(),
        "a bogus import rva must yield no fabricated imports"
    );
}
