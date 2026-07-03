#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{StabsEntry, parse_stabs};
use object::{Object, ObjectSection};

const REAL_STABS: &[u8] = include_bytes!("../../../corpus/native/formats/hello_stabs.o");

const N_FUN: u8 = 0x24;
const N_SO: u8 = 0x64;

#[test]
fn stabs_single_entry_recovers_name() {
    let strtab: &[u8] = b"\0sym\0";
    let mut entry: Vec<u8> = Vec::new();
    entry.extend_from_slice(&1u32.to_le_bytes());
    entry.push(0x24);
    entry.push(0);
    entry.extend_from_slice(&0u16.to_le_bytes());
    entry.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    let out: Vec<StabsEntry> = parse_stabs(&entry, strtab).expect("parse");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "sym");
    assert_eq!(out[0].value, 0xCAFE_BABE);
}

fn section_data<'a>(file: &'a object::File<'a>, name: &str) -> Vec<u8> {
    file.section_by_name(name)
        .unwrap_or_else(|| panic!("object must carry a {name} section"))
        .data()
        .unwrap_or_else(|_| panic!("{name} data"))
        .to_vec()
}

#[test]
fn real_legacy_stabs_object_walk() {
    let file: object::File<'_> = object::File::parse(REAL_STABS).expect("parse stabs object");
    let stab: Vec<u8> = section_data(&file, ".stab");
    let stabstr: Vec<u8> = section_data(&file, ".stabstr");

    let entries: Vec<StabsEntry> = parse_stabs(&stab, &stabstr).expect("parse real .stab section");
    assert!(
        entries.len() >= 4,
        "the real object carries the header plus several STABS entries; got {}",
        entries.len()
    );

    let source: &StabsEntry = entries
        .iter()
        .find(|e: &&StabsEntry| e.kind == N_SO)
        .expect("an N_SO source-file STAB must be present");
    assert_eq!(
        source.name, "disrobe_stabs.c",
        "the source-file STAB name must be recovered from the real .stabstr"
    );

    let functions: Vec<&str> = entries
        .iter()
        .filter(|e: &&StabsEntry| e.kind == N_FUN)
        .map(|e: &StabsEntry| e.name.as_str())
        .collect();
    assert!(
        functions.contains(&"disrobe_compute") && functions.contains(&"disrobe_helper"),
        "both N_FUN function STABs must be recovered; got {functions:?}"
    );

    assert!(REAL_STABS.len() < 256 * 1024, "fixture under 256KB budget");
}
