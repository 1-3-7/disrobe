#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{StabsEntry, parse_stabs};

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

#[test]
#[ignore = "FIXTURE PENDING: real STABS-bearing legacy object required"]
fn real_legacy_stabs_object_walk() {}
