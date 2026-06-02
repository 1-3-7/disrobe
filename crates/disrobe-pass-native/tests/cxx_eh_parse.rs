#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    EhEntry, SehScopeEntry, parse_itanium_lsda, parse_windows_seh_scope_table,
};

#[test]
fn itanium_lsda_minimal_entry_round_trip() {
    let mut buf: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
    buf.extend_from_slice(&64u32.to_le_bytes());
    buf.extend_from_slice(&128u32.to_le_bytes());
    buf.extend_from_slice(&192u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    let out: Vec<EhEntry> = parse_itanium_lsda(&buf).expect("lsda");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].start, 64);
}

#[test]
fn windows_seh_scope_table_round_trip() {
    let mut buf: Vec<u8> = 1u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(&200u32.to_le_bytes());
    buf.extend_from_slice(&300u32.to_le_bytes());
    buf.extend_from_slice(&400u32.to_le_bytes());
    let out: Vec<SehScopeEntry> = parse_windows_seh_scope_table(&buf).expect("seh");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].begin_address, 100);
}
