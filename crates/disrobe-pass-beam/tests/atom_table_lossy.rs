#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use disrobe_pass_beam::AtomTable;

#[test]
fn non_utf8_atom_does_not_drop_the_whole_table() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&3u32.to_be_bytes());

    data.push(4);
    data.extend_from_slice(b"head");

    data.push(3);
    data.extend_from_slice(&[0x61, 0xff, 0x62]);

    data.push(4);
    data.extend_from_slice(b"tail");

    let table: AtomTable = AtomTable::parse_utf8(&data).expect("bad byte must not abort the table");

    assert_eq!(table.atoms.len(), 3);
    assert_eq!(table.atoms[0], "head");
    assert_eq!(table.atoms[2], "tail");
    assert!(table.atoms[1].contains('\u{fffd}'));
    assert!(table.atoms[1].starts_with('a'));
    assert!(table.atoms[1].ends_with('b'));
}
