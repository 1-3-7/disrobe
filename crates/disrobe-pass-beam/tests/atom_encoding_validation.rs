#![allow(clippy::pedantic)]

use disrobe_pass_beam::etf::{ETF_MAGIC, TAG_ATOM_DEPRECATED, TAG_ATOM_UTF8, TAG_SMALL_ATOM_UTF8};
use disrobe_pass_beam::{AtomTable, Error, Term, decode_etf};

#[test]
fn short_atu8_accepts_multibyte_and_rejects_bad_utf8_mutation() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&2u32.to_be_bytes());
    data.push(3);
    data.extend_from_slice(b"abc");
    data.push(2);
    data.extend_from_slice("\u{e9}".as_bytes());

    assert!(AtomTable::parse_utf8(&data).is_ok_and(|table: AtomTable| {
        table.atoms == vec!["abc".to_owned(), "\u{e9}".to_owned()]
    }));
    data[10] = 0xff;

    assert!(matches!(
        AtomTable::parse_utf8(&data),
        Err(Error::BadAtomUtf8 { index: 2 })
    ));
}

#[test]
fn long_atu8_accepts_multibyte_varint_and_rejects_bad_utf8_mutation() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(-2i32).to_be_bytes());
    data.push(0x30);
    data.extend_from_slice(b"abc");
    data.extend_from_slice(&[0x08, 18]);
    data.extend_from_slice("\u{e9}abcdefghijklmnop".as_bytes());

    assert!(
        AtomTable::parse_utf8_any(&data).is_ok_and(|table: AtomTable| {
            table.atoms == vec!["abc".to_owned(), "\u{e9}abcdefghijklmnop".to_owned()]
        })
    );
    data[11] = 0xff;

    assert!(matches!(
        AtomTable::parse_utf8_any(&data),
        Err(Error::BadAtomUtf8 { index: 2 })
    ));
}

#[test]
fn etf_atom_utf8_accepts_multibyte_and_rejects_bad_utf8_mutation() {
    let mut data: Vec<u8> = vec![ETF_MAGIC, TAG_ATOM_UTF8, 0, 2, 0xce, 0xbb];

    assert!(decode_etf(&data).is_ok_and(|term: Term| term == Term::Atom("\u{3bb}".to_owned())));
    data[5] = 0xff;

    assert!(matches!(
        decode_etf(&data),
        Err(Error::BadAtomUtf8 { index: 0 })
    ));
}

#[test]
fn etf_small_atom_utf8_accepts_multibyte_and_rejects_bad_utf8_mutation() {
    let mut data: Vec<u8> = vec![ETF_MAGIC, TAG_SMALL_ATOM_UTF8, 4, 0xf0, 0x9f, 0x9f, 0xa6];

    assert!(decode_etf(&data).is_ok_and(|term: Term| term == Term::Atom("\u{1f7e6}".to_owned())));
    data[4] = 0xff;

    assert!(matches!(
        decode_etf(&data),
        Err(Error::BadAtomUtf8 { index: 0 })
    ));
}

#[test]
fn long_atu8_rejects_more_than_255_unicode_scalars_mutation() {
    let atom: String = "\u{1f7e6}".repeat(255);
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(-1i32).to_be_bytes());
    data.extend_from_slice(&[0x68, 0xfc]);
    data.extend_from_slice(atom.as_bytes());

    assert!(
        AtomTable::parse_utf8_any(&data)
            .is_ok_and(|table: AtomTable| { table.atoms == vec![atom] })
    );
    data[4] = 0x88;
    data[5] = 0;
    data.extend_from_slice("\u{1f7e6}".as_bytes());

    assert!(matches!(
        AtomTable::parse_utf8_any(&data),
        Err(Error::AtomTooLong {
            index: 1,
            scalars: 256,
            limit: 255
        })
    ));
}

#[test]
fn etf_atom_utf8_rejects_more_than_255_unicode_scalars_mutation() {
    let atom: String = "\u{1f7e6}".repeat(255);
    let mut data: Vec<u8> = vec![ETF_MAGIC, TAG_ATOM_UTF8, 0x03, 0xfc];
    data.extend_from_slice(atom.as_bytes());

    assert!(decode_etf(&data).is_ok_and(|term: Term| term == Term::Atom(atom)));
    data[2] = 0x04;
    data[3] = 0;
    data.extend_from_slice("\u{1f7e6}".as_bytes());

    assert!(matches!(
        decode_etf(&data),
        Err(Error::AtomTooLong {
            index: 0,
            scalars: 256,
            limit: 255
        })
    ));
}

#[test]
fn etf_deprecated_atom_rejects_more_than_255_latin1_scalars_mutation() {
    let atom: String = "a".repeat(255);
    let mut data: Vec<u8> = vec![ETF_MAGIC, TAG_ATOM_DEPRECATED, 0, 255];
    data.extend_from_slice(atom.as_bytes());

    assert!(decode_etf(&data).is_ok_and(|term: Term| term == Term::Atom(atom)));
    data[2] = 1;
    data[3] = 0;
    data.push(b'b');

    assert!(matches!(
        decode_etf(&data),
        Err(Error::AtomTooLong {
            index: 0,
            scalars: 256,
            limit: 255
        })
    ));
}

#[test]
fn long_atu8_reports_bad_compact_length_offset_mutation() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&(-1i32).to_be_bytes());
    data.push(0x30);
    data.extend_from_slice(b"abc");

    assert!(AtomTable::parse_utf8_any(&data).is_ok());
    data[4] = 0x31;

    assert!(matches!(
        AtomTable::parse_utf8_any(&data),
        Err(Error::BadCompactTerm(4))
    ));
}
