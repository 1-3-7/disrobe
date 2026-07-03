#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use disrobe_pass_beam::{BeamFile, RawBeam, Term};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, build_impt, build_loct,
    encode_compact_small, etf_atom, etf_binary, etf_list, etf_nil, etf_small_int, etf_small_tuple,
    wrap_etf, zlib_compress,
};

fn tiny_erlang_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["hello_world", "greet", "module", "compile"]);
    let attr_payload: Vec<u8> = etf_small_tuple(&[etf_atom("vsn"), etf_small_int(1)]);
    let attr: Vec<u8> = wrap_etf(&etf_list(&[attr_payload], &etf_nil()));
    let cinf_payload: Vec<u8> = etf_small_tuple(&[etf_atom("source"), etf_binary(b"hello.erl")]);
    let cinf: Vec<u8> = wrap_etf(&etf_list(&[cinf_payload], &etf_nil()));

    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 3));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 0));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(64u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(3, 0));
    code.push(19u8);
    code.push(3u8);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"StrT", &[]),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 0u32, 2u32)])),
        build_chunk(b"ImpT", &build_impt(&[])),
        build_chunk(b"LocT", &build_loct(&[])),
        build_chunk(b"Attr", &attr),
        build_chunk(b"CInf", &cinf),
    ];
    build_beam(&chunks)
}

#[test]
fn parses_raw_iff_form() {
    let buf: Vec<u8> = tiny_erlang_beam();
    let raw: RawBeam = RawBeam::parse(&buf).expect("raw parse");
    let tags: Vec<String> = raw
        .raw_chunks
        .iter()
        .map(|c| String::from_utf8_lossy(&c.tag).into_owned())
        .collect();
    assert_eq!(
        tags,
        vec![
            "AtU8".to_owned(),
            "Code".to_owned(),
            "StrT".to_owned(),
            "ExpT".to_owned(),
            "ImpT".to_owned(),
            "LocT".to_owned(),
            "Attr".to_owned(),
            "CInf".to_owned(),
        ],
        "the raw IFF walk must surface every built chunk exactly once, in file order"
    );
}

fn proplist_value<'a>(term: &'a Term, key: &str) -> Option<&'a Term> {
    term.as_list()?.iter().find_map(|entry: &Term| {
        let pair: &[Term] = entry.as_tuple()?;
        let [k, v] = pair else { return None };
        (k.as_atom() == Some(key)).then_some(v)
    })
}

#[test]
fn parses_typed_beamfile() {
    let buf: Vec<u8> = tiny_erlang_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("typed parse");
    assert_eq!(beam.module_name(), Some("hello_world"));
    assert_eq!(beam.chunks.atoms.len(), 4);
    let code = beam.chunks.code.as_ref().expect("code chunk");
    assert_eq!(code.num_functions, 1);
    assert_eq!(code.num_labels, 2);
    assert_eq!(beam.chunks.exports.len(), 1);
    assert_eq!(beam.chunks.exports[0].arity, 0);

    let attributes = beam.chunks.attributes.as_ref().expect("attributes chunk");
    let vsn: &Term = proplist_value(&attributes.term, "vsn")
        .unwrap_or_else(|| panic!("Attr must carry a vsn entry: {:?}", attributes.term));
    assert_eq!(
        vsn,
        &Term::SmallInt(1),
        "the vsn attribute must decode to the integer 1 we encoded"
    );

    let compile_info = beam
        .chunks
        .compile_info
        .as_ref()
        .expect("compile_info chunk");
    let source: &Term = proplist_value(&compile_info.term, "source")
        .unwrap_or_else(|| panic!("CInf must carry a source entry: {:?}", compile_info.term));
    assert_eq!(
        source.as_str().as_deref(),
        Some("hello.erl"),
        "the source compile-info entry must decode to the exact filename bytes"
    );
}

#[test]
fn rejects_bad_magic() {
    let mut buf: Vec<u8> = tiny_erlang_beam();
    buf[0] = b'X';
    let err = BeamFile::parse(&buf).unwrap_err();
    let msg: String = err.to_string();
    assert!(msg.contains("DR-BEAM-0002"), "got: {msg}");
}

#[test]
fn rejects_truncated_chunk() {
    let buf: Vec<u8> = tiny_erlang_beam();
    let trimmed: Vec<u8> = buf[..buf.len() - 10].to_vec();
    let _ = BeamFile::parse(&trimmed).unwrap_err();
}

#[test]
fn literal_chunk_round_trips() {
    let atoms: Vec<u8> = build_atu8(&["m_lit"]);
    let mut lit_etf: Vec<u8> = Vec::new();
    let inner: Vec<u8> = wrap_etf(&etf_small_int(42));
    lit_etf.extend_from_slice(&1u32.to_be_bytes());
    let size: u32 = u32::try_from(inner.len()).unwrap();
    lit_etf.extend_from_slice(&size.to_be_bytes());
    lit_etf.extend_from_slice(&inner);
    let compressed: Vec<u8> = zlib_compress(&lit_etf);
    let mut litt_data: Vec<u8> = Vec::new();
    let uncompressed_size: u32 = u32::try_from(lit_etf.len()).unwrap();
    litt_data.extend_from_slice(&uncompressed_size.to_be_bytes());
    litt_data.extend_from_slice(&compressed);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(1, 0, &[3u8])),
        build_chunk(b"LitT", &litt_data),
    ];
    let buf: Vec<u8> = build_beam(&chunks);
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let lits = beam.chunks.literals.as_ref().expect("literals");
    assert_eq!(lits.literals.len(), 1);
}
