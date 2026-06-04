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

use disrobe_pass_beam::{BeamFile, DebugInfo, parse_dbgi};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, etf_atom, etf_binary, etf_list, etf_map,
    etf_nil, etf_small_int, etf_small_tuple, wrap_etf, zlib_compress,
};

fn build_elixir_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["Elixir.Greeter", "elixir_erl", "hello"]);

    let hello_clause: Vec<u8> =
        etf_small_tuple(&[etf_nil(), etf_nil(), etf_nil(), etf_binary(b"world")]);
    let metadata: Vec<u8> = etf_map(&[
        (
            etf_binary(b"definitions"),
            etf_list(
                &[etf_small_tuple(&[
                    etf_small_tuple(&[etf_atom("hello"), etf_small_int(0)]),
                    etf_atom("def"),
                    etf_atom("public"),
                    etf_list(&[hello_clause], &etf_nil()),
                ])],
                &etf_nil(),
            ),
        ),
        (
            etf_binary(b"attributes"),
            etf_list(
                &[etf_small_tuple(&[etf_atom("vsn"), etf_small_int(1)])],
                &etf_nil(),
            ),
        ),
    ]);
    let metadata_etf: Vec<u8> = wrap_etf(&metadata);
    let compressed_metadata: Vec<u8> = zlib_compress(&metadata_etf);

    let dbgi_payload: Vec<u8> = etf_small_tuple(&[
        etf_atom("debug_info_v1"),
        etf_atom("elixir_erl"),
        etf_binary(&compressed_metadata),
    ]);
    let dbgi: Vec<u8> = wrap_etf(&dbgi_payload);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(0, 0, &[3u8])),
        build_chunk(b"Dbgi", &dbgi),
    ];
    build_beam(&chunks)
}

#[test]
fn dbgi_decodes_as_elixir_v1() {
    let buf: Vec<u8> = build_elixir_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    match info {
        DebugInfo::ElixirV1 { backend, .. } => assert_eq!(backend, "elixir_erl"),
        _ => panic!("expected ElixirV1"),
    }
}

#[test]
fn recovers_elixir_definitions_and_source() {
    let buf: Vec<u8> = build_elixir_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let dbgi = beam.chunks.dbgi.as_ref().expect("dbgi");
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    let recovered = disrobe_pass_beam::recover_elixir(beam.module_name().unwrap(), &info)
        .expect("recover elixir");
    assert_eq!(recovered.module, "Elixir.Greeter");
    assert!(
        recovered
            .definitions
            .iter()
            .any(|d| d.name == "hello" && d.kind == "def"),
        "expected hello/0 def, got {:?}",
        recovered.definitions
    );
    assert!(
        recovered.attributes.iter().any(|(k, _)| k == "vsn"),
        "expected vsn attribute"
    );
    assert!(
        recovered.source.contains("defmodule Greeter do"),
        "expected stripped module header, got:\n{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("def hello do"),
        "expected rendered def hello, got:\n{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("\"world\""),
        "expected rendered clause body, got:\n{}",
        recovered.source
    );
    assert!(recovered.source.trim_end().ends_with("end"));
}
