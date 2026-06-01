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

use disrobe_pass_beam::{BeamFile, DebugInfo, ElixirRecovery, parse_dbgi, recover_elixir};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, etf_atom, etf_binary, etf_list, etf_map,
    etf_nil, etf_small_int, etf_small_tuple, wrap_etf,
};

fn build_uncompressed_elixir_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["Elixir.Math", "elixir_erl", "add", "pi"]);
    let metadata: Vec<u8> = etf_map(&[
        (
            etf_binary(b"definitions"),
            etf_list(
                &[etf_small_tuple(&[
                    etf_small_tuple(&[etf_atom("add"), etf_small_int(2)]),
                    etf_atom("def"),
                    etf_atom("public"),
                    etf_list(&[etf_atom("clause_one")], &etf_nil()),
                ])],
                &etf_nil(),
            ),
        ),
        (
            etf_binary(b"attributes"),
            etf_list(
                &[
                    etf_small_tuple(&[etf_atom("moduledoc"), etf_binary(b"math module")]),
                    etf_small_tuple(&[etf_atom("pi"), etf_binary(b"3.14")]),
                ],
                &etf_nil(),
            ),
        ),
    ]);
    let dbgi_payload: Vec<u8> =
        etf_small_tuple(&[etf_atom("debug_info_v1"), etf_atom("elixir_erl"), metadata]);
    let dbgi: Vec<u8> = wrap_etf(&dbgi_payload);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(0, 0, &[3u8])),
        build_chunk(b"Dbgi", &dbgi),
    ];
    build_beam(&chunks)
}

#[test]
fn elixir_recovery_emits_source_with_attributes() {
    let buf: Vec<u8> = build_uncompressed_elixir_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let dbgi = beam.chunks.dbgi.as_ref().unwrap();
    let info: DebugInfo = parse_dbgi(&dbgi.term).expect("parse dbgi");
    let recovered: ElixirRecovery =
        recover_elixir(beam.module_name().unwrap(), &info).expect("recover");
    assert_eq!(recovered.backend, "elixir_erl");
    assert!(recovered.source.starts_with("defmodule Elixir.Math do"));
    assert!(recovered.source.contains("@moduledoc"));
    assert!(recovered.source.contains("@pi"));
    assert!(recovered.source.contains("def add"));
}
