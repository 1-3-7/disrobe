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

use disrobe_pass_beam::{BeamFile, ErlangSurface, RecoverySource, recover_erlang};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, encode_compact_small,
    etf_atom, etf_int, etf_list, etf_nil, etf_small_int, etf_small_tuple, wrap_etf,
};

fn build_erlang_beam_with_dbgi() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["m_surface", "greet", "world", "module"]);

    let module_attr: Vec<u8> = etf_small_tuple(&[
        etf_atom("attribute"),
        etf_int(1),
        etf_atom("module"),
        etf_atom("m_surface"),
    ]);
    let export_attr: Vec<u8> = etf_small_tuple(&[
        etf_atom("attribute"),
        etf_int(2),
        etf_atom("export"),
        etf_list(
            &[etf_small_tuple(&[etf_atom("greet"), etf_small_int(0)])],
            &etf_nil(),
        ),
    ]);
    let func_form: Vec<u8> = etf_small_tuple(&[
        etf_atom("function"),
        etf_int(3),
        etf_atom("greet"),
        etf_small_int(0),
        etf_nil(),
    ]);
    let forms: Vec<u8> = etf_list(&[module_attr, export_attr, func_form], &etf_nil());

    let inner: Vec<u8> = etf_small_tuple(&[etf_atom("abstract_v1"), forms]);
    let payload: Vec<u8> = etf_small_tuple(&[etf_atom("raw_abstract_v1"), inner]);
    let dbgi: Vec<u8> = wrap_etf(&payload);

    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 0));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(19u8);
    code.push(3u8);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 0u32, 2u32)])),
        build_chunk(b"Dbgi", &dbgi),
    ];
    build_beam(&chunks)
}

fn build_erlang_beam_without_dbgi() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["m_core_only", "noop"]);
    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 0));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(19u8);
    code.push(3u8);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 0u32, 2u32)])),
    ];
    build_beam(&chunks)
}

#[test]
fn recovers_surface_from_abstract_code() {
    let buf: Vec<u8> = build_erlang_beam_with_dbgi();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    assert_eq!(surface.module, "m_surface");
    assert_eq!(surface.recovered_from, RecoverySource::AbstractCode);
    assert!(surface.source.contains("-module(m_surface)."));
    assert!(surface.source.contains("greet/0"));
}

#[test]
fn falls_back_to_core_lift_when_no_dbgi() {
    let buf: Vec<u8> = build_erlang_beam_without_dbgi();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
    assert_eq!(surface.module, "m_core_only");
    assert_eq!(surface.recovered_from, RecoverySource::CoreLifted);
    assert!(surface.source.contains("-module(m_core_only)."));
    assert!(surface.source.contains("noop"));
}
