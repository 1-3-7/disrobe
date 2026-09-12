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

use std::collections::BTreeMap;
use std::io::Write;

use disrobe_pass_beam::body_lift::render::render_body;
use disrobe_pass_beam::body_lift::{LiftedBody, build_label_index, lift_body};
use disrobe_pass_beam::chunks::{ExportEntry, LiteralChunk, parse_export_table};
use disrobe_pass_beam::core_erlang::CoreModule;
use disrobe_pass_beam::disasm::{Instruction, Operand};
use disrobe_pass_beam::{
    BeamFile, Chunks, CodeChunk, Error, EzArchive, EzQuota, RawBeam, Term, decode_etf, disassemble,
    erlang_abstract, lift,
};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, encode_compact_small,
    zlib_compress,
};

fn minimal_chunks() -> Chunks {
    let atoms: Vec<u8> = build_atu8(&["m"]);
    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(0, 0, &[3u8])),
    ];
    let buf: Vec<u8> = build_beam(&chunks);
    BeamFile::parse(&buf).expect("parse minimal beam").chunks
}

fn ins(name: &'static str, operands: Vec<Operand>) -> Instruction {
    Instruction {
        offset: 0,
        opcode: 0,
        name,
        operands,
    }
}

fn zip_with(entries: &[(&str, zip::CompressionMethod, Vec<u8>)]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut writer: ZipWriter<std::io::Cursor<&mut Vec<u8>>> =
            ZipWriter::new(std::io::Cursor::new(&mut buf));
        for (name, method, data) in entries {
            let opts: SimpleFileOptions = SimpleFileOptions::default().compression_method(*method);
            writer.start_file(*name, opts).expect("start file");
            writer.write_all(data).expect("write entry");
        }
        writer.finish().expect("finish");
    }
    buf
}

#[test]
fn ez_rejects_compression_bomb_by_aggregate_ratio() {
    let bomb: Vec<u8> = vec![0u8; 8 * 1024 * 1024];
    let buf: Vec<u8> = zip_with(&[(
        "app-1.0/ebin/bomb.beam",
        zip::CompressionMethod::Deflated,
        bomb,
    )]);
    let err: Error = EzArchive::parse(&buf).expect_err("bomb must be rejected");
    assert!(
        matches!(err, Error::EzQuotaExceeded { .. }),
        "expected quota error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0021"));
}

#[test]
fn ez_rejects_too_many_entries() {
    let entries: Vec<(String, zip::CompressionMethod, Vec<u8>)> = (0..40)
        .map(|i: u32| {
            (
                format!("app-1.0/ebin/m{i}.txt"),
                zip::CompressionMethod::Stored,
                b"x".to_vec(),
            )
        })
        .collect();
    let borrowed: Vec<(&str, zip::CompressionMethod, Vec<u8>)> = entries
        .iter()
        .map(|(n, m, d): &(String, zip::CompressionMethod, Vec<u8>)| (n.as_str(), *m, d.clone()))
        .collect();
    let buf: Vec<u8> = zip_with(&borrowed);
    let tight: EzQuota = EzQuota {
        max_entries: 8,
        ..EzQuota::default_safe()
    };
    let err: Error = EzArchive::parse_with_quota(&buf, tight).expect_err("entry cap");
    assert!(matches!(err, Error::EzQuotaExceeded { .. }));
}

#[test]
fn ez_rejects_oversized_declared_entry() {
    let buf: Vec<u8> = zip_with(&[(
        "app-1.0/ebin/big.beam",
        zip::CompressionMethod::Stored,
        vec![0u8; 4096],
    )]);
    let tiny: EzQuota = EzQuota {
        max_per_entry_uncompressed: 1024,
        ..EzQuota::default_safe()
    };
    let err: Error = EzArchive::parse_with_quota(&buf, tiny).expect_err("per-entry cap");
    assert!(matches!(err, Error::EzQuotaExceeded { .. }));
}

#[test]
fn ez_rejects_path_traversal() {
    let buf: Vec<u8> = zip_with(&[(
        "../../etc/evil.beam",
        zip::CompressionMethod::Stored,
        b"x".to_vec(),
    )]);
    let err: Error = EzArchive::parse(&buf).expect_err("path traversal");
    assert!(
        matches!(err, Error::EzUnsafePath(_)),
        "expected unsafe-path error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0022"));
}

#[test]
fn ez_unrestricted_admits_otherwise_bomb_shaped_input() {
    let buf: Vec<u8> = zip_with(&[(
        "app-1.0/ebin/wide.txt",
        zip::CompressionMethod::Deflated,
        vec![7u8; 2 * 1024 * 1024],
    )]);
    let archive: EzArchive =
        EzArchive::parse_with_quota(&buf, EzQuota::unrestricted()).expect("unrestricted ok");
    assert_eq!(archive.entries.len(), 1);
}

#[test]
fn ez_rejects_non_zip_bytes_without_panic() {
    let err: Error = EzArchive::parse(&[0u8; 64]).expect_err("not a zip");
    assert!(matches!(err, Error::Zip(_)));
}

#[test]
fn raw_parse_rejects_oversized_form_length() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"FOR1");
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    buf.extend_from_slice(b"BEAM");
    let err: Error = RawBeam::parse(&buf).expect_err("form length lie");
    assert!(err.to_string().contains("DR-BEAM-0005"));
}

#[test]
fn raw_parse_rejects_oversized_chunk_length() {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"Code");
    body.extend_from_slice(&0xFFFF_0000u32.to_be_bytes());
    body.extend_from_slice(&[0u8; 4]);
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"FOR1");
    let form_len: u32 = u32::try_from(4 + body.len()).unwrap();
    buf.extend_from_slice(&form_len.to_be_bytes());
    buf.extend_from_slice(b"BEAM");
    buf.extend_from_slice(&body);
    let err: Error = RawBeam::parse(&buf).expect_err("chunk length lie");
    assert!(err.to_string().contains("DR-BEAM-0006"));
}

#[test]
fn beam_parse_rejects_oversized_code_subheader() {
    let atoms: Vec<u8> = build_atu8(&["m"]);
    let mut bad_code: Vec<u8> = Vec::new();
    bad_code.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    bad_code.extend_from_slice(&[0u8; 16]);
    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &bad_code),
    ];
    let buf: Vec<u8> = build_beam(&chunks);
    let err: Error = BeamFile::parse(&buf).expect_err("code subheader lie");
    assert!(err.to_string().contains("DR-BEAM-0010"));
}

#[test]
fn beam_parse_rejects_missing_atom_chunk() {
    let chunks: Vec<Vec<u8>> = vec![build_chunk(b"Code", &build_code_chunk(0, 0, &[3u8]))];
    let buf: Vec<u8> = build_beam(&chunks);
    let err: Error = BeamFile::parse(&buf).expect_err("no atom chunk");
    assert!(err.to_string().contains("DR-BEAM-0007"));
}

#[test]
fn etf_rejects_bad_magic_byte() {
    let err: Error = decode_etf(&[0u8, 1, 2, 3]).expect_err("bad etf magic");
    assert!(err.to_string().contains("DR-BEAM-0014"));
}

#[test]
fn etf_rejects_unknown_tag_without_panic() {
    let err: Error = decode_etf(&[131u8, 200u8]).expect_err("unknown etf tag");
    assert!(err.to_string().contains("DR-BEAM-0015"));
}

#[test]
fn etf_rejects_truncated_atom_length() {
    let err: Error = decode_etf(&[131u8, 118u8, 0xFF, 0xFF]).expect_err("truncated atom");
    assert!(err.to_string().contains("DR-BEAM-0004"));
}

#[test]
fn atom_table_oversized_count_does_not_pre_allocate_oom() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
    data.push(1u8);
    data.push(b'a');
    let atoms: Vec<u8> = data;
    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(0, 0, &[3u8])),
    ];
    let buf: Vec<u8> = build_beam(&chunks);
    let err: Error = BeamFile::parse(&buf).expect_err("oversized atom count must error, not OOM");
    assert!(
        matches!(err, Error::TableCountTooLarge { .. }),
        "expected table-count error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0024"));
}

#[test]
fn lift_does_not_panic_on_module_without_code() {
    let atoms: Vec<u8> = build_atu8(&["m"]);
    let chunks: Vec<Vec<u8>> = vec![build_chunk(b"AtU8", &atoms)];
    let buf: Vec<u8> = build_beam(&chunks);
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse without code");
    let err: Error = disrobe_pass_beam::lift(&beam).expect_err("no code chunk");
    assert!(err.to_string().contains("DR-BEAM-0007"));
}

#[test]
fn etf_compressed_huge_declared_size_does_not_pre_allocate_gigabytes() {
    let real: Vec<u8> = zlib_compress(&[131u8, 97u8, 7u8]);
    let mut data: Vec<u8> = Vec::with_capacity(6 + real.len());
    data.push(131u8);
    data.push(80u8);
    data.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    data.extend_from_slice(&real);
    let err: Error = decode_etf(&data).expect_err("declared size lie must error, not OOM");
    assert!(
        matches!(err, Error::Zlib(..)),
        "expected zlib size-mismatch error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0016"));
}

#[test]
fn etf_deeply_nested_tuples_error_instead_of_stack_overflow() {
    let mut data: Vec<u8> = Vec::with_capacity(2 + 4_000);
    data.push(131u8);
    for _ in 0..2_000u32 {
        data.push(104u8);
        data.push(1u8);
    }
    data.push(97u8);
    data.push(0u8);
    let err: Error = decode_etf(&data).expect_err("deep nesting must error, not overflow");
    assert!(
        matches!(err, Error::DepthExceeded { .. }),
        "expected depth-exceeded error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0023"));
}

#[test]
fn disasm_ext_list_huge_size_does_not_pre_allocate_gigabytes() {
    let mut code: Vec<u8> = Vec::with_capacity(8);
    code.push(1u8);
    code.push(0x17u8);
    code.push(0b1_1000u8 | (2u8 << 5));
    code.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    let chunk: CodeChunk = CodeChunk {
        sub_size: 16,
        instruction_set: 0,
        opcode_max: 181,
        num_labels: 0,
        num_functions: 0,
        code,
    };
    let err: Error = disassemble(&chunk).expect_err("huge list size lie must error, not OOM");
    assert!(
        matches!(err, Error::Truncated { .. }),
        "expected truncation error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0004"));
}

#[test]
fn self_referential_put_list_chain_stays_bounded() {
    let chunks: Chunks = minimal_chunks();
    let index: BTreeMap<u32, (String, u32)> = build_label_index(&chunks);
    let mut instrs: Vec<Instruction> = vec![
        ins("label", vec![Operand::Literal(1)]),
        ins("move", vec![Operand::Atom(0), Operand::XReg(0)]),
    ];
    for _ in 0..200u32 {
        instrs.push(ins(
            "put_list",
            vec![Operand::XReg(0), Operand::XReg(0), Operand::XReg(0)],
        ));
    }
    instrs.push(ins("return", Vec::new()));
    let body: LiftedBody = lift_body(&instrs, 0, &chunks, &index);
    assert!(
        !body.lift_complete,
        "self-referential cons bomb must report degraded, not a faithful lift"
    );
    let rendered: String = render_body(&body.stmts, 1);
    assert!(
        rendered.len() < 200_000,
        "cons-bomb output must stay bounded, got {} bytes",
        rendered.len()
    );
    assert!(
        rendered.contains("disrobe-oversized"),
        "cons-bomb cap must emit the bounded placeholder marker:\n{rendered}"
    );
}

#[test]
fn self_referential_put_tuple2_chain_stays_bounded() {
    let chunks: Chunks = minimal_chunks();
    let index: BTreeMap<u32, (String, u32)> = build_label_index(&chunks);
    let mut instrs: Vec<Instruction> = vec![
        ins("label", vec![Operand::Literal(1)]),
        ins("move", vec![Operand::Atom(0), Operand::XReg(0)]),
    ];
    for _ in 0..200u32 {
        instrs.push(ins(
            "put_tuple2",
            vec![
                Operand::XReg(0),
                Operand::List(vec![Operand::XReg(0), Operand::XReg(0)]),
            ],
        ));
    }
    instrs.push(ins("return", Vec::new()));
    let body: LiftedBody = lift_body(&instrs, 0, &chunks, &index);
    assert!(!body.lift_complete, "tuple bomb must report degraded");
    let rendered: String = render_body(&body.stmts, 1);
    assert!(
        rendered.len() < 200_000,
        "tuple-bomb output must stay bounded, got {} bytes",
        rendered.len()
    );
}

#[test]
fn put_tuple_huge_declared_size_does_not_pre_allocate_gigabytes() {
    let chunks: Chunks = minimal_chunks();
    let index: BTreeMap<u32, (String, u32)> = build_label_index(&chunks);
    let instrs: Vec<Instruction> = vec![
        ins("label", vec![Operand::Literal(1)]),
        ins(
            "put_tuple",
            vec![Operand::Literal(0xFFFF_FFFF), Operand::XReg(0)],
        ),
        ins("put", vec![Operand::Atom(0)]),
        ins("return", Vec::new()),
    ];
    let body: LiftedBody = lift_body(&instrs, 0, &chunks, &index);
    let rendered: String = render_body(&body.stmts, 1);
    assert!(
        rendered.len() < 100_000,
        "clamped put_tuple must stay bounded, got {} bytes",
        rendered.len()
    );
}

#[test]
fn reconverging_diamond_cfg_lifts_bounded_not_exponential() {
    let chunks: Chunks = minimal_chunks();
    let index: BTreeMap<u32, (String, u32)> = build_label_index(&chunks);
    let mut instrs: Vec<Instruction> = vec![ins("label", vec![Operand::Literal(1)])];
    let depth: u32 = 64;
    for d in 0..depth {
        let here: u64 = u64::from(1 + d);
        let join: u32 = 1 + d + 1;
        instrs.push(ins("label", vec![Operand::Literal(here)]));
        instrs.push(ins(
            "is_eq_exact",
            vec![Operand::Label(join), Operand::XReg(0), Operand::Atom(0)],
        ));
        instrs.push(ins("jump", vec![Operand::Label(join)]));
    }
    instrs.push(ins("label", vec![Operand::Literal(u64::from(1 + depth))]));
    instrs.push(ins("return", Vec::new()));
    let body: LiftedBody = lift_body(&instrs, 1, &chunks, &index);
    assert!(
        !body.lift_complete,
        "a 2^64 reconverging diamond must report degraded, not a faithful lift"
    );
    let rendered: String = render_body(&body.stmts, 1);
    assert!(
        rendered.len() < 16 * 1024 * 1024,
        "diamond CFG must stay bounded (degraded), got {} bytes",
        rendered.len()
    );
    assert!(
        rendered.contains("fan-in capped"),
        "the per-label fan-in cap must engage on a reconverging diamond"
    );
}

#[test]
fn cyclic_cfg_back_edge_does_not_recurse_forever() {
    let chunks: Chunks = minimal_chunks();
    let index: BTreeMap<u32, (String, u32)> = build_label_index(&chunks);
    let instrs: Vec<Instruction> = vec![
        ins("label", vec![Operand::Literal(1)]),
        ins("jump", vec![Operand::Label(2)]),
        ins("label", vec![Operand::Literal(2)]),
        ins("jump", vec![Operand::Label(1)]),
    ];
    let body: LiftedBody = lift_body(&instrs, 0, &chunks, &index);
    assert!(!body.lift_complete, "a cyclic CFG must report degraded");
    let rendered: String = render_body(&body.stmts, 1);
    assert!(
        rendered.contains("cyclic block"),
        "cycle must bail to a marker, not hang:\n{rendered}"
    );
}

#[test]
fn renderer_deeply_nested_op_term_does_not_stack_overflow() {
    let mut term: Term = Term::Tuple(vec![
        Term::Atom("integer".to_owned()),
        Term::SmallInt(0),
        Term::SmallInt(1),
    ]);
    for _ in 0..4_000u32 {
        term = Term::Tuple(vec![
            Term::Atom("op".to_owned()),
            Term::SmallInt(0),
            Term::Atom("+".to_owned()),
            term,
            Term::Tuple(vec![
                Term::Atom("integer".to_owned()),
                Term::SmallInt(0),
                Term::SmallInt(0),
            ]),
        ]);
    }
    let clause: Term = Term::Tuple(vec![
        Term::Atom("clause".to_owned()),
        Term::SmallInt(0),
        Term::Nil,
        Term::Nil,
        Term::List {
            elements: vec![term],
            tail: Box::new(Term::Nil),
        },
    ]);
    let rendered: String = erlang_abstract::render_function("f", &[clause]);
    assert!(
        rendered.contains("disrobe-too-deep"),
        "deep term must truncate to the depth marker"
    );
    assert!(
        rendered.len() < 5_000_000,
        "deep-term render must stay bounded, got {} bytes",
        rendered.len()
    );
}

#[test]
fn disasm_deeply_nested_lists_error_instead_of_stack_overflow() {
    let mut code: Vec<u8> = Vec::with_capacity(2 + 2_000);
    code.push(1u8);
    for _ in 0..1_000u32 {
        code.push(0x17u8);
        code.push(0x10u8);
    }
    code.push(0x10u8);
    let chunk: CodeChunk = CodeChunk {
        sub_size: 16,
        instruction_set: 0,
        opcode_max: 181,
        num_labels: 0,
        num_functions: 0,
        code,
    };
    let err: Error = disassemble(&chunk).expect_err("deep nesting must error, not overflow");
    assert!(
        matches!(err, Error::DepthExceeded { .. }),
        "expected depth-exceeded error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0023"));
}

const MAX_FUN_ARITY: u32 = 1024;

fn build_litt(uncompressed_size: u32, zlib_stream: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::with_capacity(4 + zlib_stream.len());
    data.extend_from_slice(&uncompressed_size.to_be_bytes());
    data.extend_from_slice(zlib_stream);
    data
}

fn litt_inner_with_one_literal(etf_payload: &[u8]) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::with_capacity(8 + etf_payload.len());
    inner.extend_from_slice(&1u32.to_be_bytes());
    inner.extend_from_slice(
        &u32::try_from(etf_payload.len())
            .expect("payload fits")
            .to_be_bytes(),
    );
    inner.extend_from_slice(etf_payload);
    inner
}

#[test]
fn litt_huge_declared_uncompressed_size_errors_instead_of_oom() {
    let small_inner: Vec<u8> = litt_inner_with_one_literal(&[131u8, 97u8, 7u8]);
    let stream: Vec<u8> = zlib_compress(&small_inner);
    let data: Vec<u8> = build_litt(0xFFFF_FFFF, &stream);
    let err: Error = LiteralChunk::parse(&data).expect_err("declared-size lie must error, not OOM");
    assert!(
        matches!(err, Error::Zlib("LitT", _)),
        "expected LitT zlib size-mismatch error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0016"));
}

#[test]
fn litt_zlib_bomb_stays_within_inflate_ceiling() {
    let bomb_inner: Vec<u8> = vec![0u8; 512 * 1024 * 1024];
    let stream: Vec<u8> = zlib_compress(&bomb_inner);
    assert!(
        stream.len() < 4 * 1024 * 1024,
        "compressed bomb must be small to be a valid amplifier, got {} bytes",
        stream.len()
    );
    let data: Vec<u8> = build_litt(u32::try_from(bomb_inner.len()).expect("size fits"), &stream);
    let err: Error = LiteralChunk::parse(&data).expect_err("inflate past ceiling must error");
    assert!(
        matches!(err, Error::Zlib("LitT", _)),
        "expected LitT inflate-ceiling error, got {err}"
    );
}

#[test]
fn litt_valid_small_literal_table_round_trips() {
    let etf_payload: Vec<u8> = vec![131u8, 97u8, 42u8];
    let inner: Vec<u8> = litt_inner_with_one_literal(&etf_payload);
    let stream: Vec<u8> = zlib_compress(&inner);
    let data: Vec<u8> = build_litt(u32::try_from(inner.len()).expect("size fits"), &stream);
    let chunk: LiteralChunk = LiteralChunk::parse(&data).expect("valid LitT must parse");
    assert_eq!(chunk.literals.len(), 1);
    assert_eq!(chunk.literals[0], Term::SmallInt(42));
}

#[test]
fn export_table_clamps_adversarial_arity_at_parse_boundary() {
    let data: Vec<u8> = build_expt(&[(1u32, 0xFFFF_FFFF, 7u32)]);
    let entries: Vec<ExportEntry> = parse_export_table(&data).expect("export table parses");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].arity, MAX_FUN_ARITY,
        "u32::MAX arity must saturate to the BEAM-safe cap, not drive a 4-billion-element loop"
    );
}

#[test]
fn export_table_rejects_count_past_available_rows() {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&2u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&7u32.to_be_bytes());
    let err: Error = parse_export_table(&data).expect_err("count must fit declared rows");
    assert!(
        matches!(err, Error::TableCountTooLarge { .. }),
        "expected table-count error, got {err}"
    );
    assert!(err.to_string().contains("DR-BEAM-0024"));
}

fn build_huge_arity_func_info_beam(arity: u32) -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["m", "f"]);
    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, arity));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(19u8);
    code.push(3u8);
    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, arity, 2u32)])),
    ];
    build_beam(&chunks)
}

#[test]
fn func_info_huge_arity_lift_stays_bounded() {
    let buf: Vec<u8> = build_huge_arity_func_info_beam(0xFFFF_FFFF);
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse beam with hostile arity");
    let core: CoreModule = lift(&beam).expect("lift must not OOM on hostile arity");
    for f in &core.functions {
        assert!(
            f.arity <= MAX_FUN_ARITY,
            "function arity {} must be clamped to <= {MAX_FUN_ARITY}, never u32::MAX",
            f.arity
        );
        for clause in &f.clauses {
            assert!(
                clause.params.len() <= MAX_FUN_ARITY as usize,
                "params vector {} must stay bounded by the arity cap",
                clause.params.len()
            );
        }
    }
}

#[test]
fn func_info_valid_arity_lifts_correctly() {
    let buf: Vec<u8> = build_huge_arity_func_info_beam(2);
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse beam with valid arity");
    let core: CoreModule = lift(&beam).expect("lift");
    let f: &disrobe_pass_beam::CoreFunction = core
        .functions
        .iter()
        .find(|f: &&disrobe_pass_beam::CoreFunction| f.name == "f")
        .expect("function f recovered");
    assert_eq!(f.arity, 2);
    assert_eq!(f.clauses[0].params, vec!["X0".to_owned(), "X1".to_owned()]);
}
