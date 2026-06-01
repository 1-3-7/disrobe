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

use std::io::Write;

use disrobe_pass_beam::{
    BeamFile, CodeChunk, Error, EzArchive, EzQuota, RawBeam, decode_etf, disassemble,
};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::common::{build_atu8, build_beam, build_chunk, build_code_chunk, zlib_compress};

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
    assert!(err.to_string().contains("DR-BEAM-0004"));
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
