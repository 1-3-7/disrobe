#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::needless_type_cast
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::error::Error;
use disrobe_pass_native::packers::{MpressRecoveryStatus, MpressUnpackOutput, unpack_mpress};

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("mpress");
    p
}

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = corpus_dir();
    p.push(name);
    fs::read(&p).ok()
}

fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew: u32 = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]);
    let pe_off: usize = e_lfanew as usize;
    if pe_off + 4 > bytes.len() {
        return false;
    }
    &bytes[pe_off..pe_off + 4] == b"PE\0\0"
}

#[test]
fn test_mpress_hello_structural_recovery() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.exe") else {
        eprintln!("skip: corpus hello.exe missing");
        return;
    };
    let out: MpressUnpackOutput = match unpack_mpress(&packed) {
        Ok(v) => v,
        Err(e) => panic!("MPRESS recovery failed on hello.exe: {e:?}"),
    };
    assert_eq!(
        out.recovery_status,
        MpressRecoveryStatus::LzmatDecoded,
        "v0.8 unpacker must produce LzmatDecoded byte-level recovery"
    );
    assert!(
        looks_like_pe(&out.original_pe),
        "synthesized PE must have MZ + PE\\0\\0 signature"
    );
    assert!(
        out.info.mpress_page_count > 0,
        "MPRESS header page_count must be non-zero"
    );
    assert!(
        out.info.mpress_payload_len > 0,
        "MPRESS header payload_len must be non-zero"
    );
    assert_eq!(
        out.lzmat_payload.len(),
        out.info.mpress_payload_len as usize
    );
    let target_decoded_size: usize = (out.info.mpress_page_count as usize) << 12;
    assert_eq!(
        out.decoded_payload.len(),
        target_decoded_size,
        "decoded payload must match page_count * 0x1000"
    );
    println!(
        "hello LzmatDecoded: pages={} payload_len={:#x} decoded_size={} synth_pe_size={} mpress2_size={}",
        out.info.mpress_page_count,
        out.info.mpress_payload_len,
        out.decoded_payload.len(),
        out.original_pe.len(),
        out.info.mpress2_raw_size,
    );
    assert!(out.info.address_of_entry_point >= out.info.mpress2_va);
    assert!(
        out.info
            .address_of_entry_point
            .saturating_sub(out.info.mpress2_va)
            < out.info.mpress2_vsize,
        "AEP must point inside .MPRESS2 stub"
    );
}

#[test]
fn test_mpress_taskmgr_structural_recovery() {
    let Some(packed): Option<Vec<u8>> = read_corpus("taskmgr.packed.mpress.exe") else {
        eprintln!("skip: corpus taskmgr.packed.mpress.exe missing");
        return;
    };
    let out: MpressUnpackOutput = match unpack_mpress(&packed) {
        Ok(v) => v,
        Err(e) => panic!("MPRESS recovery failed on taskmgr: {e:?}"),
    };
    assert_eq!(
        out.recovery_status,
        MpressRecoveryStatus::LzmatDecoded,
        "taskmgr must reach LzmatDecoded recovery"
    );
    assert!(
        looks_like_pe(&out.original_pe),
        "recovered taskmgr must be PE"
    );
    assert!(
        out.info.mpress_page_count >= 0x100,
        "taskmgr should have many pages (>=0x100)"
    );
    let target_decoded_size: usize = (out.info.mpress_page_count as usize) << 12;
    assert_eq!(out.decoded_payload.len(), target_decoded_size);
    println!(
        "taskmgr LzmatDecoded: pages={} payload_len={:#x} decoded_size={} synth_pe_size={} decompressed_img_size={} mpress2_size={}",
        out.info.mpress_page_count,
        out.info.mpress_payload_len,
        out.decoded_payload.len(),
        out.original_pe.len(),
        out.decompressed_image.len(),
        out.info.mpress2_raw_size,
    );
    assert_eq!(
        out.decompressed_image.len(),
        out.info.size_of_image as usize
    );
}

#[test]
fn test_mpress_layout_is_two_sections() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.exe") else {
        eprintln!("skip: corpus hello.exe missing");
        return;
    };
    let out: MpressUnpackOutput = unpack_mpress(&packed).expect("hello must structurally unpack");
    assert_eq!(out.section_names.len(), 2);
    assert!(
        out.section_names.iter().any(|n: &String| n.contains("mp1")),
        "section_names must include mp1 marker"
    );
    assert!(
        out.section_names.iter().any(|n: &String| n.contains("mp2")),
        "section_names must include mp2 marker"
    );
}

#[test]
fn test_mpress_payload_matches_lzmat_stream_start() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.exe") else {
        eprintln!("skip: corpus hello.exe missing");
        return;
    };
    let out: MpressUnpackOutput = unpack_mpress(&packed).expect("unpack hello");
    let mpress1_raw_start: usize = out.info.mpress1_raw_off as usize + 6;
    let payload_first_16: &[u8] = &packed[mpress1_raw_start..mpress1_raw_start + 16];
    assert_eq!(&out.lzmat_payload[..16], payload_first_16);
}

fn compute_primary_byte_recovery(
    original: &[u8],
    decoded_image: &[u8],
    _decoded_section_va_base: u32,
) -> (usize, usize) {
    let pe_off: usize = u32::from_le_bytes([
        original[0x3C],
        original[0x3D],
        original[0x3E],
        original[0x3F],
    ]) as usize;
    let num_sec: usize = u16::from_le_bytes([original[pe_off + 6], original[pe_off + 7]]) as usize;
    let size_opt: usize =
        u16::from_le_bytes([original[pe_off + 0x14], original[pe_off + 0x15]]) as usize;
    let sec_off: usize = pe_off + 24 + size_opt;
    let mut matches: usize = 0;
    let mut compared: usize = 0;
    for i in 0..num_sec {
        let base: usize = sec_off + i * 40;
        let name: String = String::from_utf8_lossy(&original[base..base + 8])
            .trim_end_matches('\0')
            .to_string();
        let vsize: u32 = u32::from_le_bytes([
            original[base + 8],
            original[base + 9],
            original[base + 10],
            original[base + 11],
        ]);
        let vaddr: u32 = u32::from_le_bytes([
            original[base + 12],
            original[base + 13],
            original[base + 14],
            original[base + 15],
        ]);
        let raw_off: u32 = u32::from_le_bytes([
            original[base + 20],
            original[base + 21],
            original[base + 22],
            original[base + 23],
        ]);
        if !(name == ".text"
            || name == ".rdata"
            || name == ".data"
            || name == ".didat"
            || name.starts_with(".text"))
        {
            continue;
        }
        let dec_off: usize = vaddr as usize;
        let take: usize = (vsize as usize)
            .min(decoded_image.len().saturating_sub(dec_off))
            .min(original.len().saturating_sub(raw_off as usize));
        for (a, b) in decoded_image[dec_off..dec_off + take]
            .iter()
            .zip(original[raw_off as usize..raw_off as usize + take].iter())
        {
            compared += 1;
            if a == b {
                matches += 1;
            }
        }
    }
    (matches, compared)
}

#[test]
fn test_mpress_hello_byte_recovery() {
    let Some(packed): Option<Vec<u8>> = read_corpus("hello.exe") else {
        eprintln!("skip: corpus hello.exe missing");
        return;
    };
    let Some(original): Option<Vec<u8>> = read_corpus("hello.original.exe") else {
        eprintln!("skip: corpus hello.original.exe missing");
        return;
    };
    let out: MpressUnpackOutput =
        unpack_mpress(&packed).expect("MPRESS unpack on hello.exe must succeed");
    assert_eq!(out.recovery_status, MpressRecoveryStatus::LzmatDecoded);
    let (matches, compared): (usize, usize) =
        compute_primary_byte_recovery(&original, &out.decompressed_image, 0x1000);
    let pct: f64 = 100.0 * matches as f64 / compared.max(1) as f64;
    println!("hello primary byte recovery: {matches}/{compared} = {pct:.2}%");
    assert!(
        pct >= 90.0,
        "byte recovery {pct:.2}% must be >= 90% on hello.exe primary sections"
    );
}

#[test]
fn test_mpress_taskmgr_byte_recovery() {
    let Some(packed): Option<Vec<u8>> = read_corpus("taskmgr.packed.mpress.exe") else {
        eprintln!("skip: corpus taskmgr.packed.mpress.exe missing");
        return;
    };
    let Some(original): Option<Vec<u8>> = read_corpus("taskmgr.original.exe") else {
        eprintln!("skip: corpus taskmgr.original.exe missing");
        return;
    };
    let out: MpressUnpackOutput =
        unpack_mpress(&packed).expect("MPRESS unpack on taskmgr must succeed");
    assert_eq!(out.recovery_status, MpressRecoveryStatus::LzmatDecoded);
    let (matches, compared): (usize, usize) =
        compute_primary_byte_recovery(&original, &out.decompressed_image, 0x1000);
    let pct: f64 = 100.0 * matches as f64 / compared.max(1) as f64;
    println!("taskmgr primary byte recovery: {matches}/{compared} = {pct:.2}%");
    assert!(
        pct >= 90.0,
        "byte recovery {pct:.2}% must be >= 90% on taskmgr primary sections"
    );
}

#[test]
fn test_mpress_rejects_non_mpress_input() {
    let mut buf: Vec<u8> = vec![0u8; 1024];
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_off: u32 = 0x80;
    buf[0x3C] = u8::try_from(pe_off & 0xFF).unwrap_or(0);
    buf[0x3D] = u8::try_from((pe_off >> 8) & 0xFF).unwrap_or(0);
    buf[0x3E] = u8::try_from((pe_off >> 16) & 0xFF).unwrap_or(0);
    buf[0x3F] = u8::try_from((pe_off >> 24) & 0xFF).unwrap_or(0);
    buf[0x80] = b'P';
    buf[0x81] = b'E';
    let r: Result<MpressUnpackOutput, Error> = unpack_mpress(&buf);
    assert!(
        r.is_err(),
        "must reject buffers without .MPRESS1/2 sections"
    );
}
