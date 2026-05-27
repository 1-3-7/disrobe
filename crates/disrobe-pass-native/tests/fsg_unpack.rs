#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::error::Error;
use disrobe_pass_native::packers::{FsgUnpackOutput, unpack_fsg};

fn corpus_path(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("fsg");
    p.push(name);
    p
}

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    let p: PathBuf = corpus_path(name);
    fs::read(&p).ok()
}

fn expect_fsg_anchors(out: &FsgUnpackOutput) {
    assert!(
        out.image_base == 0x0040_0000 || out.image_base == 0x0100_0000,
        "unexpected ImageBase 0x{:08X}",
        out.image_base
    );
    assert!(
        out.unpack_dest_va >= out.image_base,
        "unpack_dest_va must be inside image"
    );
    assert!(
        out.packed_stream_va >= out.image_base,
        "packed stream VA must be inside image"
    );
    assert!(
        out.import_meta_va >= out.image_base,
        "import-meta VA must be inside image"
    );
    assert!(
        !out.raw_image.is_empty(),
        "decompressed image must be non-empty"
    );
    assert!(
        out.raw_image.len() >= 0x1000,
        "decompressed image must be at least one page (got {} bytes)",
        out.raw_image.len()
    );
}

#[test]
fn test_fsg_aatools_setup_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        eprintln!("skip: aatools_setup.packed.fsg.exe missing");
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_hash_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("Hash.packed.fsg.exe") else {
        eprintln!("skip: Hash.packed.fsg.exe missing");
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_ftp_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_corpus("ftp.packed.fsg.exe") else {
        eprintln!("skip: ftp.packed.fsg.exe missing");
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
}

#[test]
fn test_fsg_rejects_non_fsg_pe() {
    let mut bytes: Vec<u8> = vec![0u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0xC0u32.to_le_bytes());
    bytes[0xC0..0xC4].copy_from_slice(b"PE\0\0");
    bytes[0xC4..0xC6].copy_from_slice(&0x014Cu16.to_le_bytes());
    bytes[0xC6..0xC8].copy_from_slice(&1u16.to_le_bytes());
    bytes[0xD8..0xDA].copy_from_slice(&0xE0u16.to_le_bytes());
    bytes[0xDC..0xDE].copy_from_slice(&0x010Bu16.to_le_bytes());
    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&bytes);
    assert!(r.is_err(), "non-FSG PE must not unpack");
}

#[test]
fn test_fsg_unpacked_pe_runs_structural_check() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        eprintln!("skip: aatools_setup.packed.fsg.exe missing");
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    expect_fsg_anchors(&out);
    let starts_with_code: bool = out.raw_image.first().is_some_and(|&b: &u8| b != 0x00);
    assert!(
        starts_with_code,
        "first byte of unpacked image should not be NUL (would indicate bss-only output)"
    );
}

struct OriginalSection {
    rva: u32,
    bytes: Vec<u8>,
}

fn parse_original_sections(pe: &[u8]) -> Option<(u32, Vec<OriginalSection>)> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return None;
    }
    let pe_off: usize = u32::from_le_bytes(pe[0x3C..0x40].try_into().ok()?) as usize;
    if pe_off + 0x18 > pe.len() || &pe[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    let nsec: u16 = u16::from_le_bytes(pe[pe_off + 6..pe_off + 8].try_into().ok()?);
    let opt_sz: u16 = u16::from_le_bytes(pe[pe_off + 0x14..pe_off + 0x16].try_into().ok()?);
    let ib: u32 = u32::from_le_bytes(pe[pe_off + 0x34..pe_off + 0x38].try_into().ok()?);
    let sec_off: usize = pe_off + 0x18 + opt_sz as usize;
    let mut out: Vec<OriginalSection> = Vec::new();
    for i in 0..nsec as usize {
        let so: usize = sec_off + 0x28 * i;
        if so + 0x28 > pe.len() {
            return None;
        }
        let vs: u32 = u32::from_le_bytes(pe[so + 8..so + 12].try_into().ok()?);
        let rva: u32 = u32::from_le_bytes(pe[so + 12..so + 16].try_into().ok()?);
        let rs: u32 = u32::from_le_bytes(pe[so + 16..so + 20].try_into().ok()?);
        let ro: usize = u32::from_le_bytes(pe[so + 20..so + 24].try_into().ok()?) as usize;
        let take: usize = (rs.min(vs)) as usize;
        if ro + take > pe.len() {
            continue;
        }
        out.push(OriginalSection {
            rva,
            bytes: pe[ro..ro + take].to_vec(),
        });
    }
    Some((ib, out))
}

fn byte_diff_pct(a: &[u8], b: &[u8]) -> f64 {
    let n: usize = a.len().min(b.len());
    if n == 0 {
        return 100.0;
    }
    let diffs: usize = a
        .iter()
        .zip(b.iter())
        .filter(|(x, y): &(&u8, &u8)| x != y)
        .count();
    (diffs as f64 / n as f64) * 100.0
}

fn assert_round_trip(packed_name: &str, original_name: &str, max_byte_diff_pct: f64) {
    let Some(packed): Option<Vec<u8>> = read_corpus(packed_name) else {
        eprintln!("skip: {packed_name} missing");
        return;
    };
    let Some(orig): Option<Vec<u8>> = read_corpus(original_name) else {
        eprintln!("skip: {original_name} missing");
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    let (orig_ib, sections) = parse_original_sections(&orig).expect("parse original PE");
    assert_eq!(
        orig_ib, out.image_base,
        "original ImageBase 0x{orig_ib:08X} != unpack_fsg ImageBase 0x{:08X}",
        out.image_base
    );
    let dest_rva: u32 = out.unpack_dest_va.saturating_sub(out.image_base);
    println!(
        "{packed_name}: image_base=0x{:08X} dest_rva=0x{:X} raw_image_len={}",
        out.image_base,
        dest_rva,
        out.raw_image.len()
    );
    let mut total: u64 = 0;
    let mut diffs: u64 = 0;
    let mut sections_witnessed: usize = 0;
    for sec in &sections {
        if sec.bytes.is_empty() {
            continue;
        }
        if sec.rva < dest_rva {
            continue;
        }
        let off: usize = (sec.rva - dest_rva) as usize;
        if off >= out.raw_image.len() {
            continue;
        }
        let avail: usize = out.raw_image.len() - off;
        let take: usize = sec.bytes.len().min(avail);
        let recovered: &[u8] = &out.raw_image[off..off + take];
        let original_slice: &[u8] = &sec.bytes[..take];
        let pct: f64 = byte_diff_pct(recovered, original_slice);
        let d: usize = recovered
            .iter()
            .zip(original_slice.iter())
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count();
        total += take as u64;
        diffs += d as u64;
        sections_witnessed += 1;
        println!(
            "  sec RVA=0x{:08X} witnessed {take} bytes  diff={d} ({pct:.3}%)",
            sec.rva
        );
    }
    assert!(
        sections_witnessed >= 1,
        "no sections witnessed for {packed_name}"
    );
    if total == 0 {
        return;
    }
    let total_pct: f64 = (diffs as f64 / total as f64) * 100.0;
    println!(
        "{packed_name}: total {total} bytes witnessed, {diffs} diffs ({total_pct:.3}%) - threshold {max_byte_diff_pct:.2}%"
    );
    assert!(
        total_pct <= max_byte_diff_pct,
        "{packed_name}: byte-diff {total_pct:.3}% exceeds threshold {max_byte_diff_pct:.2}%"
    );
}

#[test]
fn test_fsg_aatools_setup_byte_diff_witness() {
    assert_round_trip(
        "aatools_setup.packed.fsg.exe",
        "aatools_setup.original.exe",
        5.0,
    );
}

#[test]
fn test_fsg_hash_byte_diff_witness() {
    assert_round_trip("Hash.packed.fsg.exe", "Hash.original.exe", 5.0);
}

#[test]
fn test_fsg_ftp_byte_diff_witness() {
    assert_round_trip("ftp.packed.fsg.exe", "ftp.original.exe", 5.0);
}

#[test]
fn test_fsg_synthetic_truncated_stream_errors_cleanly() {
    let Some(packed): Option<Vec<u8>> = read_corpus("aatools_setup.packed.fsg.exe") else {
        eprintln!("skip: aatools_setup.packed.fsg.exe missing");
        return;
    };
    let truncated: Vec<u8> = packed[..0x250].to_vec();
    let r: Result<FsgUnpackOutput, Error> = unpack_fsg(&truncated);
    assert!(r.is_err(), "truncated stream must error, not panic or hang");
}
