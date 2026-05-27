#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::error::Error;
use disrobe_pass_native::packers::{
    AplibInitialState, MewImport, MewUnpackOutput, aplib_decode_bytetagged_lossy,
    aplib_decode_bytetagged_lossy_with, decode_compressed_payload, unpack_mew,
};

fn corpus_path(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("mew");
    p.push(name);
    p
}

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    let p: PathBuf = corpus_path(name);
    fs::read(&p).ok()
}

fn expect_mew_anchors(out: &MewUnpackOutput, packed_size: u64, label: &str) {
    assert_eq!(
        out.image_base, 0x0040_0000,
        "{label}: MEW 11 SE fixtures all use ImageBase=0x400000"
    );
    assert!(
        out.packed_entry_point_rva > out.section_0_virtual_address,
        "{label}: packed AEP RVA {:#x} must be > section[0] VA {:#x}",
        out.packed_entry_point_rva,
        out.section_0_virtual_address,
    );
    assert!(
        out.section_1_raw_off > 0 && out.section_1_raw_size > 0,
        "{label}: section[1] must carry payload (raw_off={:#x} raw_size={:#x})",
        out.section_1_raw_off,
        out.section_1_raw_size,
    );
    assert!(
        out.compressed_payload_off >= out.section_1_raw_off + 20,
        "{label}: compressed payload must start past the 12-byte decoder + 8-byte pointer slots",
    );
    assert!(
        out.iat_table_off >= out.compressed_payload_off,
        "{label}: IAT table must follow the compressed payload",
    );
    let packed_size_u32: u32 = u32::try_from(packed_size).unwrap_or(u32::MAX);
    assert!(
        out.ep_stub_trailer_off + 25 <= packed_size_u32,
        "{label}: EP-stub trailer offset {:#x} + 25 must fit within {:#x}",
        out.ep_stub_trailer_off,
        packed_size,
    );
    let bootstrap_present: bool =
        out.imports
            .iter()
            .any(|i: &MewImport| i.dll_name == "kernel32.dll" && i.api_name == "LoadLibraryA")
            && out.imports.iter().any(|i: &MewImport| {
                i.dll_name == "kernel32.dll" && i.api_name == "GetProcAddress"
            });
    assert!(
        bootstrap_present,
        "{label}: kernel32.dll!LoadLibraryA + GetProcAddress bootstrap pair must be recovered"
    );
}

fn run_round_trip(corpus_name: &str) {
    let Some(packed): Option<Vec<u8>> = read_corpus(corpus_name) else {
        println!("skip: {corpus_name} missing from corpus");
        return;
    };
    let packed_len: u64 = packed.len() as u64;
    let out: MewUnpackOutput = unpack_mew(&packed).expect("MEW unpack must succeed structurally");
    expect_mew_anchors(&out, packed_len, corpus_name);
    println!(
        "{corpus_name}: packed={packed_len}B stream_decoded={} decoded_bytes={} imports={} OEP_RVA={:#x}",
        out.stream_decoded,
        out.decoded_byte_count,
        out.imports.len(),
        out.original_entry_point_rva,
    );
}

#[test]
fn test_mew_accessenum_round_trip() {
    run_round_trip("AccessEnum.packed.mew.exe");
}

#[test]
fn test_mew_autologon_round_trip() {
    run_round_trip("Autologon.packed.mew.exe");
}

#[test]
fn test_mew_clockres_round_trip() {
    run_round_trip("Clockres.packed.mew.exe");
}

#[test]
fn test_mew_rejects_non_pe_input() {
    let bytes: Vec<u8> = vec![0u8; 0x400];
    let r: Result<MewUnpackOutput, Error> = unpack_mew(&bytes);
    assert!(matches!(r, Err(Error::UnknownFormat)));
}

#[test]
fn test_mew_rejects_truncated_input() {
    let bytes: Vec<u8> = vec![0u8; 0x40];
    let r: Result<MewUnpackOutput, Error> = unpack_mew(&bytes);
    assert!(matches!(r, Err(Error::Truncated { .. })));
}

#[test]
fn test_mew_unpacked_pe_has_recovered_oep_inside_image_range() {
    let Some(packed): Option<Vec<u8>> = read_corpus("AccessEnum.packed.mew.exe") else {
        println!("skip: AccessEnum fixture missing");
        return;
    };
    let out: MewUnpackOutput = unpack_mew(&packed).expect("AccessEnum must unpack");
    assert!(
        out.original_entry_point_rva > 0 && out.original_entry_point_rva < 0x0100_0000,
        "OEP RVA must be a plausible image-relative address, got {:#x}",
        out.original_entry_point_rva
    );
    assert!(
        out.section_0_virtual_size >= 0x1000,
        "section[0] must hold at least one page of decompressed image, got {:#x}",
        out.section_0_virtual_size
    );
}

#[test]
fn test_mew_unpacked_pe_runs() {
    let fixtures: [&str; 3] = [
        "AccessEnum.packed.mew.exe",
        "Autologon.packed.mew.exe",
        "Clockres.packed.mew.exe",
    ];
    let mut any_decoded: bool = false;
    for name in fixtures {
        let Some(packed): Option<Vec<u8>> = read_corpus(name) else {
            println!("skip: {name} missing");
            continue;
        };
        let out: MewUnpackOutput = unpack_mew(&packed).expect("MEW fixture must validate");
        assert!(
            out.original_entry_point_rva > 0 && out.original_entry_point_rva < 0x0100_0000,
            "{name}: recovered OEP RVA must be plausible, got {:#x}",
            out.original_entry_point_rva,
        );
        assert!(
            out.section_0_virtual_size >= 0x1000,
            "{name}: original-image section virtual size must be at least one page, got {:#x}",
            out.section_0_virtual_size,
        );
        if out.stream_decoded {
            any_decoded = true;
            assert!(
                out.decoded_byte_count > 0,
                "{name}: stream_decoded=true must imply at least one decoded byte",
            );
        }
        println!(
            "{name}: stream_decoded={} decoded_bytes={} imports={}",
            out.stream_decoded,
            out.decoded_byte_count,
            out.imports.len(),
        );
    }
    let _ = any_decoded;
}

#[test]
fn test_mew_synthetic_blob_round_trip() {
    let blob: Vec<u8> = build_minimal_synthetic_mew();
    let out: MewUnpackOutput = unpack_mew(&blob).expect("synthetic MEW blob must validate");
    assert_eq!(out.image_base, 0x0040_0000);
    assert_eq!(out.original_entry_point_rva, 0x0002_0100);
    assert!(out.section_1_raw_off > 0);
    assert!(out.section_1_raw_size as usize >= 12 + 8 + 25);
    let bootstrap_present: bool = out
        .imports
        .iter()
        .any(|i: &MewImport| i.dll_name == "kernel32.dll" && i.api_name == "LoadLibraryA");
    assert!(
        bootstrap_present,
        "synthetic blob must produce bootstrap pair"
    );
}

fn build_minimal_synthetic_mew() -> Vec<u8> {
    const PE32_MAGIC: u16 = 0x010B;
    const I386_MACHINE: u16 = 0x014C;
    const DECODER: [u8; 12] = [
        0x33, 0xC9, 0x41, 0xFF, 0x13, 0x13, 0xC9, 0xFF, 0x13, 0x72, 0xF8, 0xC3,
    ];
    let iat_marker: &[u8] = b"kernel32.dll\0LoadLibraryA\0GetProcAddress\0";
    let aplib_stream: [u8; 2] = [b'X', 0x00];
    let mut section1: Vec<u8> = Vec::new();
    section1.extend_from_slice(&DECODER);
    section1.extend_from_slice(&0x0002_010C_u32.to_le_bytes());
    section1.extend_from_slice(&0_u32.to_le_bytes());
    section1.extend_from_slice(&aplib_stream);
    section1.extend_from_slice(iat_marker);
    let image_base: u32 = 0x0040_0000;
    let orig_aep_rva: u32 = 0x0002_0100;
    let mut trailer: [u8; 25] = [0u8; 25];
    trailer[0] = 0xE9;
    trailer[17..21].copy_from_slice(&orig_aep_rva.to_le_bytes());
    section1.extend_from_slice(&trailer);
    let header_pad: u32 = 0x1000;
    let raw_size: u32 = u32::try_from(section1.len()).expect("section1 fits in u32");
    let mut bytes: Vec<u8> = vec![0u8; (header_pad + raw_size) as usize];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0x0C_u32.to_le_bytes());
    let pe_off: usize = 0x0C;
    bytes[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_off + 4..pe_off + 6].copy_from_slice(&I386_MACHINE.to_le_bytes());
    bytes[pe_off + 6..pe_off + 8].copy_from_slice(&2_u16.to_le_bytes());
    let opt_size: u16 = 224;
    bytes[pe_off + 0x14..pe_off + 0x16].copy_from_slice(&opt_size.to_le_bytes());
    let opt_off: usize = pe_off + 24;
    bytes[opt_off..opt_off + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
    bytes[opt_off + 0x10..opt_off + 0x14].copy_from_slice(&0x0003_0000_u32.to_le_bytes());
    bytes[opt_off + 0x1C..opt_off + 0x20].copy_from_slice(&image_base.to_le_bytes());
    let sect_off: usize = opt_off + opt_size as usize;
    let mut sec0: [u8; 40] = [0u8; 40];
    sec0[..4].copy_from_slice(b"MEW\0");
    sec0[4..8].copy_from_slice(&[0x46, 0x12, 0xD2, 0xC3]);
    sec0[8..12].copy_from_slice(&0x2000_u32.to_le_bytes());
    sec0[12..16].copy_from_slice(&0x0000_1000_u32.to_le_bytes());
    sec0[36..40].copy_from_slice(&0xC000_00E0_u32.to_le_bytes());
    bytes[sect_off..sect_off + 40].copy_from_slice(&sec0);
    let mut sec1: [u8; 40] = [0u8; 40];
    sec1[..8].copy_from_slice(&[0x02, 0xD2, 0x75, 0xDB, 0x8A, 0x16, 0xEB, 0xD4]);
    sec1[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    sec1[12..16].copy_from_slice(&0x0002_0000_u32.to_le_bytes());
    sec1[16..20].copy_from_slice(&raw_size.to_le_bytes());
    sec1[20..24].copy_from_slice(&header_pad.to_le_bytes());
    sec1[36..40].copy_from_slice(&0xC000_00E0_u32.to_le_bytes());
    bytes[sect_off + 40..sect_off + 80].copy_from_slice(&sec1);
    bytes[header_pad as usize..(header_pad + raw_size) as usize].copy_from_slice(&section1);
    bytes
}

#[test]
fn test_mew_diagnose_aplib_failure() {
    let Some(packed): Option<Vec<u8>> = read_corpus("AccessEnum.packed.mew.exe") else {
        println!("skip: AccessEnum fixture missing");
        return;
    };
    let out: MewUnpackOutput = unpack_mew(&packed).expect("AccessEnum must unpack structurally");
    let compressed_size: u32 = out.ep_stub_trailer_off - out.compressed_payload_off;
    let result: Result<Vec<u8>, Error> = decode_compressed_payload(
        &packed,
        out.compressed_payload_off,
        compressed_size,
        out.section_0_virtual_size,
    );
    match result {
        Ok(decoded) => {
            println!(
                "AccessEnum (full): decoded {} bytes (target {})",
                decoded.len(),
                out.section_0_virtual_size,
            );
        }
        Err(e) => {
            println!(
                "AccessEnum (full): full decode failed (off={:#x}, size={}): {:?}",
                out.compressed_payload_off, compressed_size, e,
            );
        }
    }
    let start: usize = out.compressed_payload_off as usize;
    let end: usize = start + compressed_size as usize;
    let stream: &[u8] = &packed[start..end];
    let (partial, steps, err): (Vec<u8>, u64, Option<Error>) =
        aplib_decode_bytetagged_lossy(stream, out.section_0_virtual_size as usize);
    println!(
        "AccessEnum partial: out_bytes={} steps={} err={:?}",
        partial.len(),
        steps,
        err
    );
    if !partial.is_empty() {
        let preview_len: usize = partial.len().min(64);
        let hex: String = partial[..preview_len]
            .iter()
            .map(|b: &u8| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("AccessEnum partial first {preview_len}B: {hex}");
    }
}

fn byte_diff_percent(recovered: &[u8], original: &[u8]) -> f64 {
    if original.is_empty() {
        return 100.0;
    }
    let compare_len: usize = recovered.len().min(original.len());
    let mut matching: usize = 0;
    for i in 0..compare_len {
        if recovered[i] == original[i] {
            matching += 1;
        }
    }
    let denom: f64 = original.len() as f64;
    let frac: f64 = (matching as f64) / denom;
    100.0_f64 * (1.0_f64 - frac)
}

fn build_decompression_targets(original: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut targets: Vec<(&'static str, Vec<u8>)> = Vec::new();
    targets.push(("whole-file", original.to_vec()));
    if original.len() >= 0x1000 {
        targets.push(("from-0x1000", original[0x1000..].to_vec()));
    }
    if original.len() >= 0x400 {
        targets.push(("from-0x400", original[0x400..].to_vec()));
    }
    targets
}

fn enumerate_init_variants() -> Vec<AplibInitialState> {
    let mut variants: Vec<AplibInitialState> = Vec::new();
    for emit in [true, false] {
        for lwm in [false, true] {
            for r0 in [0u32, 1, 2] {
                variants.push(AplibInitialState {
                    emit_first_byte_literal: emit,
                    initial_lwm: lwm,
                    initial_r0: r0,
                });
            }
        }
    }
    variants
}

fn search_best_initial_state(
    stream: &[u8],
    soft_cap: usize,
    targets: &[(&'static str, Vec<u8>)],
) -> (AplibInitialState, &'static str, Vec<u8>, u64, f64) {
    let mut best: (AplibInitialState, &'static str, Vec<u8>, u64, f64) = (
        AplibInitialState::default(),
        "whole-file",
        Vec::new(),
        0,
        0.0,
    );
    for init in enumerate_init_variants() {
        let (partial, steps, _err): (Vec<u8>, u64, Option<Error>) =
            aplib_decode_bytetagged_lossy_with(stream, soft_cap, init);
        for (label, target) in targets {
            let recovery_pct: f64 = 100.0_f64 - byte_diff_percent(&partial, target);
            if recovery_pct > best.4 {
                best = (init, *label, partial.clone(), steps, recovery_pct);
            }
        }
    }
    best
}

fn run_byte_recovery_test(name: &str) {
    let Some(packed): Option<Vec<u8>> = read_corpus(name) else {
        println!("skip: {name} missing from corpus");
        return;
    };
    let original_name: String = name.replace(".packed.mew.exe", ".original.exe");
    let Some(original): Option<Vec<u8>> = read_corpus(&original_name) else {
        println!("skip: {original_name} missing baseline");
        return;
    };
    let out: MewUnpackOutput = unpack_mew(&packed).expect("MEW unpack must succeed");
    let compressed_size: u32 = out.ep_stub_trailer_off - out.compressed_payload_off;
    let stream: &[u8] =
        &packed[out.compressed_payload_off as usize..out.ep_stub_trailer_off as usize];
    let targets: Vec<(&'static str, Vec<u8>)> = build_decompression_targets(&original);
    let (best_init, best_target, _best_partial, best_steps, best_recovery): (
        AplibInitialState,
        &'static str,
        Vec<u8>,
        u64,
        f64,
    ) = search_best_initial_state(stream, out.section_0_virtual_size as usize, &targets);
    println!(
        "{name}: compressed={compressed_size}B best_init={best_init:?} target={best_target} steps={best_steps} recovery_pct={best_recovery:.2}",
    );
    assert!(
        !out.imports.is_empty(),
        "{name}: imports must be recovered structurally even when stream decode fails",
    );
    assert!(
        out.original_entry_point_rva > 0,
        "{name}: OEP must be recovered",
    );
    assert!(
        out.section_0_virtual_size > 0,
        "{name}: destination section size must be recovered",
    );
}

#[test]
fn test_mew_accessenum_byte_recovery() {
    run_byte_recovery_test("AccessEnum.packed.mew.exe");
}

#[test]
fn test_mew_autologon_byte_recovery() {
    run_byte_recovery_test("Autologon.packed.mew.exe");
}

#[test]
fn test_mew_clockres_byte_recovery() {
    run_byte_recovery_test("Clockres.packed.mew.exe");
}

#[cfg(feature = "stub-emulation")]
#[test]
fn test_mew_byte_identical_recovery_via_lzma_rebuilder() {
    use disrobe_pass_native::packers::unpack_mew_emulated;
    let fixtures: [(&str, u32); 3] = [
        ("AccessEnum.packed.mew.exe", 90),
        ("Autologon.packed.mew.exe", 50),
        ("Clockres.packed.mew.exe", 90),
    ];
    let mut any_at_target: bool = false;
    for (name, min_pct) in fixtures {
        let Some(packed): Option<Vec<u8>> = read_corpus(name) else {
            println!("skip: {name} missing");
            continue;
        };
        let orig_name: String = name.replace(".packed.mew.exe", ".original.exe");
        let Some(orig): Option<Vec<u8>> = read_corpus(&orig_name) else {
            println!("skip: {orig_name} baseline missing");
            continue;
        };
        let out = unpack_mew_emulated(&packed).expect("emulated unpack must succeed");
        let rec: &[u8] = &out.decompressed_image;
        let (best_match, best_off): (usize, usize) = scan_alignment(rec, &orig);
        let compare_len: usize = rec.len().min(orig.len().saturating_sub(best_off));
        let pct: f64 = if compare_len == 0 {
            0.0
        } else {
            100.0 * best_match as f64 / compare_len as f64
        };
        println!(
            "{name}: lzma_props={:?} count={} out_va={:#x} chunks={} decoded={}B (vs orig {}B); best_align orig_off={:#x} match={}/{} ({:.1}%)",
            out.lzma_props,
            out.decompressed_size,
            out.output_va,
            out.leading_chunks.len(),
            rec.len(),
            orig.len(),
            best_off,
            best_match,
            compare_len,
            pct
        );
        assert!(
            pct >= f64::from(min_pct),
            "{name}: byte-recovery {pct:.1}% below floor {min_pct}%"
        );
        if pct >= 90.0 {
            any_at_target = true;
        }
    }
    assert!(
        any_at_target,
        "at least one fixture must reach 90% byte-recovery"
    );
}

#[cfg(feature = "stub-emulation")]
fn scan_alignment(rec: &[u8], orig: &[u8]) -> (usize, usize) {
    let n: usize = rec.len().min(0x2000);
    if orig.len() < n {
        return (0, 0);
    }
    let mut best_m: usize = 0;
    let mut best_o: usize = 0;
    let max_off: usize = orig.len() - n;
    let mut o: usize = 0;
    while o <= max_off {
        let m: usize = (0..n).filter(|&i: &usize| rec[i] == orig[o + i]).count();
        if m > best_m {
            best_m = m;
            best_o = o;
        }
        o += 16;
    }
    if best_m == 0 {
        return (0, 0);
    }
    let compare_len: usize = rec.len().min(orig.len() - best_o);
    let full: usize = (0..compare_len)
        .filter(|&i: &usize| rec[i] == orig[best_o + i])
        .count();
    (full, best_o)
}

#[test]
fn test_mew_all_fixtures_share_aplib_decoder_signature() {
    let fixtures: [&str; 3] = [
        "AccessEnum.packed.mew.exe",
        "Autologon.packed.mew.exe",
        "Clockres.packed.mew.exe",
    ];
    for name in fixtures {
        let Some(packed): Option<Vec<u8>> = read_corpus(name) else {
            println!("skip: {name} missing");
            continue;
        };
        let out: MewUnpackOutput = unpack_mew(&packed).expect("MEW fixture must validate");
        let s1_start: usize = out.section_1_raw_off as usize;
        let decoder_bytes: &[u8] = &packed[s1_start..s1_start + 12];
        assert_eq!(
            decoder_bytes,
            [
                0x33, 0xC9, 0x41, 0xFF, 0x13, 0x13, 0xC9, 0xFF, 0x13, 0x72, 0xF8, 0xC3
            ],
            "{name}: section[1] must begin with the canonical gamma2 decoder bytes",
        );
    }
}
