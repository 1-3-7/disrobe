#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_precision_loss
)]

use disrobe_pass_native::packers::{
    MpressRecoveryStatus, MpressUnpackOutput, Packer, UnpackerStatus, detect, unpack_mpress,
};

const PACKED: &[u8] = include_bytes!(
    "../../../corpus/native/packers/mpress/gauntlet/gauntlet_target.packed.mpress219.exe"
);

const ORIGINAL: &[u8] =
    include_bytes!("../../../corpus/native/packers/mpress/gauntlet/gauntlet_target.original.exe");

fn parse_pe_sections(bytes: &[u8]) -> Vec<(String, usize, usize, usize)> {
    let pe_off: usize =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    let num_sec: usize = u16::from_le_bytes([bytes[pe_off + 6], bytes[pe_off + 7]]) as usize;
    let size_opt: usize = u16::from_le_bytes([bytes[pe_off + 0x14], bytes[pe_off + 0x15]]) as usize;
    let sec_off: usize = pe_off + 24 + size_opt;
    let mut sections: Vec<(String, usize, usize, usize)> = Vec::with_capacity(num_sec);
    for i in 0..num_sec {
        let base: usize = sec_off + i * 40;
        let name: String = String::from_utf8_lossy(&bytes[base..base + 8])
            .trim_end_matches('\0')
            .to_owned();
        let vsize: usize = u32::from_le_bytes([
            bytes[base + 8],
            bytes[base + 9],
            bytes[base + 10],
            bytes[base + 11],
        ]) as usize;
        let vaddr: usize = u32::from_le_bytes([
            bytes[base + 12],
            bytes[base + 13],
            bytes[base + 14],
            bytes[base + 15],
        ]) as usize;
        let raw_off: usize = u32::from_le_bytes([
            bytes[base + 20],
            bytes[base + 21],
            bytes[base + 22],
            bytes[base + 23],
        ]) as usize;
        sections.push((name, vsize, vaddr, raw_off));
    }
    sections
}

fn section_byte_recovery(
    original: &[u8],
    decoded_image: &[u8],
    section_name: &str,
) -> (usize, usize) {
    let sections: Vec<(String, usize, usize, usize)> = parse_pe_sections(original);
    let mut total_matches: usize = 0;
    let mut total_compared: usize = 0;
    for (name, vsize, vaddr, raw_off) in &sections {
        if name != section_name {
            continue;
        }
        let take: usize = (*vsize)
            .min(decoded_image.len().saturating_sub(*vaddr))
            .min(original.len().saturating_sub(*raw_off));
        for (&dec_byte, &orig_byte) in decoded_image[*vaddr..*vaddr + take]
            .iter()
            .zip(original[*raw_off..*raw_off + take].iter())
        {
            total_compared += 1;
            if dec_byte == orig_byte {
                total_matches += 1;
            }
        }
    }
    (total_matches, total_compared)
}

#[test]
fn mpress_v219_gauntlet_detects_packed_sample() {
    let detections: Vec<_> = detect(PACKED);
    assert!(
        detections.iter().any(|d| d.packer == Packer::Mpress),
        "MPRESS v2.19-packed binary must be detected as Mpress, got: {detections:?}",
    );
    assert_eq!(
        Packer::Mpress.unpacker_status(),
        UnpackerStatus::Implemented,
        "Mpress must be in the Implemented tier",
    );
}

#[test]
fn mpress_v219_gauntlet_unpacks_lzmat_decoded() {
    let out: MpressUnpackOutput =
        unpack_mpress(PACKED).expect("MPRESS v2.19 gauntlet_target must unpack without error");
    assert_eq!(
        out.recovery_status,
        MpressRecoveryStatus::LzmatDecoded,
        "v2.19 gauntlet fixture must reach LzmatDecoded (full LZMAT stream decoded)",
    );
    assert!(
        out.info.mpress_page_count > 0,
        "page_count must be non-zero: {}",
        out.info.mpress_page_count,
    );
    assert!(
        out.info.mpress_payload_len > 0,
        "payload_len must be non-zero: {}",
        out.info.mpress_payload_len,
    );
    assert_eq!(
        out.lzmat_payload.len(),
        out.info.mpress_payload_len as usize,
        "lzmat_payload length must match header-declared payload_len",
    );
    let target_decoded_size: usize = (out.info.mpress_page_count as usize) << 12;
    assert_eq!(
        out.decoded_payload.len(),
        target_decoded_size,
        "decoded_payload.len must equal page_count * 4096",
    );
    println!(
        "mpress v2.19 gauntlet: pages={} payload_len={:#x} decoded_size={} decompressed_img_size={} mpress2_size={}",
        out.info.mpress_page_count,
        out.info.mpress_payload_len,
        out.decoded_payload.len(),
        out.decompressed_image.len(),
        out.info.mpress2_raw_size,
    );
}

#[test]
fn mpress_v219_gauntlet_text_section_byte_exact() {
    let out: MpressUnpackOutput = unpack_mpress(PACKED).expect("gauntlet unpack must succeed");
    assert_eq!(out.recovery_status, MpressRecoveryStatus::LzmatDecoded);

    let (text_matches, text_compared): (usize, usize) =
        section_byte_recovery(ORIGINAL, &out.decompressed_image, ".text");
    assert!(
        text_compared > 0,
        ".text section must be present and non-empty in the original",
    );
    let text_pct: f64 = 100.0 * text_matches as f64 / text_compared as f64;

    let (rdata_matches, rdata_compared): (usize, usize) =
        section_byte_recovery(ORIGINAL, &out.decompressed_image, ".rdata");
    let rdata_pct: f64 = if rdata_compared > 0 {
        100.0 * rdata_matches as f64 / rdata_compared as f64
    } else {
        0.0
    };

    println!(
        "mpress v2.19 gauntlet byte recovery: .text {text_matches}/{text_compared} = {text_pct:.2}%  .rdata {rdata_matches}/{rdata_compared} = {rdata_pct:.2}%",
    );

    assert!(
        text_pct >= 90.0,
        ".text byte recovery {text_pct:.2}% must be >= 90% on gauntlet fixture (MPRESS LZMAT decode is byte-exact for code sections)",
    );
    assert!(
        rdata_pct >= 85.0,
        ".rdata byte recovery {rdata_pct:.2}% must be >= 85% on gauntlet fixture (residual = IAT thunks rebuilt by loader at runtime, absent from decompressed image)",
    );
}

#[test]
fn mpress_v219_gauntlet_section_layout_is_two_mpress_sections() {
    let out: MpressUnpackOutput = unpack_mpress(PACKED).expect("gauntlet unpack");
    assert_eq!(
        out.section_names.len(),
        2,
        "MPRESS always produces exactly two sections (.MPRESS1 and .MPRESS2)",
    );
    assert!(
        out.section_names.iter().any(|n: &String| n.contains("mp1")),
        "section_names must include mp1 marker, got {:?}",
        out.section_names,
    );
    assert!(
        out.section_names.iter().any(|n: &String| n.contains("mp2")),
        "section_names must include mp2 marker, got {:?}",
        out.section_names,
    );
}
