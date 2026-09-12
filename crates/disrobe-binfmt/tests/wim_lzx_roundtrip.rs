#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use disrobe_binfmt::containers::wim::{
    RESHDR_FLAG_COMPRESSED, WIM_FLAG_COMPRESS_LZX, WIM_FLAG_COMPRESSION, WIM_HEADER_LEN, WIM_MAGIC,
    WimArchive, WimCompression,
};
use disrobe_binfmt::containers::{
    decompress_named_resource, lzx_build_resource_body, lzx_compress_chunk, parse_wim,
};
use disrobe_binfmt::extract::ExtractionResult;
use disrobe_binfmt::{ContainerKind, ExtractionQuota, extract_to};

const WIM_CHUNK_SIZE: u32 = 32_768;

const LZX_BLOCKTYPE_VERBATIM: u16 = 1;

const LZX_BLOCKTYPE_ALIGNED: u16 = 2;

const LZX_BLOCKTYPE_BITS: u32 = 3;

fn lzx_declared_block_type(chunk: &[u8]) -> u16 {
    let first: u16 = u16::from_le_bytes([
        chunk.first().copied().unwrap_or(0),
        chunk.get(1).copied().unwrap_or(0),
    ]);
    first >> (u16::BITS - LZX_BLOCKTYPE_BITS)
}

const fn chunk_table_len(chunk_count: usize) -> usize {
    chunk_count.saturating_sub(1) * 4
}

fn known_plaintext(len: usize, seed: u32) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::with_capacity(len);
    let phrase: &[u8] = b"\\Windows\\System32\\drivers ";
    let mut state: u32 = seed;
    while data.len() < len {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        if state.trailing_zeros() >= 5 {
            data.extend_from_slice(phrase);
        } else {
            data.push((state >> 16) as u8);
            data.push((state >> 8) as u8);
        }
    }
    data.truncate(len);
    data
}

fn compress_resource(plaintext: &[u8], aligned: bool) -> Vec<u8> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut offset: usize = 0;
    while offset < plaintext.len() {
        let end: usize = (offset + WIM_CHUNK_SIZE as usize).min(plaintext.len());
        let compressed: Vec<u8> =
            lzx_compress_chunk(&plaintext[offset..end], aligned).expect("compress lzx chunk");
        chunks.push(compressed);
        offset = end;
    }
    assert_encoder_emits_a_spec_shaped_resource(plaintext, &chunks, aligned);
    lzx_build_resource_body(&chunks)
}

fn assert_encoder_emits_a_spec_shaped_resource(
    plaintext: &[u8],
    chunks: &[Vec<u8>],
    aligned: bool,
) {
    let expected_chunks: usize = plaintext.len().div_ceil(WIM_CHUNK_SIZE as usize);
    assert_eq!(
        chunks.len(),
        expected_chunks,
        "a resource of {} bytes is split into {expected_chunks} chunks of at most {WIM_CHUNK_SIZE}",
        plaintext.len()
    );

    let want_type: u16 = if aligned {
        LZX_BLOCKTYPE_ALIGNED
    } else {
        LZX_BLOCKTYPE_VERBATIM
    };
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(
            lzx_declared_block_type(chunk),
            want_type,
            "chunk {index} must open with the 3-bit LZX block type {want_type} in the high bits of \
             its first 16-bit little-endian unit, read straight from the bytes and not through the \
             decoder under test"
        );
    }

    let compressed_total: usize = chunks.iter().map(Vec::len).sum();
    assert!(
        compressed_total < plaintext.len(),
        "the encoder must actually encode: {compressed_total} compressed bytes against {} \
         plaintext bytes means a round trip could pass on a pair that copies rather than codes",
        plaintext.len()
    );
}

fn assert_decoder_reads_the_bitstream(plaintext: &[u8], aligned: bool) {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut offset: usize = 0;
    while offset < plaintext.len() {
        let end: usize = (offset + WIM_CHUNK_SIZE as usize).min(plaintext.len());
        chunks.push(
            lzx_compress_chunk(&plaintext[offset..end], aligned).expect("compress lzx chunk"),
        );
        offset = end;
    }
    let table: usize = chunk_table_len(chunks.len());
    let mut body: Vec<u8> = lzx_build_resource_body(&chunks);
    let victim: usize = table + chunks.first().map_or(0, Vec::len) / 2;
    let byte: &mut u8 = body
        .get_mut(victim)
        .expect("the compressed body reaches into its first chunk");
    *byte ^= 0xff;

    let wim: Vec<u8> = build_wim_with_boot_resource(plaintext, &body);
    let archive: WimArchive = parse_wim(&wim).expect("parse lzx wim with a damaged chunk");
    let outcome: disrobe_binfmt::Result<Vec<u8>> = decompress_named_resource(
        &wim,
        &archive.header,
        &archive.header.boot_metadata,
        &ExtractionQuota::unrestricted(),
    );
    match outcome {
        Err(_) => {}
        Ok(decoded) => assert_ne!(
            decoded, plaintext,
            "flipping a byte inside the first compressed chunk still reproduced the plaintext, so \
             the decoder is not reading the bitstream it was handed (aligned={aligned})"
        ),
    }
}

fn write_reshdr(header: &mut [u8], at: usize, size: u64, flags: u8, offset: u64, original: u64) {
    header[at..at + 7].copy_from_slice(&size.to_le_bytes()[..7]);
    header[at + 7] = flags;
    header[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
    header[at + 16..at + 24].copy_from_slice(&original.to_le_bytes());
}

fn build_wim_with_boot_resource(plaintext: &[u8], body: &[u8]) -> Vec<u8> {
    let xml_text: &[u8] = b"<WIM><IMAGE INDEX=\"1\"><NAME>boot</NAME></IMAGE></WIM>";
    let mut xml: Vec<u8> = vec![0xff, 0xfe];
    for &byte in xml_text {
        xml.push(byte);
        xml.push(0);
    }

    let header_len: usize = WIM_HEADER_LEN;
    let body_offset: u64 = header_len as u64;
    let xml_offset: u64 = body_offset + body.len() as u64;

    let mut header: Vec<u8> = vec![0u8; header_len];
    header[0..8].copy_from_slice(WIM_MAGIC);
    header[8..12].copy_from_slice(&(header_len as u32).to_le_bytes());
    header[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    let flags: u32 = WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_LZX;
    header[16..20].copy_from_slice(&flags.to_le_bytes());
    header[20..24].copy_from_slice(&WIM_CHUNK_SIZE.to_le_bytes());
    header[40..42].copy_from_slice(&1u16.to_le_bytes());
    header[42..44].copy_from_slice(&1u16.to_le_bytes());
    header[44..48].copy_from_slice(&1u32.to_le_bytes());

    write_reshdr(
        &mut header,
        96,
        body.len() as u64,
        RESHDR_FLAG_COMPRESSED,
        body_offset,
        plaintext.len() as u64,
    );
    write_reshdr(
        &mut header,
        72,
        xml.len() as u64,
        0,
        xml_offset,
        xml.len() as u64,
    );

    let mut image: Vec<u8> = header;
    image.extend_from_slice(body);
    image.extend_from_slice(&xml);
    image
}

fn temp_out(tag: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-wim-lzx-{tag}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn assert_lzx_resource_round_trips(len: usize, aligned: bool, tag: &str) {
    let plaintext: Vec<u8> = known_plaintext(len, 0x1357_2468 ^ (len as u32));
    let body: Vec<u8> = compress_resource(&plaintext, aligned);
    let wim: Vec<u8> = build_wim_with_boot_resource(&plaintext, &body);

    let archive: WimArchive = parse_wim(&wim).expect("parse synthetic lzx wim");
    assert_eq!(
        archive.header.compression,
        WimCompression::Lzx,
        "header must advertise LZX"
    );
    assert!(
        archive.header.boot_metadata.is_compressed(),
        "boot resource must be flagged compressed"
    );
    assert_eq!(
        archive.header.boot_metadata.original_size as usize,
        plaintext.len(),
        "declared original size must match the known plaintext"
    );

    let decoded: Vec<u8> = decompress_named_resource(
        &wim,
        &archive.header,
        &archive.header.boot_metadata,
        &ExtractionQuota::unrestricted(),
    )
    .expect("decompress lzx boot resource");
    assert_eq!(
        decoded, plaintext,
        "direct LZX resource decode is not byte-identical to the known plaintext (aligned={aligned})"
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_out(tag);

    let out_dir: PathBuf = scratch.path().to_path_buf();
    let result: ExtractionResult =
        extract_to(ContainerKind::Wim, &wim, &out_dir).expect("extract_to lzx wim");
    assert_eq!(result.kind, ContainerKind::Wim);
    let written: Vec<u8> = std::fs::read(out_dir.join(".disrobe-wim-boot-metadata.dec.bin"))
        .expect("extract_to must write the decoded LZX boot resource");
    assert_eq!(
        written, plaintext,
        "extract_to LZX output is not byte-identical to the known plaintext (aligned={aligned})"
    );
    assert!(
        !result
            .integrity_violations
            .iter()
            .any(|v: &String| v.contains("wim-decompress")),
        "a valid LZX resource must not raise a decompression violation: {:?}",
        result.integrity_violations
    );
    let _ = std::fs::remove_dir_all(&out_dir);

    assert_decoder_reads_the_bitstream(&plaintext, aligned);
}

#[test]
fn lzx_single_chunk_verbatim_resource_round_trips() {
    assert_lzx_resource_round_trips(8_000, false, "single-verbatim");
}

#[test]
fn lzx_single_chunk_aligned_resource_round_trips() {
    assert_lzx_resource_round_trips(8_000, true, "single-aligned");
}

#[test]
fn lzx_multichunk_verbatim_resource_round_trips() {
    assert_lzx_resource_round_trips(100_000, false, "multi-verbatim");
}

#[test]
fn lzx_multichunk_aligned_resource_round_trips() {
    assert_lzx_resource_round_trips(100_000, true, "multi-aligned");
}

#[test]
fn lzx_resource_spanning_exact_chunk_boundary_round_trips() {
    assert_lzx_resource_round_trips(WIM_CHUNK_SIZE as usize * 2, false, "exact-boundary");
}
