#![expect(
    unsafe_code,
    reason = "a bounding global allocator implements the unsafe GlobalAlloc trait"
)]
#![allow(clippy::expect_used, clippy::panic)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use disrobe_binfmt::Error;
use disrobe_binfmt::container::ContainerKind;
use disrobe_binfmt::containers::bare_stream::detect_lzma_alone;
use disrobe_binfmt::containers::btrfs_send::replay_btrfs_send;
use disrobe_binfmt::containers::cab::{
    CabArchive, CabMember, CabRefusal, parse_cab, read_cab_members,
};
use disrobe_binfmt::containers::jffs2::{Jffs2Walk, walk_jffs2};
use disrobe_binfmt::containers::lz4_block;
use disrobe_binfmt::containers::nsis::{
    NsisArchive, NsisCompression, NsisHeader, decode_solid_region, detect_nsis, parse_nsis_archive,
};
use disrobe_binfmt::containers::nsis_bzip2;
use disrobe_binfmt::containers::ubifs::walk_ubifs;
use disrobe_binfmt::containers::unityfs::{UnityFsArchive, extract_nodes, parse};
use disrobe_binfmt::containers::wim::{
    RESHDR_FLAG_COMPRESSED, WIM_FLAG_COMPRESS_XPRESS, WIM_FLAG_COMPRESSION, WimCompression,
    WimHeader, WimResource,
};
use disrobe_binfmt::containers::wim_codec::decompress_wim_resource;
use disrobe_binfmt::containers::wim_image::extract_wim_files;
use disrobe_binfmt::containers::xalz::parse_xalz;
use disrobe_binfmt::containers::xar::{XarArchive, file_data, parse_xar};
use disrobe_binfmt::quota::ExtractionQuota;
use disrobe_binfmt::{ExtractionResult, extract_to_with_quota};

const MAX_SINGLE_ALLOCATION: usize = 96 * 1024 * 1024;
const MAX_LIVE_BYTES: usize = 512 * 1024 * 1024;
const BOMB_BYTES: usize = 72 * 1024 * 1024;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

struct BoundedAlloc;

fn reserve(size: usize) -> bool {
    if size > MAX_SINGLE_ALLOCATION {
        return false;
    }
    let before: usize = LIVE_BYTES.fetch_add(size, Ordering::Relaxed);
    if before + size > MAX_LIVE_BYTES {
        LIVE_BYTES.fetch_sub(size, Ordering::Relaxed);
        return false;
    }
    true
}

unsafe impl GlobalAlloc for BoundedAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        let ptr: *mut u8 = unsafe { System.alloc(layout) };
        if ptr.is_null() {
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > MAX_SINGLE_ALLOCATION {
            return std::ptr::null_mut();
        }
        let growth: usize = new_size.saturating_sub(layout.size());
        if !reserve(growth) {
            return std::ptr::null_mut();
        }
        let moved: *mut u8 = unsafe { System.realloc(ptr, layout, new_size) };
        if moved.is_null() {
            LIVE_BYTES.fetch_sub(growth, Ordering::Relaxed);
        } else {
            LIVE_BYTES.fetch_sub(layout.size().saturating_sub(new_size), Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOC: BoundedAlloc = BoundedAlloc;

fn compressed_zeros<W: std::io::Write>(mut encoder: W, total: usize) -> W {
    let chunk: Vec<u8> = vec![0u8; 1024 * 1024];
    let mut written: usize = 0;
    while written < total {
        let step: usize = chunk.len().min(total - written);
        encoder.write_all(&chunk[..step]).expect("encode zeros");
        written += step;
    }
    encoder
}

fn zlib_bomb() -> Vec<u8> {
    let encoder: flate2::write::ZlibEncoder<Vec<u8>> =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    compressed_zeros(encoder, BOMB_BYTES)
        .finish()
        .expect("zlib finish")
}

fn gzip_of(payload: &[u8]) -> Vec<u8> {
    let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(payload).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn gzip_bomb() -> Vec<u8> {
    let encoder: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    compressed_zeros(encoder, BOMB_BYTES)
        .finish()
        .expect("gzip finish")
}

fn lzma_alone_bomb() -> Vec<u8> {
    let options: liblzma::stream::LzmaOptions =
        liblzma::stream::LzmaOptions::new_preset(1).expect("lzma preset");
    let stream: liblzma::stream::Stream =
        liblzma::stream::Stream::new_lzma_encoder(&options).expect("lzma-alone encoder");
    let encoder: liblzma::write::XzEncoder<Vec<u8>> =
        liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    compressed_zeros(encoder, BOMB_BYTES)
        .finish()
        .expect("lzma finish")
}

fn scratch(purpose: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let dir: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(purpose).expect("create scratch directory");
    let out: PathBuf = dir.path().join("out");
    (dir, out)
}

const UBI_PEB: usize = 16 * 1024;
const UBI_VID_OFFSET: usize = 64;
const UBI_DATA_OFFSET: usize = 128;

fn ubi_peb(vol_id: u32, lnum: u32) -> Vec<u8> {
    let mut peb: Vec<u8> = vec![0xFFu8; UBI_PEB];
    peb[0..4].copy_from_slice(b"UBI#");
    peb[16..20].copy_from_slice(&(UBI_VID_OFFSET as u32).to_be_bytes());
    peb[20..24].copy_from_slice(&(UBI_DATA_OFFSET as u32).to_be_bytes());
    let vid: &mut [u8] = &mut peb[UBI_VID_OFFSET..UBI_VID_OFFSET + 64];
    vid[0..4].copy_from_slice(b"UBI!");
    vid[4] = 2;
    vid[8..12].copy_from_slice(&vol_id.to_be_bytes());
    vid[12..16].copy_from_slice(&lnum.to_be_bytes());
    vid[20..32].fill(0);
    peb
}

#[test]
fn ubi_lnum_past_the_image_is_refused() {
    let image: Vec<u8> = [ubi_peb(0, 0xFFFF_FFFF), ubi_peb(0, 0)].concat();
    let error: Error = walk_ubifs(&image, 64 * 1024 * 1024).expect_err("lnum 0xFFFFFFFF");
    assert!(
        matches!(&error, Error::Ubifs(message) if message.contains("logical erase block 4294967295")),
        "{error:?}"
    );
}

#[test]
fn ubi_reassembly_is_charged_to_the_total_cap() {
    let image: Vec<u8> = [ubi_peb(0, 1), ubi_peb(1, 1)].concat();
    let one_volume: u64 = 2 * (UBI_PEB - UBI_DATA_OFFSET) as u64;
    let error: Error =
        walk_ubifs(&image, one_volume + one_volume / 2).expect_err("two volumes over the cap");
    assert!(
        matches!(&error, Error::QuotaExceeded { entry, .. } if entry == "vol1"),
        "{error:?}"
    );
}

const fn wim_lookup_table_header(original_size: u64, chunk_size: u32) -> WimHeader {
    let empty: WimResource = WimResource {
        size: 0,
        flags: 0,
        offset: 0,
        original_size: 0,
    };
    WimHeader {
        header_size: 208,
        version: 0x0001_0d00,
        flags: WIM_FLAG_COMPRESSION | WIM_FLAG_COMPRESS_XPRESS,
        compression: WimCompression::Xpress,
        chunk_size,
        guid: [0u8; 16],
        part_number: 1,
        total_parts: 1,
        image_count: 1,
        offset_table: WimResource {
            size: 16,
            flags: RESHDR_FLAG_COMPRESSED,
            offset: 208,
            original_size,
        },
        xml_data: empty,
        boot_metadata: empty,
        boot_index: 0,
        integrity: empty,
    }
}

#[test]
fn wim_lookup_table_is_bounded_by_the_caller_quota() {
    let bytes: Vec<u8> = vec![0u8; 208 + 16];
    let header: WimHeader = wim_lookup_table_header(u64::from(u32::MAX), u32::MAX);
    let error: Error = extract_wim_files(&bytes, &header, &ExtractionQuota::default())
        .expect_err("4 GiB lookup table");
    assert!(
        matches!(&error, Error::QuotaExceeded { entry, .. } if entry == "wim-resource"),
        "{error:?}"
    );
}

#[test]
fn wim_chunk_count_overflow_is_refused() {
    let error: Error = decompress_wim_resource(
        &[0u8; 16],
        WimCompression::Xpress,
        u64::MAX,
        1,
        &ExtractionQuota::unrestricted(),
    )
    .expect_err("chunk table overflow");
    assert!(
        matches!(&error, Error::Decompression(message) if message.contains("chunk table size overflow")),
        "{error:?}"
    );
}

fn jffs2_node(nodetype: u16, body: &[u8]) -> Vec<u8> {
    let mut node: Vec<u8> = Vec::new();
    node.extend_from_slice(&0x1985u16.to_le_bytes());
    node.extend_from_slice(&nodetype.to_le_bytes());
    node.extend_from_slice(&(12 + body.len() as u32).to_le_bytes());
    node.extend_from_slice(&0u32.to_le_bytes());
    node.extend_from_slice(body);
    while !node.len().is_multiple_of(4) {
        node.push(0xFF);
    }
    node
}

fn jffs2_zlib_file(name: &str, declared: u32, compressed: &[u8]) -> Vec<u8> {
    let mut dirent: Vec<u8> = Vec::new();
    for field in [1u32, 1, 2, 0] {
        dirent.extend_from_slice(&field.to_le_bytes());
    }
    dirent.extend_from_slice(&[name.len() as u8, 8, 0, 0]);
    dirent.extend_from_slice(&[0u8; 8]);
    dirent.extend_from_slice(name.as_bytes());

    let mut inode: Vec<u8> = Vec::new();
    for field in [2u32, 1, 0o100_644, 0, declared, 0, 0, 0, 0] {
        inode.extend_from_slice(&field.to_le_bytes());
    }
    inode.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    inode.extend_from_slice(&declared.to_le_bytes());
    inode.extend_from_slice(&[6, 0, 0, 0]);
    inode.extend_from_slice(&[0u8; 8]);
    inode.extend_from_slice(compressed);

    [jffs2_node(0xE001, &dirent), jffs2_node(0xE002, &inode)].concat()
}

#[test]
fn jffs2_zlib_fragment_is_bounded_by_its_declared_size() {
    let image: Vec<u8> = jffs2_zlib_file("bomb", 4096, &zlib_bomb());
    let walk: Jffs2Walk = walk_jffs2(&image, 64 * 1024 * 1024).expect("walk jffs2");
    assert!(
        walk.notes
            .iter()
            .any(|note: &String| note.contains("zlib output exceeds the declared 4096 bytes")),
        "{:?}",
        walk.notes
    );
    assert_eq!(walk.files.len(), 1);
    assert!(walk.files[0].data.len() <= 4096);
}

const NSIS_MAGIC: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's', b't',
];

fn nsis_without_crc(header_size: u32, region: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&NSIS_MAGIC);
    bytes.extend_from_slice(&header_size.to_le_bytes());
    bytes.extend_from_slice(&(28 + region.len() as u32).to_le_bytes());
    bytes.extend_from_slice(region);
    bytes
}

#[test]
fn nsis_solid_lzma_declaring_a_4_gib_dictionary_stops_at_the_caller_cap() {
    let alone: Vec<u8> = lzma_alone_bomb();
    let mut region: Vec<u8> = Vec::with_capacity(alone.len());
    region.push(alone[0]);
    region.extend_from_slice(&u32::MAX.to_le_bytes());
    region.extend_from_slice(&alone[13..]);
    let bytes: Vec<u8> = nsis_without_crc(100, &region);
    let header: NsisHeader = detect_nsis(&bytes).expect("nsis first header");
    let archive: NsisArchive = NsisArchive {
        header,
        compression: NsisCompression::Lzma,
        solid: true,
        unicode: false,
        data_region_offset: 28,
        files: Vec::new(),
    };
    let error: Error = decode_solid_region(&bytes, &archive, 1024 * 1024).expect_err("capped");
    assert!(matches!(error, Error::Nsis(_)), "{error:?}");
}

#[derive(Default)]
struct MsbBitWriter {
    bytes: Vec<u8>,
    pending: u8,
    filled: u32,
}

impl MsbBitWriter {
    fn put(&mut self, value: u32, count: u32) {
        for shift in (0..count).rev() {
            self.pending = (self.pending << 1) | ((value >> shift) & 1) as u8;
            self.filled += 1;
            if self.filled == 8 {
                self.bytes.push(self.pending);
                self.pending = 0;
                self.filled = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.bytes.push(self.pending << (8 - self.filled));
        }
        self.bytes
    }
}

const BZ_RUNA: u32 = 0;
const BZ_RUNB: u32 = 1;
const BZ_EOB: u32 = 2;

fn nsis_bzip2_block_of_byte_0x81(symbols: &[u32]) -> Vec<u8> {
    let mut writer: MsbBitWriter = MsbBitWriter::default();
    writer.put(0x31, 8);
    writer.put(0, 24);
    writer.put(0b0000_0000_1000_0000, 16);
    writer.put(0b0100_0000_0000_0000, 16);
    writer.put(2, 3);
    let selectors: u32 = symbols.len().div_ceil(50) as u32;
    writer.put(selectors, 15);
    for _ in 0..selectors {
        writer.put(0, 1);
    }
    for _ in 0..2 {
        writer.put(2, 5);
        writer.put(0, 3);
    }
    for &symbol in symbols {
        writer.put(symbol, 2);
    }
    writer.put(0x17, 8);
    writer.finish()
}

#[test]
fn nsis_bzip2_block_ending_inside_a_run_is_refused() {
    let block: Vec<u8> = nsis_bzip2_block_of_byte_0x81(&[BZ_RUNB, BZ_RUNA, BZ_EOB]);
    let error: Error = nsis_bzip2::decompress(&block, 1024 * 1024).expect_err("run past block");
    assert!(
        matches!(&error, Error::Decompression(message) if message.contains("ends inside a run")),
        "{error:?}"
    );

    let installer: Vec<u8> = nsis_without_crc(100, &block);
    let error: Error = parse_nsis_archive(&installer).expect_err("header stream is corrupt");
    assert!(matches!(error, Error::Nsis(_)), "{error:?}");
}

#[test]
fn nsis_bzip2_run_longer_than_a_block_is_refused() {
    let mut symbols: Vec<u32> = vec![BZ_RUNA; 65];
    symbols.push(BZ_EOB);
    let block: Vec<u8> = nsis_bzip2_block_of_byte_0x81(&symbols);
    let error: Error = nsis_bzip2::decompress(&block, 1024 * 1024).expect_err("run too long");
    assert!(
        matches!(&error, Error::Decompression(message) if message.contains("run length exceeds the block size")),
        "{error:?}"
    );
}

#[test]
fn gzip_member_bomb_is_bounded_by_the_per_entry_cap() {
    let mut image: Vec<u8> = vec![0xde, 0xaf, 0xbe, 0xad];
    for (name, member) in [
        ("bomb.bin", gzip_bomb()),
        ("ok.txt", gzip_of(b"small member")),
    ] {
        image.push(0x87);
        image.extend_from_slice(&(name.len() as u16).to_le_bytes());
        image.extend_from_slice(name.as_bytes());
        image.extend_from_slice(&(member.len() as u32).to_le_bytes());
        image.extend_from_slice(&member);
    }
    let quota: ExtractionQuota = ExtractionQuota {
        max_per_entry_uncompressed: 1024 * 1024,
        ..ExtractionQuota::default()
    };
    let (_dir, out): (disrobe_core::scratch::ScratchDir, PathBuf) = scratch("declared-size-gzip");
    let result: ExtractionResult =
        extract_to_with_quota(ContainerKind::FwDlinkDeafbead, &image, &out, quota)
            .expect("the small member still extracts");
    assert!(
        result
            .integrity_violations
            .iter()
            .any(|violation: &String| {
                violation.contains("bomb.bin")
                    && violation.contains("read cap 1048576 bytes exceeded")
            }),
        "{:?}",
        result.integrity_violations
    );
    assert!(
        result
            .entries
            .iter()
            .any(|entry: &disrobe_binfmt::ExtractedEntry| entry.name == "ok.txt")
    );
    assert!(
        !result
            .entries
            .iter()
            .any(|entry: &disrobe_binfmt::ExtractedEntry| entry.name == "bomb.bin")
    );
}

#[test]
fn lz4_match_past_the_output_bound_is_refused() {
    let mut block: Vec<u8> = vec![0x1F, b'a', 0x01, 0x00];
    block.extend(std::iter::repeat_n(0xFFu8, 300_000));
    block.push(0);
    let error: Error = lz4_block::decompress(&block, 16).expect_err("76 MB match into 16 bytes");
    assert!(
        matches!(&error, Error::Decompression(message) if message.contains("16-byte output bound")),
        "{error:?}"
    );
}

fn lzms_cab(member_size: u32, block_payload: &[u8], cb_uncomp: u16) -> Vec<u8> {
    let name: &[u8] = b"member.bin";
    let coff_files: u32 = 36 + 8;
    let data_start: u32 = coff_files + 16 + name.len() as u32 + 1;
    let total: u32 = data_start + 8 + block_payload.len() as u32;
    let mut cab: Vec<u8> = Vec::new();
    cab.extend_from_slice(b"MSCF");
    for field in [0u32, total, 0, coff_files, 0] {
        cab.extend_from_slice(&field.to_le_bytes());
    }
    cab.extend_from_slice(&[3, 1]);
    for field in [1u16, 1, 0, 0, 0] {
        cab.extend_from_slice(&field.to_le_bytes());
    }
    cab.extend_from_slice(&data_start.to_le_bytes());
    cab.extend_from_slice(&1u16.to_le_bytes());
    cab.extend_from_slice(&5u16.to_le_bytes());
    cab.extend_from_slice(&member_size.to_le_bytes());
    cab.extend_from_slice(&[0u8; 12]);
    cab.extend_from_slice(name);
    cab.push(0);
    cab.extend_from_slice(&0u32.to_le_bytes());
    cab.extend_from_slice(&(block_payload.len() as u16).to_le_bytes());
    cab.extend_from_slice(&cb_uncomp.to_le_bytes());
    cab.extend_from_slice(block_payload);
    cab
}

fn first_member_outcome(bytes: &[u8], cap: u64) -> Result<Vec<u8>, CabRefusal> {
    let archive: CabArchive = parse_cab(bytes).expect("parse cab");
    let mut outcome: Option<Result<Vec<u8>, CabRefusal>> = None;
    read_cab_members(
        bytes,
        &archive,
        cap,
        |_member: &CabMember, result: Result<&[u8], CabRefusal>| {
            if outcome.is_none() {
                outcome = Some(result.map(<[u8]>::to_vec));
            }
            Ok(())
        },
    )
    .expect("read cab members");
    outcome.expect("one member visited")
}

#[test]
fn lzms_block_continued_in_the_next_cabinet_is_refused() {
    let payload: &[u8] = b"the first part of a block the next cabinet continues";
    let bytes: Vec<u8> = lzms_cab(payload.len() as u32, payload, 0);
    let outcome: Result<Vec<u8>, CabRefusal> = first_member_outcome(&bytes, 1024 * 1024);
    assert!(
        matches!(&outcome, Err(CabRefusal::Decode { reason, .. }) if reason.contains("continued in the next cabinet")),
        "{outcome:?}"
    );
}

#[test]
fn lzms_folder_member_declaring_4_gib_is_refused_before_decoding() {
    let bytes: Vec<u8> = lzms_cab(u32::MAX, &[0u8; 64], 0xFFFF);
    let outcome: Result<Vec<u8>, CabRefusal> = first_member_outcome(
        &bytes,
        ExtractionQuota::default().max_per_entry_uncompressed,
    );
    assert!(
        matches!(&outcome, Err(CabRefusal::OverCap { size, .. }) if *size == u64::from(u32::MAX)),
        "{outcome:?}"
    );
}

fn xalz_declaring(size: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = b"XALZ".to_vec();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&[0x10, b'M']);
    bytes
}

#[test]
fn xalz_declaring_4_gib_is_refused_by_the_per_entry_cap() {
    let (_dir, out): (disrobe_core::scratch::ScratchDir, PathBuf) = scratch("declared-size-xalz");
    let error: Error = extract_to_with_quota(
        ContainerKind::Xalz,
        &xalz_declaring(u32::MAX),
        &out,
        ExtractionQuota::default(),
    )
    .expect_err("0xFFFFFFFF bytes");
    assert!(
        matches!(&error, Error::Xalz(message) if message.contains("536870912-byte entry cap")),
        "{error:?}"
    );
}

#[test]
fn xalz_declared_size_does_not_size_the_output_reservation() {
    let error: Error =
        parse_xalz(&xalz_declaring(u32::MAX), u64::from(u32::MAX)).expect_err("short decode");
    assert!(
        matches!(&error, Error::Xalz(message) if message.contains("decoded 1 bytes")),
        "{error:?}"
    );
}

fn btrfs_command(out: &mut Vec<u8>, command: u16, attributes: &[(u16, &[u8])]) {
    let mut body: Vec<u8> = Vec::new();
    for (kind, value) in attributes {
        body.extend_from_slice(&kind.to_le_bytes());
        body.extend_from_slice(&(value.len() as u16).to_le_bytes());
        body.extend_from_slice(value);
    }
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&command.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&body);
}

#[test]
fn btrfs_send_links_are_charged_to_the_total_cap() {
    let mut stream: Vec<u8> = b"btrfs-stream\0".to_vec();
    stream.extend_from_slice(&1u32.to_le_bytes());
    btrfs_command(&mut stream, 3, &[(15, b"f")]);
    let data: Vec<u8> = vec![0x5Au8; 60_000];
    btrfs_command(
        &mut stream,
        15,
        &[(15, b"f"), (19, &0u64.to_le_bytes()), (20, &data)],
    );
    for index in 0..12_000u32 {
        let path: String = format!("link{index}");
        btrfs_command(&mut stream, 10, &[(15, path.as_bytes()), (18, b"f")]);
    }
    btrfs_command(&mut stream, 21, &[]);
    let error: Error = replay_btrfs_send(&stream, 1024 * 1024).expect_err("links over the cap");
    assert!(
        matches!(&error, Error::BtrfsSend(message) if message.contains("total cap 1048576")),
        "{error:?}"
    );
}

fn unityfs_bundle_with_aliased_nodes(node_data: &[u8], node_count: u32) -> Vec<u8> {
    let mut info: Vec<u8> = vec![0u8; 16];
    info.extend_from_slice(&1i32.to_be_bytes());
    info.extend_from_slice(&(node_data.len() as u32).to_be_bytes());
    info.extend_from_slice(&(node_data.len() as u32).to_be_bytes());
    info.extend_from_slice(&0u16.to_be_bytes());
    info.extend_from_slice(&(node_count as i32).to_be_bytes());
    for index in 0..node_count {
        info.extend_from_slice(&0i64.to_be_bytes());
        info.extend_from_slice(&(node_data.len() as i64).to_be_bytes());
        info.extend_from_slice(&4u32.to_be_bytes());
        info.extend_from_slice(format!("n{index}").as_bytes());
        info.push(0);
    }
    let mut bundle: Vec<u8> = b"UnityFS\0".to_vec();
    bundle.extend_from_slice(&7u32.to_be_bytes());
    bundle.extend_from_slice(b"5.x.x\0");
    bundle.extend_from_slice(b"2021.3.0f1\0");
    let size_at: usize = bundle.len();
    bundle.extend_from_slice(&0i64.to_be_bytes());
    bundle.extend_from_slice(&(info.len() as u32).to_be_bytes());
    bundle.extend_from_slice(&(info.len() as u32).to_be_bytes());
    bundle.extend_from_slice(&0u32.to_be_bytes());
    bundle.resize(bundle.len().next_multiple_of(16), 0);
    bundle.extend_from_slice(&info);
    bundle.extend_from_slice(node_data);
    let total: i64 = bundle.len() as i64;
    bundle[size_at..size_at + 8].copy_from_slice(&total.to_be_bytes());
    bundle
}

#[test]
fn unityfs_aliased_node_copies_are_charged_to_the_total_cap() {
    let bundle: Vec<u8> = unityfs_bundle_with_aliased_nodes(&vec![0x33u8; 65_536], 12_000);
    let archive: UnityFsArchive = parse(&bundle).expect("parse bundle");
    let error: Error = extract_nodes(&bundle, &archive, 1024 * 1024).expect_err("aliased copies");
    assert!(
        matches!(&error, Error::QuotaExceeded { reason, .. } if reason.contains("node copies")),
        "{error:?}"
    );
}

#[test]
fn lzma_alone_detection_decodes_without_buffering_the_output() {
    let mut stream: Vec<u8> = lzma_alone_bomb();
    stream[5..13].copy_from_slice(&(BOMB_BYTES as u64).to_le_bytes());
    assert!(detect_lzma_alone(&stream));
}

fn xar_with_one_lzma_member(declared: u64, member: &[u8]) -> Vec<u8> {
    let toc: String = format!(
        "<?xml version=\"1.0\"?><xar><toc><file id=\"1\"><name>bomb</name><type>file</type><data><length>{}</length><offset>0</offset><size>{declared}</size><encoding style=\"application/x-lzma\"/></data></file></toc></xar>",
        member.len()
    );
    let mut toc_encoder: flate2::write::ZlibEncoder<Vec<u8>> =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    toc_encoder.write_all(toc.as_bytes()).expect("toc write");
    let toc_compressed: Vec<u8> = toc_encoder.finish().expect("toc finish");
    let mut out: Vec<u8> = b"xar!".to_vec();
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(toc_compressed.len() as u64).to_be_bytes());
    out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&toc_compressed);
    out.extend_from_slice(member);
    out
}

#[test]
fn xar_lzma_member_is_bounded_by_its_declared_size() {
    let image: Vec<u8> = xar_with_one_lzma_member(16, &lzma_alone_bomb());
    let archive: XarArchive = parse_xar(&image).expect("parse xar");
    let error: Error = file_data(&image, &archive, &archive.files[0]).expect_err("bomb member");
    assert!(
        matches!(&error, Error::Decompression(message) if message.contains("xar lzma member") && message.contains("bomb cap 17")),
        "{error:?}"
    );
}
