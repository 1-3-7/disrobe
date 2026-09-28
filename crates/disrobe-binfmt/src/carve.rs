use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use disrobe_core::byte_search;
use disrobe_core::shannon_entropy;

use crate::container::{
    ContainerKind, MAGIC_SIGNATURES, MagicSignature, TAR_USTAR, TAR_USTAR_OFFSET,
};
use crate::containers::cpio::CpioVariant;
use crate::extract::{ExtractionResult, extract_to_with_quota};
use crate::quota::ExtractionQuota;
use disrobe_core::scratch::ScratchDir;

pub const DEFAULT_MAX_DEPTH: u32 = 10;

const MIN_VALID_EXTENT: usize = 4;
const MIN_PADDING_RUN: usize = 16;
const STREAM_DECODE_CAP: u64 = 4 * 1024 * 1024 * 1024;
const SCAN_HIT_CAP: usize = 1 << 20;
const TOTAL_WORK_CHUNK_CAP: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChunkClass {
    Valid,
    Unknown,
    Padding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedChunk {
    pub class: ChunkClass,
    pub start: u64,
    pub end: u64,
    pub kind: Option<ContainerKind>,
    pub entropy: f64,
    pub carved_path: Option<PathBuf>,
    pub padding_byte: Option<u8>,
}

impl CarvedChunk {
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveNode {
    pub depth: u32,
    pub source: String,
    pub size: u64,
    pub chunks: Vec<CarvedChunk>,
    pub children: Vec<Self>,
    pub extraction_kind: Option<ContainerKind>,
    pub skipped_recursion: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveReport {
    pub root: CarveNode,
    pub max_depth: u32,
    pub nodes_visited: usize,
    pub chunks_total: usize,
    pub bytes_carved: u64,
    pub work_budget_exhausted: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CarveConfig {
    pub max_depth: u32,
    pub quota: ExtractionQuota,
}

impl CarveConfig {
    #[must_use]
    pub const fn new(max_depth: u32) -> Self {
        Self {
            max_depth,
            quota: ExtractionQuota::default_safe(),
        }
    }
}

impl Default for CarveConfig {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DEPTH)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MagicHit {
    offset: usize,
    kind: ContainerKind,
}

#[derive(Debug)]
struct WorkBudget {
    remaining_nodes: usize,
    remaining_chunks: usize,
    seen_digests: BTreeSet<[u8; 32]>,
    exhausted: bool,
}

impl WorkBudget {
    const fn new() -> Self {
        Self {
            remaining_nodes: TOTAL_WORK_CHUNK_CAP,
            remaining_chunks: TOTAL_WORK_CHUNK_CAP,
            seen_digests: BTreeSet::new(),
            exhausted: false,
        }
    }

    const fn take_node(&mut self) -> bool {
        if self.remaining_nodes == 0 {
            self.exhausted = true;
            return false;
        }
        self.remaining_nodes -= 1;
        true
    }

    const fn take_chunks(&mut self, n: usize) -> bool {
        if self.remaining_chunks < n {
            self.exhausted = true;
            return false;
        }
        self.remaining_chunks -= n;
        true
    }

    fn first_visit(&mut self, bytes: &[u8]) -> bool {
        let digest: [u8; 32] = *blake3::hash(bytes).as_bytes();
        self.seen_digests.insert(digest)
    }
}

#[must_use]
pub fn carve_recursive(
    bytes: &[u8],
    source: &str,
    config: CarveConfig,
    destination: Option<&Path>,
) -> CarveReport {
    let mut budget: WorkBudget = WorkBudget::new();
    let mut nodes_visited: usize = 0;
    let mut chunks_total: usize = 0;
    let mut bytes_carved: u64 = 0;
    let scratch: Option<ScratchDir> = match destination {
        Some(_) => None,
        None => ScratchDir::create("carve").ok(),
    };
    let extraction_root: Option<&Path> =
        destination.map_or_else(|| scratch.as_ref().map(ScratchDir::path), Some);
    let root: CarveNode = carve_node(
        bytes,
        source,
        0,
        config,
        extraction_root,
        destination.is_some(),
        &mut budget,
        &mut nodes_visited,
        &mut chunks_total,
        &mut bytes_carved,
    );
    CarveReport {
        root,
        max_depth: config.max_depth,
        nodes_visited,
        chunks_total,
        bytes_carved,
        work_budget_exhausted: budget.exhausted,
    }
}

#[allow(clippy::too_many_arguments)]
fn carve_node(
    bytes: &[u8],
    source: &str,
    depth: u32,
    config: CarveConfig,
    scratch: Option<&Path>,
    durable: bool,
    budget: &mut WorkBudget,
    nodes_visited: &mut usize,
    chunks_total: &mut usize,
    bytes_carved: &mut u64,
) -> CarveNode {
    *nodes_visited += 1;
    let mut notes: Vec<String> = Vec::new();
    if !budget.take_node() {
        notes.push("work budget exhausted: node cap reached".to_owned());
        return CarveNode {
            depth,
            source: source.to_owned(),
            size: bytes.len() as u64,
            chunks: Vec::new(),
            children: Vec::new(),
            extraction_kind: None,
            skipped_recursion: true,
            notes,
        };
    }
    if !budget.first_visit(bytes) {
        notes.push("cycle guard: identical bytes already carved on this path".to_owned());
        return CarveNode {
            depth,
            source: source.to_owned(),
            size: bytes.len() as u64,
            chunks: Vec::new(),
            children: Vec::new(),
            extraction_kind: None,
            skipped_recursion: true,
            notes,
        };
    }

    let hits: Vec<MagicHit> = scan_magics(bytes);
    let chunks: Vec<CarvedChunk> = build_chunks(bytes, &hits);
    if !budget.take_chunks(chunks.len()) {
        notes.push("work budget exhausted: chunk cap reached".to_owned());
    }
    *chunks_total += chunks.len();
    for chunk in &chunks {
        *bytes_carved += chunk.len();
    }

    let extraction_kind: Option<ContainerKind> = crate::container::detect_container(bytes);
    let mut children: Vec<CarveNode> = Vec::new();
    let mut written_chunks: Vec<CarvedChunk> = Vec::with_capacity(chunks.len());

    let next_depth_ok: bool = depth + 1 < config.max_depth;
    for (index, mut chunk) in chunks.into_iter().enumerate() {
        if let (ChunkClass::Valid, Some(kind)) = (chunk.class, chunk.kind) {
            let slice: &[u8] = &bytes[chunk.start as usize..chunk.end as usize];
            if let Some(dir) = scratch {
                let carved_dir: PathBuf = dir.join(format!("d{depth}-c{index}"));
                if let Some(written) = extract_chunk(kind, slice, &carved_dir, config.quota) {
                    if durable {
                        chunk.carved_path = Some(written.dir.clone());
                    }
                    if !next_depth_ok {
                        notes.push(format!(
                            "max-depth {} reached: not recursing into {} chunk at offset {}",
                            config.max_depth,
                            kind.label(),
                            chunk.start
                        ));
                    }
                    for (rel, file_bytes) in written.files {
                        if !next_depth_ok {
                            continue;
                        }
                        if let Some(label) = skip_magic_label(&file_bytes) {
                            notes.push(format!(
                                "skip-magic allowlist: {rel} is a {label} leaf, not recursed"
                            ));
                            continue;
                        }
                        let child: CarveNode = carve_node(
                            &file_bytes,
                            &rel,
                            depth + 1,
                            config,
                            scratch,
                            durable,
                            budget,
                            nodes_visited,
                            chunks_total,
                            bytes_carved,
                        );
                        children.push(child);
                    }
                } else {
                    chunk.class = ChunkClass::Unknown;
                    chunk.kind = None;
                    notes.push(format!(
                        "candidate {} at offset {} failed trial-extract, demoted to unknown",
                        kind.label(),
                        chunk.start
                    ));
                }
            }
        }
        written_chunks.push(chunk);
    }

    CarveNode {
        depth,
        source: source.to_owned(),
        size: bytes.len() as u64,
        chunks: written_chunks,
        children,
        extraction_kind,
        skipped_recursion: false,
        notes,
    }
}

#[derive(Debug)]
struct WrittenChunk {
    dir: PathBuf,
    files: Vec<(String, Vec<u8>)>,
}

fn extract_chunk(
    kind: ContainerKind,
    slice: &[u8],
    out_dir: &Path,
    quota: ExtractionQuota,
) -> Option<WrittenChunk> {
    let result: ExtractionResult = extract_to_with_quota(kind, slice, out_dir, quota).ok()?;
    let mut files: Vec<(String, Vec<u8>)> = Vec::with_capacity(result.entries.len());
    for entry in &result.entries {
        if entry.name.starts_with(".disrobe-") {
            continue;
        }
        let Some(disk) = entry.disk_path.as_ref() else {
            continue;
        };
        if let Ok(data) = std::fs::read(disk) {
            files.push((entry.name.clone(), data));
        }
    }
    Some(WrittenChunk {
        dir: out_dir.to_path_buf(),
        files,
    })
}

fn build_chunks(bytes: &[u8], hits: &[MagicHit]) -> Vec<CarvedChunk> {
    let mut chunks: Vec<CarvedChunk> = Vec::new();
    let mut cursor: usize = 0;
    let len: usize = bytes.len();
    for hit in hits {
        if hit.offset < cursor {
            continue;
        }
        let Some(extent): Option<usize> = validated_extent(bytes, hit) else {
            continue;
        };
        let end: usize = hit.offset + extent;
        if end <= hit.offset || end > len {
            continue;
        }
        if hit.offset > cursor {
            emit_gap(bytes, cursor, hit.offset, &mut chunks);
        }
        chunks.push(CarvedChunk {
            class: ChunkClass::Valid,
            start: hit.offset as u64,
            end: end as u64,
            kind: Some(hit.kind),
            entropy: shannon_entropy(&bytes[hit.offset..end]),
            carved_path: None,
            padding_byte: None,
        });
        cursor = end;
    }
    if cursor < len {
        emit_gap(bytes, cursor, len, &mut chunks);
    }
    if chunks.is_empty() && len > 0 {
        emit_gap(bytes, 0, len, &mut chunks);
    }
    chunks
}

fn emit_gap(bytes: &[u8], start: usize, end: usize, chunks: &mut Vec<CarvedChunk>) {
    if end <= start {
        return;
    }
    let mut segment_start: usize = start;
    let mut i: usize = start;
    while i < end {
        let run_byte: u8 = bytes[i];
        let mut j: usize = i + 1;
        while j < end && bytes[j] == run_byte {
            j += 1;
        }
        if j - i >= MIN_PADDING_RUN {
            push_unknown(bytes, segment_start, i, chunks);
            chunks.push(CarvedChunk {
                class: ChunkClass::Padding,
                start: i as u64,
                end: j as u64,
                kind: None,
                entropy: 0.0,
                carved_path: None,
                padding_byte: Some(run_byte),
            });
            segment_start = j;
        }
        i = j;
    }
    push_unknown(bytes, segment_start, end, chunks);
}

fn push_unknown(bytes: &[u8], start: usize, end: usize, chunks: &mut Vec<CarvedChunk>) {
    if end <= start {
        return;
    }
    chunks.push(CarvedChunk {
        class: ChunkClass::Unknown,
        start: start as u64,
        end: end as u64,
        kind: None,
        entropy: shannon_entropy(&bytes[start..end]),
        carved_path: None,
        padding_byte: None,
    });
}

fn scan_magics(bytes: &[u8]) -> Vec<MagicHit> {
    let mut hits: Vec<MagicHit> = Vec::new();
    for signature in MAGIC_SIGNATURES
        .iter()
        .filter(|signature: &&MagicSignature| extent_bounder(signature.kind).is_some())
    {
        let mut from: usize = 0;
        while from < bytes.len() && hits.len() < SCAN_HIT_CAP {
            let Some(rel): Option<usize> = byte_search::find(&bytes[from..], signature.magic)
            else {
                break;
            };
            let at: usize = from + rel;
            if at >= signature.offset {
                hits.push(MagicHit {
                    offset: at - signature.offset,
                    kind: signature.kind,
                });
            }
            from = at + 1;
        }
    }
    hits.sort_by(|a: &MagicHit, b: &MagicHit| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| format_priority(a.kind).cmp(&format_priority(b.kind)))
    });
    hits.dedup_by_key(|h: &mut MagicHit| (h.offset, h.kind));
    hits
}

const fn format_priority(kind: ContainerKind) -> u8 {
    match kind {
        ContainerKind::Zip
        | ContainerKind::SevenZ
        | ContainerKind::Rar
        | ContainerKind::Cab
        | ContainerKind::Squashfs
        | ContainerKind::Iso
        | ContainerKind::Wim
        | ContainerKind::UnityFs
        | ContainerKind::Cpio
        | ContainerKind::Ar => 0,
        ContainerKind::Tar => 1,
        _ => 2,
    }
}

type ExtentBounder = fn(&[u8]) -> Option<usize>;

fn extent_bounder(kind: ContainerKind) -> Option<ExtentBounder> {
    match kind {
        ContainerKind::Zip => Some(zip_extent),
        ContainerKind::SevenZ => Some(sevenz_extent),
        ContainerKind::Rar => Some(rar_extent),
        ContainerKind::Cab => Some(cab_extent),
        ContainerKind::Gzip => Some(|tail: &[u8]| stream_extent(tail, StreamKind::Gzip)),
        ContainerKind::Xz => Some(|tail: &[u8]| stream_extent(tail, StreamKind::Xz)),
        ContainerKind::Zstd => Some(|tail: &[u8]| stream_extent(tail, StreamKind::Zstd)),
        ContainerKind::Bzip2 => Some(|tail: &[u8]| stream_extent(tail, StreamKind::Bzip2)),
        ContainerKind::Tar => Some(tar_extent),
        ContainerKind::Squashfs => Some(squashfs_extent),
        ContainerKind::Minidump => Some(crate::containers::minidump::minidump_extent),
        ContainerKind::Iso => Some(iso_extent),
        ContainerKind::Wim => Some(wim_extent),
        ContainerKind::UnityFs => Some(unityfs_extent),
        ContainerKind::Cpio => Some(cpio_extent),
        ContainerKind::Ar => Some(ar_extent),
        _ => None,
    }
}

fn validated_extent(bytes: &[u8], hit: &MagicHit) -> Option<usize> {
    let tail: &[u8] = bytes.get(hit.offset..)?;
    if tail.len() < MIN_VALID_EXTENT {
        return None;
    }
    let extent: usize = extent_bounder(hit.kind)?(tail)?;
    if extent < MIN_VALID_EXTENT || extent > tail.len() {
        return None;
    }
    Some(extent)
}

const ZIP_EOCD_MAGIC: &[u8; 4] = b"PK\x05\x06";
const ZIP_CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4B50;
const ZIP_EOCD_FIXED_LEN: usize = 22;

fn zip_extent(bytes: &[u8]) -> Option<usize> {
    memchr::memmem::find_iter(bytes, ZIP_EOCD_MAGIC).find_map(|eocd: usize| {
        let cd_size: usize = usize::try_from(u32_le(bytes, eocd + 12)?).ok()?;
        let cd_start: usize = usize::try_from(u32_le(bytes, eocd + 16)?).ok()?;
        if cd_start.checked_add(cd_size)? != eocd {
            return None;
        }
        if cd_size > 0 && u32_le(bytes, cd_start)? != ZIP_CENTRAL_HEADER_SIGNATURE {
            return None;
        }
        let comment_len: usize = usize::from(u16_le(bytes, eocd + 20)?);
        let end: usize = eocd
            .checked_add(ZIP_EOCD_FIXED_LEN)?
            .checked_add(comment_len)?;
        (end <= bytes.len()).then_some(end)
    })
}

#[derive(Debug, Clone, Copy)]
enum StreamKind {
    Gzip,
    Xz,
    Zstd,
    Bzip2,
}

fn stream_extent(bytes: &[u8], kind: StreamKind) -> Option<usize> {
    let measured: Measured = match kind {
        StreamKind::Gzip => return gzip_exact_extent(bytes),
        StreamKind::Xz => xz_exact_extent(bytes)?,
        StreamKind::Zstd => zstd_exact_extent(bytes)?,
        StreamKind::Bzip2 => bzip2_exact_extent(bytes)?,
    };
    match measured {
        Measured::Ends(end) => {
            decode_validate(bytes.get(..end)?, kind)?;
            Some(end)
        }
        Measured::PastCap => {
            decode_validate(bytes, kind)?;
            Some(trim_trailing_zero_padding(bytes))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Measured {
    Ends(usize),
    PastCap,
}

const XZ_MEMLIMIT: u64 = 256 * 1024 * 1024;
const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;
const ZSTD_SKIPPABLE_LOW: u32 = 0x184D_2A50;
const ZSTD_SKIPPABLE_HIGH: u32 = 0x184D_2A5F;

fn xz_exact_extent(bytes: &[u8]) -> Option<Measured> {
    let mut stream: liblzma::stream::Stream =
        liblzma::stream::Stream::new_stream_decoder(XZ_MEMLIMIT, 0).ok()?;
    let mut scratch: [u8; 16 * 1024] = [0u8; 16 * 1024];
    loop {
        let consumed: usize = usize::try_from(stream.total_in()).ok()?;
        let produced: u64 = stream.total_out();
        let input: &[u8] = bytes.get(consumed..)?;
        let status: liblzma::stream::Status = stream
            .process(input, &mut scratch, liblzma::stream::Action::Finish)
            .ok()?;
        if status == liblzma::stream::Status::StreamEnd {
            return usize::try_from(stream.total_in()).ok().map(Measured::Ends);
        }
        if stream.total_out() > STREAM_DECODE_CAP {
            return Some(Measured::PastCap);
        }
        if stream.total_out() == produced && usize::try_from(stream.total_in()).ok()? == consumed {
            return None;
        }
    }
}

fn zstd_exact_extent(bytes: &[u8]) -> Option<Measured> {
    let mut end: usize = 0;
    while let Some(magic) = u32_le(bytes, end) {
        let is_frame: bool = magic == ZSTD_FRAME_MAGIC;
        if !is_frame && !(ZSTD_SKIPPABLE_LOW..=ZSTD_SKIPPABLE_HIGH).contains(&magic) {
            break;
        }
        let frame_len: usize =
            zstd::zstd_safe::find_frame_compressed_size(bytes.get(end..)?).ok()?;
        if frame_len == 0 {
            break;
        }
        end = end.checked_add(frame_len)?;
    }
    (end > 0).then_some(Measured::Ends(end))
}

fn bzip2_exact_extent(bytes: &[u8]) -> Option<Measured> {
    let mut end: usize = 0;
    let mut scratch: [u8; 16 * 1024] = [0u8; 16 * 1024];
    let mut produced: u64 = 0;
    while bytes.get(end..end.checked_add(3)?) == Some(b"BZh".as_slice()) {
        let mut decompress: bzip2::Decompress = bzip2::Decompress::new(false);
        let stream: &[u8] = bytes.get(end..)?;
        loop {
            let consumed: usize = usize::try_from(decompress.total_in()).ok()?;
            let before: u64 = decompress.total_out();
            let status: bzip2::Status = decompress
                .decompress(stream.get(consumed..)?, &mut scratch)
                .ok()?;
            if status == bzip2::Status::StreamEnd {
                break;
            }
            if produced.saturating_add(decompress.total_out()) > STREAM_DECODE_CAP {
                return Some(Measured::PastCap);
            }
            if decompress.total_out() == before
                && usize::try_from(decompress.total_in()).ok()? == consumed
            {
                return None;
            }
        }
        produced = produced.saturating_add(decompress.total_out());
        end = end.checked_add(usize::try_from(decompress.total_in()).ok()?)?;
    }
    (end > 0).then_some(Measured::Ends(end))
}

fn trim_trailing_zero_padding(bytes: &[u8]) -> usize {
    let mut end: usize = bytes.len();
    while end > MIN_VALID_EXTENT && bytes[end - 1] == 0 {
        end -= 1;
    }
    end
}

fn decode_validate(bytes: &[u8], kind: StreamKind) -> Option<()> {
    let mut sink: std::io::Sink = std::io::sink();
    let drained: std::io::Result<u64> = match kind {
        StreamKind::Gzip => {
            let mut dec: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(bytes);
            std::io::copy(&mut (&mut dec).take(STREAM_DECODE_CAP), &mut sink)
        }
        StreamKind::Xz => {
            let mut dec: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(bytes);
            std::io::copy(&mut (&mut dec).take(STREAM_DECODE_CAP), &mut sink)
        }
        StreamKind::Zstd => match zstd::stream::read::Decoder::new(bytes) {
            Ok(mut dec) => std::io::copy(&mut (&mut dec).take(STREAM_DECODE_CAP), &mut sink),
            Err(_) => return None,
        },
        StreamKind::Bzip2 => {
            let mut dec: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(bytes);
            std::io::copy(&mut (&mut dec).take(STREAM_DECODE_CAP), &mut sink)
        }
    };
    (drained.ok()? > 0).then_some(())
}

const GZIP_FLAG_FTEXT: u8 = 0x01;
const GZIP_FLAG_FHCRC: u8 = 0x02;
const GZIP_FLAG_FEXTRA: u8 = 0x04;
const GZIP_FLAG_FNAME: u8 = 0x08;
const GZIP_FLAG_FCOMMENT: u8 = 0x10;
const GZIP_TRAILER_LEN: usize = 8;

fn gzip_exact_extent(bytes: &[u8]) -> Option<usize> {
    let body_start: usize = gzip_header_len(bytes)?;
    let body: &[u8] = bytes.get(body_start..)?;
    let mut decompressor: flate2::Decompress = flate2::Decompress::new(false);
    let mut scratch: [u8; 16 * 1024] = [0u8; 16 * 1024];
    loop {
        let in_before: u64 = decompressor.total_in();
        let consumed_so_far: usize = usize::try_from(in_before).ok()?;
        let remaining: &[u8] = body.get(consumed_so_far..)?;
        let status: flate2::Status = decompressor
            .decompress(remaining, &mut scratch, flate2::FlushDecompress::None)
            .ok()?;
        let produced: u64 = decompressor.total_out();
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError => {
                if decompressor.total_in() == in_before && remaining.is_empty() {
                    return None;
                }
                if decompressor.total_in() == in_before
                    && status == flate2::Status::BufError
                    && !remaining.is_empty()
                {
                    return None;
                }
            }
        }
        if produced > STREAM_DECODE_CAP {
            return None;
        }
    }
    let deflate_consumed: usize = usize::try_from(decompressor.total_in()).ok()?;
    let total: usize = body_start + deflate_consumed + GZIP_TRAILER_LEN;
    if total > bytes.len() {
        return None;
    }
    Some(total)
}

fn gzip_header_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 10 || bytes[0] != 0x1f || bytes[1] != 0x8b || bytes[2] != 0x08 {
        return None;
    }
    let flags: u8 = bytes[3];
    let mut off: usize = 10;
    if flags & GZIP_FLAG_FEXTRA != 0 {
        let xlen: usize = u16_le(bytes, off)? as usize;
        off = off.checked_add(2)?.checked_add(xlen)?;
    }
    if flags & GZIP_FLAG_FNAME != 0 {
        off = skip_zero_terminated(bytes, off)?;
    }
    if flags & GZIP_FLAG_FCOMMENT != 0 {
        off = skip_zero_terminated(bytes, off)?;
    }
    if flags & GZIP_FLAG_FHCRC != 0 {
        off = off.checked_add(2)?;
    }
    let _ = GZIP_FLAG_FTEXT;
    if off > bytes.len() {
        return None;
    }
    Some(off)
}

fn skip_zero_terminated(bytes: &[u8], from: usize) -> Option<usize> {
    let rel: usize = bytes.get(from..)?.iter().position(|&b: &u8| b == 0)?;
    Some(from + rel + 1)
}

const TAR_BLOCK: usize = 512;

fn tar_extent(bytes: &[u8]) -> Option<usize> {
    let magic_end: usize = TAR_USTAR_OFFSET + TAR_USTAR.len();
    if bytes.len() < magic_end {
        return None;
    }
    let mut cursor: usize = 0;
    loop {
        let header: &[u8] = bytes.get(cursor..cursor + TAR_BLOCK)?;
        if header.iter().all(|&b: &u8| b == 0) {
            let mut end: usize = cursor + TAR_BLOCK;
            if let Some(second) = bytes.get(end..end + TAR_BLOCK)
                && second.iter().all(|&b: &u8| b == 0)
            {
                end += TAR_BLOCK;
            }
            return Some(end.min(bytes.len()));
        }
        if &header[TAR_USTAR_OFFSET..magic_end] != TAR_USTAR
            && cursor == 0
            && !header[TAR_USTAR_OFFSET..magic_end]
                .iter()
                .all(|&b: &u8| b == 0)
        {
            return None;
        }
        let size: u64 = parse_octal(&header[124..136])?;
        let data_blocks: usize = usize::try_from(size.div_ceil(TAR_BLOCK as u64)).ok()?;
        cursor = cursor
            .checked_add(TAR_BLOCK)?
            .checked_add(data_blocks.checked_mul(TAR_BLOCK)?)?;
        if cursor > bytes.len() {
            return Some(bytes.len());
        }
    }
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let trimmed: &[u8] = field
        .split(|&b: &u8| b == 0 || b == b' ')
        .find(|s: &&[u8]| !s.is_empty())
        .map_or(&[] as &[u8], |value: &[u8]| value);
    if trimmed.is_empty() {
        return Some(0);
    }
    let mut value: u64 = 0;
    for &b in trimmed {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

fn squashfs_extent(bytes: &[u8]) -> Option<usize> {
    let sb: crate::containers::squashfs::SquashfsSuperblock =
        crate::containers::squashfs::parse_squashfs_superblock(bytes, 0).ok()?;
    let total: usize = usize::try_from(sb.bytes_used).ok()?;
    if total < MIN_VALID_EXTENT || total > bytes.len() {
        return None;
    }
    Some(total)
}

const SEVENZ_START_HEADER_LEN: usize = 32;

fn sevenz_extent(bytes: &[u8]) -> Option<usize> {
    let start_header: &[u8] = bytes.get(12..SEVENZ_START_HEADER_LEN)?;
    if u32_le(bytes, 8)? != crc32fast::hash(start_header) {
        return None;
    }
    let next_header_offset: usize = usize::try_from(u64_le(bytes, 12)?).ok()?;
    let next_header_size: usize = usize::try_from(u64_le(bytes, 20)?).ok()?;
    SEVENZ_START_HEADER_LEN
        .checked_add(next_header_offset)?
        .checked_add(next_header_size)
}

const CAB_VERSION: [u8; 2] = [3, 1];

fn cab_extent(bytes: &[u8]) -> Option<usize> {
    if u32_le(bytes, 4)? != 0 || bytes.get(24..26)? != CAB_VERSION {
        return None;
    }
    usize::try_from(u32_le(bytes, 8)?).ok()
}

const RAR_MAX_BLOCKS: usize = 1 << 20;
const RAR5_SIGNATURE_LEN: usize = 8;
const RAR5_FLAG_EXTRA_AREA: u64 = 0x01;
const RAR5_FLAG_DATA_AREA: u64 = 0x02;
const RAR5_END_OF_ARCHIVE: u64 = 5;
const RAR4_SIGNATURE_LEN: usize = 7;
const RAR4_MIN_HEADER_LEN: usize = 7;
const RAR4_FLAG_LONG_BLOCK: u16 = 0x8000;
const RAR4_FLAG_LARGE_FILE: u16 = 0x0100;
const RAR4_FILE_HEADER: u8 = 0x74;
const RAR4_SERVICE_HEADER: u8 = 0x7A;
const RAR4_END_OF_ARCHIVE: u8 = 0x7B;

fn rar_extent(bytes: &[u8]) -> Option<usize> {
    if bytes.get(6) == Some(&1) {
        rar5_extent(bytes)
    } else {
        rar4_extent(bytes)
    }
}

fn rar5_vint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    disrobe_bytes::read_uleb128_at(bytes, at).ok()
}

fn rar5_extent(bytes: &[u8]) -> Option<usize> {
    let mut pos: usize = RAR5_SIGNATURE_LEN;
    for _ in 0..RAR_MAX_BLOCKS {
        let header_crc: u32 = u32_le(bytes, pos)?;
        let size_at: usize = pos.checked_add(4)?;
        let (header_size, size_len): (u64, usize) = rar5_vint(bytes, size_at)?;
        let header_start: usize = size_at.checked_add(size_len)?;
        let header_end: usize = header_start.checked_add(usize::try_from(header_size).ok()?)?;
        if crc32fast::hash(bytes.get(size_at..header_end)?) != header_crc {
            return None;
        }
        let (block_type, type_len): (u64, usize) = rar5_vint(bytes, header_start)?;
        let flags_at: usize = header_start.checked_add(type_len)?;
        let (flags, flags_len): (u64, usize) = rar5_vint(bytes, flags_at)?;
        let mut cursor: usize = flags_at.checked_add(flags_len)?;
        if flags & RAR5_FLAG_EXTRA_AREA != 0 {
            let (_, extra_len): (u64, usize) = rar5_vint(bytes, cursor)?;
            cursor = cursor.checked_add(extra_len)?;
        }
        let data_size: u64 = if flags & RAR5_FLAG_DATA_AREA != 0 {
            rar5_vint(bytes, cursor)?.0
        } else {
            0
        };
        let block_end: usize = header_end.checked_add(usize::try_from(data_size).ok()?)?;
        if block_end > bytes.len() {
            return None;
        }
        if block_type == RAR5_END_OF_ARCHIVE {
            return Some(block_end);
        }
        pos = block_end;
    }
    None
}

fn rar4_block(bytes: &[u8], pos: usize) -> Option<(u8, usize)> {
    let header_crc: u16 = u16_le(bytes, pos)?;
    let block_type: u8 = *bytes.get(pos.checked_add(2)?)?;
    let flags: u16 = u16_le(bytes, pos.checked_add(3)?)?;
    let header_size: usize = usize::from(u16_le(bytes, pos.checked_add(5)?)?);
    if header_size < RAR4_MIN_HEADER_LEN {
        return None;
    }
    let header_end: usize = pos.checked_add(header_size)?;
    let crc: u32 = crc32fast::hash(bytes.get(pos + 2..header_end)?);
    if crc & 0xFFFF != u32::from(header_crc) {
        return None;
    }
    let low_size: u64 = if flags & RAR4_FLAG_LONG_BLOCK != 0 {
        u64::from(u32_le(bytes, pos.checked_add(7)?)?)
    } else {
        0
    };
    let high_size: u64 = if matches!(block_type, RAR4_FILE_HEADER | RAR4_SERVICE_HEADER)
        && flags & RAR4_FLAG_LARGE_FILE != 0
    {
        u64::from(u32_le(bytes, pos.checked_add(32)?)?)
    } else {
        0
    };
    let data_size: u64 = (high_size << 32) | low_size;
    let block_end: usize = header_end.checked_add(usize::try_from(data_size).ok()?)?;
    (block_end <= bytes.len()).then_some((block_type, block_end))
}

fn rar4_extent(bytes: &[u8]) -> Option<usize> {
    let mut pos: usize = RAR4_SIGNATURE_LEN;
    let mut file_blocks: usize = 0;
    for _ in 0..RAR_MAX_BLOCKS {
        let Some((block_type, block_end)): Option<(u8, usize)> = rar4_block(bytes, pos) else {
            break;
        };
        pos = block_end;
        match block_type {
            RAR4_END_OF_ARCHIVE => return Some(pos),
            RAR4_FILE_HEADER => file_blocks += 1,
            _ => {}
        }
    }
    (file_blocks > 0).then_some(pos)
}

const ISO_DESCRIPTOR_OFFSET: usize = 32_768;
const ISO_DESCRIPTOR_LEN: usize = 2048;
const ISO_PRIMARY_DESCRIPTOR: u8 = 1;

fn iso_extent(bytes: &[u8]) -> Option<usize> {
    let descriptor: &[u8] =
        bytes.get(ISO_DESCRIPTOR_OFFSET..ISO_DESCRIPTOR_OFFSET + ISO_DESCRIPTOR_LEN)?;
    if descriptor[0] != ISO_PRIMARY_DESCRIPTOR || &descriptor[1..6] != b"CD001" {
        return None;
    }
    let block_count: u32 = u32_le(descriptor, 80)?;
    let block_size: u16 = u16_le(descriptor, 128)?;
    if block_size < 512 || !block_size.is_power_of_two() {
        return None;
    }
    let end: usize = usize::try_from(u64::from(block_count) * u64::from(block_size)).ok()?;
    (end >= ISO_DESCRIPTOR_OFFSET + ISO_DESCRIPTOR_LEN).then_some(end)
}

fn wim_extent(bytes: &[u8]) -> Option<usize> {
    let header: crate::containers::wim::WimHeader =
        crate::containers::wim::parse_wim_header(bytes).ok()?;
    let mut end: u64 = u64::from(header.header_size);
    for resource in [
        header.offset_table,
        header.xml_data,
        header.boot_metadata,
        header.integrity,
    ] {
        if resource.size != 0 {
            end = end.max(resource.offset.checked_add(resource.size)?);
        }
    }
    usize::try_from(end).ok()
}

fn unityfs_extent(bytes: &[u8]) -> Option<usize> {
    let header: crate::containers::unityfs::UnityFsHeader =
        crate::containers::unityfs::parse_header(bytes).ok()?;
    usize::try_from(header.size).ok()
}

const CPIO_MAX_MEMBERS: usize = 1 << 20;
const CPIO_BIN_MAGIC: u16 = 0o070_707;
const CPIO_TRAILER: &[u8] = b"TRAILER!!!\0";

#[derive(Debug, Clone, Copy)]
struct CpioMember {
    header_len: usize,
    name_size: usize,
    file_size: usize,
    align: usize,
}

fn ascii_number(field: &[u8], radix: u32) -> Option<usize> {
    usize::from_str_radix(std::str::from_utf8(field).ok()?, radix).ok()
}

fn cpio_member(header: &[u8], variant: CpioVariant) -> Option<CpioMember> {
    match variant {
        CpioVariant::Newc | CpioVariant::Crc => {
            let magic: &[u8] = if variant == CpioVariant::Newc {
                crate::containers::cpio::NEWC_MAGIC
            } else {
                crate::containers::cpio::CRC_MAGIC
            };
            if header.get(..6)? != magic {
                return None;
            }
            Some(CpioMember {
                header_len: 110,
                name_size: ascii_number(header.get(94..102)?, 16)?,
                file_size: ascii_number(header.get(54..62)?, 16)?,
                align: 4,
            })
        }
        CpioVariant::Odc => {
            if header.get(..6)? != crate::containers::cpio::ODC_MAGIC {
                return None;
            }
            Some(CpioMember {
                header_len: 76,
                name_size: ascii_number(header.get(59..65)?, 8)?,
                file_size: ascii_number(header.get(65..76)?, 8)?,
                align: 1,
            })
        }
        CpioVariant::BinLittleEndian | CpioVariant::BinBigEndian => {
            let word = |at: usize| -> Option<u16> {
                if variant == CpioVariant::BinLittleEndian {
                    u16_le(header, at)
                } else {
                    disrobe_bytes::read_u16_be_at(header, at).ok()
                }
            };
            if word(0)? != CPIO_BIN_MAGIC {
                return None;
            }
            let file_size: u32 = (u32::from(word(22)?) << 16) | u32::from(word(24)?);
            Some(CpioMember {
                header_len: 26,
                name_size: usize::from(word(20)?),
                file_size: usize::try_from(file_size).ok()?,
                align: 2,
            })
        }
    }
}

fn cpio_extent(bytes: &[u8]) -> Option<usize> {
    let variant: CpioVariant = crate::containers::cpio::detect_cpio_variant(bytes)?;
    let mut pos: usize = 0;
    for _ in 0..CPIO_MAX_MEMBERS {
        let member: CpioMember = cpio_member(bytes.get(pos..)?, variant)?;
        let name_start: usize = pos.checked_add(member.header_len)?;
        let name_end: usize = name_start.checked_add(member.name_size)?;
        let name: &[u8] = bytes.get(name_start..name_end)?;
        let data_start: usize = name_end.checked_next_multiple_of(member.align)?;
        let data_end: usize = data_start.checked_add(member.file_size)?;
        let next: usize = data_end.checked_next_multiple_of(member.align)?;
        if next > bytes.len() {
            return None;
        }
        if name == CPIO_TRAILER {
            return Some(next);
        }
        pos = next;
    }
    None
}

const AR_GLOBAL_HEADER_LEN: usize = 8;
const AR_MEMBER_HEADER_LEN: usize = 60;
const AR_MEMBER_TERMINATOR: &[u8] = b"`\n";

fn ar_member_end(bytes: &[u8], at: usize) -> Option<usize> {
    let header: &[u8] = bytes.get(at..at.checked_add(AR_MEMBER_HEADER_LEN)?)?;
    if &header[58..60] != AR_MEMBER_TERMINATOR {
        return None;
    }
    let size_field: &[u8] = header[48..58].split(|&b: &u8| b == b' ').next()?;
    let size: usize = ascii_number(size_field, 10)?;
    let data_end: usize = at.checked_add(AR_MEMBER_HEADER_LEN)?.checked_add(size)?;
    if data_end > bytes.len() {
        return None;
    }
    if data_end % 2 == 1 && bytes.get(data_end) == Some(&b'\n') {
        return Some(data_end + 1);
    }
    Some(data_end)
}

fn ar_extent(bytes: &[u8]) -> Option<usize> {
    let mut end: usize = AR_GLOBAL_HEADER_LEN;
    let mut members: usize = 0;
    while let Some(member_end) = ar_member_end(bytes, end) {
        end = member_end;
        members += 1;
    }
    (members > 0).then_some(end)
}

#[must_use]
pub fn is_skip_magic(magic: &[u8]) -> bool {
    skip_magic_label(magic).is_some()
}

#[must_use]
pub fn skip_magic_label(magic: &[u8]) -> Option<&'static str> {
    DEFAULT_SKIP
        .iter()
        .find(|s: &&SkipMagic| magic.starts_with(s.magic))
        .map(|s: &SkipMagic| s.label)
}

#[derive(Debug, Clone, Copy)]
struct SkipMagic {
    magic: &'static [u8],
    label: &'static str,
}

const DEFAULT_SKIP: &[SkipMagic] = &[
    SkipMagic {
        magic: &[0xff, 0xd8, 0xff],
        label: "jpeg",
    },
    SkipMagic {
        magic: &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
        label: "png",
    },
    SkipMagic {
        magic: b"GIF87a",
        label: "gif",
    },
    SkipMagic {
        magic: b"GIF89a",
        label: "gif",
    },
    SkipMagic {
        magic: b"%PDF-",
        label: "pdf",
    },
    SkipMagic {
        magic: b"SQLite format 3\x00",
        label: "sqlite",
    },
    SkipMagic {
        magic: b"RIFF",
        label: "riff-media",
    },
    SkipMagic {
        magic: b"OggS",
        label: "ogg",
    },
    SkipMagic {
        magic: &[0x00, 0x00, 0x01, 0x00],
        label: "ico",
    },
    SkipMagic {
        magic: b"BM",
        label: "bmp",
    },
];

#[inline]
fn u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    disrobe_bytes::read_u16_le_at(bytes, off).ok()
}

#[inline]
fn u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, off).ok()
}

#[inline]
fn u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    disrobe_bytes::read_u64_le_at(bytes, off).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut enc: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload).expect("gz write");
        enc.finish().expect("gz finish")
    }

    fn synth_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut zw: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, body) in files {
            zw.start_file(*name, opts).expect("start");
            zw.write_all(body).expect("write");
        }
        zw.finish().expect("finish").into_inner()
    }

    #[test]
    fn gzip_stream_extent_is_exact() {
        let gz: Vec<u8> = gzip(b"hello recursive carve");
        let hit: MagicHit = MagicHit {
            offset: 0,
            kind: ContainerKind::Gzip,
        };
        assert_eq!(validated_extent(&gz, &hit), Some(gz.len()));
    }

    #[test]
    fn a_gzip_stream_far_below_the_decode_cap_is_still_measured() {
        const PAYLOAD_LEN: usize = 16 * 1024 * 1024;
        assert!(
            u64::try_from(PAYLOAD_LEN).unwrap_or(u64::MAX) < STREAM_DECODE_CAP,
            "the payload must sit well under the cap for this test to mean anything"
        );
        let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i: usize| (i % 251) as u8).collect();
        let gz: Vec<u8> = gzip(&payload);
        assert_eq!(
            gzip_exact_extent(&gz),
            Some(gz.len()),
            "a stream whose output is {PAYLOAD_LEN} bytes is far below the {STREAM_DECODE_CAP} \
             byte cap and must be measured rather than abandoned"
        );
    }

    #[test]
    fn gzip_extent_when_embedded_with_trailing_padding() {
        let gz: Vec<u8> = gzip(b"embedded gzip stream payload");
        let mut buf: Vec<u8> = gz.clone();
        buf.extend(std::iter::repeat_n(0u8, 64));
        let hit: MagicHit = MagicHit {
            offset: 0,
            kind: ContainerKind::Gzip,
        };
        assert_eq!(validated_extent(&buf, &hit), Some(gz.len()));
    }

    #[test]
    fn zip_extent_is_exact() {
        let z: Vec<u8> = synth_zip(&[("a.txt", b"alpha")]);
        let hit: MagicHit = MagicHit {
            offset: 0,
            kind: ContainerKind::Zip,
        };
        assert_eq!(validated_extent(&z, &hit), Some(z.len()));
    }

    #[test]
    fn a_zip_followed_by_more_than_64_kib_ends_at_its_own_directory() {
        let first: Vec<u8> = synth_zip(&[("a.txt", b"alpha")]);
        let second: Vec<u8> = synth_zip(&[("b.txt", b"bravo"), ("c.txt", b"charlie")]);
        let mut buf: Vec<u8> = first.clone();
        buf.extend(std::iter::repeat_n(0x5Au8, 100 * 1024));
        buf.extend_from_slice(&second);
        let hit: MagicHit = MagicHit {
            offset: 0,
            kind: ContainerKind::Zip,
        };
        assert_eq!(validated_extent(&buf, &hit), Some(first.len()));
        let later: MagicHit = MagicHit {
            offset: buf.len() - second.len(),
            kind: ContainerKind::Zip,
        };
        assert_eq!(validated_extent(&buf, &later), Some(second.len()));
    }

    #[test]
    fn scan_finds_gzip_at_nonzero_offset() {
        let gz: Vec<u8> = gzip(b"payload");
        let mut buf: Vec<u8> = vec![0x55u8; 100];
        buf.extend_from_slice(&gz);
        let hits: Vec<MagicHit> = scan_magics(&buf);
        assert!(
            hits.iter()
                .any(|h: &MagicHit| h.kind == ContainerKind::Gzip && h.offset == 100),
            "gzip must be found at offset 100, got {hits:?}"
        );
    }

    #[test]
    fn an_xz_stream_ends_where_its_decoder_stops_so_a_following_rootfs_is_carved() {
        let payload: Vec<u8> = (0..4096usize).map(|i: usize| (i % 251) as u8).collect();
        let mut xz: Vec<u8> = Vec::new();
        {
            let mut encoder: liblzma::write::XzEncoder<&mut Vec<u8>> =
                liblzma::write::XzEncoder::new(&mut xz, 6);
            std::io::Write::write_all(&mut encoder, &payload).expect("xz encode");
            encoder.finish().expect("xz finish");
        }
        let rootfs: Vec<u8> =
            crate::containers::squashfs::build_real_squashfs("init", b"rootfs body");
        let mut image: Vec<u8> = xz.clone();
        image.extend_from_slice(&rootfs);
        let hit: MagicHit = MagicHit {
            offset: 0,
            kind: ContainerKind::Xz,
        };
        assert_eq!(validated_extent(&image, &hit), Some(xz.len()));
        let hits: Vec<MagicHit> = scan_magics(&image);
        let chunks: Vec<CarvedChunk> = build_chunks(&image, &hits);
        assert!(
            chunks.iter().any(
                |chunk: &CarvedChunk| chunk.kind == Some(ContainerKind::Squashfs)
                    && chunk.start == xz.len() as u64
            ),
            "the squashfs rootfs after the xz kernel must be its own chunk: {chunks:?}"
        );
    }

    #[test]
    fn zstd_and_bzip2_streams_end_where_their_decoders_stop() {
        let payload: &[u8] = b"a stream followed by unrelated bytes";
        let zst: Vec<u8> = zstd::encode_all(payload, 3).expect("zstd encode");
        let mut bz: Vec<u8> = Vec::new();
        {
            let mut encoder: bzip2::write::BzEncoder<&mut Vec<u8>> =
                bzip2::write::BzEncoder::new(&mut bz, bzip2::Compression::best());
            std::io::Write::write_all(&mut encoder, payload).expect("bzip2 encode");
            encoder.finish().expect("bzip2 finish");
        }
        for (kind, stream) in [(ContainerKind::Zstd, zst), (ContainerKind::Bzip2, bz)] {
            let mut buf: Vec<u8> = stream.clone();
            buf.extend_from_slice(&[0x11u8; 64]);
            let hit: MagicHit = MagicHit { offset: 0, kind };
            assert_eq!(validated_extent(&buf, &hit), Some(stream.len()), "{kind:?}");
        }
    }

    fn junk(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i: usize| (i as u8).wrapping_mul(31).wrapping_add(seed) | 0x80)
            .collect()
    }

    fn corpus(relative: &str) -> Vec<u8> {
        let path: PathBuf = PathBuf::from(format!(
            "{}/../../corpus/{relative}",
            env!("CARGO_MANIFEST_DIR")
        ));
        std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
            panic!("fixture {} is missing: {error}", path.display())
        })
    }

    fn newc_member(name: &str, mode: u32, body: &[u8]) -> Vec<u8> {
        let mut member: Vec<u8> = b"070701".to_vec();
        let name_size: u32 = u32::try_from(name.len() + 1).expect("name fits");
        let body_size: u32 = u32::try_from(body.len()).expect("body fits");
        for field in [1, mode, 0, 0, 1, 0, body_size, 0, 0, 0, 0, name_size, 0] {
            member.extend_from_slice(format!("{field:08X}").as_bytes());
        }
        member.extend_from_slice(name.as_bytes());
        member.push(0);
        member.resize(member.len().next_multiple_of(4), 0);
        member.extend_from_slice(body);
        member.resize(member.len().next_multiple_of(4), 0);
        member
    }

    fn newc_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive: Vec<u8> = Vec::new();
        for (name, body) in files {
            archive.extend(newc_member(name, 0o100_644, body));
        }
        archive.extend(newc_member("TRAILER!!!", 0, b""));
        archive
    }

    #[test]
    fn formats_outside_the_old_twelve_signatures_are_carved_with_their_exact_extent() {
        let cpio: Vec<u8> = newc_archive(&[
            ("init", b"#!/bin/sh\n"),
            ("motd", b"carved out of a larger blob"),
        ]);
        let cases: [(ContainerKind, Vec<u8>); 3] = [
            (ContainerKind::Cpio, cpio),
            (
                ContainerKind::Iso,
                corpus("binfmt/iso/joliet-rockridge.iso"),
            ),
            (ContainerKind::Ar, corpus("binfmt/deb/lzma.deb")),
        ];
        for (kind, payload) in cases {
            let prefix: Vec<u8> = junk(1000, 3);
            let mut blob: Vec<u8> = prefix.clone();
            blob.extend_from_slice(&payload);
            blob.extend(junk(777, 9));
            let report: CarveReport = carve_recursive(&blob, "blob", CarveConfig::new(1), None);
            let start: u64 = prefix.len() as u64;
            let end: u64 = start + payload.len() as u64;
            let carved: Vec<(ChunkClass, Option<ContainerKind>, u64, u64)> = report
                .root
                .chunks
                .iter()
                .map(|chunk: &CarvedChunk| (chunk.class, chunk.kind, chunk.start, chunk.end))
                .collect();
            assert!(
                carved.contains(&(ChunkClass::Valid, Some(kind), start, end)),
                "{kind:?} at {start}..{end} must be a valid carved chunk: {carved:?} {:?}",
                report.root.notes
            );
        }
    }

    #[test]
    fn real_rar_archives_end_at_their_last_block_not_at_the_end_of_the_blob() {
        for name in [
            "normal-rar4.rar",
            "store-rar4.rar",
            "ppmd-rar4.rar",
            "normal-rar5.rar",
            "store-rar5.rar",
            "multiblock-rar5.rar",
            "filter-e8e9-rar5.rar",
            "multiblock-lz-rar3.rar",
            "filter-e8-rar3.rar",
        ] {
            let archive: Vec<u8> = corpus(&format!("binfmt/rar/{name}"));
            let mut blob: Vec<u8> = archive.clone();
            blob.extend(junk(300, 5));
            let hit: MagicHit = MagicHit {
                offset: 0,
                kind: ContainerKind::Rar,
            };
            assert_eq!(validated_extent(&blob, &hit), Some(archive.len()), "{name}");
        }
    }

    #[test]
    fn seven_zip_and_cab_extents_come_from_their_headers() {
        let mut writer: sevenz_rust2::SevenZWriter<std::io::Cursor<Vec<u8>>> =
            sevenz_rust2::SevenZWriter::new(std::io::Cursor::new(Vec::new())).expect("7z writer");
        writer
            .push_archive_entry(
                sevenz_rust2::SevenZArchiveEntry::new_file("member.txt"),
                Some(b"seven zip member body".as_slice()),
            )
            .expect("7z entry");
        let sevenz: Vec<u8> = writer.finish().expect("7z finish").into_inner();

        let mut builder: cab::CabinetBuilder = cab::CabinetBuilder::new();
        builder
            .add_folder(cab::CompressionType::MsZip)
            .add_file("member.txt");
        let mut cab_writer: cab::CabinetWriter<std::io::Cursor<Vec<u8>>> = builder
            .build(std::io::Cursor::new(Vec::new()))
            .expect("cab build");
        while let Some(mut file) = cab_writer.next_file().expect("next cab file") {
            file.write_all(b"cabinet member body").expect("cab write");
        }
        let cabinet: Vec<u8> = cab_writer.finish().expect("cab finish").into_inner();

        for (kind, archive) in [
            (ContainerKind::SevenZ, sevenz),
            (ContainerKind::Cab, cabinet),
        ] {
            let mut blob: Vec<u8> = archive.clone();
            blob.extend(junk(300, 7));
            let hit: MagicHit = MagicHit { offset: 0, kind };
            assert_eq!(
                validated_extent(&blob, &hit),
                Some(archive.len()),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn carve_splits_padding_and_unknown() {
        let mut buf: Vec<u8> = vec![0u8; 32];
        buf.extend_from_slice(b"random non-magic content here 123456");
        let report: CarveReport = carve_recursive(&buf, "test", CarveConfig::default(), None);
        let padding: usize = report
            .root
            .chunks
            .iter()
            .filter(|c: &&CarvedChunk| c.class == ChunkClass::Padding)
            .count();
        assert!(
            padding >= 1,
            "must carve a padding run: {:?}",
            report.root.chunks
        );
    }

    #[test]
    fn is_skip_magic_flags_media() {
        assert!(is_skip_magic(&[0xff, 0xd8, 0xff, 0xe0]));
        assert!(is_skip_magic(b"%PDF-1.7"));
        assert!(is_skip_magic(b"SQLite format 3\x00rest"));
        assert!(!is_skip_magic(b"PK\x03\x04"));
    }

    #[test]
    fn skip_magic_labels_exposed() {
        assert_eq!(skip_magic_label(&[0xff, 0xd8, 0xff, 0xe0]), Some("jpeg"));
        assert_eq!(skip_magic_label(b"%PDF-1.4"), Some("pdf"));
        assert_eq!(skip_magic_label(b"PK\x03\x04"), None);
    }

    #[test]
    fn carve_output_directories_are_tool_named_not_archive_derived() {
        let source: &str = include_str!("carve.rs");
        let mut sites: Vec<&str> = Vec::new();
        for line in source.lines() {
            if line.contains("split_once") || line.contains("include_str!") {
                continue;
            }
            let Some(rest) = line.split_once(".join(") else {
                continue;
            };
            sites.push(rest.1);
        }
        assert_eq!(sites.len(), 1, "carve gained a new path-building site");
        assert!(
            sites[0].starts_with("format!(\"d{depth}-c{index}\")"),
            "carve output directories must stay tool-numbered: {}",
            sites[0]
        );
    }
}
