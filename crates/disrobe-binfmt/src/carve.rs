use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use disrobe_core::byte_search;
use disrobe_core::shannon_entropy;

use crate::container::ContainerKind;
use crate::extract::{ExtractionResult, extract_to_with_quota};
use crate::quota::ExtractionQuota;

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
pub fn carve_recursive(bytes: &[u8], source: &str, config: CarveConfig) -> CarveReport {
    let mut budget: WorkBudget = WorkBudget::new();
    let mut nodes_visited: usize = 0;
    let mut chunks_total: usize = 0;
    let mut bytes_carved: u64 = 0;
    let scratch: Option<tempfile::TempDir> = tempfile::tempdir().ok();
    let root: CarveNode = carve_node(
        bytes,
        source,
        0,
        config,
        scratch.as_ref().map(tempfile::TempDir::path),
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
                    chunk.carved_path = Some(written.dir.clone());
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
    for sig in MAGIC_SIGNATURES {
        let mut from: usize = 0;
        while from < bytes.len() && hits.len() < SCAN_HIT_CAP {
            let Some(rel): Option<usize> = byte_search::find(&bytes[from..], sig.magic) else {
                break;
            };
            let at: usize = from + rel;
            if at >= sig.expected_offset_lo && at <= sig.expected_offset_hi {
                hits.push(MagicHit {
                    offset: at - sig.magic_offset_in_format,
                    kind: sig.kind,
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
        | ContainerKind::Squashfs => 0,
        ContainerKind::TarGz
        | ContainerKind::TarXz
        | ContainerKind::TarBz2
        | ContainerKind::TarZst
        | ContainerKind::Tar => 1,
        _ => 2,
    }
}

#[derive(Debug, Clone, Copy)]
struct MagicSig {
    magic: &'static [u8],
    kind: ContainerKind,
    magic_offset_in_format: usize,
    expected_offset_lo: usize,
    expected_offset_hi: usize,
}

const TAR_USTAR_OFFSET: usize = 257;

const MAGIC_SIGNATURES: &[MagicSig] = &[
    MagicSig {
        magic: b"PK\x03\x04",
        kind: ContainerKind::Zip,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c],
        kind: ContainerKind::SevenZ,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: b"Rar!\x1a\x07\x01\x00",
        kind: ContainerKind::Rar,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: b"Rar!\x1a\x07\x00",
        kind: ContainerKind::Rar,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: b"MSCF",
        kind: ContainerKind::Cab,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: &[0xfd, b'7', b'z', b'X', b'Z', 0x00],
        kind: ContainerKind::Xz,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: &[0x1f, 0x8b],
        kind: ContainerKind::Gzip,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: &[0x28, 0xb5, 0x2f, 0xfd],
        kind: ContainerKind::Zstd,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: &[0x42, 0x5a, 0x68],
        kind: ContainerKind::Bzip2,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: b"ustar",
        kind: ContainerKind::Tar,
        magic_offset_in_format: TAR_USTAR_OFFSET,
        expected_offset_lo: TAR_USTAR_OFFSET,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: b"hsqs",
        kind: ContainerKind::Squashfs,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
    MagicSig {
        magic: b"MDMP",
        kind: ContainerKind::Minidump,
        magic_offset_in_format: 0,
        expected_offset_lo: 0,
        expected_offset_hi: usize::MAX,
    },
];

fn validated_extent(bytes: &[u8], hit: &MagicHit) -> Option<usize> {
    let tail: &[u8] = bytes.get(hit.offset..)?;
    if tail.len() < MIN_VALID_EXTENT {
        return None;
    }
    let extent: usize = match hit.kind {
        ContainerKind::Zip => zip_extent(tail)?,
        ContainerKind::Gzip => stream_extent(tail, StreamKind::Gzip)?,
        ContainerKind::Xz => stream_extent(tail, StreamKind::Xz)?,
        ContainerKind::Zstd => stream_extent(tail, StreamKind::Zstd)?,
        ContainerKind::Bzip2 => stream_extent(tail, StreamKind::Bzip2)?,
        ContainerKind::Tar => tar_extent(tail)?,
        ContainerKind::Squashfs => squashfs_extent(tail)?,
        ContainerKind::Minidump => crate::containers::minidump::minidump_extent(tail)?,
        _ => trial_parse_extent(tail, hit.kind)?,
    };
    if extent < MIN_VALID_EXTENT || extent > tail.len() {
        return None;
    }
    Some(extent)
}

fn zip_extent(bytes: &[u8]) -> Option<usize> {
    let cd_start: usize = crate::structural::locate_zip_central_directory(bytes)?;
    let eocd: usize = find_eocd(bytes)?;
    let comment_len: usize = u16_le(bytes, eocd + 20)? as usize;
    let end: usize = eocd + 22 + comment_len;
    if end <= cd_start || end > bytes.len() {
        return None;
    }
    Some(end)
}

const ZIP_EOCD_SIGNATURE: u32 = 0x0605_4B50;

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let len: usize = bytes.len();
    if len < 22 {
        return None;
    }
    let budget: usize = 0xFFFF + 22 + 4;
    let start: usize = len.saturating_sub(budget);
    let mut off: usize = len - 22;
    while off >= start {
        if u32_le(bytes, off) == Some(ZIP_EOCD_SIGNATURE) {
            return Some(off);
        }
        if off == 0 {
            break;
        }
        off -= 1;
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum StreamKind {
    Gzip,
    Xz,
    Zstd,
    Bzip2,
}

fn stream_extent(bytes: &[u8], kind: StreamKind) -> Option<usize> {
    match kind {
        StreamKind::Gzip => gzip_exact_extent(bytes),
        StreamKind::Xz | StreamKind::Zstd | StreamKind::Bzip2 => {
            decode_validate(bytes, kind)?;
            Some(trim_trailing_zero_padding(bytes))
        }
    }
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
    let mut produced: u64 = 0;
    loop {
        let in_before: u64 = decompressor.total_in();
        let consumed_so_far: usize = usize::try_from(in_before).ok()?;
        let remaining: &[u8] = body.get(consumed_so_far..)?;
        let status: flate2::Status = decompressor
            .decompress(remaining, &mut scratch, flate2::FlushDecompress::None)
            .ok()?;
        produced = produced.saturating_add(decompressor.total_out());
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
    if bytes.len() < TAR_USTAR_OFFSET + 5 {
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
        if &header[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5] != b"ustar"
            && cursor == 0
            && !header[TAR_USTAR_OFFSET..TAR_USTAR_OFFSET + 5]
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

fn trial_parse_extent(bytes: &[u8], kind: ContainerKind) -> Option<usize> {
    if crate::container::detect_container(bytes) == Some(kind) {
        Some(bytes.len())
    } else {
        None
    }
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
    let s: &[u8] = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let s: &[u8] = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
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
    fn carve_splits_padding_and_unknown() {
        let mut buf: Vec<u8> = vec![0u8; 32];
        buf.extend_from_slice(b"random non-magic content here 123456");
        let report: CarveReport = carve_recursive(&buf, "test", CarveConfig::default());
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
}
