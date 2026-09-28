use std::collections::BTreeMap;

use crate::error::{Error, Result};

use super::lzms::lzms_decompress;

const CAB_MAGIC: [u8; 4] = *b"MSCF";
const CFHEADER_FIXED_LEN: usize = 36;
const CFFOLDER_FIXED_LEN: usize = 8;
const CFFILE_FIXED_LEN: usize = 16;
const CFDATA_FIXED_LEN: usize = 8;

const CFHDR_PREV_CABINET: u16 = 0x0001;
const CFHDR_NEXT_CABINET: u16 = 0x0002;
const CFHDR_RESERVE_PRESENT: u16 = 0x0004;

const COMPTYPE_MASK: u16 = 0x000f;
const COMPTYPE_NONE: u16 = 0;
const COMPTYPE_MSZIP: u16 = 1;
const COMPTYPE_QUANTUM: u16 = 2;
const COMPTYPE_LZX: u16 = 3;
const COMPTYPE_LZMS: u16 = 5;

const FOLDER_CONTINUED_FROM_PREV: u16 = 0xfffd;
const MAX_NAME_BYTES: usize = 256;
const MSZIP_SIGNATURE: [u8; 2] = *b"CK";
const DEFLATE_WINDOW: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabMember {
    pub name: String,
    pub size: u32,
    pub folder_offset: u32,
    pub folder_index: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CabCodec {
    Stored,
    MsZip,
    Quantum,
    Lzx(u16),
    Lzms,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CabFolder {
    pub data_offset: u32,
    pub num_blocks: u16,
    pub codec: CabCodec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabArchive {
    pub folders: Vec<CabFolder>,
    pub members: Vec<CabMember>,
    data_reserve: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CabRefusal {
    #[error("another member of the cabinet has the same name, so neither copy is authoritative")]
    DuplicateName,
    #[error("the member continues into another cabinet of a multi-cabinet set")]
    SpansCabinets,
    #[error("the member names folder {index}, which the cabinet does not declare")]
    MissingFolder { index: u16 },
    #[error("the folder declares no data blocks, so the member has no backing data")]
    NoDataBlocks,
    #[error("the folder uses {0} compression, which is not decoded")]
    UnsupportedCodec(String),
    #[error("the member declares {size} bytes, above the {cap}-byte per-entry cap")]
    OverCap { size: u64, cap: u64 },
    #[error("the member ends at folder offset {end}, but the folder holds only {available} bytes")]
    ExtentPastFolder { end: u64, available: u64 },
    #[error("folder data block {block} failed to decode: {reason}")]
    Decode { block: u16, reason: String },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CabReadStats {
    pub folder_passes: u32,
    pub blocks_decoded: u64,
}

impl CabArchive {
    #[must_use]
    pub fn uses_codec(&self, codec: CabCodec) -> bool {
        self.folders.iter().any(|f: &CabFolder| f.codec == codec)
    }
}

pub fn parse_cab(bytes: &[u8]) -> Result<CabArchive> {
    if bytes.len() < CFHEADER_FIXED_LEN || bytes[..4] != CAB_MAGIC {
        return Err(Error::Cab(
            "not a cabinet (missing MSCF signature)".to_owned(),
        ));
    }
    let coff_files: u32 = read_u32(bytes, 16)?;
    let num_folders: u16 = read_u16(bytes, 26)?;
    let num_files: u16 = read_u16(bytes, 28)?;
    let flags: u16 = read_u16(bytes, 30)?;

    let mut cursor: usize = CFHEADER_FIXED_LEN;
    let mut folder_reserve: usize = 0;
    let mut data_reserve: usize = 0;
    if flags & CFHDR_RESERVE_PRESENT != 0 {
        let header_reserve: u16 = read_u16(bytes, 36)?;
        folder_reserve = usize::from(read_u8(bytes, 38)?);
        data_reserve = usize::from(read_u8(bytes, 39)?);
        cursor = 40 + usize::from(header_reserve);
    }
    if flags & CFHDR_PREV_CABINET != 0 {
        cursor = skip_cstring(bytes, cursor)?;
        cursor = skip_cstring(bytes, cursor)?;
    }
    if flags & CFHDR_NEXT_CABINET != 0 {
        cursor = skip_cstring(bytes, cursor)?;
        cursor = skip_cstring(bytes, cursor)?;
    }

    let folder_table_len: usize = usize::from(num_folders) * (CFFOLDER_FIXED_LEN + folder_reserve);
    if cursor.saturating_add(folder_table_len) > bytes.len() {
        return Err(Error::Cab(format!(
            "the header declares {num_folders} folders, past the end of the {}-byte cabinet",
            bytes.len()
        )));
    }
    let mut folders: Vec<CabFolder> = Vec::with_capacity(usize::from(num_folders));
    for _ in 0..num_folders {
        let data_offset: u32 = read_u32(bytes, cursor)?;
        let num_blocks: u16 = read_u16(bytes, cursor + 4)?;
        let comp_type: u16 = read_u16(bytes, cursor + 6)?;
        folders.push(CabFolder {
            data_offset,
            num_blocks,
            codec: codec_from_type(comp_type),
        });
        cursor += CFFOLDER_FIXED_LEN + folder_reserve;
    }

    let mut cursor: usize = usize::try_from(coff_files)
        .map_err(|_| Error::Cab(format!("file table offset {coff_files} does not fit")))?;
    let min_table_len: usize = usize::from(num_files) * (CFFILE_FIXED_LEN + 1);
    if cursor.saturating_add(min_table_len) > bytes.len() {
        return Err(Error::Cab(format!(
            "the header declares {num_files} files at offset {coff_files}, past the end of the {}-byte cabinet",
            bytes.len()
        )));
    }
    let mut members: Vec<CabMember> = Vec::with_capacity(usize::from(num_files));
    for _ in 0..num_files {
        let size: u32 = read_u32(bytes, cursor)?;
        let folder_offset: u32 = read_u32(bytes, cursor + 4)?;
        let folder_index: u16 = read_u16(bytes, cursor + 8)?;
        let name_start: usize = cursor + CFFILE_FIXED_LEN;
        let name_end: usize = bytes
            .get(name_start..)
            .and_then(|tail: &[u8]| {
                tail.iter()
                    .take(MAX_NAME_BYTES + 1)
                    .position(|&b: &u8| b == 0)
            })
            .map(|rel: usize| name_start + rel)
            .ok_or_else(|| {
                Error::Cab(format!(
                    "file name at offset {name_start} is unterminated within {MAX_NAME_BYTES} bytes"
                ))
            })?;
        let name: String = String::from_utf8_lossy(&bytes[name_start..name_end]).into_owned();
        members.push(CabMember {
            name,
            size,
            folder_offset,
            folder_index,
        });
        cursor = name_end + 1;
    }

    Ok(CabArchive {
        folders,
        members,
        data_reserve,
    })
}

pub fn read_cab_members<F>(
    bytes: &[u8],
    archive: &CabArchive,
    per_member_cap: u64,
    mut visit: F,
) -> Result<CabReadStats>
where
    F: FnMut(&CabMember, std::result::Result<&[u8], CabRefusal>) -> Result<()>,
{
    let mut name_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for member in &archive.members {
        *name_counts.entry(member.name.as_str()).or_insert(0) += 1;
    }
    let mut by_folder: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    for (index, member) in archive.members.iter().enumerate() {
        let refusal: Option<CabRefusal> = if name_counts
            .get(member.name.as_str())
            .is_some_and(|&count: &usize| count > 1)
        {
            Some(CabRefusal::DuplicateName)
        } else if member.folder_index >= FOLDER_CONTINUED_FROM_PREV {
            Some(CabRefusal::SpansCabinets)
        } else if usize::from(member.folder_index) >= archive.folders.len() {
            Some(CabRefusal::MissingFolder {
                index: member.folder_index,
            })
        } else if u64::from(member.size) > per_member_cap {
            Some(CabRefusal::OverCap {
                size: u64::from(member.size),
                cap: per_member_cap,
            })
        } else {
            None
        };
        match refusal {
            Some(refusal) => visit(member, Err(refusal))?,
            None => by_folder
                .entry(member.folder_index)
                .or_default()
                .push(index),
        }
    }

    let mut stats: CabReadStats = CabReadStats::default();
    for (folder_index, mut indices) in by_folder {
        indices.sort_by_key(|&index: &usize| (archive.members[index].folder_offset, index));
        let folder: CabFolder = archive.folders[usize::from(folder_index)];
        let mut stream: FolderStream<'_> =
            match FolderStream::open(bytes, folder, archive.data_reserve) {
                Ok(stream) => stream,
                Err(refusal) => {
                    for index in indices {
                        visit(&archive.members[index], Err(refusal.clone()))?;
                    }
                    continue;
                }
            };
        stats.folder_passes += 1;
        for index in indices {
            let member: &CabMember = &archive.members[index];
            let outcome: std::result::Result<&[u8], CabRefusal> = stream.member_bytes(member);
            visit(member, outcome)?;
        }
        stats.blocks_decoded += stream.blocks_decoded;
    }
    Ok(stats)
}

enum BlockDecoder {
    Stored,
    MsZip {
        inflater: Box<flate2::Decompress>,
        history: Vec<u8>,
    },
    Lzx(Box<lzxd::Lzxd>),
    Lzms,
}

struct FolderStream<'a> {
    bytes: &'a [u8],
    data_reserve: usize,
    decoder: BlockDecoder,
    cursor: usize,
    blocks_total: u16,
    blocks_decoded: u64,
    window: Vec<u8>,
    window_start: u64,
    failure: Option<CabRefusal>,
}

impl<'a> FolderStream<'a> {
    fn open(
        bytes: &'a [u8],
        folder: CabFolder,
        data_reserve: usize,
    ) -> std::result::Result<Self, CabRefusal> {
        if folder.num_blocks == 0 {
            return Err(CabRefusal::NoDataBlocks);
        }
        let decoder: BlockDecoder = match folder.codec {
            CabCodec::Stored => BlockDecoder::Stored,
            CabCodec::MsZip => BlockDecoder::MsZip {
                inflater: Box::new(flate2::Decompress::new(false)),
                history: Vec::with_capacity(DEFLATE_WINDOW),
            },
            CabCodec::Lzx(window_bits) => {
                BlockDecoder::Lzx(Box::new(lzxd::Lzxd::new(lzx_window(window_bits)?)))
            }
            CabCodec::Lzms => BlockDecoder::Lzms,
            CabCodec::Quantum => return Err(CabRefusal::UnsupportedCodec("Quantum".to_owned())),
            CabCodec::Unknown(comp_type) => {
                return Err(CabRefusal::UnsupportedCodec(format!(
                    "unknown type {comp_type:#06x}"
                )));
            }
        };
        let cursor: usize =
            usize::try_from(folder.data_offset).map_err(|_| CabRefusal::Decode {
                block: 0,
                reason: format!("data offset {} does not fit", folder.data_offset),
            })?;
        Ok(Self {
            bytes,
            data_reserve,
            decoder,
            cursor,
            blocks_total: folder.num_blocks,
            blocks_decoded: 0,
            window: Vec::new(),
            window_start: 0,
            failure: None,
        })
    }

    fn member_bytes(&mut self, member: &CabMember) -> std::result::Result<&[u8], CabRefusal> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        let start: u64 = u64::from(member.folder_offset);
        let end: u64 = start + u64::from(member.size);
        loop {
            if self.window_start < start {
                let drop: u64 = (start - self.window_start).min(self.window.len() as u64);
                self.window.drain(..drop as usize);
                self.window_start += drop;
            }
            let decoded_end: u64 = self.window_start + self.window.len() as u64;
            if decoded_end >= end && self.window_start <= start {
                break;
            }
            if self.blocks_decoded >= u64::from(self.blocks_total) {
                return Err(CabRefusal::ExtentPastFolder {
                    end,
                    available: decoded_end,
                });
            }
            if let Err(refusal) = self.decode_next_block() {
                self.failure = Some(refusal.clone());
                return Err(refusal);
            }
        }
        let from: usize = (start - self.window_start) as usize;
        let to: usize = (end - self.window_start) as usize;
        Ok(&self.window[from..to])
    }

    fn decode_next_block(&mut self) -> std::result::Result<(), CabRefusal> {
        let block: u16 = self.blocks_decoded as u16;
        let fail = |reason: String| CabRefusal::Decode { block, reason };
        let checksum: u32 =
            read_u32(self.bytes, self.cursor).map_err(|e: Error| fail(e.to_string()))?;
        let cb_data: u16 =
            read_u16(self.bytes, self.cursor + 4).map_err(|e: Error| fail(e.to_string()))?;
        let cb_uncomp: u16 =
            read_u16(self.bytes, self.cursor + 6).map_err(|e: Error| fail(e.to_string()))?;
        let reserve_start: usize = self.cursor + CFDATA_FIXED_LEN;
        let data_start: usize = reserve_start + self.data_reserve;
        let data_end: usize = data_start + usize::from(cb_data);
        let checked: &[u8] = self.bytes.get(reserve_start..data_end).ok_or_else(|| {
            fail(format!(
                "the {cb_data}-byte block at offset {data_start} runs past the end of the cabinet"
            ))
        })?;
        if checksum != 0 {
            let computed: u32 =
                cab_checksum(checked) ^ (u32::from(cb_data) | (u32::from(cb_uncomp) << 16));
            if computed != checksum {
                return Err(fail(format!(
                    "checksum {checksum:#010x} does not match the computed {computed:#010x}"
                )));
            }
        }
        let data: &[u8] = &checked[self.data_reserve..];
        let expected: usize = usize::from(cb_uncomp);
        let before: usize = self.window.len();
        match &mut self.decoder {
            BlockDecoder::Stored => {
                if cb_data != cb_uncomp {
                    return Err(fail(format!(
                        "a stored block holds {cb_data} bytes but declares {cb_uncomp}"
                    )));
                }
                self.window.extend_from_slice(data);
            }
            BlockDecoder::MsZip { inflater, history } => {
                let decoded: Vec<u8> =
                    inflate_mszip_block(inflater, history, data, expected).map_err(&fail)?;
                self.window.extend_from_slice(&decoded);
            }
            BlockDecoder::Lzx(lzx) => {
                let decoded: &[u8] = lzx
                    .decompress_next(data, expected)
                    .map_err(|e: lzxd::DecompressError| fail(e.to_string()))?;
                self.window.extend_from_slice(decoded);
            }
            BlockDecoder::Lzms => {
                if cb_uncomp == 0 {
                    self.window.extend_from_slice(data);
                } else {
                    let decoded: Vec<u8> = lzms_decompress(data, expected)
                        .map_err(|e: Error| fail(format!("lzms: {e}")))?;
                    self.window.extend_from_slice(&decoded);
                }
            }
        }
        let produced: usize = self.window.len() - before;
        if cb_uncomp != 0 && produced != expected {
            return Err(fail(format!(
                "the block produced {produced} bytes but declares {expected}"
            )));
        }
        self.cursor = data_end;
        self.blocks_decoded += 1;
        Ok(())
    }
}

fn inflate_mszip_block(
    inflater: &mut flate2::Decompress,
    history: &mut Vec<u8>,
    data: &[u8],
    expected: usize,
) -> std::result::Result<Vec<u8>, String> {
    let body: &[u8] = data
        .strip_prefix(&MSZIP_SIGNATURE)
        .ok_or_else(|| "the block lacks the MSZIP `CK` signature".to_owned())?;
    inflater.reset(false);
    if !history.is_empty() {
        let length: u16 = history.len() as u16;
        let mut primer: Vec<u8> = Vec::with_capacity(history.len() + 5);
        primer.push(0);
        primer.extend_from_slice(&length.to_le_bytes());
        primer.extend_from_slice(&(!length).to_le_bytes());
        primer.extend_from_slice(history);
        let mut sink: Vec<u8> = Vec::with_capacity(history.len());
        inflater
            .decompress_vec(&primer, &mut sink, flate2::FlushDecompress::Sync)
            .map_err(|e: flate2::DecompressError| format!("priming the window: {e}"))?;
        if sink.len() != history.len() {
            return Err("priming the window with the previous block failed".to_owned());
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(expected);
    inflater
        .decompress_vec(body, &mut out, flate2::FlushDecompress::Finish)
        .map_err(|e: flate2::DecompressError| format!("deflate: {e}"))?;
    if out.len() != expected {
        return Err(format!(
            "deflate produced {} bytes but the block declares {expected}",
            out.len()
        ));
    }
    if out.len() >= DEFLATE_WINDOW {
        history.clear();
        history.extend_from_slice(&out[out.len() - DEFLATE_WINDOW..]);
    } else {
        let overflow: usize = (history.len() + out.len()).saturating_sub(DEFLATE_WINDOW);
        history.drain(..overflow);
        history.extend_from_slice(&out);
    }
    Ok(out)
}

fn lzx_window(window_bits: u16) -> std::result::Result<lzxd::WindowSize, CabRefusal> {
    let size: lzxd::WindowSize = match window_bits {
        15 => lzxd::WindowSize::KB32,
        16 => lzxd::WindowSize::KB64,
        17 => lzxd::WindowSize::KB128,
        18 => lzxd::WindowSize::KB256,
        19 => lzxd::WindowSize::KB512,
        20 => lzxd::WindowSize::MB1,
        21 => lzxd::WindowSize::MB2,
        other => {
            return Err(CabRefusal::UnsupportedCodec(format!(
                "LZX with a 2^{other}-byte window"
            )));
        }
    };
    Ok(size)
}

const fn codec_from_type(comp_type: u16) -> CabCodec {
    match comp_type & COMPTYPE_MASK {
        COMPTYPE_NONE => CabCodec::Stored,
        COMPTYPE_MSZIP => CabCodec::MsZip,
        COMPTYPE_QUANTUM => CabCodec::Quantum,
        COMPTYPE_LZX => CabCodec::Lzx((comp_type >> 8) & 0x1f),
        COMPTYPE_LZMS => CabCodec::Lzms,
        _ => CabCodec::Unknown(comp_type),
    }
}

fn cab_checksum(bytes: &[u8]) -> u32 {
    let mut value: u32 = 0;
    let mut words = bytes.chunks_exact(4);
    for word in &mut words {
        value ^= u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
    }
    let tail: u32 = match *words.remainder() {
        [a] => u32::from(a),
        [a, b] => (u32::from(a) << 8) | u32::from(b),
        [a, b, c] => (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c),
        _ => 0,
    };
    value ^ tail
}

fn read_u8(bytes: &[u8], at: usize) -> Result<u8> {
    bytes
        .get(at)
        .copied()
        .ok_or_else(|| Error::Cab(format!("truncated reading a byte at offset {at}")))
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at)
        .map_err(|_| Error::Cab(format!("truncated reading u16 at offset {at}")))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at)
        .map_err(|_| Error::Cab(format!("truncated reading u32 at offset {at}")))
}

fn skip_cstring(bytes: &[u8], start: usize) -> Result<usize> {
    let rel: usize = bytes
        .get(start..)
        .and_then(|tail: &[u8]| {
            tail.iter()
                .take(MAX_NAME_BYTES + 1)
                .position(|&b: &u8| b == 0)
        })
        .ok_or_else(|| {
            Error::Cab(format!(
                "cabinet set name at offset {start} is unterminated"
            ))
        })?;
    Ok(start + rel + 1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::containers::cab_lzms::build_lzms_cab;

    type Seen = Vec<(String, std::result::Result<Vec<u8>, CabRefusal>)>;

    fn collect(bytes: &[u8], cap: u64) -> (Seen, CabReadStats) {
        let archive: CabArchive = parse_cab(bytes).expect("parse cab");
        let mut seen: Seen = Vec::new();
        let stats: CabReadStats = read_cab_members(
            bytes,
            &archive,
            cap,
            |member: &CabMember, outcome: std::result::Result<&[u8], CabRefusal>| {
                seen.push((member.name.clone(), outcome.map(<[u8]>::to_vec)));
                Ok(())
            },
        )
        .expect("read cab members");
        (seen, stats)
    }

    fn crate_built_cab(codec: cab::CompressionType, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder: cab::CabinetBuilder = cab::CabinetBuilder::new();
        let folder: &mut cab::FolderBuilder = builder.add_folder(codec);
        for (name, _) in files {
            folder.add_file(*name);
        }
        let mut writer: cab::CabinetWriter<Cursor<Vec<u8>>> =
            builder.build(Cursor::new(Vec::new())).expect("cab build");
        let mut index: usize = 0;
        while let Some(mut file) = writer.next_file().expect("next file") {
            file.write_all(files[index].1).expect("cab write");
            index += 1;
        }
        writer.finish().expect("cab finish").into_inner()
    }

    fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
        let mut state: u32 = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect()
    }

    #[test]
    fn mszip_folder_is_decoded_once_for_all_members() {
        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        for index in 0..12u32 {
            let mut body: Vec<u8> = pseudo_random(9_000, index + 1);
            body.extend_from_slice(format!("member {index} text tail ").repeat(200).as_bytes());
            members.push((format!("m{index:02}.bin"), body));
        }
        let files: Vec<(&str, &[u8])> = members
            .iter()
            .map(|(name, body): &(String, Vec<u8>)| (name.as_str(), body.as_slice()))
            .collect();
        let bytes: Vec<u8> = crate_built_cab(cab::CompressionType::MsZip, &files);
        let archive: CabArchive = parse_cab(&bytes).expect("parse");
        assert_eq!(archive.folders.len(), 1);
        let blocks: u64 = u64::from(archive.folders[0].num_blocks);
        assert!(
            blocks > 4,
            "fixture must span several data blocks, got {blocks}"
        );
        let (seen, stats): (Seen, CabReadStats) = collect(&bytes, 1 << 24);
        assert_eq!(stats.folder_passes, 1);
        assert_eq!(
            stats.blocks_decoded, blocks,
            "each data block decodes exactly once"
        );
        assert_eq!(seen.len(), members.len());
        for ((name, body), (got_name, got)) in members.iter().zip(seen.iter()) {
            assert_eq!(name, got_name);
            assert_eq!(
                got.as_ref().expect("member bytes"),
                body,
                "{name} differs from its input"
            );
        }
    }

    #[test]
    fn duplicate_names_are_refused_not_aliased() {
        let files: [(&str, &[u8]); 3] = [
            ("dup.txt", b"first body"),
            ("solo.txt", b"unique body"),
            ("dup.txt", b"second, different body"),
        ];
        let bytes: Vec<u8> = crate_built_cab(cab::CompressionType::MsZip, &files);
        let (seen, _): (Seen, CabReadStats) = collect(&bytes, 1 << 20);
        let dups: Vec<&std::result::Result<Vec<u8>, CabRefusal>> = seen
            .iter()
            .filter(|(name, _)| name == "dup.txt")
            .map(|(_, outcome)| outcome)
            .collect();
        assert_eq!(dups, vec![&Err(CabRefusal::DuplicateName); 2]);
        let solo: &(String, std::result::Result<Vec<u8>, CabRefusal>) = seen
            .iter()
            .find(|(name, _)| name == "solo.txt")
            .expect("solo");
        assert_eq!(solo.1.as_deref(), Ok(&b"unique body"[..]));
    }

    #[test]
    fn stored_folder_members_equal_their_inputs() {
        let a: Vec<u8> = pseudo_random(70_000, 7);
        let b: &[u8] = b"short stored member";
        let bytes: Vec<u8> =
            crate_built_cab(cab::CompressionType::None, &[("a.bin", &a), ("b.txt", b)]);
        let (seen, stats): (Seen, CabReadStats) = collect(&bytes, 1 << 24);
        assert_eq!(stats.folder_passes, 1);
        assert_eq!(seen[0].1.as_deref(), Ok(a.as_slice()));
        assert_eq!(seen[1].1.as_deref(), Ok(b));
    }

    #[test]
    fn corrupted_block_checksum_refuses_the_folder_members() {
        let body: Vec<u8> = pseudo_random(3_000, 3);
        let mut bytes: Vec<u8> = crate_built_cab(cab::CompressionType::None, &[("x.bin", &body)]);
        let archive: CabArchive = parse_cab(&bytes).expect("parse");
        let data_at: usize = archive.folders[0].data_offset as usize + CFDATA_FIXED_LEN + 10;
        bytes[data_at] ^= 0x55;
        let (seen, _): (Seen, CabReadStats) = collect(&bytes, 1 << 20);
        assert!(
            matches!(&seen[0].1, Err(CabRefusal::Decode { reason, .. }) if reason.contains("checksum")),
            "{seen:?}"
        );
    }

    #[test]
    fn over_cap_member_is_refused_and_later_members_still_decode() {
        let big: Vec<u8> = pseudo_random(5_000, 9);
        let small: &[u8] = b"after the refused member";
        let bytes: Vec<u8> = crate_built_cab(
            cab::CompressionType::MsZip,
            &[("big.bin", &big), ("small.txt", small)],
        );
        let (seen, _): (Seen, CabReadStats) = collect(&bytes, 1_000);
        assert_eq!(
            seen[0].1,
            Err(CabRefusal::OverCap {
                size: 5_000,
                cap: 1_000
            })
        );
        assert_eq!(seen[1].1.as_deref(), Ok(small));
    }

    #[test]
    fn lzms_folder_members_round_trip() {
        let big: Vec<u8> = pseudo_random(80_000, 0x0bad_f00d);
        let small: &[u8] = b"second member, short and sweet";
        let texty: Vec<u8> = b"AAAABBBBCCCCDDDD".repeat(400);
        let files: [(&str, &[u8]); 3] =
            [("rand.bin", &big), ("note.txt", small), ("rle.dat", &texty)];
        let bytes: Vec<u8> = build_lzms_cab(&files);
        let archive: CabArchive = parse_cab(&bytes).expect("parse");
        assert!(archive.uses_codec(CabCodec::Lzms));
        let (seen, stats): (Seen, CabReadStats) = collect(&bytes, 1 << 24);
        assert_eq!(stats.folder_passes, 1);
        for ((name, original), (got_name, got)) in files.iter().zip(seen.iter()) {
            assert_eq!(name, got_name);
            assert_eq!(
                got.as_deref(),
                Ok(*original),
                "lzms member `{name}` differs"
            );
        }
    }

    fn raw_lzms_block_cab(file_name: &str, block_payload: &[u8], cb_uncomp: u16) -> Vec<u8> {
        let coff_files: u32 = (CFHEADER_FIXED_LEN + CFFOLDER_FIXED_LEN) as u32;
        let data_start: u32 = coff_files + (CFFILE_FIXED_LEN + file_name.len() + 1) as u32;
        let member_size: u32 = if cb_uncomp == 0 {
            block_payload.len() as u32
        } else {
            u32::from(cb_uncomp)
        };
        let mut cab: Vec<u8> = Vec::new();
        cab.extend_from_slice(&CAB_MAGIC);
        cab.extend_from_slice(&0u32.to_le_bytes());
        let total: u32 = data_start + CFDATA_FIXED_LEN as u32 + block_payload.len() as u32;
        cab.extend_from_slice(&total.to_le_bytes());
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&coff_files.to_le_bytes());
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&[3, 1]);
        for field in [1u16, 1, 0, 0, 0] {
            cab.extend_from_slice(&field.to_le_bytes());
        }
        cab.extend_from_slice(&data_start.to_le_bytes());
        cab.extend_from_slice(&1u16.to_le_bytes());
        cab.extend_from_slice(&COMPTYPE_LZMS.to_le_bytes());
        cab.extend_from_slice(&member_size.to_le_bytes());
        cab.extend_from_slice(&[0u8; 12]);
        cab.extend_from_slice(file_name.as_bytes());
        cab.push(0);
        cab.extend_from_slice(&0u32.to_le_bytes());
        cab.extend_from_slice(&(block_payload.len() as u16).to_le_bytes());
        cab.extend_from_slice(&cb_uncomp.to_le_bytes());
        cab.extend_from_slice(block_payload);
        cab
    }

    #[test]
    fn stored_block_in_an_lzms_folder_passes_through() {
        let payload: &[u8] = b"uncompressed stored bytes in an lzms folder block";
        let bytes: Vec<u8> = raw_lzms_block_cab("stored.bin", payload, 0);
        let (seen, _): (Seen, CabReadStats) = collect(&bytes, 1 << 20);
        assert_eq!(seen[0].1.as_deref(), Ok(payload));
    }

    #[test]
    fn odd_length_lzms_block_is_refused() {
        let bytes: Vec<u8> = raw_lzms_block_cab("x.bin", &[0u8; 13], 64);
        let (seen, _): (Seen, CabReadStats) = collect(&bytes, 1 << 20);
        assert!(
            matches!(&seen[0].1, Err(CabRefusal::Decode { reason, .. }) if reason.starts_with("lzms")),
            "{seen:?}"
        );
    }

    #[test]
    fn non_cab_is_rejected() {
        assert!(parse_cab(b"not a cab at all").is_err());
    }

    #[test]
    fn checksum_matches_the_published_example() {
        assert_eq!(cab_checksum(b"\x0e\0\x0e\0Hello, world!\n"), 0x7f2e_1a4c);
    }
}
