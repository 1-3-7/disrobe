use serde::{Deserialize, Serialize};

use crate::containers::oodle::{OodleCensus, OodleError};
use crate::error::{Error, Result};
use crate::quota::{BoundedVecWriter, bounded_prealloc};
use disrobe_bytes::ByteReader;

pub const BLOCK_MAGIC_ANVIL_33: u64 = 0x1004_FA99_57FB_AA33;
pub const BLOCK_MAGIC_V34: u64 = 0x1014_FA99_57FB_AA34;
pub const BLOCK_MAGIC_V37: u64 = 0x1015_FA99_57FB_AA37;
pub const BLOCK_MAGIC_ANVIL_33_BYTES: [u8; 8] = BLOCK_MAGIC_ANVIL_33.to_le_bytes();
pub const BLOCK_MAGIC_V34_BYTES: [u8; 8] = BLOCK_MAGIC_V34.to_le_bytes();
pub const BLOCK_MAGIC_V37_BYTES: [u8; 8] = BLOCK_MAGIC_V37.to_le_bytes();
const BLOCK_MAGIC_CORE: [u8; 5] = [0xAA, 0xFB, 0x57, 0x99, 0xFA];
const BLOCK_MAGIC_TAIL: u8 = 0x10;

pub const BLOCK_HEADER_LEN: usize = 0x13;
pub const MAX_CHUNKS_PER_BLOCK: usize = 4096;
pub const MAX_CHUNK_UNPACKED: u32 = 1 << 20;
pub const MAX_BLOCK_UNPACKED: u64 = 1 << 30;

pub const PACK_METHOD_ZSTD: u16 = 3;
pub const PACK_METHOD_STREAMING: u16 = 7;
pub const PACK_METHOD_OODLE_KRAKEN: u16 = 13;
pub const PACK_METHOD_OODLE_LEVIATHAN: u16 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockMagic {
    Anvil33,
    V34,
    V35,
    V36,
    V37,
}

impl BlockMagic {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let head: &[u8; 8] = bytes.get(..8)?.try_into().ok()?;
        if head[1..6] != BLOCK_MAGIC_CORE || head[7] != BLOCK_MAGIC_TAIL {
            return None;
        }
        match (head[0], head[6]) {
            (0x33, 0x04) => Some(Self::Anvil33),
            (0x34, 0x14) => Some(Self::V34),
            (0x35, 0x14 | 0x15) => Some(Self::V35),
            (0x36, 0x14 | 0x15) => Some(Self::V36),
            (0x37, 0x15) => Some(Self::V37),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Anvil33 => "anvil-aa33",
            Self::V34 => "scimitar-aa34",
            Self::V35 => "scimitar-aa35",
            Self::V36 => "scimitar-aa36",
            Self::V37 => "scimitar-aa37",
        }
    }

    #[must_use]
    pub const fn modern_layout(self) -> bool {
        !matches!(self, Self::Anvil33)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackMethod {
    Zstd,
    Streaming,
    OodleKraken,
    OodleLeviathan,
    Unknown(u16),
}

impl PackMethod {
    #[must_use]
    pub const fn from_code(code: u16) -> Self {
        match code {
            PACK_METHOD_ZSTD => Self::Zstd,
            PACK_METHOD_STREAMING => Self::Streaming,
            PACK_METHOD_OODLE_KRAKEN => Self::OodleKraken,
            PACK_METHOD_OODLE_LEVIATHAN => Self::OodleLeviathan,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Zstd => PACK_METHOD_ZSTD,
            Self::Streaming => PACK_METHOD_STREAMING,
            Self::OodleKraken => PACK_METHOD_OODLE_KRAKEN,
            Self::OodleLeviathan => PACK_METHOD_OODLE_LEVIATHAN,
            Self::Unknown(code) => code,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Streaming => "streaming",
            Self::OodleKraken => "oodle-kraken",
            Self::OodleLeviathan => "oodle-leviathan",
            Self::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeChunk {
    pub unpacked: u32,
    pub packed: u32,
    pub checksum: u32,
    pub data_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeBlock {
    pub magic: BlockMagic,
    pub raw_magic: u64,
    pub version: u16,
    pub pack_method: PackMethod,
    pub flags: u16,
    pub chunks: Vec<ForgeChunk>,
    pub total_len: usize,
    pub unpacked_total: u64,
    pub packed_total: u64,
}

impl ForgeBlock {
    #[must_use]
    pub fn compressed_chunks(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk: &&ForgeChunk| chunk.unpacked != chunk.packed)
            .count()
    }
}

#[must_use]
pub fn detect_block(bytes: &[u8]) -> Option<BlockMagic> {
    BlockMagic::from_bytes(bytes)
}

const fn malformed(detail: String) -> Error {
    Error::ForgeMalformed(detail)
}

fn truncated(what: &str, at: usize) -> Error {
    malformed(format!("block {what} truncated at offset {at}"))
}

pub fn parse_block(bytes: &[u8]) -> Result<ForgeBlock> {
    let Some(magic): Option<BlockMagic> = BlockMagic::from_bytes(bytes) else {
        let raw: u64 = bytes
            .get(..8)
            .and_then(|head: &[u8]| head.try_into().ok())
            .map_or(0, u64::from_le_bytes);
        return Err(Error::ForgeBlockUnsupported {
            magic: raw,
            reason: "the first eight bytes are not a known CompressedFileData magic",
        });
    };
    if !magic.modern_layout() {
        return Err(Error::ForgeBlockUnsupported {
            magic: BLOCK_MAGIC_ANVIL_33,
            reason: "the AC1/ACU/GRB block header layout has no verified reference",
        });
    }
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let raw_magic: u64 = reader.read_u64_le().map_err(|_| truncated("magic", 0))?;
    let version: u16 = reader.read_u16_le().map_err(|_| truncated("version", 8))?;
    let method_code: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("pack method", 10))?;
    let zero: u8 = reader
        .read_u8()
        .map_err(|_| truncated("reserved byte", 12))?;
    let flags: u16 = reader.read_u16_le().map_err(|_| truncated("flags", 13))?;
    let chunk_count: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("chunk count", 15))?;
    let count_high: u16 = reader
        .read_u16_le()
        .map_err(|_| truncated("chunk count high word", 17))?;
    if zero != 0 || count_high != 0 {
        return Err(malformed(format!(
            "block header reserved fields are {zero:#x} and {count_high:#x}, expected zero"
        )));
    }
    let count: usize = usize::from(chunk_count);
    if count > MAX_CHUNKS_PER_BLOCK {
        return Err(malformed(format!(
            "block declares {count} chunks, above the {MAX_CHUNKS_PER_BLOCK}-chunk cap"
        )));
    }
    let pack_method: PackMethod = PackMethod::from_code(method_code);
    let mut chunks: Vec<ForgeChunk> = Vec::with_capacity(count);
    let mut unpacked_total: u64 = 0;
    let mut packed_total: u64 = 0;
    for index in 0..count {
        let unpacked: u32 = reader
            .read_u32_le()
            .map_err(|_| truncated("size table", reader.position()))?;
        let packed: u32 = reader
            .read_u32_le()
            .map_err(|_| truncated("size table", reader.position()))?;
        if unpacked > MAX_CHUNK_UNPACKED {
            return Err(malformed(format!(
                "chunk {index} declares {unpacked} unpacked bytes, above the {MAX_CHUNK_UNPACKED}-byte cap"
            )));
        }
        if unpacked < packed {
            return Err(Error::ForgeChunkSize {
                entry: "block".to_owned(),
                chunk: index,
                declared: u64::from(unpacked),
                decoded: u64::from(packed),
            });
        }
        unpacked_total += u64::from(unpacked);
        packed_total += u64::from(packed);
        if unpacked_total > MAX_BLOCK_UNPACKED {
            return Err(malformed(format!(
                "block unpacked total passes the {MAX_BLOCK_UNPACKED}-byte cap at chunk {index}"
            )));
        }
        chunks.push(ForgeChunk {
            unpacked,
            packed,
            checksum: 0,
            data_offset: 0,
        });
    }
    if pack_method == PackMethod::Streaming {
        for chunk in &mut chunks {
            chunk.checksum = reader
                .read_u32_le()
                .map_err(|_| truncated("checksum table", reader.position()))?;
        }
        for chunk in &mut chunks {
            chunk.data_offset = reader.position();
            reader
                .skip(chunk.packed as usize)
                .map_err(|_| truncated("chunk data", chunk.data_offset))?;
        }
    } else {
        for chunk in &mut chunks {
            chunk.checksum = reader
                .read_u32_le()
                .map_err(|_| truncated("chunk checksum", reader.position()))?;
            chunk.data_offset = reader.position();
            reader
                .skip(chunk.packed as usize)
                .map_err(|_| truncated("chunk data", chunk.data_offset))?;
        }
    }
    Ok(ForgeBlock {
        magic,
        raw_magic,
        version,
        pack_method,
        flags,
        chunks,
        total_len: reader.position(),
        unpacked_total,
        packed_total,
    })
}

#[must_use]
pub fn chunk_data<'a>(bytes: &'a [u8], chunk: &ForgeChunk) -> Option<&'a [u8]> {
    bytes.get(chunk.data_offset..chunk.data_offset.checked_add(chunk.packed as usize)?)
}

#[must_use]
pub fn adler32_seed0(bytes: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    const BATCH: usize = 5_552;
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    for batch in bytes.chunks(BATCH) {
        for &byte in batch {
            a += u32::from(byte);
            b += a;
        }
        a %= MODULUS;
        b %= MODULUS;
    }
    (b << 16) | a
}

pub fn verify_checksums(bytes: &[u8], block: &ForgeBlock, entry: &str) -> Result<()> {
    for (index, chunk) in block.chunks.iter().enumerate() {
        let data: &[u8] =
            chunk_data(bytes, chunk).ok_or_else(|| truncated("chunk data", chunk.data_offset))?;
        let actual: u32 = adler32_seed0(data);
        if actual != chunk.checksum {
            return Err(Error::ForgeChunkChecksum {
                entry: entry.to_owned(),
                chunk: index,
                expected: chunk.checksum,
                actual,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct BlockDecoder {
    pub census: OodleCensus,
}

impl BlockDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decode(
        &mut self,
        bytes: &[u8],
        block: &ForgeBlock,
        entry: &str,
        max_unpacked: u64,
    ) -> Result<Vec<u8>> {
        if block.unpacked_total > max_unpacked {
            return Err(Error::QuotaExceeded {
                entry: entry.to_owned(),
                reason: format!(
                    "block declares {} unpacked bytes, above the {max_unpacked}-byte cap",
                    block.unpacked_total
                ),
            });
        }
        verify_checksums(bytes, block, entry)?;
        let mut out: Vec<u8> = Vec::with_capacity(bounded_prealloc(block.unpacked_total));
        for (index, chunk) in block.chunks.iter().enumerate() {
            let data: &[u8] = chunk_data(bytes, chunk)
                .ok_or_else(|| truncated("chunk data", chunk.data_offset))?;
            if chunk.unpacked == chunk.packed {
                out.extend_from_slice(data);
                continue;
            }
            let decoded: Vec<u8> =
                self.decode_chunk(block, data, chunk.unpacked as usize, entry, index)?;
            out.extend_from_slice(&decoded);
        }
        Ok(out)
    }

    fn decode_chunk(
        &mut self,
        block: &ForgeBlock,
        data: &[u8],
        declared: usize,
        entry: &str,
        index: usize,
    ) -> Result<Vec<u8>> {
        match block.pack_method {
            PackMethod::Zstd => decode_zstd_chunk(data, declared, entry, index),
            PackMethod::OodleKraken | PackMethod::OodleLeviathan => {
                crate::containers::oodle::decode(data, declared, &mut self.census).map_err(
                    |detail: OodleError| Error::ForgeOodle {
                        entry: entry.to_owned(),
                        chunk: index,
                        detail,
                    },
                )
            }
            PackMethod::Streaming => Err(Error::ForgePackMethodUnsupported {
                magic: block.raw_magic,
                method: PACK_METHOD_STREAMING,
                codec: "streaming blocks carry no compression, yet this chunk is smaller than its unpacked size",
            }),
            PackMethod::Unknown(code) => Err(Error::ForgePackMethodUnsupported {
                magic: block.raw_magic,
                method: code,
                codec: "no public source maps this pack method to a codec",
            }),
        }
    }
}

fn decode_zstd_chunk(data: &[u8], declared: usize, entry: &str, index: usize) -> Result<Vec<u8>> {
    let mut writer: BoundedVecWriter = BoundedVecWriter::new(declared);
    zstd::stream::copy_decode(data, &mut writer).map_err(|error: std::io::Error| {
        malformed(format!(
            "entry `{entry}` chunk {index}: zstd decode failed: {error}"
        ))
    })?;
    writer
        .finish_exact()
        .map_err(
            |mismatch: disrobe_bytes::quota::DecodedSizeMismatch| Error::ForgeChunkSize {
                entry: entry.to_owned(),
                chunk: index,
                declared: mismatch.expected as u64,
                decoded: mismatch.decoded as u64,
            },
        )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn adler32_seed0_matches_hand_values() {
        assert_eq!(adler32_seed0(&[]), 0);
        assert_eq!(adler32_seed0(&[1]), 0x0001_0001);
        assert_eq!(adler32_seed0(b"abc"), 0x024A_0126);
        let long: Vec<u8> = (0..20_000u32).map(|i: u32| (i % 251) as u8).collect();
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        for &byte in &long {
            a = (a + u32::from(byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        assert_eq!(adler32_seed0(&long), (b << 16) | a);
    }

    #[test]
    fn block_magic_patterns_are_recognised_and_rejected() {
        assert_eq!(
            BlockMagic::from_bytes(&BLOCK_MAGIC_V37_BYTES),
            Some(BlockMagic::V37)
        );
        assert_eq!(
            BlockMagic::from_bytes(&BLOCK_MAGIC_V34_BYTES),
            Some(BlockMagic::V34)
        );
        assert_eq!(
            BlockMagic::from_bytes(&BLOCK_MAGIC_ANVIL_33_BYTES),
            Some(BlockMagic::Anvil33)
        );
        assert_eq!(BlockMagic::from_bytes(&[0x37, 0xAA]), None);
        assert_eq!(BlockMagic::from_bytes(b"scimitar"), None);
        let mut wrong_tail: [u8; 8] = BLOCK_MAGIC_V37_BYTES;
        wrong_tail[7] = 0x11;
        assert_eq!(BlockMagic::from_bytes(&wrong_tail), None);
    }

    #[test]
    fn pack_methods_round_trip_their_codes() {
        for code in [3u16, 7, 13, 15, 0, 1, 99] {
            assert_eq!(PackMethod::from_code(code).code(), code);
        }
        assert_eq!(PackMethod::from_code(15), PackMethod::OodleLeviathan);
        assert_eq!(PackMethod::from_code(2), PackMethod::Unknown(2));
    }
}
