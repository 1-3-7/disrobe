use disrobe_bytes::align_up_usize;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::quota::{ExtractionQuota, QuotaGuard};

const FV_SIGNATURE: u32 = 0x4856_465F;
const FV_ZERO_VECTOR_LEN: usize = 16;
const FV_HEADER_FIXED_LEN: usize = 56;
const FFS_HEADER_LEN: usize = 24;
const FFS_HEADER2_LEN: usize = 32;
const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
const FFS_FILE_ALIGN: usize = 8;
const SECTION_HEADER_LEN: usize = 4;
const SECTION_HEADER2_LEN: usize = 8;
const SECTION_ALIGN: usize = 4;
const GUID_DEFINED_FIXED_LEN: usize = 20;
const COMPRESSION_HEADER_LEN: usize = 5;
const PI_COMPRESSION_HEADER_LEN: usize = 8;
const CRC32_VENDOR_HEADER_LEN: usize = 4;
const EDK2_BROTLI_HEADER_LEN: usize = 16;

const FFS_FILETYPE_RAW: u8 = 0x01;
const FFS_FILETYPE_FFS_PAD: u8 = 0xF0;

const SECTION_COMPRESSION: u8 = 0x01;
const SECTION_GUID_DEFINED: u8 = 0x02;
const SECTION_DISPOSABLE: u8 = 0x03;
const SECTION_PE32: u8 = 0x10;
const SECTION_PIC: u8 = 0x11;
const SECTION_TE: u8 = 0x12;
const SECTION_DXE_DEPEX: u8 = 0x13;
const SECTION_VERSION: u8 = 0x14;
const SECTION_USER_INTERFACE: u8 = 0x15;
const SECTION_COMPATIBILITY16: u8 = 0x16;
const SECTION_FIRMWARE_VOLUME_IMAGE: u8 = 0x17;
const SECTION_FREEFORM_SUBTYPE_GUID: u8 = 0x18;
const SECTION_RAW: u8 = 0x19;
const SECTION_PEI_DEPEX: u8 = 0x1B;
const SECTION_SMM_DEPEX: u8 = 0x1C;

const COMPRESSION_TYPE_NONE: u8 = 0x00;
const COMPRESSION_TYPE_STANDARD: u8 = 0x01;

const MAX_FV_DEPTH: usize = 16;
const MAX_FFS_FILES: usize = 500_000;
const MAX_SECTIONS_PER_FILE: usize = 100_000;
const DECOMPRESSED_CEILING_MULTIPLIER: u64 = 16;

const fn guid_from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let d1b: [u8; 4] = d1.to_le_bytes();
    let d2b: [u8; 2] = d2.to_le_bytes();
    let d3b: [u8; 2] = d3.to_le_bytes();
    [
        d1b[0], d1b[1], d1b[2], d1b[3], d2b[0], d2b[1], d3b[0], d3b[1], d4[0], d4[1], d4[2], d4[3],
        d4[4], d4[5], d4[6], d4[7],
    ]
}

const GUID_FFS2: [u8; 16] = guid_from_fields(
    0x8C8C_E578,
    0x8A3D,
    0x4F1C,
    [0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3],
);
const GUID_FFS3: [u8; 16] = guid_from_fields(
    0x5473_C07A,
    0x3DCB,
    0x4DCA,
    [0xBD, 0x6F, 0x1E, 0x96, 0x89, 0xE7, 0x34, 0x9A],
);
const GUID_LZMA_CUSTOM_COMPRESS: [u8; 16] = guid_from_fields(
    0xEE4E_5898,
    0x3914,
    0x4259,
    [0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF],
);
const GUID_BROTLI_CUSTOM_COMPRESS: [u8; 16] = guid_from_fields(
    0x3D53_2050,
    0x5CDA,
    0x4FD0,
    [0x87, 0x9E, 0x0F, 0x7F, 0x63, 0x0D, 0x5A, 0xFB],
);
const GUID_TIANO_CUSTOM_COMPRESS: [u8; 16] = guid_from_fields(
    0xA312_80AD,
    0x481E,
    0x41B6,
    [0x95, 0xE8, 0x12, 0x7F, 0x4C, 0x98, 0x47, 0x79],
);
const GUID_CRC32_SECTION: [u8; 16] = guid_from_fields(
    0xFC1B_CDB0,
    0x7D31,
    0x49AA,
    [0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83],
);

#[must_use]
pub fn guid_to_string(guid: &[u8; 16]) -> String {
    let d1: u32 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2: u16 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3: u16 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

fn guid_is_placeholder(guid: &[u8; 16]) -> bool {
    guid.iter().all(|b: &u8| *b == 0x00) || guid.iter().all(|b: &u8| *b == 0xFF)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FvFileSystemKind {
    Ffs2,
    Ffs3,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FvHeader {
    pub file_system: FvFileSystemKind,
    pub file_system_guid: [u8; 16],
    pub fv_length: u64,
    pub header_length: u16,
    pub revision: u8,
    pub ext_header_offset: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FvFileType {
    Raw,
    Freeform,
    SecurityCore,
    PeiCore,
    DxeCore,
    Peim,
    CombinedPeimDriver,
    Driver,
    CombinedSmmDxe,
    Application,
    Smm,
    FirmwareVolumeImage,
    SmmCore,
    MmStandalone,
    MmCoreStandalone,
    FfsPad,
    OemOrUnknown(u8),
}

impl FvFileType {
    #[must_use]
    const fn from_byte(value: u8) -> Self {
        match value {
            0x01 => Self::Raw,
            0x02 => Self::Freeform,
            0x03 => Self::SecurityCore,
            0x04 => Self::PeiCore,
            0x05 => Self::DxeCore,
            0x06 => Self::Peim,
            0x07 => Self::Driver,
            0x08 => Self::CombinedPeimDriver,
            0x09 => Self::Application,
            0x0A => Self::Smm,
            0x0B => Self::FirmwareVolumeImage,
            0x0C => Self::CombinedSmmDxe,
            0x0D => Self::SmmCore,
            0x0E => Self::MmStandalone,
            0x0F => Self::MmCoreStandalone,
            0xF0 => Self::FfsPad,
            other => Self::OemOrUnknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FvCompressionCodec {
    Standard,
    Lzma,
    Brotli,
    TianoGuided,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiCompressionAlgorithm {
    Standard,
    Tiano,
}

impl PiCompressionAlgorithm {
    const fn params(self) -> crate::containers::lha_huff::LhaParams {
        match self {
            Self::Standard => crate::containers::lha_huff::LhaParams {
                history_bits: 14,
                offset_bits: 4,
            },
            Self::Tiano => crate::containers::lha_huff::LhaParams {
                history_bits: 20,
                offset_bits: 5,
            },
        }
    }

    const fn codec(self) -> FvCompressionCodec {
        match self {
            Self::Standard => FvCompressionCodec::Standard,
            Self::Tiano => FvCompressionCodec::TianoGuided,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Tiano => "tiano",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FvCodecOutcome {
    pub codec: FvCompressionCodec,
    pub verified: bool,
    pub recovered: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FvSectionRecord {
    pub kind: u8,
    pub kind_name: String,
    pub depth: usize,
    pub size: u64,
    pub codec: Option<FvCodecOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FvFileRecord {
    pub guid: [u8; 16],
    pub file_type: FvFileType,
    pub depth: usize,
    pub name: Option<String>,
    pub size: u64,
    pub sections: Vec<FvSectionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FvPeImage {
    pub file_guid: [u8; 16],
    pub name: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FvExtraction {
    pub volumes_walked: usize,
    pub files: Vec<FvFileRecord>,
    pub pe_images: Vec<FvPeImage>,
    pub notes: Vec<String>,
    pub truncated: bool,
}

fn u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at).ok()
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at).ok()
}

fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    disrobe_bytes::read_u64_le_at(bytes, at).ok()
}

fn u24_le(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 3)
        .map(|s: &[u8]| u32::from(s[0]) | (u32::from(s[1]) << 8) | (u32::from(s[2]) << 16))
}

fn guid16(bytes: &[u8], at: usize) -> Option<[u8; 16]> {
    let slice: &[u8] = bytes.get(at..at + 16)?;
    let mut out: [u8; 16] = [0u8; 16];
    out.copy_from_slice(slice);
    Some(out)
}

fn fv_err(message: impl Into<String>) -> Error {
    Error::UefiFirmwareVolume(message.into())
}

#[must_use]
pub fn detect_uefi_fv(bytes: &[u8]) -> bool {
    parse_fv_header(bytes).is_ok()
}

pub fn parse_fv_header(bytes: &[u8]) -> Result<FvHeader> {
    if bytes.len() < FV_HEADER_FIXED_LEN {
        return Err(fv_err(format!(
            "input {} bytes is shorter than the {FV_HEADER_FIXED_LEN}-byte fixed firmware volume header",
            bytes.len()
        )));
    }
    let signature: u32 = u32_le(bytes, FV_ZERO_VECTOR_LEN + 16 + 8)
        .ok_or_else(|| fv_err("truncated signature field"))?;
    if signature != FV_SIGNATURE {
        return Err(fv_err(format!(
            "signature 0x{signature:08x} does not match _FVH"
        )));
    }
    let file_system_guid: [u8; 16] =
        guid16(bytes, FV_ZERO_VECTOR_LEN).ok_or_else(|| fv_err("truncated file system guid"))?;
    let fv_length: u64 = u64_le(bytes, FV_ZERO_VECTOR_LEN + 16)
        .ok_or_else(|| fv_err("truncated fv length field"))?;
    let header_length: u16 = u16_le(bytes, FV_ZERO_VECTOR_LEN + 16 + 8 + 4 + 4)
        .ok_or_else(|| fv_err("truncated header length field"))?;
    let checksum_offset: usize = FV_ZERO_VECTOR_LEN + 16 + 8 + 4 + 4 + 2;
    let stored_checksum: u16 =
        u16_le(bytes, checksum_offset).ok_or_else(|| fv_err("truncated header checksum field"))?;
    let ext_header_offset: u16 = u16_le(bytes, checksum_offset + 2)
        .ok_or_else(|| fv_err("truncated extended header offset field"))?;
    let revision: u8 = *bytes
        .get(checksum_offset + 2 + 2 + 1)
        .ok_or_else(|| fv_err("truncated revision field"))?;
    if header_length as usize > bytes.len() || (header_length as usize) < FV_HEADER_FIXED_LEN {
        return Err(fv_err(format!(
            "declared header length {header_length} is out of range for the {}-byte input",
            bytes.len()
        )));
    }
    if fv_length < header_length as u64 {
        return Err(fv_err(format!(
            "declared fv length {fv_length} is smaller than the header length {header_length}"
        )));
    }
    let header_bytes: &[u8] = &bytes[..header_length as usize];
    let mut sum: u16 = 0;
    for chunk in header_bytes.chunks(2) {
        let word: u16 = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0])
        };
        sum = sum.wrapping_add(word);
    }
    if sum != 0 {
        return Err(fv_err(format!(
            "header checksum does not sum to zero (residual 0x{sum:04x}, stored field 0x{stored_checksum:04x})"
        )));
    }
    let file_system: FvFileSystemKind = if file_system_guid == GUID_FFS2 {
        FvFileSystemKind::Ffs2
    } else if file_system_guid == GUID_FFS3 {
        FvFileSystemKind::Ffs3
    } else {
        FvFileSystemKind::Other
    };
    Ok(FvHeader {
        file_system,
        file_system_guid,
        fv_length,
        header_length,
        revision,
        ext_header_offset,
    })
}

#[derive(Clone)]
struct FvBudget {
    quota: QuotaGuard,
    limits: ExtractionQuota,
    depth: usize,
    decompressed_total: u64,
    decompressed_ceiling: u64,
}

impl FvBudget {
    fn new(quota: ExtractionQuota, input_len: u64) -> Self {
        Self {
            quota: QuotaGuard::new(quota),
            limits: quota,
            depth: 0,
            decompressed_total: 0,
            decompressed_ceiling: input_len
                .saturating_mul(DECOMPRESSED_CEILING_MULTIPLIER)
                .max(4 * 1024 * 1024),
        }
    }

    fn remaining_pi_decompressed(&self, compressed: u64) -> u64 {
        let report: &crate::quota::QuotaReport = self.quota.report();
        let aggregate_compressed: u64 = report.total_compressed_bytes.saturating_add(compressed);
        let aggregate_limit: u64 = aggregate_compressed
            .saturating_mul(self.limits.max_aggregate_ratio)
            .saturating_sub(report.total_uncompressed_bytes);
        let ratio_limit: u64 = if compressed == 0 {
            u64::MAX
        } else {
            compressed.saturating_mul(self.limits.max_per_entry_ratio)
        };
        self.decompressed_ceiling
            .saturating_sub(self.decompressed_total)
            .min(self.limits.max_per_entry_uncompressed)
            .min(
                self.limits
                    .max_total_uncompressed
                    .saturating_sub(report.total_uncompressed_bytes),
            )
            .min(ratio_limit)
            .min(aggregate_limit)
    }

    fn admit_pi_decompressed(&mut self, entry: &str, amount: u64, compressed: u64) -> Result<()> {
        let new_total: u64 = self.decompressed_total.saturating_add(amount);
        let remaining: u64 = self.remaining_pi_decompressed(compressed);
        if amount > remaining {
            return Err(Error::QuotaExceeded {
                entry: entry.to_owned(),
                reason: format!(
                    "declared output {amount} exceeds remaining firmware extraction allowance {remaining}"
                ),
            });
        }
        self.quota.admit_entry(entry, amount, compressed)?;
        self.decompressed_total = new_total;
        Ok(())
    }

    fn admit_decompressed(&mut self, entry: &str, amount: u64) -> Result<()> {
        let new_total: u64 = self.decompressed_total.saturating_add(amount);
        if new_total > self.decompressed_ceiling {
            return Err(Error::QuotaExceeded {
                entry: entry.to_owned(),
                reason: format!(
                    "cumulative decompressed bytes {new_total} exceeds the {}-byte ceiling",
                    self.decompressed_ceiling
                ),
            });
        }
        self.decompressed_total = new_total;
        Ok(())
    }
}

fn decode_ui_name(payload: &[u8]) -> Option<String> {
    let mut units: Vec<u16> = Vec::with_capacity(payload.len() / 2);
    for chunk in payload.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        let unit: u16 = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

fn decompress_pi_compression(
    payload: &[u8],
    outer_uncompressed_len: Option<u32>,
    algorithm: PiCompressionAlgorithm,
    budget: &mut FvBudget,
    entry: &str,
) -> Result<Vec<u8>> {
    let compressed_len: u32 = u32_le(payload, 0).ok_or_else(|| {
        fv_err(format!(
            "truncated {} compressed-size header",
            algorithm.name()
        ))
    })?;
    let original_len: u32 = u32_le(payload, 4).ok_or_else(|| {
        fv_err(format!(
            "truncated {} original-size header",
            algorithm.name()
        ))
    })?;
    if original_len == 0 {
        return Err(fv_err(format!(
            "{} stream declares zero output bytes",
            algorithm.name()
        )));
    }
    if let Some(outer_len) = outer_uncompressed_len
        && outer_len != original_len
    {
        return Err(fv_err(format!(
            "{} stream declares {original_len} output bytes but its compression section declares {outer_len}",
            algorithm.name()
        )));
    }
    let compressed_len: usize = usize::try_from(compressed_len).map_err(|_| {
        fv_err(format!(
            "{} compressed size does not fit usize",
            algorithm.name()
        ))
    })?;
    let exact_len: usize = PI_COMPRESSION_HEADER_LEN
        .checked_add(compressed_len)
        .ok_or_else(|| fv_err(format!("{} compressed extent overflow", algorithm.name())))?;
    if payload.len() != exact_len {
        return Err(fv_err(format!(
            "{} stream declares {compressed_len} compressed bytes but its payload contains {}",
            algorithm.name(),
            payload.len().saturating_sub(PI_COMPRESSION_HEADER_LEN)
        )));
    }
    let compressed: &[u8] = payload
        .get(PI_COMPRESSION_HEADER_LEN..)
        .ok_or_else(|| fv_err(format!("truncated {} payload header", algorithm.name())))?;
    if compressed.last() != Some(&0) {
        return Err(fv_err(format!(
            "{} stream is missing its terminal zero byte",
            algorithm.name()
        )));
    }
    let compressed_size: u64 = u64::try_from(compressed.len()).unwrap_or(u64::MAX);
    let remaining: u64 = budget.remaining_pi_decompressed(compressed_size);
    if u64::from(original_len) > remaining {
        return Err(Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!(
                "declared {} output {} exceeds remaining firmware decompression ceiling {remaining}",
                algorithm.name(),
                original_len
            ),
        });
    }
    let expected_len: usize = usize::try_from(original_len).map_err(|_| {
        fv_err(format!(
            "{} output size does not fit usize",
            algorithm.name()
        ))
    })?;
    let checkpoint: FvBudget = budget.clone();
    budget.admit_pi_decompressed(entry, u64::from(original_len), compressed_size)?;
    match crate::containers::lha_huff::decode_exact(algorithm.params(), compressed, expected_len) {
        Ok(decoded) => Ok(decoded),
        Err(error) => {
            *budget = checkpoint;
            Err(error)
        }
    }
}

fn decompress_lzma_guided(payload: &[u8], budget: &mut FvBudget, entry: &str) -> Result<Vec<u8>> {
    let cap: u64 = budget
        .decompressed_ceiling
        .saturating_sub(budget.decompressed_total);
    let decoded: Vec<u8> = crate::containers::bare_stream::decompress_lzma_alone(payload, cap)?;
    budget.admit_decompressed(entry, decoded.len() as u64)?;
    Ok(decoded)
}

fn decompress_brotli_guided(payload: &[u8], budget: &mut FvBudget, entry: &str) -> Result<Vec<u8>> {
    let declared_size: u64 =
        u64_le(payload, 0).ok_or_else(|| fv_err("truncated EDK2 Brotli decoded-size header"))?;
    let _scratch_size: u64 =
        u64_le(payload, 8).ok_or_else(|| fv_err("truncated EDK2 Brotli scratch-size header"))?;
    let compressed: &[u8] = payload
        .get(EDK2_BROTLI_HEADER_LEN..)
        .ok_or_else(|| fv_err("truncated EDK2 Brotli payload header"))?;
    let cap: u64 = budget
        .decompressed_ceiling
        .saturating_sub(budget.decompressed_total);
    if declared_size > cap {
        return Err(Error::QuotaExceeded {
            entry: entry.to_owned(),
            reason: format!(
                "declared Brotli output {declared_size} exceeds remaining firmware decompression ceiling {cap}"
            ),
        });
    }
    let checkpoint: FvBudget = budget.clone();
    budget.admit_decompressed(entry, declared_size)?;
    let decoded: Vec<u8> =
        match crate::containers::bare_stream::decompress_brotli(compressed, declared_size) {
            Ok(decoded) => decoded,
            Err(error) => {
                *budget = checkpoint;
                return Err(error);
            }
        };
    if decoded.len() as u64 != declared_size {
        *budget = checkpoint;
        return Err(fv_err(format!(
            "Brotli decoded {} bytes but the EDK2 header declares {declared_size}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn process_section_stream(
    payload: &[u8],
    depth: usize,
    budget: &mut FvBudget,
    file: &mut FvFileRecord,
    out: &mut FvExtraction,
) -> Result<()> {
    if depth > MAX_FV_DEPTH {
        out.truncated = true;
        out.notes.push(format!(
            "section stream recursion exceeded max depth {MAX_FV_DEPTH}, stopped"
        ));
        return Ok(());
    }
    let mut offset: usize = 0;
    let mut count: usize = 0;
    while offset + SECTION_HEADER_LEN <= payload.len() {
        if payload[offset..]
            .iter()
            .take(SECTION_HEADER_LEN)
            .all(|b: &u8| *b == 0xFF)
        {
            break;
        }
        count += 1;
        if count > MAX_SECTIONS_PER_FILE {
            out.truncated = true;
            out.notes.push(format!(
                "{}: exceeded {MAX_SECTIONS_PER_FILE} sections in one stream, stopped",
                guid_to_string(&file.guid)
            ));
            break;
        }
        let raw_size: u32 =
            u24_le(payload, offset).ok_or_else(|| fv_err("truncated section size"))?;
        let kind: u8 = *payload
            .get(offset + 3)
            .ok_or_else(|| fv_err("truncated section type"))?;
        let (header_len, total_size): (usize, u64) = if raw_size == 0x00FF_FFFF {
            let extended: u32 = u32_le(payload, offset + SECTION_HEADER_LEN)
                .ok_or_else(|| fv_err("truncated extended section size"))?;
            (SECTION_HEADER2_LEN, u64::from(extended))
        } else {
            (SECTION_HEADER_LEN, u64::from(raw_size))
        };
        if total_size < header_len as u64 {
            out.truncated = true;
            out.notes.push(format!(
                "{}: section at stream offset {offset} declares size {total_size} smaller than its own header, stopped",
                guid_to_string(&file.guid)
            ));
            break;
        }
        let end: usize = offset
            .checked_add(usize::try_from(total_size).unwrap_or(usize::MAX))
            .filter(|e: &usize| *e <= payload.len())
            .ok_or_else(|| {
                out.truncated = true;
                fv_err(format!(
                    "section at stream offset {offset} declares size {total_size} exceeding the {}-byte containing stream",
                    payload.len()
                ))
            })?;
        let body: &[u8] = &payload[offset + header_len..end];
        record_section(kind, body, depth, total_size, header_len, budget, file, out)?;
        offset = align_up_usize(end, SECTION_ALIGN);
    }
    Ok(())
}

fn process_decoded_section_stream(
    decoded: &[u8],
    inner_depth: usize,
    budget: &mut FvBudget,
    file: &mut FvFileRecord,
    out: &mut FvExtraction,
    entry: &str,
    codec: &str,
) -> Result<()> {
    if inner_depth > MAX_FV_DEPTH {
        return Err(fv_err(format!(
            "{entry}: {codec}-decoded stream exceeds max recursion depth {MAX_FV_DEPTH}"
        )));
    }
    validate_exact_section_stream(decoded, entry, codec)?;
    let budget_before: FvBudget = budget.clone();
    let file_sections_before: usize = file.sections.len();
    let file_name_before: Option<String> = file.name.clone();
    let volumes_before: usize = out.volumes_walked;
    let files_before: usize = out.files.len();
    let images_before: usize = out.pe_images.len();
    let image_names_before: Vec<Option<String>> = out
        .pe_images
        .iter()
        .map(|image: &FvPeImage| image.name.clone())
        .collect();
    let notes_before: usize = out.notes.len();
    let truncated_before: bool = out.truncated;
    out.truncated = false;
    let parse_result: Result<()> = process_section_stream(decoded, inner_depth, budget, file, out);
    let parse_error: Option<Error> = match parse_result {
        Err(error) => Some(error),
        Ok(()) if out.truncated => Some(fv_err(format!(
            "{entry}: {codec}-decoded section stream is incomplete"
        ))),
        Ok(()) => None,
    };
    if let Some(error) = parse_error {
        *budget = budget_before;
        file.sections.truncate(file_sections_before);
        file.name = file_name_before;
        out.volumes_walked = volumes_before;
        out.files.truncate(files_before);
        out.pe_images.truncate(images_before);
        for (image, name) in out.pe_images.iter_mut().zip(image_names_before) {
            image.name = name;
        }
        out.notes.truncate(notes_before);
        out.truncated = truncated_before;
        return Err(error);
    }
    out.truncated = truncated_before;
    Ok(())
}

fn validate_exact_section_stream(payload: &[u8], entry: &str, codec: &str) -> Result<()> {
    if payload.is_empty() {
        return Err(fv_err(format!(
            "{entry}: {codec}-decoded section stream is empty"
        )));
    }
    let mut offset: usize = 0;
    let mut count: usize = 0;
    while offset < payload.len() {
        let remaining: usize = payload.len() - offset;
        if remaining < SECTION_HEADER_LEN {
            return Err(fv_err(format!(
                "{entry}: {codec}-decoded section stream has {remaining} trailing bytes"
            )));
        }
        if payload[offset..offset + SECTION_HEADER_LEN]
            .iter()
            .all(|byte: &u8| *byte == 0xFF)
        {
            if payload[offset..].iter().all(|byte: &u8| *byte == 0xFF) {
                return Ok(());
            }
            return Err(fv_err(format!(
                "{entry}: {codec}-decoded section stream has data after its terminator"
            )));
        }
        count = count.saturating_add(1);
        if count > MAX_SECTIONS_PER_FILE {
            return Err(fv_err(format!(
                "{entry}: {codec}-decoded section stream exceeds {MAX_SECTIONS_PER_FILE} sections"
            )));
        }
        let raw_size: u32 = u24_le(payload, offset)
            .ok_or_else(|| fv_err(format!("{entry}: truncated {codec} section size")))?;
        let (header_len, total_size): (usize, usize) = if raw_size == 0x00FF_FFFF {
            let extended: u32 = u32_le(payload, offset + SECTION_HEADER_LEN).ok_or_else(|| {
                fv_err(format!("{entry}: truncated {codec} extended section size"))
            })?;
            (
                SECTION_HEADER2_LEN,
                usize::try_from(extended).map_err(|_| {
                    fv_err(format!("{entry}: {codec} section size does not fit usize"))
                })?,
            )
        } else {
            (SECTION_HEADER_LEN, raw_size as usize)
        };
        if total_size < header_len {
            return Err(fv_err(format!(
                "{entry}: {codec} section at {offset} is smaller than its header"
            )));
        }
        let end: usize = offset
            .checked_add(total_size)
            .filter(|end: &usize| *end <= payload.len())
            .ok_or_else(|| {
                fv_err(format!(
                    "{entry}: {codec} section at {offset} exceeds its decoded stream"
                ))
            })?;
        if end == payload.len() {
            return Ok(());
        }
        offset = align_up_usize(end, SECTION_ALIGN);
        if offset > payload.len() {
            return Err(fv_err(format!(
                "{entry}: {codec}-decoded section padding is truncated"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_section(
    kind: u8,
    body: &[u8],
    depth: usize,
    total_size: u64,
    header_len: usize,
    budget: &mut FvBudget,
    file: &mut FvFileRecord,
    out: &mut FvExtraction,
) -> Result<()> {
    let kind_name: String = section_kind_name(kind).to_owned();
    let mut codec_outcome: Option<FvCodecOutcome> = None;
    match kind {
        SECTION_PE32 => {
            out.pe_images.push(FvPeImage {
                file_guid: file.guid,
                name: file.name.clone(),
                data: body.to_vec(),
            });
        }
        SECTION_USER_INTERFACE => {
            if file.name.is_none() {
                file.name = decode_ui_name(body);
            }
        }
        SECTION_COMPRESSION => {
            let uncompressed_len: u32 = u32_le(body, 0)
                .ok_or_else(|| fv_err("truncated compression section uncompressed length"))?;
            let compression_type: u8 = *body
                .get(4)
                .ok_or_else(|| fv_err("truncated compression section type byte"))?;
            let compressed: &[u8] = body
                .get(COMPRESSION_HEADER_LEN..)
                .ok_or_else(|| fv_err("truncated compression section payload"))?;
            match compression_type {
                COMPRESSION_TYPE_NONE => {
                    let inner_depth: usize = depth + 1;
                    process_section_stream(compressed, inner_depth, budget, file, out)?;
                }
                COMPRESSION_TYPE_STANDARD => {
                    let entry: String = guid_to_string(&file.guid);
                    let budget_before: FvBudget = budget.clone();
                    match decompress_pi_compression(
                        compressed,
                        Some(uncompressed_len),
                        PiCompressionAlgorithm::Standard,
                        budget,
                        &entry,
                    )
                    .and_then(|decoded: Vec<u8>| {
                        process_decoded_section_stream(
                            &decoded,
                            depth + 1,
                            budget,
                            file,
                            out,
                            &entry,
                            PiCompressionAlgorithm::Standard.name(),
                        )?;
                        Ok(decoded)
                    }) {
                        Ok(decoded) => {
                            let note: String =
                                format!("standard compression decoded to {} bytes", decoded.len());
                            out.notes.push(format!("{entry}: {note}"));
                            codec_outcome = Some(FvCodecOutcome {
                                codec: PiCompressionAlgorithm::Standard.codec(),
                                verified: true,
                                recovered: true,
                                note,
                            });
                        }
                        Err(error) => {
                            *budget = budget_before;
                            let note: String =
                                format!("standard compression decode failed: {error}");
                            out.notes.push(format!("{entry}: {note}"));
                            codec_outcome = Some(FvCodecOutcome {
                                codec: PiCompressionAlgorithm::Standard.codec(),
                                verified: false,
                                recovered: false,
                                note,
                            });
                        }
                    }
                }
                other => {
                    let outcome: FvCodecOutcome = FvCodecOutcome {
                        codec: FvCompressionCodec::Unknown,
                        verified: false,
                        recovered: false,
                        note: format!("unrecognized compression type byte 0x{other:02x}"),
                    };
                    out.notes
                        .push(format!("{}: {}", guid_to_string(&file.guid), outcome.note));
                    codec_outcome = Some(outcome);
                }
            }
        }
        SECTION_GUID_DEFINED => {
            record_guid_defined_section(
                body,
                header_len,
                depth,
                budget,
                file,
                out,
                &mut codec_outcome,
            )?;
        }
        SECTION_FIRMWARE_VOLUME_IMAGE => {
            walk_volume(body, depth + 1, budget, out)?;
        }
        _ => {}
    }
    file.sections.push(FvSectionRecord {
        kind,
        kind_name,
        depth,
        size: total_size.saturating_sub(header_len as u64),
        codec: codec_outcome,
    });
    Ok(())
}

fn record_guid_defined_section(
    body: &[u8],
    common_header_len: usize,
    depth: usize,
    budget: &mut FvBudget,
    file: &mut FvFileRecord,
    out: &mut FvExtraction,
    codec_outcome: &mut Option<FvCodecOutcome>,
) -> Result<()> {
    if body.len() < GUID_DEFINED_FIXED_LEN {
        return Err(fv_err("truncated guid-defined section fixed header"));
    }
    let section_guid: [u8; 16] =
        guid16(body, 0).ok_or_else(|| fv_err("truncated guid-defined section guid"))?;
    let data_offset: u16 =
        u16_le(body, 16).ok_or_else(|| fv_err("truncated guid-defined section data offset"))?;
    let minimum_data_offset: usize = common_header_len
        .checked_add(GUID_DEFINED_FIXED_LEN)
        .ok_or_else(|| fv_err("guid-defined section header length overflow"))?;
    let data_offset: usize = data_offset as usize;
    if data_offset < minimum_data_offset {
        return Err(fv_err(format!(
            "guid-defined section data offset {data_offset} precedes the {minimum_data_offset}-byte fixed header"
        )));
    }
    let relative_offset: usize = data_offset - common_header_len;
    let payload: &[u8] = body.get(relative_offset..).ok_or_else(|| {
        fv_err(format!(
            "guid-defined section data offset {data_offset} exceeds its {}-byte declared section",
            body.len().saturating_add(common_header_len)
        ))
    })?;
    let entry: String = guid_to_string(&file.guid);
    if section_guid == GUID_LZMA_CUSTOM_COMPRESS {
        let budget_before: FvBudget = budget.clone();
        match decompress_lzma_guided(payload, budget, &entry) {
            Ok(decoded) => {
                let inner_depth: usize = depth + 1;
                if let Err(error) = process_decoded_section_stream(
                    &decoded,
                    inner_depth,
                    budget,
                    file,
                    out,
                    &entry,
                    "LZMA",
                ) {
                    *budget = budget_before;
                    return Err(error);
                }
                *codec_outcome = Some(FvCodecOutcome {
                    codec: FvCompressionCodec::Lzma,
                    verified: true,
                    recovered: true,
                    note: format!("lzma guided section decoded to {} bytes", decoded.len()),
                });
            }
            Err(e) => {
                *budget = budget_before;
                out.notes
                    .push(format!("{entry}: lzma guided section decode failed: {e}"));
                *codec_outcome = Some(FvCodecOutcome {
                    codec: FvCompressionCodec::Lzma,
                    verified: true,
                    recovered: false,
                    note: format!("lzma guided section present but decode failed: {e}"),
                });
            }
        }
    } else if section_guid == GUID_CRC32_SECTION {
        if payload.len() < CRC32_VENDOR_HEADER_LEN {
            return Err(fv_err("truncated crc32 guided section payload"));
        }
        let stored_crc: u32 =
            u32_le(payload, 0).ok_or_else(|| fv_err("truncated crc32 guided section crc field"))?;
        let inner: &[u8] = &payload[CRC32_VENDOR_HEADER_LEN..];
        let actual_crc: u32 = crc32fast::hash(inner);
        let ok: bool = actual_crc == stored_crc;
        process_section_stream(inner, depth + 1, budget, file, out)?;
        *codec_outcome = Some(FvCodecOutcome {
            codec: FvCompressionCodec::Unknown,
            verified: true,
            recovered: true,
            note: format!(
                "crc32 integrity section, stored=0x{stored_crc:08x} actual=0x{actual_crc:08x} match={ok}"
            ),
        });
    } else if section_guid == GUID_BROTLI_CUSTOM_COMPRESS {
        let budget_before: FvBudget = budget.clone();
        let decoded: Vec<u8> = match decompress_brotli_guided(payload, budget, &entry) {
            Ok(decoded) => decoded,
            Err(error) => {
                *budget = budget_before;
                return Err(error);
            }
        };
        let inner_depth: usize = depth + 1;
        if let Err(error) = process_decoded_section_stream(
            &decoded,
            inner_depth,
            budget,
            file,
            out,
            &entry,
            "Brotli",
        ) {
            *budget = budget_before;
            return Err(error);
        }
        out.notes.push(format!(
            "{entry}: Brotli guided section decoded to {} bytes",
            decoded.len()
        ));
        *codec_outcome = Some(FvCodecOutcome {
            codec: FvCompressionCodec::Brotli,
            verified: true,
            recovered: true,
            note: format!("Brotli guided section decoded to {} bytes", decoded.len()),
        });
    } else if section_guid == GUID_TIANO_CUSTOM_COMPRESS {
        let budget_before: FvBudget = budget.clone();
        match decompress_pi_compression(
            payload,
            None,
            PiCompressionAlgorithm::Tiano,
            budget,
            &entry,
        )
        .and_then(|decoded: Vec<u8>| {
            process_decoded_section_stream(
                &decoded,
                depth + 1,
                budget,
                file,
                out,
                &entry,
                PiCompressionAlgorithm::Tiano.name(),
            )?;
            Ok(decoded)
        }) {
            Ok(decoded) => {
                let note: String =
                    format!("tiano guided section decoded to {} bytes", decoded.len());
                out.notes.push(format!("{entry}: {note}"));
                *codec_outcome = Some(FvCodecOutcome {
                    codec: PiCompressionAlgorithm::Tiano.codec(),
                    verified: true,
                    recovered: true,
                    note,
                });
            }
            Err(error) => {
                *budget = budget_before;
                let note: String = format!("tiano guided section decode failed: {error}");
                out.notes.push(format!("{entry}: {note}"));
                *codec_outcome = Some(FvCodecOutcome {
                    codec: PiCompressionAlgorithm::Tiano.codec(),
                    verified: false,
                    recovered: false,
                    note,
                });
            }
        }
    } else {
        out.notes.push(format!(
            "{entry}: guid-defined section with unrecognized guid {} detected; left opaque",
            guid_to_string(&section_guid)
        ));
        *codec_outcome = Some(FvCodecOutcome {
            codec: FvCompressionCodec::Unknown,
            verified: false,
            recovered: false,
            note: format!(
                "unrecognized guid-defined section {}",
                guid_to_string(&section_guid)
            ),
        });
    }
    Ok(())
}

const fn section_kind_name(kind: u8) -> &'static str {
    match kind {
        SECTION_COMPRESSION => "compression",
        SECTION_GUID_DEFINED => "guid-defined",
        SECTION_DISPOSABLE => "disposable",
        SECTION_PE32 => "pe32",
        SECTION_PIC => "pic",
        SECTION_TE => "te",
        SECTION_DXE_DEPEX => "dxe-depex",
        SECTION_VERSION => "version",
        SECTION_USER_INTERFACE => "user-interface",
        SECTION_COMPATIBILITY16 => "compatibility16",
        SECTION_FIRMWARE_VOLUME_IMAGE => "firmware-volume-image",
        SECTION_FREEFORM_SUBTYPE_GUID => "freeform-subtype-guid",
        SECTION_RAW => "raw",
        SECTION_PEI_DEPEX => "pei-depex",
        SECTION_SMM_DEPEX => "smm-depex",
        _ => "unknown",
    }
}

fn walk_volume(
    bytes: &[u8],
    depth: usize,
    budget: &mut FvBudget,
    out: &mut FvExtraction,
) -> Result<()> {
    if depth > MAX_FV_DEPTH {
        out.truncated = true;
        out.notes.push(format!(
            "volume recursion exceeded max depth {MAX_FV_DEPTH}, stopped"
        ));
        return Ok(());
    }
    budget.depth = budget.depth.max(depth);
    let header: FvHeader = parse_fv_header(bytes)?;
    out.volumes_walked += 1;
    let fv_end: usize = usize::try_from(header.fv_length)
        .unwrap_or(bytes.len())
        .min(bytes.len());
    let region: &[u8] = &bytes[..fv_end];
    let mut offset: usize = header.header_length as usize;
    let mut file_count: usize = 0;
    loop {
        offset = align_up_usize(offset, FFS_FILE_ALIGN);
        if offset + FFS_HEADER_LEN > region.len() {
            break;
        }
        if region[offset..offset + FFS_HEADER_LEN]
            .iter()
            .all(|b: &u8| *b == 0xFF)
        {
            break;
        }
        file_count += 1;
        if file_count > MAX_FFS_FILES {
            out.truncated = true;
            out.notes.push(format!(
                "volume exceeded {MAX_FFS_FILES} ffs files, stopped"
            ));
            break;
        }
        let file_guid: [u8; 16] =
            guid16(region, offset).ok_or_else(|| fv_err("truncated ffs file guid"))?;
        let file_type_byte: u8 = *region
            .get(offset + 16 + 2)
            .ok_or_else(|| fv_err("truncated ffs file type"))?;
        let attributes: u8 = *region
            .get(offset + 16 + 2 + 1)
            .ok_or_else(|| fv_err("truncated ffs file attributes"))?;
        let small_size: u32 = u24_le(region, offset + 16 + 2 + 1 + 1)
            .ok_or_else(|| fv_err("truncated ffs file size"))?;
        let large_file: bool = attributes & FFS_ATTRIB_LARGE_FILE != 0;
        let (header_len, file_size): (usize, u64) = if large_file {
            let extended: u64 = u64_le(region, offset + FFS_HEADER_LEN)
                .ok_or_else(|| fv_err("truncated ffs file extended size"))?;
            (FFS_HEADER2_LEN, extended)
        } else {
            (FFS_HEADER_LEN, u64::from(small_size))
        };
        if file_size < header_len as u64 {
            out.truncated = true;
            out.notes.push(format!(
                "ffs file at offset {offset} declares size {file_size} smaller than its own header, stopped"
            ));
            break;
        }
        let file_end: usize = match offset
            .checked_add(usize::try_from(file_size).unwrap_or(usize::MAX))
        {
            Some(e) if e <= region.len() => e,
            _ => {
                out.truncated = true;
                out.notes.push(format!(
                    "ffs file at offset {offset} declares size {file_size} exceeding the {}-byte containing volume, stopped",
                    region.len()
                ));
                break;
            }
        };
        let file_type: FvFileType = FvFileType::from_byte(file_type_byte);
        if file_type_byte != FFS_FILETYPE_FFS_PAD && !guid_is_placeholder(&file_guid) {
            budget
                .quota
                .admit_entry(&guid_to_string(&file_guid), file_size, file_size)?;
            let mut record: FvFileRecord = FvFileRecord {
                guid: file_guid,
                file_type,
                depth,
                name: None,
                size: file_size,
                sections: Vec::new(),
            };
            let content: &[u8] = &region[offset + header_len..file_end];
            if file_type_byte != FFS_FILETYPE_RAW {
                process_section_stream(content, depth, budget, &mut record, out)?;
            }
            if let Some(name) = record.name.clone() {
                for pe in out
                    .pe_images
                    .iter_mut()
                    .filter(|p: &&mut FvPeImage| p.file_guid == record.guid)
                {
                    pe.name = Some(name.clone());
                }
            }
            out.files.push(record);
        }
        offset = file_end;
    }
    Ok(())
}

pub fn extract_uefi_fv(bytes: &[u8], quota: ExtractionQuota) -> Result<FvExtraction> {
    let mut budget: FvBudget = FvBudget::new(quota, bytes.len() as u64);
    let mut out: FvExtraction = FvExtraction::default();
    walk_volume(bytes, 0, &mut budget, &mut out)?;
    Ok(out)
}

#[cfg(test)]
fn fv_section(kind: u8, body: &[u8]) -> Vec<u8> {
    let total: usize = SECTION_HEADER_LEN + body.len();
    let mut section: Vec<u8> = Vec::with_capacity(align_up_usize(total, SECTION_ALIGN));
    section.extend_from_slice(&(total as u32).to_le_bytes()[..3]);
    section.push(kind);
    section.extend_from_slice(body);
    let padded: usize = align_up_usize(section.len(), SECTION_ALIGN);
    section.resize(padded, 0u8);
    section
}

#[cfg(test)]
pub(crate) fn hostile_named_image(name: &str, body: &[u8]) -> Option<Vec<u8>> {
    let ui_section_decoding_breaks_at_the_first_embedded_nul: bool = name.contains('\u{0}');
    if ui_section_decoding_breaks_at_the_first_embedded_nul {
        return None;
    }

    let pe_section: Vec<u8> = fv_section(SECTION_PE32, body);
    let name_units: Vec<u8> = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0u8, 0u8])
        .collect();
    let ui_section: Vec<u8> = fv_section(SECTION_USER_INTERFACE, &name_units);

    let mut section_stream: Vec<u8> = Vec::new();
    section_stream.extend_from_slice(&ui_section);
    section_stream.extend_from_slice(&pe_section);

    let ffs_file_guid: [u8; 16] = guid_from_fields(
        0x1234_5678,
        0x9abc,
        0xdef0,
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );
    let file_size: usize = FFS_HEADER_LEN + section_stream.len();
    let mut ffs_file: Vec<u8> = vec![0u8; FFS_HEADER_LEN];
    ffs_file[0..16].copy_from_slice(&ffs_file_guid);
    ffs_file[18] = 0x07;
    ffs_file[19] = 0x00;
    ffs_file[20..23].copy_from_slice(&(file_size as u32).to_le_bytes()[..3]);
    ffs_file[23] = 0x00;
    ffs_file.extend_from_slice(&section_stream);

    let header_length: usize = FV_HEADER_FIXED_LEN;
    let fv_length: usize = header_length + ffs_file.len();
    let mut fv: Vec<u8> = vec![0u8; fv_length];
    fv[16..32].copy_from_slice(&GUID_FFS2);
    fv[32..40].copy_from_slice(&(fv_length as u64).to_le_bytes());
    fv[40..44].copy_from_slice(&FV_SIGNATURE.to_le_bytes());
    fv[48..50].copy_from_slice(&(header_length as u16).to_le_bytes());
    fv[55] = 2;
    fv[header_length..].copy_from_slice(&ffs_file);

    let mut checksum: u16 = 0;
    for chunk in fv[..header_length].chunks(2) {
        let word: u16 = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0])
        };
        checksum = checksum.wrapping_add(word);
    }
    let residual: u16 = 0u16.wrapping_sub(checksum);
    fv[50..52].copy_from_slice(&residual.to_le_bytes());

    Some(fv)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    const OUTER_FV: &[u8] = include_bytes!("../../tests/fixtures/uefi_fv/outer.fv");
    const INNER_FV: &[u8] = include_bytes!("../../tests/fixtures/uefi_fv/inner.fv");
    const HELLO_A_EFI: &[u8] = include_bytes!("../../tests/fixtures/uefi_fv/hello_a.efi");
    const HELLO_B_EFI: &[u8] = include_bytes!("../../tests/fixtures/uefi_fv/hello_b.efi");

    const HELLO_A_GUID: [u8; 16] = guid_from_fields(
        0xA157_0E16,
        0xF657,
        0x408F,
        [0x95, 0x64, 0x2F, 0xF7, 0x89, 0x8D, 0xAD, 0x4C],
    );
    const HELLO_B_GUID: [u8; 16] = guid_from_fields(
        0x9BA3_47BC,
        0x000E,
        0x4E86,
        [0xBD, 0x50, 0x0B, 0x06, 0x84, 0xF0, 0x41, 0xC3],
    );

    #[test]
    fn detects_real_edk2_built_outer_and_inner_volumes() {
        assert!(detect_uefi_fv(OUTER_FV));
        assert!(detect_uefi_fv(INNER_FV));
        assert!(!detect_uefi_fv(b"not a firmware volume at all, padded out"));
    }

    #[test]
    fn parses_real_header_fields() {
        let header: FvHeader = parse_fv_header(OUTER_FV).expect("outer header parses");
        assert_eq!(header.file_system, FvFileSystemKind::Ffs2);
        assert_eq!(header.fv_length, OUTER_FV.len() as u64);
        assert_eq!(header.revision, 2);
    }

    #[test]
    fn recovers_both_driver_files_with_real_guid_and_name() {
        let extraction: FvExtraction =
            extract_uefi_fv(OUTER_FV, ExtractionQuota::default_safe()).expect("extract");
        assert!(!extraction.truncated);
        assert_eq!(extraction.volumes_walked, 2);
        let hello_a: &FvFileRecord = extraction
            .files
            .iter()
            .find(|f: &&FvFileRecord| f.guid == HELLO_A_GUID)
            .expect("HelloA recovered");
        assert_eq!(hello_a.file_type, FvFileType::Driver);
        assert_eq!(hello_a.name.as_deref(), Some("HelloA"));
        let hello_b: &FvFileRecord = extraction
            .files
            .iter()
            .find(|f: &&FvFileRecord| f.guid == HELLO_B_GUID)
            .expect("HelloB recovered");
        assert_eq!(hello_b.file_type, FvFileType::Driver);
    }

    #[test]
    fn recovers_hello_a_pe_image_byte_identical_to_the_prebuild_efi() {
        let extraction: FvExtraction =
            extract_uefi_fv(OUTER_FV, ExtractionQuota::default_safe()).expect("extract");
        let recovered: &FvPeImage = extraction
            .pe_images
            .iter()
            .find(|p: &&FvPeImage| p.file_guid == HELLO_A_GUID)
            .expect("HelloA pe image recovered");
        assert_eq!(recovered.data.as_slice(), HELLO_A_EFI);
        assert_eq!(recovered.name.as_deref(), Some("HelloA"));
    }

    #[test]
    fn recovers_hello_b_standard_compression_byte_identical_to_the_prebuild_efi() {
        let extraction: FvExtraction =
            extract_uefi_fv(OUTER_FV, ExtractionQuota::default_safe()).expect("extract");
        let hello_b: &FvFileRecord = extraction
            .files
            .iter()
            .find(|f: &&FvFileRecord| f.guid == HELLO_B_GUID)
            .expect("HelloB recovered");
        let compression: &FvSectionRecord = hello_b
            .sections
            .iter()
            .find(|s: &&FvSectionRecord| s.kind == SECTION_COMPRESSION)
            .expect("compression section present");
        let codec: &FvCodecOutcome = compression.codec.as_ref().expect("codec outcome recorded");
        assert_eq!(codec.codec, FvCompressionCodec::Standard);
        assert!(codec.verified);
        assert!(codec.recovered);
        let recovered: &FvPeImage = extraction
            .pe_images
            .iter()
            .find(|image: &&FvPeImage| image.file_guid == HELLO_B_GUID)
            .expect("HelloB pe image recovered");
        assert_eq!(recovered.data.as_slice(), HELLO_B_EFI);
        assert_eq!(recovered.name.as_deref(), Some("HelloB"));
    }

    #[test]
    fn recovers_the_nested_lzma_compressed_inner_volume() {
        let extraction: FvExtraction =
            extract_uefi_fv(OUTER_FV, ExtractionQuota::default_safe()).expect("extract");
        assert_eq!(extraction.volumes_walked, 2);
        let lzma_note: bool = extraction
            .files
            .iter()
            .flat_map(|f: &FvFileRecord| f.sections.iter())
            .filter_map(|s: &FvSectionRecord| s.codec.as_ref())
            .any(|c: &FvCodecOutcome| {
                c.codec == FvCompressionCodec::Lzma && c.verified && c.recovered
            });
        assert!(lzma_note);
    }

    #[test]
    fn standalone_inner_volume_parses_identically() {
        let extraction: FvExtraction = extract_uefi_fv(INNER_FV, ExtractionQuota::default_safe())
            .expect("extract inner directly");
        assert_eq!(extraction.volumes_walked, 1);
        assert_eq!(extraction.files.len(), 2);
    }

    #[test]
    fn truncated_input_never_panics_and_reports_honestly() {
        for cut in (0..OUTER_FV.len()).step_by(4099) {
            let _ = extract_uefi_fv(&OUTER_FV[..cut], ExtractionQuota::default_safe());
        }
    }

    #[test]
    fn corrupted_block_map_length_lies_are_rejected_not_trusted() {
        let mut corrupted: Vec<u8> = OUTER_FV.to_vec();
        corrupted[32..40].copy_from_slice(&(u64::MAX).to_le_bytes());
        let result: Result<FvExtraction> =
            extract_uefi_fv(&corrupted, ExtractionQuota::default_safe());
        assert!(result.is_err());
    }

    #[test]
    fn guid_string_matches_expected_mixed_endian_form() {
        assert_eq!(
            guid_to_string(&HELLO_A_GUID),
            "a1570e16-f657-408f-9564-2ff7898dad4c"
        );
    }

    #[test]
    fn zero_length_ffs_file_does_not_infinite_loop() {
        let mut corrupted: Vec<u8> = INNER_FV.to_vec();
        let header: FvHeader = parse_fv_header(&corrupted).expect("header");
        let offset: usize = header.header_length as usize;
        corrupted[offset + 20] = 0x00;
        corrupted[offset + 21] = 0x00;
        corrupted[offset + 22] = 0x00;
        let result: FvExtraction = extract_uefi_fv(&corrupted, ExtractionQuota::default_safe())
            .expect("a zero-length file yields an honest truncated report, not an error");
        assert!(result.truncated);
    }

    fn nest_compression_type_none_sections(layers: usize) -> Vec<u8> {
        let mut stream: Vec<u8> = Vec::new();
        for _ in 0..layers {
            let mut body: Vec<u8> = Vec::new();
            body.extend_from_slice(&0u32.to_le_bytes());
            body.push(COMPRESSION_TYPE_NONE);
            body.extend_from_slice(&stream);
            let total_size: usize = SECTION_HEADER_LEN + body.len();
            let mut section: Vec<u8> = Vec::with_capacity(total_size);
            section.extend_from_slice(&(total_size as u32).to_le_bytes()[..3]);
            section.push(SECTION_COMPRESSION);
            section.extend_from_slice(&body);
            let padded_len: usize = align_up_usize(section.len(), SECTION_ALIGN);
            section.resize(padded_len, 0u8);
            stream = section;
        }
        stream
    }

    #[test]
    fn nested_compression_none_sections_beyond_the_depth_ceiling_are_bounded_not_unbounded() {
        let layers: usize = MAX_FV_DEPTH + 24;
        let payload: Vec<u8> = nest_compression_type_none_sections(layers);
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), payload.len() as u64);
        let mut file: FvFileRecord = FvFileRecord {
            guid: [0u8; 16],
            file_type: FvFileType::Driver,
            depth: 0,
            name: None,
            size: payload.len() as u64,
            sections: Vec::new(),
        };
        let mut out: FvExtraction = FvExtraction::default();
        process_section_stream(&payload, 0, &mut budget, &mut file, &mut out).expect(
            "depth-capped recursion through the compression-type-none branch reports truncation, it never errors or panics",
        );
        assert!(out.truncated);
        assert_eq!(file.sections.len(), MAX_FV_DEPTH + 1);
        assert!(
            out.notes
                .iter()
                .any(|n: &String| n.contains("section stream recursion exceeded max depth"))
        );
    }

    #[test]
    fn nested_crc32_guided_sections_beyond_the_depth_ceiling_are_bounded_not_unbounded() {
        let mut inner: Vec<u8> = Vec::new();
        for _ in 0..(MAX_FV_DEPTH + 24) {
            let mut guid_defined_body: Vec<u8> = Vec::new();
            guid_defined_body.extend_from_slice(&GUID_CRC32_SECTION);
            let data_offset: u16 = (SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN) as u16;
            guid_defined_body.extend_from_slice(&data_offset.to_le_bytes());
            guid_defined_body.extend_from_slice(&[0u8; 2]);
            let stored_crc: u32 = crc32fast::hash(&inner);
            guid_defined_body.extend_from_slice(&stored_crc.to_le_bytes());
            guid_defined_body.extend_from_slice(&inner);
            let total_size: usize = SECTION_HEADER_LEN + guid_defined_body.len();
            let mut section: Vec<u8> = Vec::with_capacity(total_size);
            section.extend_from_slice(&(total_size as u32).to_le_bytes()[..3]);
            section.push(SECTION_GUID_DEFINED);
            section.extend_from_slice(&guid_defined_body);
            let padded_len: usize = align_up_usize(section.len(), SECTION_ALIGN);
            section.resize(padded_len, 0u8);
            inner = section;
        }
        let payload: Vec<u8> = inner;
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), payload.len() as u64);
        let mut file: FvFileRecord = FvFileRecord {
            guid: [0u8; 16],
            file_type: FvFileType::Driver,
            depth: 0,
            name: None,
            size: payload.len() as u64,
            sections: Vec::new(),
        };
        let mut out: FvExtraction = FvExtraction::default();
        process_section_stream(&payload, 0, &mut budget, &mut file, &mut out).expect(
            "depth-capped recursion through the crc32 guided-section branch reports truncation, it never errors or panics",
        );
        assert!(out.truncated);
        assert_eq!(file.sections.len(), MAX_FV_DEPTH + 1);
        assert!(
            out.notes
                .iter()
                .any(|n: &String| n.contains("section stream recursion exceeded max depth"))
        );
    }

    fn brotli_guid_offset(bytes: &[u8]) -> usize {
        bytes
            .windows(GUID_BROTLI_CUSTOM_COMPRESS.len())
            .position(|window: &[u8]| window == GUID_BROTLI_CUSTOM_COMPRESS)
            .expect("Brotli guided-section GUID")
    }

    fn edk2_brotli_payload() -> &'static [u8] {
        const BROTLI_FV: &[u8] =
            include_bytes!("../../tests/fixtures/uefi_fv/edk2_brotli_guided.fv");
        let guid_offset: usize = brotli_guid_offset(BROTLI_FV);
        let section_offset: usize = guid_offset - SECTION_HEADER_LEN;
        let section_size: usize = u24_le(BROTLI_FV, section_offset)
            .and_then(|value: u32| usize::try_from(value).ok())
            .expect("normal guided section size");
        &BROTLI_FV[guid_offset + GUID_DEFINED_FIXED_LEN..section_offset + section_size]
    }

    fn edk2_tiano_payload() -> &'static [u8] {
        const TIANO_FV: &[u8] = include_bytes!("../../tests/fixtures/uefi_fv/edk2_tiano_guided.fv");
        let guid_offset: usize = TIANO_FV
            .windows(GUID_TIANO_CUSTOM_COMPRESS.len())
            .position(|window: &[u8]| window == GUID_TIANO_CUSTOM_COMPRESS)
            .expect("Tiano guided-section GUID");
        let section_offset: usize = guid_offset - SECTION_HEADER_LEN;
        let section_size: usize = u24_le(TIANO_FV, section_offset)
            .and_then(|value: u32| usize::try_from(value).ok())
            .expect("normal guided section size");
        &TIANO_FV[guid_offset + GUID_DEFINED_FIXED_LEN..section_offset + section_size]
    }

    fn edk2_standard_payload_range() -> std::ops::Range<usize> {
        (0..INNER_FV
            .len()
            .saturating_sub(COMPRESSION_HEADER_LEN + PI_COMPRESSION_HEADER_LEN))
            .find_map(|offset: usize| {
                let section_size: usize =
                    u24_le(INNER_FV, offset).and_then(|value: u32| usize::try_from(value).ok())?;
                if INNER_FV.get(offset + 3) != Some(&SECTION_COMPRESSION)
                    || INNER_FV.get(offset + 8) != Some(&COMPRESSION_TYPE_STANDARD)
                {
                    return None;
                }
                let section_end: usize = offset.checked_add(section_size)?;
                let payload_start: usize =
                    offset.checked_add(SECTION_HEADER_LEN + COMPRESSION_HEADER_LEN)?;
                let compressed_len: usize = u32_le(INNER_FV, payload_start)
                    .and_then(|value: u32| usize::try_from(value).ok())?;
                let payload_end: usize = payload_start
                    .checked_add(PI_COMPRESSION_HEADER_LEN)?
                    .checked_add(compressed_len)?;
                (payload_end == section_end && payload_end <= INNER_FV.len())
                    .then_some(payload_start..payload_end)
            })
            .expect("real EDK2 Standard stream")
    }

    fn first_ffs_file(volume: &[u8]) -> &[u8] {
        let header: FvHeader = parse_fv_header(volume).expect("firmware header");
        let start: usize = header.header_length as usize;
        let size: usize = u24_le(volume, start + 20)
            .and_then(|value: u32| usize::try_from(value).ok())
            .expect("normal FFS file size");
        &volume[start..start + size]
    }

    fn ffs_file_range_containing(volume: &[u8], target: usize) -> std::ops::Range<usize> {
        let header: FvHeader = parse_fv_header(volume).expect("firmware header");
        let mut start: usize = header.header_length as usize;
        while start + FFS_HEADER_LEN <= volume.len() {
            let size: usize = u24_le(volume, start + 20)
                .and_then(|value: u32| usize::try_from(value).ok())
                .expect("normal FFS file size");
            let end: usize = start.checked_add(size).expect("FFS file extent");
            if (start..end).contains(&target) {
                return start..end;
            }
            start = align_up_usize(end, FFS_FILE_ALIGN);
        }
        panic!("target offset is not inside an FFS file")
    }

    fn brotli_guided_body(data_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::with_capacity(GUID_DEFINED_FIXED_LEN + payload.len());
        body.extend_from_slice(&GUID_BROTLI_CUSTOM_COMPRESS);
        body.extend_from_slice(&data_offset.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(payload);
        body
    }

    fn tiano_guided_body(data_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::with_capacity(GUID_DEFINED_FIXED_LEN + payload.len());
        body.extend_from_slice(&GUID_TIANO_CUSTOM_COMPRESS);
        body.extend_from_slice(&data_offset.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(payload);
        body
    }

    fn edk2_brotli_encode(payload: &[u8]) -> Vec<u8> {
        let mut compressed: Vec<u8> = Vec::new();
        {
            let mut encoder: brotli::CompressorWriter<&mut Vec<u8>> =
                brotli::CompressorWriter::new(&mut compressed, 4096, 9, 22);
            std::io::Write::write_all(&mut encoder, payload).expect("compress section stream");
        }
        let mut encoded: Vec<u8> = Vec::with_capacity(EDK2_BROTLI_HEADER_LEN + compressed.len());
        encoded.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&0u64.to_le_bytes());
        encoded.extend_from_slice(&compressed);
        encoded
    }

    fn empty_driver_record() -> FvFileRecord {
        FvFileRecord {
            guid: [0x42; 16],
            file_type: FvFileType::Driver,
            depth: 0,
            name: Some("BrotliDriver".to_owned()),
            size: 0,
            sections: Vec::new(),
        }
    }

    #[test]
    fn extended_brotli_guided_section_uses_its_eight_byte_common_header_for_data_offset() {
        let payload: &[u8] = edk2_brotli_payload();
        let body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER2_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("extended guided header fits"),
            payload,
        );
        let section_size: usize = SECTION_HEADER2_LEN + body.len();
        let mut stream: Vec<u8> = Vec::with_capacity(section_size);
        stream.extend_from_slice(&[0xff, 0xff, 0xff, SECTION_GUID_DEFINED]);
        stream.extend_from_slice(
            &u32::try_from(section_size)
                .expect("section size fits")
                .to_le_bytes(),
        );
        stream.extend_from_slice(&body);
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), stream.len() as u64);
        let mut file: FvFileRecord = empty_driver_record();
        let mut extraction: FvExtraction = FvExtraction::default();

        process_section_stream(&stream, 0, &mut budget, &mut file, &mut extraction)
            .expect("decode extended Brotli guided section");

        assert_eq!(extraction.pe_images.len(), 1);
        assert_eq!(extraction.pe_images[0].data, HELLO_A_EFI);
    }

    #[test]
    fn extended_tiano_guided_section_uses_its_eight_byte_common_header_for_data_offset() {
        let payload: &[u8] = edk2_tiano_payload();
        let body: Vec<u8> = tiano_guided_body(
            u16::try_from(SECTION_HEADER2_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("extended guided header fits"),
            payload,
        );
        let section_size: usize = SECTION_HEADER2_LEN + body.len();
        let mut stream: Vec<u8> = Vec::with_capacity(section_size);
        stream.extend_from_slice(&[0xff, 0xff, 0xff, SECTION_GUID_DEFINED]);
        stream.extend_from_slice(
            &u32::try_from(section_size)
                .expect("section size fits")
                .to_le_bytes(),
        );
        stream.extend_from_slice(&body);
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), stream.len() as u64);
        let mut file: FvFileRecord = empty_driver_record();
        file.name = Some("TianoDriver".to_owned());
        let mut extraction: FvExtraction = FvExtraction::default();

        process_section_stream(&stream, 0, &mut budget, &mut file, &mut extraction)
            .expect("decode extended Tiano guided section");

        assert_eq!(extraction.pe_images.len(), 1);
        assert_eq!(extraction.pe_images[0].data, HELLO_B_EFI);
    }

    #[test]
    fn brotli_guided_section_rejects_data_offset_before_its_fixed_header() {
        let body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN - 1)
                .expect("invalid offset fits"),
            edk2_brotli_payload(),
        );
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
        let mut file: FvFileRecord = empty_driver_record();
        let mut extraction: FvExtraction = FvExtraction::default();
        let mut outcome: Option<FvCodecOutcome> = None;

        let error: Error = record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut budget,
            &mut file,
            &mut extraction,
            &mut outcome,
        )
        .expect_err("reject guided DataOffset inside the fixed header");
        assert!(error.to_string().contains("data offset"), "{error}");
    }

    #[test]
    fn brotli_guided_section_rejects_truncated_malformed_and_trailing_streams() {
        let valid: &[u8] = edk2_brotli_payload();
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        cases.push(("truncated", valid[..valid.len() - 1].to_vec()));
        let mut malformed: Vec<u8> = valid.to_vec();
        malformed[16..].fill(0xff);
        cases.push(("malformed", malformed));
        let mut trailing: Vec<u8> = valid.to_vec();
        trailing.extend_from_slice(b"trailing");
        cases.push(("trailing", trailing));

        for (label, payload) in cases {
            let body: Vec<u8> = brotli_guided_body(
                u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN)
                    .expect("normal guided header fits"),
                &payload,
            );
            let mut budget: FvBudget =
                FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
            let mut file: FvFileRecord = empty_driver_record();
            let mut extraction: FvExtraction = FvExtraction::default();
            let mut outcome: Option<FvCodecOutcome> = None;
            let error: Error = record_guid_defined_section(
                &body,
                SECTION_HEADER_LEN,
                0,
                &mut budget,
                &mut file,
                &mut extraction,
                &mut outcome,
            )
            .expect_err("reject incomplete or invalid Brotli stream");
            assert!(
                error.to_string().contains(label),
                "{label} stream returned {error}"
            );
            assert!(extraction.pe_images.is_empty());
        }
    }

    #[test]
    fn tiano_stream_requires_exact_extent_terminal_padding_and_matching_algorithm() {
        let valid: &[u8] = edk2_tiano_payload();
        let expected_len: u32 = u32_le(valid, 4).expect("Tiano original size");
        let mut valid_budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), valid.len() as u64);
        let decoded: Vec<u8> = decompress_pi_compression(
            valid,
            None,
            PiCompressionAlgorithm::Tiano,
            &mut valid_budget,
            "TianoDriver",
        )
        .expect("decode exact EDK2 Tiano stream");
        assert_eq!(decoded.len(), expected_len as usize);

        let mut truncated: Vec<u8> = valid[..valid.len() - 1].to_vec();
        let truncated_len: u32 = u32::try_from(truncated.len() - PI_COMPRESSION_HEADER_LEN)
            .expect("truncated compressed size fits");
        truncated[..4].copy_from_slice(&truncated_len.to_le_bytes());
        let mut trailing: Vec<u8> = valid.to_vec();
        let terminal: u8 = trailing.pop().expect("terminal zero");
        trailing.extend_from_slice(&[0x5a, terminal]);
        let trailing_len: u32 = u32::try_from(trailing.len() - PI_COMPRESSION_HEADER_LEN)
            .expect("trailing compressed size fits");
        trailing[..4].copy_from_slice(&trailing_len.to_le_bytes());

        for (label, payload) in [("truncated", truncated), ("trailing", trailing)] {
            let mut budget: FvBudget =
                FvBudget::new(ExtractionQuota::default_safe(), payload.len() as u64);
            let error: Error = decompress_pi_compression(
                &payload,
                None,
                PiCompressionAlgorithm::Tiano,
                &mut budget,
                "TianoDriver",
            )
            .expect_err("reject inexact Tiano stream");
            assert_eq!(budget.decompressed_total, 0, "{label}: {error}");
        }

        let mut cross_budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), valid.len() as u64);
        let cross_error: Error = decompress_pi_compression(
            valid,
            None,
            PiCompressionAlgorithm::Standard,
            &mut cross_budget,
            "TianoDriver",
        )
        .expect_err("standard parameters must not decode a Tiano stream");
        assert_eq!(cross_budget.decompressed_total, 0, "{cross_error}");

        let standard_range: std::ops::Range<usize> = edk2_standard_payload_range();
        let standard: &[u8] = &INNER_FV[standard_range];
        let mut reverse_budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), standard.len() as u64);
        let reverse_error: Error = decompress_pi_compression(
            standard,
            None,
            PiCompressionAlgorithm::Tiano,
            &mut reverse_budget,
            "HelloB",
        )
        .expect_err("Tiano parameters must not decode a Standard stream");
        assert_eq!(reverse_budget.decompressed_total, 0, "{reverse_error}");
    }

    #[test]
    fn tiano_declared_output_is_rejected_before_allocation_when_quota_is_exhausted() {
        let valid: &[u8] = edk2_tiano_payload();
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), valid.len() as u64);
        budget.decompressed_ceiling = 835;
        let error: Error = decompress_pi_compression(
            valid,
            None,
            PiCompressionAlgorithm::Tiano,
            &mut budget,
            "TianoDriver",
        )
        .expect_err("reject declared output above remaining quota");
        assert!(matches!(error, Error::QuotaExceeded { .. }));
        assert_eq!(budget.decompressed_total, 0);
    }

    #[test]
    fn public_extraction_quota_bounds_tiano_output_before_recovery() {
        const TIANO_FV: &[u8] = include_bytes!("../../tests/fixtures/uefi_fv/edk2_tiano_guided.fv");
        let quotas: [ExtractionQuota; 3] = [
            ExtractionQuota {
                max_per_entry_uncompressed: 500,
                ..ExtractionQuota::default_safe()
            },
            ExtractionQuota {
                max_total_uncompressed: 1_000,
                ..ExtractionQuota::default_safe()
            },
            ExtractionQuota {
                max_per_entry_ratio: 1,
                ..ExtractionQuota::default_safe()
            },
        ];
        for quota in quotas {
            let extraction: FvExtraction =
                extract_uefi_fv(TIANO_FV, quota).expect("quota refusal remains local to the codec");
            assert!(extraction.pe_images.is_empty());
            let outcome: &FvCodecOutcome = extraction
                .files
                .iter()
                .flat_map(|file: &FvFileRecord| file.sections.iter())
                .filter_map(|section: &FvSectionRecord| section.codec.as_ref())
                .find(|codec: &&FvCodecOutcome| codec.codec == FvCompressionCodec::TianoGuided)
                .expect("Tiano quota outcome");
            assert!(!outcome.verified);
            assert!(!outcome.recovered);
            assert!(outcome.note.contains("quota exceeded"), "{}", outcome.note);
        }
    }

    #[test]
    fn malformed_decoded_stream_restores_budget_and_prior_outputs() {
        let mut decoded: Vec<u8> = fv_section(SECTION_PE32, b"valid prefix");
        decoded.extend_from_slice(&[0x01, 0x02, 0x03]);
        let encoded: Vec<u8> = edk2_brotli_encode(&decoded);
        let body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("normal guided header fits"),
            &encoded,
        );
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
        let mut file: FvFileRecord = empty_driver_record();
        let mut extraction: FvExtraction = FvExtraction {
            pe_images: vec![FvPeImage {
                file_guid: [0x24; 16],
                name: Some("Prior".to_owned()),
                data: b"prior".to_vec(),
            }],
            ..FvExtraction::default()
        };
        let mut outcome: Option<FvCodecOutcome> = None;

        let error: Error = record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut budget,
            &mut file,
            &mut extraction,
            &mut outcome,
        )
        .expect_err("reject malformed decoded section stream");

        assert!(error.to_string().contains("trailing bytes"), "{error}");
        assert_eq!(budget.decompressed_total, 0);
        assert_eq!(budget.quota.report().entries_accepted, 0);
        assert_eq!(extraction.pe_images.len(), 1);
        assert_eq!(extraction.pe_images[0].data, b"prior");
        assert!(file.sections.is_empty());

        let valid_body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("normal guided header fits"),
            edk2_brotli_payload(),
        );
        record_guid_defined_section(
            &valid_body,
            SECTION_HEADER_LEN,
            0,
            &mut budget,
            &mut file,
            &mut extraction,
            &mut outcome,
        )
        .expect("valid sibling decodes after malformed stream rollback");
        assert_eq!(extraction.pe_images.len(), 2);
        assert_eq!(extraction.pe_images[1].data, HELLO_A_EFI);
    }

    #[test]
    fn corrupt_standard_file_does_not_hide_a_valid_sibling_file() {
        let standard_range: std::ops::Range<usize> = edk2_standard_payload_range();
        let inner_header: FvHeader = parse_fv_header(INNER_FV).expect("inner firmware header");
        let inner_file_range: std::ops::Range<usize> =
            ffs_file_range_containing(INNER_FV, standard_range.start);
        let inner_file: &[u8] = &INNER_FV[inner_file_range.clone()];
        let mut corrupt_file: Vec<u8> = inner_file.to_vec();
        let corrupt_offset: usize =
            standard_range.start + PI_COMPRESSION_HEADER_LEN + 1 - inner_file_range.start;
        corrupt_file[corrupt_offset] ^= 0xff;
        let sibling_volume: Vec<u8> =
            hostile_named_image("Sibling", b"valid sibling").expect("construct sibling volume");
        let sibling_file: &[u8] = first_ffs_file(&sibling_volume);
        let mut combined: Vec<u8> = INNER_FV.to_vec();
        let mut output_offset: usize = inner_header.header_length as usize;
        combined[output_offset..].fill(0xff);
        combined[output_offset..output_offset + sibling_file.len()].copy_from_slice(sibling_file);
        output_offset = align_up_usize(output_offset + sibling_file.len(), FFS_FILE_ALIGN);
        combined[output_offset..output_offset + corrupt_file.len()].copy_from_slice(&corrupt_file);

        let extraction: FvExtraction = extract_uefi_fv(&combined, ExtractionQuota::default_safe())
            .expect("extract sibling files");
        assert!(extraction.pe_images.iter().any(|image: &FvPeImage| {
            image.name.as_deref() == Some("Sibling") && image.data == b"valid sibling"
        }));
        assert!(
            extraction
                .pe_images
                .iter()
                .all(|image: &FvPeImage| image.file_guid != HELLO_B_GUID)
        );
        let failed_codec: &FvCodecOutcome = extraction
            .files
            .iter()
            .flat_map(|file: &FvFileRecord| file.sections.iter())
            .filter_map(|section: &FvSectionRecord| section.codec.as_ref())
            .find(|codec: &&FvCodecOutcome| codec.codec == FvCompressionCodec::Standard)
            .expect("failed Standard outcome");
        assert!(!failed_codec.verified);
        assert!(!failed_codec.recovered);
        assert!(
            extraction
                .notes
                .iter()
                .any(|note: &String| note.contains("standard compression decode failed"))
        );
    }

    #[test]
    fn brotli_guided_output_and_aggregate_decompression_are_bounded_before_recursion() {
        let payload: &[u8] = edk2_brotli_payload();
        let body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("normal guided header fits"),
            payload,
        );
        let mut output_budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
        output_budget.decompressed_ceiling = HELLO_A_EFI.len() as u64;
        let mut file: FvFileRecord = empty_driver_record();
        let mut extraction: FvExtraction = FvExtraction::default();
        let mut outcome: Option<FvCodecOutcome> = None;
        let output_error: Error = record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut output_budget,
            &mut file,
            &mut extraction,
            &mut outcome,
        )
        .expect_err("decoded section stream exceeds output ceiling");
        assert!(matches!(output_error, Error::QuotaExceeded { .. }));
        assert!(extraction.pe_images.is_empty());

        let mut aggregate_budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
        aggregate_budget.decompressed_ceiling = 1_000;
        let mut aggregate_file: FvFileRecord = empty_driver_record();
        let mut aggregate_extraction: FvExtraction = FvExtraction::default();
        let mut first_outcome: Option<FvCodecOutcome> = None;
        record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut aggregate_budget,
            &mut aggregate_file,
            &mut aggregate_extraction,
            &mut first_outcome,
        )
        .expect("first decoded stream fits aggregate ceiling");
        let mut second_outcome: Option<FvCodecOutcome> = None;
        let aggregate_error: Error = record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut aggregate_budget,
            &mut aggregate_file,
            &mut aggregate_extraction,
            &mut second_outcome,
        )
        .expect_err("second decoded stream exceeds aggregate ceiling");
        assert!(matches!(aggregate_error, Error::QuotaExceeded { .. }));
        assert_eq!(aggregate_extraction.pe_images.len(), 1);
    }

    #[test]
    fn unknown_guid_keeps_a_malformed_payload_opaque_without_probing_brotli() {
        let mut body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("normal guided header fits"),
            b"not a Brotli stream",
        );
        body[0] ^= 0x01;
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
        let mut file: FvFileRecord = empty_driver_record();
        let mut extraction: FvExtraction = FvExtraction::default();
        let mut outcome: Option<FvCodecOutcome> = None;

        record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut budget,
            &mut file,
            &mut extraction,
            &mut outcome,
        )
        .expect("unknown GUID remains opaque");

        assert!(extraction.pe_images.is_empty());
        assert_eq!(budget.decompressed_total, 0);
        assert!(matches!(
            outcome,
            Some(FvCodecOutcome {
                codec: FvCompressionCodec::Unknown,
                recovered: false,
                ..
            })
        ));
    }

    #[test]
    fn failed_brotli_recursion_restores_existing_image_names() {
        let nested_fv: Vec<u8> =
            hostile_named_image("NestedName", b"nested image").expect("construct nested volume");
        let mut decoded: Vec<u8> = fv_section(SECTION_FIRMWARE_VOLUME_IMAGE, &nested_fv);
        decoded.extend_from_slice(&[8, 0, 0, SECTION_PE32]);
        let encoded: Vec<u8> = edk2_brotli_encode(&decoded);
        let body: Vec<u8> = brotli_guided_body(
            u16::try_from(SECTION_HEADER_LEN + GUID_DEFINED_FIXED_LEN)
                .expect("normal guided header fits"),
            &encoded,
        );
        let nested_guid: [u8; 16] = guid_from_fields(
            0x1234_5678,
            0x9abc,
            0xdef0,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        );
        let mut budget: FvBudget =
            FvBudget::new(ExtractionQuota::default_safe(), body.len() as u64);
        let mut file: FvFileRecord = empty_driver_record();
        let mut extraction: FvExtraction = FvExtraction {
            pe_images: vec![FvPeImage {
                file_guid: nested_guid,
                name: Some("OriginalName".to_owned()),
                data: b"existing image".to_vec(),
            }],
            ..FvExtraction::default()
        };
        let mut outcome: Option<FvCodecOutcome> = None;

        record_guid_defined_section(
            &body,
            SECTION_HEADER_LEN,
            0,
            &mut budget,
            &mut file,
            &mut extraction,
            &mut outcome,
        )
        .expect_err("nested parse fails after renaming matching images");

        assert_eq!(extraction.pe_images.len(), 1);
        assert_eq!(
            extraction.pe_images[0].name.as_deref(),
            Some("OriginalName")
        );
        assert_eq!(budget.decompressed_total, 0);
        assert_eq!(budget.quota.report().entries_accepted, 0);
    }
}
