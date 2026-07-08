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
const CRC32_VENDOR_HEADER_LEN: usize = 4;

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
    bytes
        .get(at..at + 2)
        .map(|s: &[u8]| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|s: &[u8]| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
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

struct FvBudget {
    quota: QuotaGuard,
    depth: usize,
    decompressed_total: u64,
    decompressed_ceiling: u64,
}

impl FvBudget {
    fn new(quota: ExtractionQuota, input_len: u64) -> Self {
        Self {
            quota: QuotaGuard::new(quota),
            depth: 0,
            decompressed_total: 0,
            decompressed_ceiling: input_len
                .saturating_mul(DECOMPRESSED_CEILING_MULTIPLIER)
                .max(4 * 1024 * 1024),
        }
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

fn decompress_standard(_payload: &[u8]) -> FvCodecOutcome {
    FvCodecOutcome {
        codec: FvCompressionCodec::Standard,
        verified: false,
        recovered: false,
        note: "EFI standard/Tiano compression detected; no verified in-house decoder is wired up yet, payload left compressed".to_owned(),
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
            let compressed: &[u8] = body.get(COMPRESSION_HEADER_LEN..).unwrap_or(&[]);
            match compression_type {
                COMPRESSION_TYPE_NONE => {
                    let inner_depth: usize = depth + 1;
                    process_section_stream(compressed, inner_depth, budget, file, out)?;
                }
                COMPRESSION_TYPE_STANDARD => {
                    let outcome: FvCodecOutcome = decompress_standard(compressed);
                    out.notes.push(format!(
                        "{}: {} (declared uncompressed length {uncompressed_len})",
                        guid_to_string(&file.guid),
                        outcome.note
                    ));
                    codec_outcome = Some(outcome);
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
            record_guid_defined_section(body, depth, budget, file, out, &mut codec_outcome)?;
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
    let common_header_len: usize = SECTION_HEADER_LEN;
    let relative_offset: usize = (data_offset as usize).saturating_sub(common_header_len);
    let payload: &[u8] = body.get(relative_offset..).unwrap_or(&[]);
    let entry: String = guid_to_string(&file.guid);
    if section_guid == GUID_LZMA_CUSTOM_COMPRESS {
        match decompress_lzma_guided(payload, budget, &entry) {
            Ok(decoded) => {
                let inner_depth: usize = depth + 1;
                if inner_depth > MAX_FV_DEPTH {
                    out.truncated = true;
                    out.notes.push(format!(
                        "{entry}: lzma-decoded stream exceeds max recursion depth {MAX_FV_DEPTH}, stopped"
                    ));
                } else {
                    process_section_stream(&decoded, inner_depth, budget, file, out)?;
                }
                *codec_outcome = Some(FvCodecOutcome {
                    codec: FvCompressionCodec::Lzma,
                    verified: true,
                    recovered: true,
                    note: format!("lzma guided section decoded to {} bytes", decoded.len()),
                });
            }
            Err(e) => {
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
        out.notes.push(format!(
            "{entry}: brotli custom-compress guided section detected; no verified in-house decoder is wired up yet, payload left compressed"
        ));
        *codec_outcome = Some(FvCodecOutcome {
            codec: FvCompressionCodec::Brotli,
            verified: false,
            recovered: false,
            note: "brotli guided section detected but not decoded".to_owned(),
        });
    } else if section_guid == GUID_TIANO_CUSTOM_COMPRESS {
        out.notes.push(format!(
            "{entry}: tiano-guided (standard algorithm via guid-defined section) detected; no verified in-house decoder is wired up yet, payload left compressed"
        ));
        *codec_outcome = Some(FvCodecOutcome {
            codec: FvCompressionCodec::TianoGuided,
            verified: false,
            recovered: false,
            note: "tiano guided section detected but not decoded".to_owned(),
        });
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
    fn reports_hello_b_standard_compression_as_detected_but_unverified() {
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
        assert!(!codec.verified);
        assert!(!codec.recovered);
        assert!(
            extraction
                .pe_images
                .iter()
                .all(|p: &FvPeImage| p.file_guid != HELLO_B_GUID)
        );
        let _ = HELLO_B_EFI;
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
}
