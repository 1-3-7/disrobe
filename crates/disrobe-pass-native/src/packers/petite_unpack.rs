use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::pe_sections::{
    DataDirectory, PeImage, PeSection, parse_pe_image, read_u16 as read_u16_le,
    read_u32 as read_u32_le,
};
use crate::error::{Error, Result};

const PETITE_MAX_PREALLOC: usize = 256 * 1024 * 1024;

const PETITE_MAX_IMAGE_RATIO: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredImport {
    pub dll: String,
    pub functions: Vec<RecoveredImportFn>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredImportFn {
    pub name: String,
    pub hint: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpackReport {
    pub packed_size: u64,
    pub unpacked_size: u64,
    pub original_image_base: u64,
    pub original_entry_point_rva: u32,
    pub recovered_section_count: u16,
    pub recovered_imports: Vec<RecoveredImport>,
    pub byte_recoverable_pct: u32,
    pub stream_decoded: bool,
}

#[derive(Debug, Clone)]
pub struct UnpackResult {
    pub bytes: Vec<u8>,
    pub report: UnpackReport,
}

const DOS_HEADER_SIZE: usize = 64;
const PE_SIGNATURE_LEN: usize = 4;
const COFF_HEADER_LEN: usize = 20;
const OPTIONAL_HEADER_STANDARD_LEN: usize = 96;
const SECTION_HEADER_LEN: usize = 40;
const IMAGE_NT_OPTIONAL_HDR32_SIZE: u16 = 224;
const PE32_MAGIC: u16 = 0x010B;
const MACHINE_I386: u16 = 0x014C;
const FILE_HEADER_OFFSET_E_LFANEW: usize = 0x3C;
const PETITE_SECTION_NAME: &[u8; 8] = b"petite\x00\x00";
const PETITE_SECTION_NAME_DOTTED: &[u8; 8] = b".petite\x00";
const SECTION_ALIGNMENT_DEFAULT: u32 = 0x1000;
const FILE_ALIGNMENT_DEFAULT: u32 = 0x200;

pub fn unpack_petite(packed_bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(unpack_petite_with_report(packed_bytes)?.bytes)
}

pub fn unpack_petite_with_report(packed_bytes: &[u8]) -> Result<UnpackResult> {
    let packed: PackedPetite = parse_packed_petite(packed_bytes)?;
    let imports: Vec<RecoveredImport> = parse_petite_import_table(&packed)?;

    if parse_phase_one_stub(&packed).is_some()
        && let Ok(emu) = crate::packers::unpack_petite_phase2_emulated(packed_bytes)
        && emu.recovered_memory_image.starts_with(b"MZ")
        && let Some(image) = reconstruct_from_memory_image(
            &packed,
            &emu.recovered_memory_image,
            &emu.pre_resolution_image,
        )
    {
        let recoverable_pct: u32 = if image.bytes.is_empty() {
            0
        } else {
            let known: u64 = image.deterministic_bytes as u64;
            let total: u64 = image.bytes.len() as u64;
            ((known.saturating_mul(10_000) / total) as u32).min(10_000)
        };
        let report: UnpackReport = build_report(
            &packed,
            packed_bytes.len(),
            image.bytes.len(),
            imports,
            image.section_count,
            recoverable_pct,
            true,
        )?;
        return Ok(UnpackResult {
            bytes: image.bytes,
            report,
        });
    }

    let stream: DecodedStream = decode_petite_stream(&packed)?;
    let reconstruction: Reconstruction = reconstruct_image(&packed, &stream, &imports)?;

    let recoverable_pct: u32 = if reconstruction.bytes.is_empty() {
        0
    } else {
        let known: u64 = reconstruction.deterministic_bytes as u64;
        let total: u64 = reconstruction.bytes.len() as u64;
        ((known.saturating_mul(10_000) / total) as u32).min(10_000)
    };

    let section_count: u16 = u16::try_from(reconstruction.original_sections.len())
        .map_err(|_| Error::GoblinParse("recovered section count overflowed u16".into()))?;
    let report: UnpackReport = build_report(
        &packed,
        packed_bytes.len(),
        reconstruction.bytes.len(),
        imports,
        section_count,
        recoverable_pct,
        stream.fully_decoded,
    )?;

    Ok(UnpackResult {
        bytes: reconstruction.bytes,
        report,
    })
}

fn build_report(
    packed: &PackedPetite<'_>,
    packed_len: usize,
    unpacked_len: usize,
    imports: Vec<RecoveredImport>,
    section_count: u16,
    recoverable_pct: u32,
    stream_decoded: bool,
) -> Result<UnpackReport> {
    Ok(UnpackReport {
        packed_size: packed_len as u64,
        unpacked_size: unpacked_len as u64,
        original_image_base: packed.image.image_base,
        original_entry_point_rva: packed.image.entry_point_rva,
        recovered_section_count: section_count,
        recovered_imports: imports,
        byte_recoverable_pct: recoverable_pct,
        stream_decoded,
    })
}

#[derive(Debug, Clone)]
struct PackedPetite<'a> {
    raw: &'a [u8],
    image: PeImage,
    import_directory_rva: u32,
    iat_directory: DataDirectory,
    payload_section: usize,
    petite_section: usize,
}

#[allow(clippy::too_many_lines)]
fn parse_packed_petite(bytes: &[u8]) -> Result<PackedPetite<'_>> {
    if bytes.len() < DOS_HEADER_SIZE {
        return Err(Error::Truncated {
            needed: DOS_HEADER_SIZE,
            had: bytes.len(),
        });
    }
    if !bytes.starts_with(b"MZ") {
        return Err(Error::UnknownFormat);
    }
    let e_lfanew: usize = read_u32_le(bytes, FILE_HEADER_OFFSET_E_LFANEW)? as usize;
    let nt_min_end: usize = e_lfanew
        .checked_add(PE_SIGNATURE_LEN + COFF_HEADER_LEN + OPTIONAL_HEADER_STANDARD_LEN)
        .ok_or(Error::UnknownFormat)?;
    if bytes.len() < nt_min_end {
        return Err(Error::Truncated {
            needed: nt_min_end,
            had: bytes.len(),
        });
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return Err(Error::UnknownFormat);
    }
    let coff_off: usize = e_lfanew + PE_SIGNATURE_LEN;
    let machine: u16 = read_u16_le(bytes, coff_off)?;
    if machine != MACHINE_I386 {
        return Err(Error::GoblinParse(format!(
            "Petite is x86-only; refused machine=0x{machine:04x}"
        )));
    }
    let size_of_optional_header: u16 = read_u16_le(bytes, coff_off + 16)?;
    if size_of_optional_header < IMAGE_NT_OPTIONAL_HDR32_SIZE {
        return Err(Error::GoblinParse(format!(
            "Petite-packed PE32 must carry a 224-byte optional header; got {size_of_optional_header}"
        )));
    }
    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    let magic: u16 = read_u16_le(bytes, opt_off)?;
    if magic != PE32_MAGIC {
        return Err(Error::GoblinParse(format!(
            "Petite is PE32 only; refused optional-header magic 0x{magic:04x}"
        )));
    }
    let import_directory_rva: u32 = read_u32_le(bytes, opt_off + 96 + 8)?;
    let iat_directory: DataDirectory = DataDirectory {
        virtual_address: read_u32_le(bytes, opt_off + 96 + 96)?,
        size: read_u32_le(bytes, opt_off + 96 + 100)?,
    };
    let image: PeImage = parse_pe_image(bytes)?;
    let petite_section: usize = image
        .sections
        .iter()
        .position(|s: &PeSection| {
            &s.name == PETITE_SECTION_NAME || &s.name == PETITE_SECTION_NAME_DOTTED
        })
        .ok_or_else(|| Error::GoblinParse("no 'petite' section found".into()))?;
    let payload_section: usize = image
        .sections
        .iter()
        .enumerate()
        .find(|(idx, s): &(usize, &PeSection)| *idx != petite_section && s.raw_size > 0)
        .map(|(idx, _): (usize, &PeSection)| idx)
        .ok_or_else(|| Error::GoblinParse("no compressed-payload section found".into()))?;
    Ok(PackedPetite {
        raw: bytes,
        image,
        import_directory_rva,
        iat_directory,
        payload_section,
        petite_section,
    })
}

#[derive(Debug, Clone)]
struct DecodedStream {
    bytes: Vec<u8>,
    fully_decoded: bool,
}

fn decode_petite_stream(packed: &PackedPetite<'_>) -> Result<DecodedStream> {
    let sec: &PeSection = &packed.image.sections[packed.payload_section];
    let start: usize = sec.raw_pointer as usize;
    let len: usize = sec.raw_size as usize;
    if start
        .checked_add(len)
        .map_or(true, |end: usize| end > packed.raw.len())
    {
        return Err(Error::Truncated {
            needed: start.saturating_add(len),
            had: packed.raw.len(),
        });
    }
    let target_size: usize = (sec.virtual_size as usize)
        .min(PETITE_MAX_PREALLOC.min(packed.raw.len().saturating_mul(PETITE_MAX_IMAGE_RATIO)));
    let stub_params: Option<PhaseOneParams> = parse_phase_one_stub(packed);
    if let Some(p) = stub_params {
        let (phase1, phase1_ok): (Vec<u8>, bool) =
            decode_petite_stream_v2(packed.raw, p.compressed_file_off, p.phase1_output_bytes);
        return Ok(DecodedStream {
            bytes: phase1,
            fully_decoded: phase1_ok,
        });
    }
    let stream: &[u8] = &packed.raw[start..start + len];
    let mut padded: Vec<u8> = Vec::with_capacity(target_size);
    padded.extend_from_slice(stream);
    if padded.len() < target_size {
        padded.resize(target_size, 0);
    } else {
        padded.truncate(target_size);
    }
    Ok(DecodedStream {
        bytes: padded,
        fully_decoded: false,
    })
}

#[derive(Debug, Clone, Copy)]
struct PhaseOneParams {
    compressed_file_off: usize,

    phase1_output_bytes: u32,
}

fn parse_phase_one_stub(packed: &PackedPetite<'_>) -> Option<PhaseOneParams> {
    let payload: &PeSection = &packed.image.sections[packed.payload_section];
    let ep_rva: u32 = packed.image.entry_point_rva;
    if ep_rva < payload.virtual_address
        || ep_rva >= payload.virtual_address.saturating_add(payload.virtual_size)
    {
        return None;
    }
    let ep_file: usize = payload.raw_pointer as usize + (ep_rva - payload.virtual_address) as usize;
    if ep_file + 0x40 > packed.raw.len() {
        return None;
    }
    let ep: &[u8] = &packed.raw[ep_file..];
    if ep[0] != 0xB8 {
        return None;
    }
    if ep[5] != 0x60 {
        return None;
    }
    if ep[6..12] != [0x8D, 0xA8, 0x00, 0x60, 0xFE, 0xFF] {
        return None;
    }
    let mut scan: usize = 0x1D;
    let cap: usize = 0x60.min(ep.len() - 6);
    let mut compressed_rva: Option<u32> = None;
    let mut phase1_bytes: Option<u32> = None;
    while scan + 6 < cap {
        if ep[scan] == 0xBB && phase1_bytes.is_none() {
            phase1_bytes = Some(u32::from_le_bytes([
                ep[scan + 1],
                ep[scan + 2],
                ep[scan + 3],
                ep[scan + 4],
            ]));
            scan += 5;
            continue;
        }
        if ep[scan] == 0x8D && ep[scan + 1] == 0xB5 && compressed_rva.is_none() {
            compressed_rva = Some(u32::from_le_bytes([
                ep[scan + 2],
                ep[scan + 3],
                ep[scan + 4],
                ep[scan + 5],
            ]));
            scan += 6;
            continue;
        }
        scan += 1;
        if compressed_rva.is_some() && phase1_bytes.is_some() {
            break;
        }
    }
    let compressed_rva: u32 = compressed_rva?;
    let phase1_bytes: u32 = phase1_bytes?;
    if compressed_rva < payload.virtual_address
        || compressed_rva >= payload.virtual_address.saturating_add(payload.virtual_size)
    {
        return None;
    }
    let compressed_file_off: usize =
        payload.raw_pointer as usize + (compressed_rva - payload.virtual_address) as usize;
    if compressed_file_off >= packed.raw.len() {
        return None;
    }
    Some(PhaseOneParams {
        compressed_file_off,
        phase1_output_bytes: phase1_bytes,
    })
}

#[derive(Debug, Clone, Copy)]
struct DecoderParams {
    offset_bits: u32,
    threshold_a: u32,
    threshold_b: u32,
}

impl DecoderParams {
    fn for_output_size(output_size: u32) -> Self {
        if output_size < 0x1_0000 {
            Self {
                offset_bits: 5,
                threshold_a: 0xFFFF_C060,
                threshold_b: 0xFFFF_FC60,
            }
        } else {
            Self {
                offset_bits: 8,
                threshold_a: 0xFFFF_8300,
                threshold_b: 0xFFFF_FB00,
            }
        }
    }
}

struct PetiteBitStream<'a> {
    data: &'a [u8],
    cursor: usize,
    bit_buf: u32,
}

impl<'a> PetiteBitStream<'a> {
    fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            data,
            cursor: start,
            bit_buf: 0,
        }
    }

    fn get_bit(&mut self) -> Option<u32> {
        let new_buf: u32 = self.bit_buf.wrapping_shl(1);
        if new_buf == 0 {
            if self.cursor.checked_add(4)? > self.data.len() {
                return None;
            }
            let dword: u32 = u32::from_le_bytes([
                self.data[self.cursor],
                self.data[self.cursor + 1],
                self.data[self.cursor + 2],
                self.data[self.cursor + 3],
            ]);
            self.cursor += 4;
            let cf_out: u32 = dword >> 31;
            self.bit_buf = dword.wrapping_shl(1) | 1;
            return Some(cf_out);
        }
        let cf_out: u32 = self.bit_buf >> 31;
        self.bit_buf = new_buf;
        Some(cf_out)
    }

    fn get_count(&mut self) -> Option<u32> {
        let mut ecx: u32 = 1;
        loop {
            ecx = ecx.wrapping_shl(1) | self.get_bit()?;
            if ecx > 0x000F_FFFF {
                return None;
            }
            if self.get_bit()? == 0 {
                return Some(ecx);
            }
        }
    }

    fn read_literal(&mut self) -> Option<u8> {
        if self.cursor >= self.data.len() {
            return None;
        }
        let b: u8 = self.data[self.cursor];
        self.cursor += 1;
        Some(b)
    }
}

#[allow(clippy::too_many_lines)]
fn decode_petite_stream_v2(
    compressed: &[u8],
    compressed_start: usize,
    output_size: u32,
) -> (Vec<u8>, bool) {
    let params: DecoderParams = DecoderParams::for_output_size(output_size);
    let mut bs: PetiteBitStream<'_> = PetiteBitStream::new(compressed, compressed_start);
    let prealloc_cap: usize = (output_size as usize)
        .min(compressed.len().saturating_mul(64))
        .min(PETITE_MAX_PREALLOC);
    let mut output: Vec<u8> = Vec::with_capacity(prealloc_cap);
    let mut remaining: i64 =
        i64::from(output_size).min(i64::try_from(prealloc_cap).unwrap_or(i64::MAX));
    let mut last_offset: u32 = 0xFFFF_FFFF;
    let mut steps: u64 = 0;
    let step_cap: u64 = u64::from(output_size)
        .saturating_mul(8)
        .saturating_add(1024);

    while remaining > 0 {
        steps += 1;
        if steps > step_cap {
            return (output, false);
        }
        let raw: u8 = match bs.read_literal() {
            Some(b) => b,
            None => return (output, false),
        };
        let xor_key: u8 = u8::try_from(remaining & 0xFF).unwrap_or(0);
        output.push(raw ^ xor_key);
        remaining -= 1;
        if remaining <= 0 {
            break;
        }
        let tag: u32 = match bs.get_bit() {
            Some(b) => b,
            None => return (output, false),
        };
        if tag == 0 {
            continue;
        }
        let gamma: u32 = match bs.get_count() {
            Some(g) => g,
            None => return (output, false),
        };
        let mut eax: u32;
        let mut ecx: u32;
        let ebp: u32;
        let gamma_sub3: u32 = gamma.wrapping_sub(3);
        if gamma >= 3 {
            eax = gamma_sub3;
            let mut bits_left: u32 = params.offset_bits;
            while bits_left > 0 {
                let b: u32 = match bs.get_bit() {
                    Some(b) => b,
                    None => return (output, false),
                };
                eax = eax.wrapping_shl(1) | b;
                bits_left -= 1;
            }
            eax = !eax;
            let cf1: u32 = u32::from(eax < params.threshold_b);
            let cf2: u32 = u32::from(eax < params.threshold_a);
            ebp = 1 + cf1 + cf2;
            last_offset = eax;
            ecx = 0;
        } else {
            eax = last_offset;
            ecx = gamma_sub3.wrapping_add(1);
            ebp = 0;
        }
        let b1: u32 = match bs.get_bit() {
            Some(b) => b,
            None => return (output, false),
        };
        ecx = ecx.wrapping_shl(1) | b1;
        let b2: u32 = match bs.get_bit() {
            Some(b) => b,
            None => return (output, false),
        };
        ecx = ecx.wrapping_shl(1) | b2;
        if ecx == 0 {
            let extra: u32 = match bs.get_count() {
                Some(g) => g,
                None => return (output, false),
            };
            ecx = extra.wrapping_add(2);
        }
        ecx = ecx.wrapping_add(ebp);
        if i64::from(ecx) > remaining + 8 {
            return (output, false);
        }
        let take: i64 = i64::from(ecx).min(remaining);
        remaining -= take;
        let eax_signed: i64 = if eax >= 0x8000_0000 {
            i64::from(eax) - 0x1_0000_0000
        } else {
            i64::from(eax)
        };
        let out_len_i64: i64 = i64::try_from(output.len()).unwrap_or(i64::MAX);
        let mut src_pos: i64 = out_len_i64 + eax_signed;
        let mut copied: i64 = 0;
        while copied < take {
            let byte: u8 = if src_pos < 0 {
                0
            } else {
                let idx: usize = usize::try_from(src_pos).unwrap_or(usize::MAX);
                if idx >= output.len() { 0 } else { output[idx] }
            };
            output.push(byte);
            src_pos += 1;
            copied += 1;
        }
    }
    let fully: bool = u32::try_from(output.len()).is_ok_and(|n: u32| n == output_size);
    (output, fully)
}

fn parse_petite_import_table(packed: &PackedPetite<'_>) -> Result<Vec<RecoveredImport>> {
    let mut imports: BTreeMap<String, RecoveredImport> = BTreeMap::new();
    let mut scan_section = |start: usize, len: usize| -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        if start
            .checked_add(len)
            .map_or(true, |end: usize| end > packed.raw.len())
        {
            return Ok(());
        }
        let data: &[u8] = &packed.raw[start..start + len];
        let strings: Vec<(usize, &str, u16)> = scan_petite_strings(data);
        let dll_indices: Vec<usize> = strings
            .iter()
            .enumerate()
            .filter_map(
                |(i, (_, s, _)): (usize, &(usize, &str, u16))| {
                    if is_dll_name(s) { Some(i) } else { None }
                },
            )
            .collect();
        if dll_indices.is_empty() {
            return Ok(());
        }
        let mut function_cursor: usize = 0;
        for (k, dll_idx) in dll_indices.iter().copied().enumerate() {
            let dll_name: String = strings[dll_idx].1.to_string();
            let next_dll_idx: usize = dll_indices.get(k + 1).copied().unwrap_or(strings.len());
            let function_end: usize = dll_idx;
            let take: usize = function_end.saturating_sub(function_cursor);
            let mut funcs: Vec<RecoveredImportFn> = Vec::with_capacity(take);
            for (_, name, hint) in strings.iter().take(function_end).skip(function_cursor) {
                funcs.push(RecoveredImportFn {
                    name: (*name).to_string(),
                    hint: *hint,
                });
            }
            let key: String = dll_name.to_ascii_lowercase();
            imports
                .entry(key)
                .and_modify(|entry: &mut RecoveredImport| {
                    entry.functions.extend(funcs.iter().cloned());
                })
                .or_insert(RecoveredImport {
                    dll: dll_name,
                    functions: funcs,
                });
            function_cursor = next_dll_idx;
        }
        Ok(())
    };

    let petite_sec: &PeSection = &packed.image.sections[packed.petite_section];
    scan_section(
        petite_sec.raw_pointer as usize,
        petite_sec.raw_size as usize,
    )?;

    for (idx, sec) in packed.image.sections.iter().enumerate() {
        if idx == packed.petite_section {
            continue;
        }
        scan_section(sec.raw_pointer as usize, sec.raw_size as usize)?;
    }

    Ok(imports.into_values().collect())
}

fn scan_petite_strings(data: &[u8]) -> Vec<(usize, &str, u16)> {
    let mut out: Vec<(usize, &str, u16)> = Vec::new();
    let mut i: usize = 0;
    while i < data.len() {
        while i < data.len() && data[i] == 0 {
            i += 1;
        }
        if i >= data.len() {
            break;
        }
        let start: usize = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        let raw: &[u8] = &data[start..i];
        if raw.len() < 3 {
            continue;
        }
        if !raw.iter().all(|b: &u8| (32..=126).contains(b)) {
            continue;
        }
        let Ok(s): std::result::Result<&str, _> = std::str::from_utf8(raw) else {
            continue;
        };
        let hint: u16 = if start >= 2 {
            u16::from_le_bytes([data[start - 2], data[start - 1]])
        } else {
            0
        };
        out.push((start, s, hint));
    }
    out
}

fn is_dll_name(s: &str) -> bool {
    let bytes: &[u8] = s.as_bytes();
    if bytes.len() < 5 || bytes[bytes.len() - 4] != b'.' {
        return false;
    }
    let suffix: [u8; 3] = [
        bytes[bytes.len() - 3].to_ascii_lowercase(),
        bytes[bytes.len() - 2].to_ascii_lowercase(),
        bytes[bytes.len() - 1].to_ascii_lowercase(),
    ];
    matches!(&suffix, b"dll" | b"drv" | b"ocx")
}

#[derive(Debug, Clone)]
struct Reconstruction {
    bytes: Vec<u8>,
    deterministic_bytes: usize,
    original_sections: Vec<PeSection>,
}

#[allow(clippy::too_many_lines)]
fn reconstruct_image(
    packed: &PackedPetite<'_>,
    stream: &DecodedStream,
    imports: &[RecoveredImport],
) -> Result<Reconstruction> {
    let original_sections: Vec<PeSection> = infer_original_sections(packed, stream);
    let import_dir_bytes: Vec<u8> = build_import_directory(imports);
    let import_dir_rva: u32 = pick_import_directory_rva(packed);

    let file_alignment: u32 = if packed.image.file_alignment == 0 {
        FILE_ALIGNMENT_DEFAULT
    } else {
        packed.image.file_alignment
    };
    let section_alignment: u32 = if packed.image.section_alignment == 0 {
        SECTION_ALIGNMENT_DEFAULT
    } else {
        packed.image.section_alignment
    };

    let nt_off: usize = (packed.image.pe_header_offset as usize).max(DOS_HEADER_SIZE);
    let nt_headers_end: usize = nt_off
        + PE_SIGNATURE_LEN
        + COFF_HEADER_LEN
        + OPTIONAL_HEADER_STANDARD_LEN
        + SECTION_HEADER_LEN * original_sections.len();
    let headers_size: u32 = align_up(
        u32::try_from(nt_headers_end)
            .map_err(|_| Error::GoblinParse("header size overflowed u32".into()))?,
        file_alignment,
    );

    let mut total_raw: u32 = headers_size;
    let mut raw_offsets: Vec<u32> = Vec::with_capacity(original_sections.len());
    for sec in &original_sections {
        raw_offsets.push(total_raw);
        let raw: u32 = align_up(sec.raw_size, file_alignment);
        total_raw = total_raw
            .checked_add(raw)
            .ok_or_else(|| Error::GoblinParse("section raw size overflowed".into()))?;
    }

    let total_raw_usize: usize = total_raw as usize;
    let image_ceiling: usize =
        PETITE_MAX_PREALLOC.min(packed.raw.len().saturating_mul(PETITE_MAX_IMAGE_RATIO));
    if total_raw_usize > image_ceiling {
        return Err(Error::GoblinParse(format!(
            "Petite: reconstructed image size {total_raw_usize} exceeds safety ceiling \
             {image_ceiling} (packed input {} bytes) - refusing oversized allocation",
            packed.raw.len()
        )));
    }
    let mut image: Vec<u8> = vec![0u8; total_raw_usize];
    let dos_prefix_len: usize = nt_off.min(packed.raw.len());
    image[..dos_prefix_len].copy_from_slice(&packed.raw[..dos_prefix_len]);
    image[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
        .copy_from_slice(&u32::try_from(nt_off).unwrap_or(0).to_le_bytes());
    image[nt_off..nt_off + 4].copy_from_slice(b"PE\x00\x00");
    let coff_off: usize = nt_off + 4;
    image[coff_off..coff_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    image[coff_off + 2..coff_off + 4].copy_from_slice(
        &u16::try_from(original_sections.len())
            .map_err(|_| Error::GoblinParse("section count overflowed u16".into()))?
            .to_le_bytes(),
    );
    let timestamp: u32 = 0;
    image[coff_off + 4..coff_off + 8].copy_from_slice(&timestamp.to_le_bytes());
    let ptr_to_symtab: u32 = 0;
    image[coff_off + 8..coff_off + 12].copy_from_slice(&ptr_to_symtab.to_le_bytes());
    let num_symtab: u32 = 0;
    image[coff_off + 12..coff_off + 16].copy_from_slice(&num_symtab.to_le_bytes());
    image[coff_off + 16..coff_off + 18]
        .copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_SIZE.to_le_bytes());
    image[coff_off + 18..coff_off + 20]
        .copy_from_slice(&packed.image.coff_characteristics.to_le_bytes());

    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    image[opt_off..opt_off + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
    image[opt_off + 16..opt_off + 20].copy_from_slice(&packed.image.entry_point_rva.to_le_bytes());
    let image_base: u32 = u32::try_from(packed.image.image_base)
        .map_err(|_| Error::GoblinParse("Petite PE32 image base exceeded u32".into()))?;
    image[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
    image[opt_off + 32..opt_off + 36].copy_from_slice(&section_alignment.to_le_bytes());
    image[opt_off + 36..opt_off + 40].copy_from_slice(&file_alignment.to_le_bytes());
    let size_of_image: u32 = compute_size_of_image(&original_sections, section_alignment);
    image[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
    image[opt_off + 60..opt_off + 64].copy_from_slice(&headers_size.to_le_bytes());
    let num_data_dirs: u32 = 16;
    image[opt_off + 92..opt_off + 96].copy_from_slice(&num_data_dirs.to_le_bytes());

    let import_dir_off: usize = opt_off + 96 + 8;
    image[import_dir_off..import_dir_off + 4].copy_from_slice(&import_dir_rva.to_le_bytes());
    image[import_dir_off + 4..import_dir_off + 8]
        .copy_from_slice(&(import_dir_bytes.len() as u32).to_le_bytes());
    image[opt_off + 96 + 96..opt_off + 96 + 100]
        .copy_from_slice(&packed.iat_directory.virtual_address.to_le_bytes());
    image[opt_off + 96 + 100..opt_off + 96 + 104]
        .copy_from_slice(&packed.iat_directory.size.to_le_bytes());

    let sec_table_off: usize = opt_off + OPTIONAL_HEADER_STANDARD_LEN;
    let mut deterministic: usize =
        DOS_HEADER_SIZE + PE_SIGNATURE_LEN + COFF_HEADER_LEN + OPTIONAL_HEADER_STANDARD_LEN;

    for (i, sec) in original_sections.iter().enumerate() {
        let s: usize = sec_table_off + i * SECTION_HEADER_LEN;
        image[s..s + 8].copy_from_slice(&sec.name);
        image[s + 8..s + 12].copy_from_slice(&sec.virtual_size.to_le_bytes());
        image[s + 12..s + 16].copy_from_slice(&sec.virtual_address.to_le_bytes());
        image[s + 16..s + 20].copy_from_slice(&sec.raw_size.to_le_bytes());
        image[s + 20..s + 24].copy_from_slice(&raw_offsets[i].to_le_bytes());
        image[s + 24..s + 28].copy_from_slice(&0u32.to_le_bytes());
        image[s + 28..s + 32].copy_from_slice(&0u32.to_le_bytes());
        image[s + 32..s + 34].copy_from_slice(&0u16.to_le_bytes());
        image[s + 34..s + 36].copy_from_slice(&0u16.to_le_bytes());
        image[s + 36..s + 40].copy_from_slice(&sec.characteristics.to_le_bytes());
        deterministic += SECTION_HEADER_LEN;
    }

    let payload_va: u32 = packed.image.sections[packed.payload_section].virtual_address;
    for (i, sec) in original_sections.iter().enumerate() {
        let raw_off: usize = raw_offsets[i] as usize;
        let raw_size: usize = sec.raw_size as usize;
        let dst_end: usize = raw_off + raw_size;
        if dst_end > image.len() {
            continue;
        }
        if sec.virtual_address >= payload_va {
            let stream_off: usize = (sec.virtual_address - payload_va) as usize;
            if stream_off < stream.bytes.len() {
                let avail: usize = stream.bytes.len() - stream_off;
                let take: usize = raw_size.min(avail);
                image[raw_off..raw_off + take]
                    .copy_from_slice(&stream.bytes[stream_off..stream_off + take]);
                if stream.fully_decoded {
                    deterministic += take;
                }
            }
        }
        if covers_import_dir(sec, import_dir_rva, &import_dir_bytes) {
            let dst: usize = raw_off + (import_dir_rva - sec.virtual_address) as usize;
            let import_end: usize = dst + import_dir_bytes.len();
            if import_end <= image.len() {
                image[dst..import_end].copy_from_slice(&import_dir_bytes);
                deterministic += import_dir_bytes.len();
            }
        }
    }

    Ok(Reconstruction {
        bytes: image,
        deterministic_bytes: deterministic,
        original_sections,
    })
}

const SECTION_GAP_MIN_ZEROS: u32 = 64;

#[derive(Debug, Clone)]
struct EmulatedReconstruction {
    bytes: Vec<u8>,
    deterministic_bytes: usize,
    section_count: u16,
}

#[derive(Debug, Clone, Copy)]
struct DerivedSection {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

fn restore_consumed_import_strings(
    image: &mut [u8],
    pre_resolution: &[u8],
    region_start: u32,
    region_end: u32,
) {
    if pre_resolution.is_empty() {
        return;
    }
    let lo: usize = region_start as usize;
    let hi: usize = (region_end as usize)
        .min(image.len())
        .min(pre_resolution.len());
    for i in lo..hi {
        if image[i] == 0 && pre_resolution[i] != 0 {
            image[i] = pre_resolution[i];
        }
    }
}

fn rebuild_iat_from_oft(mem: &mut [u8]) {
    let Ok(e_lfanew): Result<u32> = read_u32_le(mem, FILE_HEADER_OFFSET_E_LFANEW) else {
        return;
    };
    let opt_off: usize = e_lfanew as usize + PE_SIGNATURE_LEN + COFF_HEADER_LEN;
    let Ok(import_dir_rva): Result<u32> = read_u32_le(mem, opt_off + 96 + 8) else {
        return;
    };
    if import_dir_rva == 0 {
        return;
    }
    let mut descriptor: usize = 0;
    loop {
        let d: usize = import_dir_rva as usize + descriptor * 20;
        if d + 20 > mem.len() {
            break;
        }
        let oft_rva: u32 = read_u32_le(mem, d).unwrap_or(0);
        let name_rva: u32 = read_u32_le(mem, d + 12).unwrap_or(0);
        let ft_rva: u32 = read_u32_le(mem, d + 16).unwrap_or(0);
        if oft_rva == 0 && name_rva == 0 && ft_rva == 0 {
            break;
        }
        if oft_rva != 0 && ft_rva != 0 && oft_rva != ft_rva {
            let mut entry: usize = 0;
            loop {
                let oft_off: usize = oft_rva as usize + entry * 4;
                let ft_off: usize = ft_rva as usize + entry * 4;
                if oft_off + 4 > mem.len() || ft_off + 4 > mem.len() {
                    break;
                }
                let oft_val: u32 = read_u32_le(mem, oft_off).unwrap_or(0);
                mem[ft_off..ft_off + 4].copy_from_slice(&oft_val.to_le_bytes());
                if oft_val == 0 {
                    break;
                }
                entry += 1;
                if entry > 0x1000 {
                    break;
                }
            }
        }
        descriptor += 1;
        if descriptor > 256 {
            break;
        }
    }
}

#[allow(clippy::too_many_lines)]
fn reconstruct_from_memory_image(
    packed: &PackedPetite<'_>,
    mem_post: &[u8],
    pre_resolution: &[u8],
) -> Option<EmulatedReconstruction> {
    let section_alignment: u32 = if packed.image.section_alignment == 0 {
        SECTION_ALIGNMENT_DEFAULT
    } else {
        packed.image.section_alignment
    };
    let file_alignment: u32 = if packed.image.file_alignment == 0 {
        FILE_ALIGNMENT_DEFAULT
    } else {
        packed.image.file_alignment
    };

    let e_lfanew: usize = read_u32_le(mem_post, FILE_HEADER_OFFSET_E_LFANEW).ok()? as usize;
    if mem_post.get(e_lfanew..e_lfanew + 4)? != b"PE\x00\x00" {
        return None;
    }
    let coff_off: usize = e_lfanew + PE_SIGNATURE_LEN;
    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    let mem_optional_len: u16 = read_u16_le(mem_post, coff_off + 16).ok()?;
    let mem_section_count: usize = read_u16_le(mem_post, coff_off + 2).ok()? as usize;
    let mem_sec_table: usize = opt_off + mem_optional_len as usize;

    let original_size_of_image: u32 = (0..mem_section_count)
        .find_map(|i: usize| {
            let s: usize = mem_sec_table + i * SECTION_HEADER_LEN;
            let name: &[u8] = mem_post.get(s..s + 8)?;
            if name.starts_with(b"petite") || name.starts_with(b".petite") {
                read_u32_le(mem_post, s + 12).ok()
            } else {
                None
            }
        })
        .unwrap_or(packed.image.size_of_image);
    if original_size_of_image <= section_alignment {
        return None;
    }

    let starts: Vec<u32> =
        detect_section_starts(mem_post, original_size_of_image, section_alignment);
    if starts.is_empty() {
        return None;
    }

    let mut mem: Vec<u8> = mem_post.to_vec();
    if starts.len() >= 2 {
        let rdata_start: u32 = starts[1];
        let rdata_end: u32 = starts.get(2).copied().unwrap_or(original_size_of_image);
        restore_consumed_import_strings(&mut mem, pre_resolution, rdata_start, rdata_end);
        rebuild_iat_from_oft(&mut mem);
    }
    let mem: &[u8] = &mem;

    let size_of_headers: u32 = if packed.image.size_of_headers == 0 {
        align_up(0x400, file_alignment)
    } else {
        packed.image.size_of_headers
    };

    let mut derived: Vec<DerivedSection> = Vec::with_capacity(starts.len());
    let mut raw_cursor: u32 = size_of_headers;
    for (idx, &start) in starts.iter().enumerate() {
        let end: u32 = starts
            .get(idx + 1)
            .copied()
            .unwrap_or(original_size_of_image);
        let virtual_size: u32 = section_virtual_size(mem, start, end);
        let raw_size: u32 = align_up(virtual_size, file_alignment);
        let name: [u8; 8] = default_section_name(idx, starts.len());
        let characteristics: u32 = default_section_characteristics(idx, starts.len());
        derived.push(DerivedSection {
            name,
            virtual_address: start,
            virtual_size,
            raw_size,
            pointer_to_raw_data: raw_cursor,
            characteristics,
        });
        raw_cursor = raw_cursor.checked_add(raw_size)?;
    }

    let total: usize = raw_cursor as usize;
    let image_ceiling: usize =
        PETITE_MAX_PREALLOC.min(packed.raw.len().saturating_mul(PETITE_MAX_IMAGE_RATIO));
    if total == 0 || total > image_ceiling {
        return None;
    }

    let mut out: Vec<u8> = vec![0u8; total];
    let header_copy: usize = (size_of_headers as usize).min(mem.len()).min(out.len());
    out[..header_copy].copy_from_slice(&mem[..header_copy]);

    let section_count: u16 = u16::try_from(derived.len()).ok()?;
    write_reconstructed_header(
        &mut out,
        packed,
        &derived,
        e_lfanew,
        size_of_headers,
        original_size_of_image,
        section_alignment,
        file_alignment,
        section_count,
    )?;

    let mut deterministic: usize = header_copy;
    for sec in &derived {
        let va: usize = sec.virtual_address as usize;
        let ptr: usize = sec.pointer_to_raw_data as usize;
        let raw: usize = sec.raw_size as usize;
        let take: usize = raw.min(mem.len().saturating_sub(va));
        if ptr + take <= out.len() && va + take <= mem.len() {
            out[ptr..ptr + take].copy_from_slice(&mem[va..va + take]);
            if sec.virtual_size > 0 {
                deterministic += take;
            }
        }
    }

    Some(EmulatedReconstruction {
        bytes: out,
        deterministic_bytes: deterministic,
        section_count,
    })
}

fn detect_section_starts(mem: &[u8], size_of_image: u32, section_alignment: u32) -> Vec<u32> {
    let section_alignment: u32 = section_alignment.max(SECTION_ALIGNMENT_DEFAULT);
    let mut starts: Vec<u32> = vec![section_alignment];
    let page_has_content = |page: u32| -> bool {
        let lo: usize = page as usize;
        let hi: usize = (page.saturating_add(section_alignment) as usize).min(mem.len());
        lo < hi && mem[lo..hi].iter().any(|b: &u8| *b != 0)
    };
    let mut last_content_page: u32 = section_alignment;
    let mut page: u32 = section_alignment.saturating_mul(2);
    while page < size_of_image {
        let this_has_content: bool = page_has_content(page);
        let mut zero_run: u32 = 0;
        let mut k: i64 = i64::from(page) - 1;
        while k >= 0 && mem.get(k as usize) == Some(&0) && zero_run < section_alignment {
            zero_run += 1;
            k -= 1;
        }
        if this_has_content && zero_run >= SECTION_GAP_MIN_ZEROS {
            starts.push(page);
        }
        if this_has_content {
            last_content_page = page;
        }
        page += section_alignment;
    }
    let trailing: u32 = last_content_page.saturating_add(section_alignment);
    if trailing < size_of_image && !starts.contains(&trailing) {
        starts.push(trailing);
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

fn section_virtual_size(mem: &[u8], start: u32, end: u32) -> u32 {
    let lo: usize = start as usize;
    let hi: usize = (end as usize).min(mem.len());
    if lo >= hi {
        return end.saturating_sub(start);
    }
    mem[lo..hi]
        .iter()
        .rposition(|b: &u8| *b != 0)
        .map_or(end - start, |off: usize| {
            u32::try_from(off + 1).unwrap_or(end - start)
        })
}

fn default_section_name(index: usize, count: usize) -> [u8; 8] {
    if index == 0 {
        *b".text\x00\x00\x00"
    } else if index + 1 == count {
        *b".reloc\x00\x00"
    } else if index == 1 {
        *b".rdata\x00\x00"
    } else {
        *b".data\x00\x00\x00"
    }
}

fn default_section_characteristics(index: usize, count: usize) -> u32 {
    if index == 0 {
        0x6000_0020
    } else if index + 1 == count {
        0x4200_0040
    } else {
        0xC000_0040
    }
}

#[allow(clippy::too_many_arguments)]
fn write_reconstructed_header(
    out: &mut [u8],
    packed: &PackedPetite<'_>,
    sections: &[DerivedSection],
    e_lfanew: usize,
    size_of_headers: u32,
    size_of_image: u32,
    section_alignment: u32,
    file_alignment: u32,
    section_count: u16,
) -> Option<()> {
    out.get(0x3c..0x40)?;
    out[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
        .copy_from_slice(&u32::try_from(e_lfanew).ok()?.to_le_bytes());
    out.get(e_lfanew..e_lfanew + 4)?;
    out[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\x00\x00");
    let coff_off: usize = e_lfanew + PE_SIGNATURE_LEN;
    out[coff_off..coff_off + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
    out[coff_off + 2..coff_off + 4].copy_from_slice(&section_count.to_le_bytes());
    out[coff_off + 16..coff_off + 18].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_SIZE.to_le_bytes());
    out[coff_off + 18..coff_off + 20]
        .copy_from_slice(&packed.image.coff_characteristics.to_le_bytes());

    let opt_off: usize = coff_off + COFF_HEADER_LEN;
    out[opt_off..opt_off + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
    out[opt_off + 16..opt_off + 20].copy_from_slice(&packed.image.entry_point_rva.to_le_bytes());
    let image_base: u32 = u32::try_from(packed.image.image_base).ok()?;
    out[opt_off + 28..opt_off + 32].copy_from_slice(&image_base.to_le_bytes());
    out[opt_off + 32..opt_off + 36].copy_from_slice(&section_alignment.to_le_bytes());
    out[opt_off + 36..opt_off + 40].copy_from_slice(&file_alignment.to_le_bytes());
    out[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
    out[opt_off + 60..opt_off + 64].copy_from_slice(&size_of_headers.to_le_bytes());

    let sec_table_off: usize = opt_off + OPTIONAL_HEADER_STANDARD_LEN;
    for (i, sec) in sections.iter().enumerate() {
        let s: usize = sec_table_off + i * SECTION_HEADER_LEN;
        out.get(s..s + SECTION_HEADER_LEN)?;
        out[s..s + 8].copy_from_slice(&sec.name);
        out[s + 8..s + 12].copy_from_slice(&sec.virtual_size.to_le_bytes());
        out[s + 12..s + 16].copy_from_slice(&sec.virtual_address.to_le_bytes());
        out[s + 16..s + 20].copy_from_slice(&sec.raw_size.to_le_bytes());
        out[s + 20..s + 24].copy_from_slice(&sec.pointer_to_raw_data.to_le_bytes());
        out[s + 24..s + 36].copy_from_slice(&[0u8; 12]);
        out[s + 36..s + 40].copy_from_slice(&sec.characteristics.to_le_bytes());
    }
    Some(())
}

fn infer_original_sections(packed: &PackedPetite<'_>, _stream: &DecodedStream) -> Vec<PeSection> {
    let payload: &PeSection = &packed.image.sections[packed.payload_section];
    let packed_total: u32 = u32::try_from(packed.raw.len()).unwrap_or(payload.virtual_size);
    let heuristic_unpacked: u32 = packed_total.saturating_mul(18).saturating_div(10);
    let estimated_unpacked: u32 = heuristic_unpacked
        .max(packed_total)
        .min(payload.virtual_size.saturating_mul(8));
    let raw_size: u32 = align_up(estimated_unpacked, FILE_ALIGNMENT_DEFAULT);
    let single: PeSection = PeSection {
        name: *b".text\x00\x00\x00",
        virtual_size: estimated_unpacked,
        virtual_address: payload.virtual_address,
        raw_size,
        raw_pointer: 0,
        pointer_to_relocations: 0,
        characteristics: 0x6000_0020,
    };
    vec![single]
}

fn pick_import_directory_rva(packed: &PackedPetite<'_>) -> u32 {
    let payload: &PeSection = &packed.image.sections[packed.payload_section];
    let preferred: u32 = packed.import_directory_rva;
    if preferred >= payload.virtual_address
        && preferred < payload.virtual_address.saturating_add(payload.virtual_size)
    {
        preferred
    } else {
        payload.virtual_address
    }
}

fn build_import_directory(imports: &[RecoveredImport]) -> Vec<u8> {
    if imports.is_empty() {
        return Vec::new();
    }
    let descriptor_size: usize = 20;
    let table_bytes: usize = descriptor_size * (imports.len() + 1);
    let iat_base: u32 = table_bytes as u32;
    let total_iat_bytes: u32 = imports
        .iter()
        .map(|imp: &RecoveredImport| ((imp.functions.len() + 1) * 4) as u32)
        .sum();
    let name_base: u32 = iat_base + total_iat_bytes;
    let total_name_bytes: u32 = imports
        .iter()
        .map(|imp: &RecoveredImport| (imp.dll.len() + 1) as u32)
        .sum();
    let hint_base: u32 = name_base + total_name_bytes;

    let mut idt: Vec<u8> = Vec::with_capacity(table_bytes);
    let mut iat_blob: Vec<u8> = Vec::with_capacity(total_iat_bytes as usize);
    let mut name_blob: Vec<u8> = Vec::with_capacity(total_name_bytes as usize);
    let mut hint_name_blob: Vec<u8> = Vec::new();

    let mut iat_cursor: u32 = iat_base;
    let mut name_cursor: u32 = name_base;
    let mut hint_cursor: u32 = hint_base;

    for imp in imports {
        idt.extend_from_slice(&0u32.to_le_bytes());
        idt.extend_from_slice(&0u32.to_le_bytes());
        idt.extend_from_slice(&0u32.to_le_bytes());
        idt.extend_from_slice(&name_cursor.to_le_bytes());
        idt.extend_from_slice(&iat_cursor.to_le_bytes());

        for func in &imp.functions {
            iat_blob.extend_from_slice(&hint_cursor.to_le_bytes());
            let name_bytes: &[u8] = func.name.as_bytes();
            hint_name_blob.extend_from_slice(&func.hint.to_le_bytes());
            hint_name_blob.extend_from_slice(name_bytes);
            hint_name_blob.push(0);
            if hint_name_blob.len() % 2 == 1 {
                hint_name_blob.push(0);
            }
            let entry_size: u32 = 2u32
                .saturating_add(name_bytes.len() as u32)
                .saturating_add(1)
                .saturating_add((name_bytes.len() as u32) & 1);
            hint_cursor = hint_cursor.saturating_add(entry_size);
        }
        iat_blob.extend_from_slice(&0u32.to_le_bytes());
        iat_cursor = iat_cursor.saturating_add(((imp.functions.len() + 1) * 4) as u32);

        name_blob.extend_from_slice(imp.dll.as_bytes());
        name_blob.push(0);
        name_cursor = name_cursor.saturating_add((imp.dll.len() + 1) as u32);
    }
    idt.resize(idt.len() + descriptor_size, 0);

    let mut out: Vec<u8> =
        Vec::with_capacity(idt.len() + iat_blob.len() + name_blob.len() + hint_name_blob.len());
    out.extend_from_slice(&idt);
    out.extend_from_slice(&iat_blob);
    out.extend_from_slice(&name_blob);
    out.extend_from_slice(&hint_name_blob);
    out
}

fn covers_import_dir(sec: &PeSection, rva: u32, blob: &[u8]) -> bool {
    let end: u32 = rva.saturating_add(blob.len() as u32);
    rva >= sec.virtual_address
        && end
            <= sec
                .virtual_address
                .saturating_add(sec.virtual_size.max(sec.raw_size))
}

fn compute_size_of_image(sections: &[PeSection], alignment: u32) -> u32 {
    let mut hi: u32 = 0;
    for sec in sections {
        let end: u32 = sec.virtual_address.saturating_add(sec.virtual_size);
        if end > hi {
            hi = end;
        }
    }
    align_up(hi, alignment)
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    let mask: u32 = alignment - 1;
    value.wrapping_add(mask) & !mask
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_minimal_petite_pe(payload_compressed: &[u8], petite_meta: &[u8]) -> Vec<u8> {
        let dos_stub_size: usize = 0xE8;
        let opt_hdr_full: usize = IMAGE_NT_OPTIONAL_HDR32_SIZE as usize;
        let nt_total: usize =
            PE_SIGNATURE_LEN + COFF_HEADER_LEN + opt_hdr_full + SECTION_HEADER_LEN * 2;
        let headers_size: usize = align_up((dos_stub_size + nt_total) as u32, 0x200) as usize;
        let payload_raw: usize = align_up(payload_compressed.len() as u32, 0x200) as usize;
        let meta_raw: usize = align_up(petite_meta.len() as u32, 0x200) as usize;
        let total: usize = headers_size + payload_raw + meta_raw;
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0..2].copy_from_slice(b"MZ");
        buf[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
            .copy_from_slice(&(dos_stub_size as u32).to_le_bytes());
        let nt: usize = dos_stub_size;
        buf[nt..nt + 4].copy_from_slice(b"PE\x00\x00");
        let coff: usize = nt + 4;
        buf[coff..coff + 2].copy_from_slice(&MACHINE_I386.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_SIZE.to_le_bytes());
        let opt: usize = coff + COFF_HEADER_LEN;
        buf[opt..opt + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x0000_d204u32.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0000_0200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x0001_b000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&(headers_size as u32).to_le_bytes());
        let sec0: usize = opt + opt_hdr_full;
        buf[sec0..sec0 + 8].copy_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00");
        buf[sec0 + 8..sec0 + 12].copy_from_slice(&0x0000_d000u32.to_le_bytes());
        buf[sec0 + 12..sec0 + 16].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        buf[sec0 + 16..sec0 + 20].copy_from_slice(&(payload_raw as u32).to_le_bytes());
        buf[sec0 + 20..sec0 + 24].copy_from_slice(&(headers_size as u32).to_le_bytes());
        buf[sec0 + 36..sec0 + 40].copy_from_slice(&0x6000_0060u32.to_le_bytes());
        let sec1: usize = sec0 + SECTION_HEADER_LEN;
        buf[sec1..sec1 + 8].copy_from_slice(PETITE_SECTION_NAME);
        buf[sec1 + 8..sec1 + 12].copy_from_slice(&(petite_meta.len() as u32).to_le_bytes());
        buf[sec1 + 12..sec1 + 16].copy_from_slice(&0x0001_a000u32.to_le_bytes());
        buf[sec1 + 16..sec1 + 20].copy_from_slice(&(meta_raw as u32).to_le_bytes());
        buf[sec1 + 20..sec1 + 24]
            .copy_from_slice(&((headers_size + payload_raw) as u32).to_le_bytes());
        buf[sec1 + 36..sec1 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

        buf[headers_size..headers_size + payload_compressed.len()]
            .copy_from_slice(payload_compressed);
        let meta_off: usize = headers_size + payload_raw;
        buf[meta_off..meta_off + petite_meta.len()].copy_from_slice(petite_meta);
        buf
    }

    fn synth_petite_metadata() -> Vec<u8> {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"MessageBoxA\x00");
        blob.extend_from_slice(&[0x41u8, 0u8]);
        blob.extend_from_slice(b"wsprintfA\x00");
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"user32.dll\x00");
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"ExitProcess\x00");
        blob.extend_from_slice(&[0u8, 0u8]);
        blob.extend_from_slice(b"kernel32.dll\x00");
        blob
    }

    #[test]
    fn rejects_non_pe_input() {
        let err: Error = unpack_petite(b"not a pe").unwrap_err();
        matches!(err, Error::Truncated { .. } | Error::UnknownFormat);
    }

    #[test]
    fn rejects_pe64_machine() {
        let mut buf: Vec<u8> = vec![0u8; 512];
        buf[..2].copy_from_slice(b"MZ");
        buf[FILE_HEADER_OFFSET_E_LFANEW..FILE_HEADER_OFFSET_E_LFANEW + 4]
            .copy_from_slice(&64u32.to_le_bytes());
        buf[64..68].copy_from_slice(b"PE\x00\x00");
        buf[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        let err: Error = unpack_petite(&buf).unwrap_err();
        matches!(err, Error::GoblinParse(_));
    }

    #[test]
    fn synthetic_pe_recovers_imports() {
        let payload: Vec<u8> = vec![0u8; 32];
        let petite_meta: Vec<u8> = synth_petite_metadata();
        let pe: Vec<u8> = build_minimal_petite_pe(&payload, &petite_meta);
        let parsed: PackedPetite<'_> = parse_packed_petite(&pe).expect("Petite layout");
        assert_eq!(parsed.image.pe_header_offset, 0xE8);
        assert_eq!(parsed.image.machine, MACHINE_I386);
        assert_eq!(
            parsed.image.size_of_optional_header,
            IMAGE_NT_OPTIONAL_HDR32_SIZE
        );
        assert_eq!(parsed.image.image_base, 0x0040_0000);
        assert_eq!(parsed.image.entry_point_rva, 0x0000_D204);
        assert_eq!(parsed.image.section_alignment, 0x1000);
        assert_eq!(parsed.image.file_alignment, 0x200);
        assert_eq!(parsed.image.size_of_image, 0x0001_B000);
        assert_eq!(parsed.image.sections.len(), 2);
        assert_eq!(parsed.image.sections[0].virtual_address, 0x1000);
        assert_eq!(
            parsed.image.sections[0].raw_pointer,
            parsed.image.size_of_headers
        );
        assert_eq!(parsed.image.sections[1].name, *PETITE_SECTION_NAME);
        assert_eq!(
            parsed
                .image
                .raw_data_directories
                .get(1)
                .map(|directory: &DataDirectory| directory.virtual_address),
            Some(parsed.import_directory_rva)
        );
        assert_eq!(
            parsed.image.raw_data_directories.get(12),
            Some(&parsed.iat_directory)
        );
        let result: UnpackResult =
            unpack_petite_with_report(&pe).expect("synthetic Petite PE must parse");
        assert!(
            !result.report.recovered_imports.is_empty(),
            "must recover at least one import: {:?}",
            result.report
        );
        let dlls: Vec<&str> = result
            .report
            .recovered_imports
            .iter()
            .map(|i: &RecoveredImport| i.dll.as_str())
            .collect();
        assert!(
            dlls.iter()
                .any(|d: &&str| d.eq_ignore_ascii_case("user32.dll")),
            "expected user32.dll among recovered DLLs: {dlls:?}"
        );
        assert!(
            dlls.iter()
                .any(|d: &&str| d.eq_ignore_ascii_case("kernel32.dll")),
            "expected kernel32.dll among recovered DLLs: {dlls:?}"
        );
    }

    #[test]
    fn synthetic_pe_recovered_blob_starts_with_mz() {
        let payload: Vec<u8> = vec![0u8; 32];
        let petite_meta: Vec<u8> = synth_petite_metadata();
        let pe: Vec<u8> = build_minimal_petite_pe(&payload, &petite_meta);
        let recovered: Vec<u8> = unpack_petite(&pe).expect("recovery must succeed");
        assert!(recovered.starts_with(b"MZ"), "recovered must begin with MZ");
        assert!(
            recovered.len() >= 256,
            "recovered must contain headers + sections"
        );
    }

    #[test]
    fn align_up_is_idempotent_on_aligned_values() {
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0, 0x200), 0);
    }

    #[test]
    fn is_dll_name_recognizes_common_suffixes() {
        assert!(is_dll_name("user32.dll"));
        assert!(is_dll_name("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL"));
        assert!(is_dll_name("kbdus.drv"));
        assert!(!is_dll_name("MessageBoxA"));
    }

    #[test]
    fn oversized_payload_virtual_size_does_not_allocate_gigabytes() {
        let payload: Vec<u8> = vec![0u8; 32];
        let petite_meta: Vec<u8> = synth_petite_metadata();
        let mut pe: Vec<u8> = build_minimal_petite_pe(&payload, &petite_meta);
        let nt: usize = 0xE8;
        let opt: usize = nt + 4 + COFF_HEADER_LEN;
        let sec0: usize = opt + IMAGE_NT_OPTIONAL_HDR32_SIZE as usize;
        pe[sec0 + 8..sec0 + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        pe[sec0 + 16..sec0 + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let start: std::time::Instant = std::time::Instant::now();
        let result: Result<Vec<u8>> = unpack_petite(&pe);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "crafted ~4 GiB section sizes must never trigger a multi-GiB allocation"
        );
        if let Ok(image) = result {
            assert!(
                image.len() <= PETITE_MAX_PREALLOC,
                "reconstructed image must respect the {PETITE_MAX_PREALLOC}-byte ceiling, got {}",
                image.len()
            );
        }
    }

    #[test]
    fn oversized_virtual_size_with_valid_raw_size_stays_bounded() {
        let payload: Vec<u8> = vec![0u8; 32];
        let petite_meta: Vec<u8> = synth_petite_metadata();
        let mut pe: Vec<u8> = build_minimal_petite_pe(&payload, &petite_meta);
        let nt: usize = 0xE8;
        let opt: usize = nt + 4 + COFF_HEADER_LEN;
        let sec0: usize = opt + IMAGE_NT_OPTIONAL_HDR32_SIZE as usize;
        pe[sec0 + 8..sec0 + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let start: std::time::Instant = std::time::Instant::now();
        let result: Result<Vec<u8>> = unpack_petite(&pe);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "a 4 GiB virtual size over a small valid raw section must never drive a 4 GiB allocation"
        );
        if let Ok(image) = result {
            assert!(
                image.len() <= PETITE_MAX_PREALLOC,
                "padded fallback stream must respect the {PETITE_MAX_PREALLOC}-byte ceiling, got {}",
                image.len()
            );
        }
    }

    #[test]
    fn v2_decode_output_is_input_proportional_not_declared_size() {
        let compressed: Vec<u8> = vec![0xABu8; 64];
        let declared_output: u32 = 0xFFFF_FFFF;
        let start: std::time::Instant = std::time::Instant::now();
        let (out, fully): (Vec<u8>, bool) =
            decode_petite_stream_v2(&compressed, 0, declared_output);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "a 4 GiB declared output over a 64-byte stream must never allocate the declared size"
        );
        let bound: usize = compressed.len().saturating_mul(64).min(PETITE_MAX_PREALLOC);
        assert!(
            out.len() <= bound,
            "decoded output must stay within the input-proportional bound {bound}, got {}",
            out.len()
        );
        assert!(
            !fully,
            "a hostile declared size can never report a full decode"
        );
    }

    #[test]
    fn detect_section_starts_bounds_scan_under_tiny_alignment() {
        let mem: Vec<u8> = vec![0u8; 0x4000];
        let start: std::time::Instant = std::time::Instant::now();
        let starts: Vec<u32> = detect_section_starts(&mem, 1_000_000_000, 1);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(300),
            "a 1-byte SectionAlignment with a 1 GB SizeOfImage must not drive a billion-iteration scan"
        );
        assert!(
            starts
                .iter()
                .all(|s: &u32| s % SECTION_ALIGNMENT_DEFAULT == 0),
            "the clamped alignment must page-align every detected section start: {starts:?}"
        );
    }
}
