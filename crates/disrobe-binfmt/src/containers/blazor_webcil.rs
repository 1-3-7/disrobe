use std::collections::BTreeMap;

use base64::Engine as _;
use disrobe_bytes::{ByteReader, LebError, read_uleb128_at};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::containers::bare_stream::{
    GzipMember, decompress_brotli, decompress_gzip_members, detect_gzip,
};
use crate::containers::dotnet_bundle::{BundleFileType, DotnetBundleEntry};
use crate::error::{Error, Result};
use crate::native_image::{NativeImage, parse_native_image};
use crate::quota::{ExtractionQuota, QuotaGuard, sanitize_entry_path};

pub const WEBCIL_MAGIC: &[u8; 4] = b"WbIL";
pub const WASM_MAGIC: &[u8; 4] = &[0x00, 0x61, 0x73, 0x6d];

const WEBCIL_HEADER_V0_LEN: usize = 28;
const WEBCIL_HEADER_V1_LEN: usize = 32;
const WEBCIL_MAX_MAJOR_VERSION: u16 = 1;
const WEBCIL_SECTION_LEN: usize = 16;
const MAX_WEBCIL_SECTIONS: usize = 96;

const WASM_DATA_SECTION_ID: u8 = 11;
const WASM_PASSIVE_SEGMENT_FLAG: u64 = 1;
const MAX_WASM_DATA_SEGMENTS: u64 = 1024;

const PE_FILE_ALIGNMENT: u32 = 0x200;
const PE_SECTION_ALIGNMENT: u32 = 0x2000;
const PE_IMAGE_BASE: u32 = 0x0040_0000;
const PE_HEADER_ORIGIN: usize = 0x80;
const COFF_HEADER_LEN: usize = 20;
const OPTIONAL_HEADER_LEN: usize = 224;
const PE_SECTION_ENTRY_LEN: usize = 40;
const NUM_DATA_DIRECTORIES: u32 = 16;
const CLR_DIRECTORY_INDEX: usize = 14;
const DEBUG_DIRECTORY_INDEX: usize = 6;

const PE32_MAGIC: u16 = 0x010B;
const PE32PLUS_MAGIC: u16 = 0x020B;
const DOS_MAGIC: u16 = 0x5A4D;
const NT_SIGNATURE: u32 = 0x0000_4550;
const METADATA_SIGNATURE: u32 = 0x424A_5342;
const COR20_HEADER_LEN: usize = 72;
const IMAGE_SCN_CODE: u32 = 0x6000_0020;
const IMAGE_SCN_INITIALIZED_DATA: u32 = 0x4000_0040;

const MAX_BOOT_MANIFEST_LEN: usize = 64 * 1024 * 1024;
const MAX_ASSEMBLIES: usize = 100_000;
const SHA256_PREFIX: &str = "sha256-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebcilSection {
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub pointer_to_raw_data: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebcilHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub reserved0: u16,
    pub cli_header_rva: u32,
    pub cli_header_size: u32,
    pub debug_rva: u32,
    pub debug_size: u32,
    pub sections: Vec<WebcilSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlazorAssemblyKind {
    Assembly,
    Core,
    Lazy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlazorIntegrity {
    Sha256([u8; 32]),
    Unparseable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlazorAssemblyRef {
    pub manifest_key: String,
    pub integrity: BlazorIntegrity,
    pub kind: BlazorAssemblyKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlazorBoot {
    pub main_assembly_name: Option<String>,
    pub assemblies: Vec<BlazorAssemblyRef>,
    pub fingerprint_to_logical: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub struct BlazorFile<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

fn blazor_err(message: &str) -> Error {
    Error::BlazorWebcil(message.to_owned())
}

fn read_u16(reader: &mut ByteReader<'_>, field: &str) -> Result<u16> {
    reader
        .read_u16_le()
        .map_err(|_| blazor_err(&format!("truncated reading {field}")))
}

fn read_u32(reader: &mut ByteReader<'_>, field: &str) -> Result<u32> {
    reader
        .read_u32_le()
        .map_err(|_| blazor_err(&format!("truncated reading {field}")))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    disrobe_bytes::read_u16_le_at(bytes, offset).map_err(|_| blazor_err("u16 read out of bounds"))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    disrobe_bytes::read_u32_le_at(bytes, offset).map_err(|_| blazor_err("u32 read out of bounds"))
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let end: usize = offset
        .checked_add(2)
        .ok_or_else(|| blazor_err("u16 write overflow"))?;
    let dst: &mut [u8] = buf
        .get_mut(offset..end)
        .ok_or_else(|| blazor_err("u16 write out of bounds"))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end: usize = offset
        .checked_add(4)
        .ok_or_else(|| blazor_err("u32 write overflow"))?;
    let dst: &mut [u8] = buf
        .get_mut(offset..end)
        .ok_or_else(|| blazor_err("u32 write out of bounds"))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_uleb128(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let (value, consumed): (u64, usize) =
        read_uleb128_at(bytes, *cursor).map_err(|err: LebError| match err {
            LebError::OutOfBounds(_) => blazor_err("truncated uleb128"),
            LebError::Overflow { .. } => blazor_err("uleb128 encoding too long"),
        })?;
    *cursor += consumed;
    Ok(value)
}

fn align_up(value: u32, alignment: u32) -> Result<u32> {
    let step: u32 = alignment.saturating_sub(1);
    value
        .checked_add(step)
        .map(|v: u32| v & !step)
        .ok_or_else(|| blazor_err("alignment overflow"))
}

fn locate_webcil_payload(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.starts_with(WEBCIL_MAGIC) {
        Ok(bytes)
    } else if bytes.starts_with(WASM_MAGIC) {
        wasm_locate_webcil(bytes)
    } else {
        Err(blazor_err(
            "input is neither a webcil payload nor a wasm-wrapped webcil",
        ))
    }
}

fn wasm_locate_webcil(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() < 8 || !bytes.starts_with(WASM_MAGIC) {
        return Err(blazor_err("not a wasm module"));
    }
    let mut cursor: usize = 8;
    while cursor < bytes.len() {
        let section_id: u8 = *bytes
            .get(cursor)
            .ok_or_else(|| blazor_err("truncated wasm section id"))?;
        cursor += 1;
        let declared: u64 = read_uleb128(bytes, &mut cursor)?;
        let section_len: usize = usize::try_from(declared)
            .map_err(|_| blazor_err("wasm section length out of range"))?;
        let section_start: usize = cursor;
        let section_end: usize = section_start
            .checked_add(section_len)
            .ok_or_else(|| blazor_err("wasm section extent overflow"))?;
        if section_end > bytes.len() {
            return Err(blazor_err("wasm section past end of module"));
        }
        if section_id == WASM_DATA_SECTION_ID {
            return wasm_webcil_from_data_section(bytes, section_start, section_end);
        }
        cursor = section_end;
    }
    Err(blazor_err("wasm wrapper has no data section"))
}

fn wasm_webcil_from_data_section(bytes: &[u8], start: usize, end: usize) -> Result<&[u8]> {
    let mut cursor: usize = start;
    let segment_count: u64 = read_uleb128(bytes, &mut cursor)?;
    if segment_count == 0 || segment_count > MAX_WASM_DATA_SEGMENTS {
        return Err(blazor_err("wasm data section segment count out of range"));
    }
    let mut webcil: Option<(usize, usize)> = None;
    for _ in 0..segment_count {
        let flags: u64 = read_uleb128(bytes, &mut cursor)?;
        if flags != WASM_PASSIVE_SEGMENT_FLAG {
            return Err(blazor_err("wasm data segment is not passive"));
        }
        let declared: u64 = read_uleb128(bytes, &mut cursor)?;
        let size: usize = usize::try_from(declared)
            .map_err(|_| blazor_err("wasm data segment size out of range"))?;
        let seg_start: usize = cursor;
        let seg_end: usize = seg_start
            .checked_add(size)
            .ok_or_else(|| blazor_err("wasm data segment extent overflow"))?;
        if seg_end > end {
            return Err(blazor_err("wasm data segment past section end"));
        }
        let segment: &[u8] = bytes
            .get(seg_start..seg_end)
            .ok_or_else(|| blazor_err("wasm data segment slice out of range"))?;
        if segment.starts_with(WEBCIL_MAGIC) {
            webcil = Some((seg_start, seg_end));
        }
        cursor = seg_end;
    }
    let (payload_start, payload_end): (usize, usize) =
        webcil.ok_or_else(|| blazor_err("wasm data section holds no WbIL payload"))?;
    bytes
        .get(payload_start..payload_end)
        .ok_or_else(|| blazor_err("wasm payload slice out of range"))
}

pub fn parse_webcil_header(payload: &[u8]) -> Result<WebcilHeader> {
    let mut reader: ByteReader<'_> = ByteReader::new(payload);
    let magic: &[u8] = reader
        .read_bytes(4)
        .map_err(|_| blazor_err("truncated webcil magic"))?;
    if magic != WEBCIL_MAGIC {
        return Err(blazor_err("missing WbIL magic"));
    }
    let version_major: u16 = read_u16(&mut reader, "webcil version major")?;
    let version_minor: u16 = read_u16(&mut reader, "webcil version minor")?;
    if version_major > WEBCIL_MAX_MAJOR_VERSION {
        return Err(blazor_err("unsupported webcil major version"));
    }
    let coff_sections: u16 = read_u16(&mut reader, "webcil coff section count")?;
    let reserved0: u16 = read_u16(&mut reader, "webcil reserved0")?;
    let cli_header_rva: u32 = read_u32(&mut reader, "webcil cli header rva")?;
    let cli_header_size: u32 = read_u32(&mut reader, "webcil cli header size")?;
    let debug_rva: u32 = read_u32(&mut reader, "webcil debug rva")?;
    let debug_size: u32 = read_u32(&mut reader, "webcil debug size")?;
    if version_major >= 1 {
        let _table_base: u32 = read_u32(&mut reader, "webcil table base")?;
    }
    if cli_header_rva == 0 {
        return Err(blazor_err("webcil declares no cli header"));
    }
    let count: usize = usize::from(coff_sections);
    if count == 0 || count > MAX_WEBCIL_SECTIONS {
        return Err(blazor_err("webcil section count out of range"));
    }
    let header_len: usize = if version_major >= 1 {
        WEBCIL_HEADER_V1_LEN
    } else {
        WEBCIL_HEADER_V0_LEN
    };
    let table_end: usize = header_len
        .checked_add(count.saturating_mul(WEBCIL_SECTION_LEN))
        .ok_or_else(|| blazor_err("webcil section table overflow"))?;
    if table_end > payload.len() {
        return Err(blazor_err("webcil section table past end of payload"));
    }
    let mut sections: Vec<WebcilSection> = Vec::with_capacity(count);
    for _ in 0..count {
        let virtual_size: u32 = read_u32(&mut reader, "section virtual size")?;
        let virtual_address: u32 = read_u32(&mut reader, "section virtual address")?;
        let raw_size: u32 = read_u32(&mut reader, "section raw size")?;
        let pointer_to_raw_data: u32 = read_u32(&mut reader, "section pointer to raw data")?;
        sections.push(WebcilSection {
            virtual_size,
            virtual_address,
            raw_size,
            pointer_to_raw_data,
        });
    }
    Ok(WebcilHeader {
        version_major,
        version_minor,
        reserved0,
        cli_header_rva,
        cli_header_size,
        debug_rva,
        debug_size,
        sections,
    })
}

fn cli_section_index(header: &WebcilHeader) -> Option<usize> {
    header.sections.iter().position(|section: &WebcilSection| {
        let start: u32 = section.virtual_address;
        let extent: u32 = section.virtual_size.max(section.raw_size);
        let end: u32 = start.saturating_add(extent);
        header.cli_header_rva >= start && header.cli_header_rva < end
    })
}

fn synthesize_pe(payload: &[u8], header: &WebcilHeader) -> Result<Vec<u8>> {
    let count: usize = header.sections.len();
    let cli_index: usize =
        cli_section_index(header).ok_or_else(|| blazor_err("cli header rva maps to no section"))?;

    let section_table_offset: usize = PE_HEADER_ORIGIN + 4 + COFF_HEADER_LEN + OPTIONAL_HEADER_LEN;
    let headers_end: usize = section_table_offset
        .checked_add(count.saturating_mul(PE_SECTION_ENTRY_LEN))
        .ok_or_else(|| blazor_err("section table overflow"))?;
    let size_of_headers: u32 = align_up(
        u32::try_from(headers_end).unwrap_or(u32::MAX),
        PE_FILE_ALIGNMENT,
    )?;

    let mut file_pointer: u32 = size_of_headers;
    let mut placements: Vec<(u32, usize, usize)> = Vec::with_capacity(count);
    let mut max_virtual_end: u32 = 0;
    let mut base_of_code: u32 = u32::MAX;
    let mut size_of_code: u32 = 0;
    let mut size_of_initialized: u32 = 0;

    for (index, section) in header.sections.iter().enumerate() {
        let raw_start: usize = section.pointer_to_raw_data as usize;
        let raw_end: usize = raw_start
            .checked_add(section.raw_size as usize)
            .ok_or_else(|| blazor_err("section raw extent overflow"))?;
        if raw_end > payload.len() {
            return Err(blazor_err("section raw data past end of webcil payload"));
        }
        placements.push((file_pointer, raw_start, raw_end));
        file_pointer = file_pointer
            .checked_add(section.raw_size)
            .ok_or_else(|| blazor_err("file pointer overflow"))?;
        file_pointer = align_up(file_pointer, PE_FILE_ALIGNMENT)?;

        let virtual_end: u32 = section
            .virtual_address
            .checked_add(section.virtual_size.max(section.raw_size))
            .ok_or_else(|| blazor_err("section virtual extent overflow"))?;
        max_virtual_end = max_virtual_end.max(virtual_end);
        base_of_code = base_of_code.min(section.virtual_address);
        if index == cli_index {
            size_of_code = size_of_code.saturating_add(section.raw_size);
        } else {
            size_of_initialized = size_of_initialized.saturating_add(section.raw_size);
        }
    }
    if base_of_code == u32::MAX {
        base_of_code = 0;
    }

    let total_len: usize = file_pointer as usize;
    let mut image: Vec<u8> = vec![0u8; total_len];

    put_u16(&mut image, 0, DOS_MAGIC)?;
    put_u32(&mut image, 0x3C, PE_HEADER_ORIGIN as u32)?;

    let pe: usize = PE_HEADER_ORIGIN;
    put_u32(&mut image, pe, NT_SIGNATURE)?;

    let coff: usize = pe + 4;
    put_u16(&mut image, coff, 0x014C)?;
    put_u16(
        &mut image,
        coff + 2,
        u16::try_from(count).unwrap_or(u16::MAX),
    )?;
    put_u32(&mut image, coff + 4, 0)?;
    put_u32(&mut image, coff + 8, 0)?;
    put_u32(&mut image, coff + 12, 0)?;
    put_u16(&mut image, coff + 16, OPTIONAL_HEADER_LEN as u16)?;
    put_u16(&mut image, coff + 18, 0x2102)?;

    let opt: usize = coff + COFF_HEADER_LEN;
    put_u16(&mut image, opt, PE32_MAGIC)?;
    put_u16(&mut image, opt + 2, 0x0008)?;
    put_u32(&mut image, opt + 4, size_of_code)?;
    put_u32(&mut image, opt + 8, size_of_initialized)?;
    put_u32(&mut image, opt + 12, 0)?;
    put_u32(&mut image, opt + 16, 0)?;
    put_u32(&mut image, opt + 20, base_of_code)?;
    put_u32(&mut image, opt + 24, 0)?;
    put_u32(&mut image, opt + 28, PE_IMAGE_BASE)?;
    put_u32(&mut image, opt + 32, PE_SECTION_ALIGNMENT)?;
    put_u32(&mut image, opt + 36, PE_FILE_ALIGNMENT)?;
    put_u16(&mut image, opt + 40, 4)?;
    put_u16(&mut image, opt + 42, 0)?;
    put_u16(&mut image, opt + 44, 0)?;
    put_u16(&mut image, opt + 46, 0)?;
    put_u16(&mut image, opt + 48, 4)?;
    put_u16(&mut image, opt + 50, 0)?;
    put_u32(&mut image, opt + 52, 0)?;
    let size_of_image: u32 = align_up(max_virtual_end, PE_SECTION_ALIGNMENT)?;
    put_u32(&mut image, opt + 56, size_of_image)?;
    put_u32(&mut image, opt + 60, size_of_headers)?;
    put_u32(&mut image, opt + 64, 0)?;
    put_u16(&mut image, opt + 68, 3)?;
    put_u16(&mut image, opt + 70, 0x0400)?;
    put_u32(&mut image, opt + 72, 0x0010_0000)?;
    put_u32(&mut image, opt + 76, 0x0000_1000)?;
    put_u32(&mut image, opt + 80, 0x0010_0000)?;
    put_u32(&mut image, opt + 84, 0x0000_1000)?;
    put_u32(&mut image, opt + 88, 0)?;
    put_u32(&mut image, opt + 92, NUM_DATA_DIRECTORIES)?;

    let directories: usize = opt + 96;
    if header.debug_rva != 0 && header.debug_size != 0 {
        put_u32(
            &mut image,
            directories + DEBUG_DIRECTORY_INDEX * 8,
            header.debug_rva,
        )?;
        put_u32(
            &mut image,
            directories + DEBUG_DIRECTORY_INDEX * 8 + 4,
            header.debug_size,
        )?;
    }
    put_u32(
        &mut image,
        directories + CLR_DIRECTORY_INDEX * 8,
        header.cli_header_rva,
    )?;
    put_u32(
        &mut image,
        directories + CLR_DIRECTORY_INDEX * 8 + 4,
        header.cli_header_size,
    )?;

    for (index, section) in header.sections.iter().enumerate() {
        let entry: usize = section_table_offset + index * PE_SECTION_ENTRY_LEN;
        let is_code: bool = index == cli_index;
        let name: [u8; 8] = section_name(is_code);
        let name_dst: &mut [u8] = image
            .get_mut(entry..entry + 8)
            .ok_or_else(|| blazor_err("section name write out of bounds"))?;
        name_dst.copy_from_slice(&name);
        let (file_ptr, raw_start, raw_end): (u32, usize, usize) = placements[index];
        put_u32(&mut image, entry + 8, section.virtual_size)?;
        put_u32(&mut image, entry + 12, section.virtual_address)?;
        put_u32(&mut image, entry + 16, section.raw_size)?;
        put_u32(&mut image, entry + 20, file_ptr)?;
        let characteristics: u32 = if is_code {
            IMAGE_SCN_CODE
        } else {
            IMAGE_SCN_INITIALIZED_DATA
        };
        put_u32(&mut image, entry + 36, characteristics)?;

        let source: &[u8] = payload
            .get(raw_start..raw_end)
            .ok_or_else(|| blazor_err("section source slice out of range"))?;
        let dst_start: usize = file_ptr as usize;
        let dst_end: usize = dst_start
            .checked_add(source.len())
            .ok_or_else(|| blazor_err("section destination overflow"))?;
        let destination: &mut [u8] = image
            .get_mut(dst_start..dst_end)
            .ok_or_else(|| blazor_err("section destination out of bounds"))?;
        destination.copy_from_slice(source);
    }

    Ok(image)
}

const fn section_name(is_code: bool) -> [u8; 8] {
    if is_code {
        [0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00]
    } else {
        [0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00]
    }
}

fn resolve_rva(image: &NativeImage<'_>, rva: u32) -> Option<usize> {
    let address: u64 = image.virtual_address_from_relative(rva)?;
    let file_offset: u64 = image.file_offset(address)?;
    usize::try_from(file_offset).ok()
}

fn validate_managed_pe(image: &[u8]) -> Result<()> {
    if le_u16(image, 0)? != DOS_MAGIC {
        return Err(blazor_err("synthesized image missing MZ magic"));
    }
    let pe: usize = usize::try_from(le_u32(image, 0x3C)?)
        .map_err(|_| blazor_err("pe header offset out of range"))?;
    if le_u32(image, pe)? != NT_SIGNATURE {
        return Err(blazor_err("synthesized image missing PE signature"));
    }
    let opt: usize = pe
        .checked_add(24)
        .ok_or_else(|| blazor_err("optional header offset overflow"))?;
    let optional_magic: u16 = le_u16(image, opt)?;
    let directories_base: usize = match optional_magic {
        PE32_MAGIC => opt
            .checked_add(96)
            .ok_or_else(|| blazor_err("data directory offset overflow"))?,
        PE32PLUS_MAGIC => opt
            .checked_add(112)
            .ok_or_else(|| blazor_err("data directory offset overflow"))?,
        _ => return Err(blazor_err("synthesized image has unknown optional magic")),
    };
    let directory_count_offset: usize = match optional_magic {
        PE32_MAGIC => opt
            .checked_add(92)
            .ok_or_else(|| blazor_err("directory count offset overflow"))?,
        PE32PLUS_MAGIC => opt
            .checked_add(108)
            .ok_or_else(|| blazor_err("directory count offset overflow"))?,
        _ => return Err(blazor_err("synthesized image has unknown optional magic")),
    };
    let number_of_directories: u32 = match optional_magic {
        PE32_MAGIC | PE32PLUS_MAGIC => le_u32(image, directory_count_offset)?,
        _ => return Err(blazor_err("synthesized image has unknown optional magic")),
    };
    let clr_directory_index: u32 = u32::try_from(CLR_DIRECTORY_INDEX)
        .map_err(|_| blazor_err("clr directory index out of range"))?;
    if clr_directory_index >= number_of_directories {
        return Err(blazor_err("synthesized image lacks a clr data directory"));
    }
    let clr_entry_delta: usize = CLR_DIRECTORY_INDEX
        .checked_mul(8)
        .ok_or_else(|| blazor_err("clr directory offset overflow"))?;
    let clr_entry: usize = directories_base
        .checked_add(clr_entry_delta)
        .ok_or_else(|| blazor_err("clr directory offset overflow"))?;
    let clr_size_offset: usize = clr_entry
        .checked_add(4)
        .ok_or_else(|| blazor_err("clr directory size offset overflow"))?;
    let clr_rva: u32 = le_u32(image, clr_entry)?;
    let clr_size: u32 = le_u32(image, clr_size_offset)?;
    let clr_size_usize: usize =
        usize::try_from(clr_size).map_err(|_| blazor_err("clr directory size is out of range"))?;
    if clr_rva == 0 || clr_size_usize < COR20_HEADER_LEN {
        return Err(blazor_err(
            "synthesized image has an invalid clr directory size",
        ));
    }

    let native_image: NativeImage<'_> = parse_native_image(image).map_err(|error: Error| {
        Error::BlazorWebcil(format!("invalid synthesized image: {error}"))
    })?;
    let clr_address: u64 = native_image
        .virtual_address_from_relative(clr_rva)
        .ok_or_else(|| blazor_err("clr virtual address overflow"))?;
    let clr_directory: &[u8] = native_image
        .bytes_at(clr_address)
        .and_then(|mapped: &[u8]| mapped.get(..clr_size_usize))
        .ok_or_else(|| blazor_err("clr header past end of synthesized image"))?;
    let cli_header_size_u32: u32 = disrobe_bytes::read_u32_le_at(clr_directory, 0)
        .map_err(|_| blazor_err("cli header size field is truncated"))?;
    let cli_header_size: usize = usize::try_from(cli_header_size_u32)
        .map_err(|_| blazor_err("cli header size is out of range"))?;
    if cli_header_size < COR20_HEADER_LEN || cli_header_size > clr_directory.len() {
        return Err(blazor_err(
            "synthesized image has an invalid cli header size",
        ));
    }
    let clr_header: &[u8] = clr_directory
        .get(..cli_header_size)
        .ok_or_else(|| blazor_err("cli header exceeds its declared directory"))?;
    let metadata_rva: u32 = disrobe_bytes::read_u32_le_at(clr_header, 8)
        .map_err(|_| blazor_err("clr metadata rva field is truncated"))?;
    let metadata_address: u64 = native_image
        .virtual_address_from_relative(metadata_rva)
        .ok_or_else(|| blazor_err("metadata virtual address overflow"))?;
    let metadata_offset: usize = resolve_rva(&native_image, metadata_rva)
        .ok_or_else(|| blazor_err("metadata rva resolves to no section"))?;
    native_image
        .bytes_at(metadata_address)
        .and_then(|mapped: &[u8]| mapped.get(..4))
        .ok_or_else(|| blazor_err("metadata signature crosses a section boundary"))?;
    if le_u32(image, metadata_offset)? != METADATA_SIGNATURE {
        return Err(blazor_err("metadata root is missing the BSJB signature"));
    }
    Ok(())
}

pub fn unwrap_webcil(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.starts_with(b"MZ") {
        validate_managed_pe(bytes)?;
        return Ok(bytes.to_vec());
    }
    let payload: &[u8] = locate_webcil_payload(bytes)?;
    let header: WebcilHeader = parse_webcil_header(payload)?;
    let image: Vec<u8> = synthesize_pe(payload, &header)?;
    validate_managed_pe(&image)?;
    Ok(image)
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBootManifest {
    #[serde(default)]
    main_assembly_name: Option<String>,
    #[serde(default)]
    resources: RawResources,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawResources {
    #[serde(default)]
    assembly: BTreeMap<String, String>,
    #[serde(default)]
    core_assembly: BTreeMap<String, String>,
    #[serde(default)]
    lazy_assembly: BTreeMap<String, String>,
    #[serde(default)]
    fingerprinting: BTreeMap<String, String>,
}

fn parse_integrity(value: &str) -> BlazorIntegrity {
    let Some(encoded): Option<&str> = value.strip_prefix(SHA256_PREFIX) else {
        return BlazorIntegrity::Unparseable;
    };
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .and_then(|decoded: Vec<u8>| <[u8; 32]>::try_from(decoded.as_slice()).ok())
        .map_or(BlazorIntegrity::Unparseable, BlazorIntegrity::Sha256)
}

fn push_assemblies(
    out: &mut Vec<BlazorAssemblyRef>,
    map: &BTreeMap<String, String>,
    kind: BlazorAssemblyKind,
) {
    for (manifest_key, integrity_value) in map {
        out.push(BlazorAssemblyRef {
            manifest_key: manifest_key.clone(),
            integrity: parse_integrity(integrity_value),
            kind,
        });
    }
}

pub fn parse_blazor_boot(bytes: &[u8]) -> Result<BlazorBoot> {
    if bytes.len() > MAX_BOOT_MANIFEST_LEN {
        return Err(blazor_err("boot manifest exceeds size cap"));
    }
    let raw: RawBootManifest = serde_json::from_slice(bytes)?;
    let mut assemblies: Vec<BlazorAssemblyRef> = Vec::new();
    push_assemblies(
        &mut assemblies,
        &raw.resources.assembly,
        BlazorAssemblyKind::Assembly,
    );
    push_assemblies(
        &mut assemblies,
        &raw.resources.core_assembly,
        BlazorAssemblyKind::Core,
    );
    push_assemblies(
        &mut assemblies,
        &raw.resources.lazy_assembly,
        BlazorAssemblyKind::Lazy,
    );
    if assemblies.len() > MAX_ASSEMBLIES {
        return Err(blazor_err("assembly count exceeds sanity cap"));
    }
    Ok(BlazorBoot {
        main_assembly_name: raw.main_assembly_name,
        assemblies,
        fingerprint_to_logical: raw.resources.fingerprinting,
    })
}

#[must_use]
pub fn detect_blazor_boot(bytes: &[u8]) -> bool {
    parse_blazor_boot(bytes).is_ok_and(|boot: BlazorBoot| !boot.assemblies.is_empty())
}

fn basename(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

fn swap_managed_extension(name: &str) -> Option<String> {
    name.strip_suffix(".wasm").map_or_else(
        || {
            name.strip_suffix(".dll")
                .map(|stem: &str| format!("{stem}.wasm"))
        },
        |stem: &str| Some(format!("{stem}.dll")),
    )
}

fn normalize_assembly_name(logical: &str) -> String {
    logical
        .strip_suffix(".wasm")
        .map_or_else(|| logical.to_owned(), |stem: &str| format!("{stem}.dll"))
}

fn resolve_asset<'a>(
    index: &BTreeMap<&'a str, &'a [u8]>,
    boot: &BlazorBoot,
    key: &str,
) -> Option<(&'a str, &'a [u8])> {
    let mut candidates: Vec<String> = vec![key.to_owned()];
    if let Some(swapped) = swap_managed_extension(key) {
        candidates.push(swapped);
    }
    for (fingerprinted, logical) in &boot.fingerprint_to_logical {
        if logical == key {
            candidates.push(fingerprinted.clone());
        }
    }
    let base: Vec<String> = candidates.clone();
    for name in &base {
        candidates.push(format!("{name}.br"));
        candidates.push(format!("{name}.gz"));
    }
    for candidate in &candidates {
        if let Some((name, data)) = index.get_key_value(candidate.as_str()) {
            return Some((name, data));
        }
    }
    None
}

fn maybe_decompress(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if bytes.starts_with(WEBCIL_MAGIC) || bytes.starts_with(WASM_MAGIC) || bytes.starts_with(b"MZ")
    {
        return Ok(bytes.to_vec());
    }
    if detect_gzip(bytes) {
        let members: Vec<GzipMember> = decompress_gzip_members(bytes, cap)?;
        return members
            .into_iter()
            .next()
            .map(|member: GzipMember| member.data)
            .ok_or_else(|| blazor_err("gzip asset produced no members"));
    }
    decompress_brotli(bytes, cap)
}

fn locate_boot_manifest(files: &[BlazorFile<'_>]) -> Result<Vec<u8>> {
    for file in files {
        if basename(file.name) == "blazor.boot.json" {
            return Ok(file.data.to_vec());
        }
    }
    for file in files {
        match basename(file.name) {
            "blazor.boot.json.br" => {
                return decompress_brotli(file.data, MAX_BOOT_MANIFEST_LEN as u64);
            }
            "blazor.boot.json.gz" => {
                let members: Vec<GzipMember> =
                    decompress_gzip_members(file.data, MAX_BOOT_MANIFEST_LEN as u64)?;
                return members
                    .into_iter()
                    .next()
                    .map(|member: GzipMember| member.data)
                    .ok_or_else(|| blazor_err("compressed boot manifest produced no members"));
            }
            _ => {}
        }
    }
    Err(blazor_err("no blazor.boot.json present in the file set"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

struct CarvedAssembly {
    relative_path: String,
    image: Vec<u8>,
    stored_len: u64,
}

fn carve_assembly(
    index: &BTreeMap<&str, &[u8]>,
    boot: &BlazorBoot,
    assembly: &BlazorAssemblyRef,
    cap: u64,
) -> Result<Option<CarvedAssembly>> {
    let Some((_on_disk_name, raw_bytes)): Option<(&str, &[u8])> =
        resolve_asset(index, boot, &assembly.manifest_key)
    else {
        return Ok(None);
    };
    let uncompressed: Vec<u8> = maybe_decompress(raw_bytes, cap)?;
    match assembly.integrity {
        BlazorIntegrity::Sha256(expected) => {
            if sha256(&uncompressed) != expected {
                return Ok(None);
            }
        }
        BlazorIntegrity::Unparseable => return Ok(None),
    }
    let image: Vec<u8> = unwrap_webcil(&uncompressed)?;
    let logical: String = boot
        .fingerprint_to_logical
        .get(&assembly.manifest_key)
        .cloned()
        .unwrap_or_else(|| assembly.manifest_key.clone());
    let relative_path: String = sanitize_entry_path(&normalize_assembly_name(&logical))?;
    Ok(Some(CarvedAssembly {
        relative_path,
        image,
        stored_len: raw_bytes.len() as u64,
    }))
}

pub fn extract_blazor_bundle(
    files: &[BlazorFile<'_>],
    quota: ExtractionQuota,
) -> Result<Vec<DotnetBundleEntry>> {
    let boot_bytes: Vec<u8> = locate_boot_manifest(files)?;
    let boot: BlazorBoot = parse_blazor_boot(&boot_bytes)?;
    let mut guard: QuotaGuard = QuotaGuard::new(quota);
    let cap: u64 = guard.max_per_entry_uncompressed();
    let index: BTreeMap<&str, &[u8]> = files
        .iter()
        .map(|file: &BlazorFile<'_>| (basename(file.name), file.data))
        .collect();
    let mut out: Vec<DotnetBundleEntry> = Vec::with_capacity(boot.assemblies.len().min(4096));
    for assembly in &boot.assemblies {
        let carved: Option<CarvedAssembly> = match carve_assembly(&index, &boot, assembly, cap) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(entry): Option<CarvedAssembly> = carved else {
            continue;
        };
        guard.admit_entry(
            &entry.relative_path,
            entry.image.len() as u64,
            entry.stored_len,
        )?;
        out.push(DotnetBundleEntry {
            relative_path: entry.relative_path,
            file_type: BundleFileType::Assembly,
            data: entry.image,
        });
    }
    Ok(out)
}

#[must_use]
pub fn detect_blazor_bundle(files: &[BlazorFile<'_>]) -> bool {
    locate_boot_manifest(files).is_ok_and(|manifest: Vec<u8>| detect_blazor_boot(&manifest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn cor20_header(metadata_rva: u32, metadata_size: u32) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&(COR20_HEADER_LEN as u32).to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(&metadata_rva.to_le_bytes());
        out.extend_from_slice(&metadata_size.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        while out.len() < COR20_HEADER_LEN {
            out.push(0);
        }
        out
    }

    fn metadata_root(streams: &[(&str, &[u8])]) -> Vec<u8> {
        let version: &[u8] = b"v4.0.30319\0\0";
        let mut header: Vec<u8> = Vec::new();
        header.extend_from_slice(&METADATA_SIGNATURE.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&1u16.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&(version.len() as u32).to_le_bytes());
        header.extend_from_slice(version);
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&(streams.len() as u16).to_le_bytes());

        let mut directory: Vec<u8> = Vec::new();
        let mut payload: Vec<u8> = Vec::new();
        let mut relative_offset: u32 = 0;
        let table_len: usize = streams
            .iter()
            .map(|(name, _): &(&str, &[u8])| {
                let raw: usize = name.len() + 1;
                8 + ((raw + 3) & !3usize)
            })
            .sum();
        let base: u32 = (header.len() + table_len) as u32;
        for (name, data) in streams {
            directory.extend_from_slice(&(base + relative_offset).to_le_bytes());
            directory.extend_from_slice(&(data.len() as u32).to_le_bytes());
            let mut name_bytes: Vec<u8> = name.as_bytes().to_vec();
            name_bytes.push(0);
            while !name_bytes.len().is_multiple_of(4) {
                name_bytes.push(0);
            }
            directory.extend_from_slice(&name_bytes);
            payload.extend_from_slice(data);
            relative_offset += data.len() as u32;
        }
        header.extend_from_slice(&directory);
        header.extend_from_slice(&payload);
        header
    }

    fn build_webcil_payload() -> Vec<u8> {
        let cli_rva: u32 = 0x2008;
        let text_va: u32 = 0x2000;
        let metadata_rva: u32 = 0x2100;
        let streams: Vec<(&str, &[u8])> = vec![
            ("#~", b"table-stream-bytes".as_slice()),
            ("#Strings", b"\0Program\0Main\0".as_slice()),
            ("#US", b"\0user-strings".as_slice()),
            ("#GUID", &[0x11u8; 16]),
            ("#Blob", b"\0blob-heap-bytes".as_slice()),
        ];
        let mut text: Vec<u8> = vec![0u8; (cli_rva - text_va) as usize];
        text.extend_from_slice(&cor20_header(metadata_rva, 0));
        text.resize((metadata_rva - text_va) as usize, 0);
        text.extend_from_slice(&metadata_root(&streams));
        let text_virtual_size: u32 = text.len() as u32;
        let text_raw_size: u32 = ((text.len() + 0x1ff) & !0x1ff) as u32;
        text.resize(text_raw_size as usize, 0);

        let rsrc_va: u32 = 0x6000;
        let rsrc: Vec<u8> = vec![0xAB; 0x200];

        let header_len: usize = WEBCIL_HEADER_V0_LEN;
        let section_table: usize = 2 * WEBCIL_SECTION_LEN;
        let mut ptr0: usize = header_len + section_table;
        ptr0 = (ptr0 + 15) & !15usize;
        let ptr1: usize = (ptr0 + text.len() + 15) & !15usize;

        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(WEBCIL_MAGIC);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&cli_rva.to_le_bytes());
        payload.extend_from_slice(&(COR20_HEADER_LEN as u32).to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());

        for (vs, va, rs, ptr) in [
            (text_virtual_size, text_va, text_raw_size, ptr0 as u32),
            (rsrc.len() as u32, rsrc_va, rsrc.len() as u32, ptr1 as u32),
        ] {
            payload.extend_from_slice(&vs.to_le_bytes());
            payload.extend_from_slice(&va.to_le_bytes());
            payload.extend_from_slice(&rs.to_le_bytes());
            payload.extend_from_slice(&ptr.to_le_bytes());
        }
        payload.resize(ptr0, 0);
        payload.extend_from_slice(&text);
        payload.resize(ptr1, 0);
        payload.extend_from_slice(&rsrc);
        payload
    }

    fn wrap_in_wasm(payload: &[u8]) -> Vec<u8> {
        fn uleb(value: usize, out: &mut Vec<u8>) {
            let mut v: usize = value;
            loop {
                let mut byte: u8 = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if v == 0 {
                    break;
                }
            }
        }
        let mut segment_bytes: Vec<u8> = Vec::new();
        let first: &[u8] = b"LB\0\0";
        segment_bytes.push(0x01);
        uleb(first.len(), &mut segment_bytes);
        segment_bytes.extend_from_slice(first);
        segment_bytes.push(0x01);
        uleb(payload.len(), &mut segment_bytes);
        segment_bytes.extend_from_slice(payload);

        let mut data_section: Vec<u8> = Vec::new();
        uleb(2, &mut data_section);
        data_section.extend_from_slice(&segment_bytes);

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(WASM_MAGIC);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(WASM_DATA_SECTION_ID);
        uleb(data_section.len(), &mut out);
        out.extend_from_slice(&data_section);
        out
    }

    fn read_streams(image: &[u8]) -> BTreeMap<String, Vec<u8>> {
        validate_managed_pe(image).expect("valid managed pe");
        let pe: usize = le_u32(image, 0x3C).unwrap() as usize;
        let opt: usize = pe + 24;
        let directories: usize = opt + 96;
        let clr_rva: u32 = le_u32(image, directories + CLR_DIRECTORY_INDEX * 8).unwrap();
        let native_image: NativeImage<'_> = parse_native_image(image).unwrap();
        let clr_offset: usize = resolve_rva(&native_image, clr_rva).unwrap();
        let metadata_rva: u32 = le_u32(image, clr_offset + 8).unwrap();
        let metadata_offset: usize = resolve_rva(&native_image, metadata_rva).unwrap();
        let version_len: u32 = le_u32(image, metadata_offset + 12).unwrap();
        let mut cursor: usize = metadata_offset + 16 + version_len as usize;
        cursor += 2;
        let stream_count: u16 = le_u16(image, cursor).unwrap();
        cursor += 2;
        let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for _ in 0..stream_count {
            let offset: u32 = le_u32(image, cursor).unwrap();
            let size: u32 = le_u32(image, cursor + 4).unwrap();
            cursor += 8;
            let name_start: usize = cursor;
            while image[cursor] != 0 {
                cursor += 1;
            }
            let name: String = String::from_utf8_lossy(&image[name_start..cursor]).into_owned();
            let name_len: usize = cursor - name_start + 1;
            cursor = name_start + ((name_len + 3) & !3usize);
            let data_start: usize = metadata_offset + offset as usize;
            let data: Vec<u8> = image[data_start..data_start + size as usize].to_vec();
            out.insert(name, data);
        }
        out
    }

    #[test]
    fn unwraps_raw_webcil_into_parseable_pe() {
        let payload: Vec<u8> = build_webcil_payload();
        let header: WebcilHeader = parse_webcil_header(&payload).expect("header");
        assert_eq!(header.version_major, 0);
        assert_eq!(header.sections.len(), 2);
        assert_eq!(header.cli_header_rva, 0x2008);
        let image: Vec<u8> = unwrap_webcil(&payload).expect("unwrap");
        validate_managed_pe(&image).expect("valid");
    }

    #[test]
    fn rejects_clr_directory_smaller_than_fixed_header() {
        let mut payload: Vec<u8> = build_webcil_payload();
        let size_start: usize = 16;
        let size_end: usize = size_start
            .checked_add(4)
            .expect("clr size field should fit");
        let size_field: &mut [u8] = payload
            .get_mut(size_start..size_end)
            .expect("clr size field should exist");
        let invalid_size: [u8; 4] = 71u32.to_le_bytes();
        size_field.copy_from_slice(&invalid_size);

        let error: Error = unwrap_webcil(&payload).expect_err("short clr directory should reject");

        assert!(matches!(
            error,
            Error::BlazorWebcil(reason) if reason.contains("invalid clr directory size")
        ));
    }

    #[test]
    fn rejects_cli_header_size_smaller_than_fixed_fields() {
        let payload: Vec<u8> = build_webcil_payload();
        let header: WebcilHeader = parse_webcil_header(&payload).expect("header");
        let mut image: Vec<u8> = synthesize_pe(&payload, &header).expect("synthesized image");
        let native_image: NativeImage<'_> =
            parse_native_image(&image).expect("native image should parse");
        let cli_offset: usize =
            resolve_rva(&native_image, header.cli_header_rva).expect("cli header should map");
        let cli_size_end: usize = cli_offset
            .checked_add(4)
            .expect("cli header size field should fit");
        let cli_size_field: &mut [u8] = image
            .get_mut(cli_offset..cli_size_end)
            .expect("cli header size field should exist");
        let invalid_size: [u8; 4] = 8u32.to_le_bytes();
        cli_size_field.copy_from_slice(&invalid_size);

        let error: Error = validate_managed_pe(&image).expect_err("short cli header should reject");

        assert!(matches!(
            error,
            Error::BlazorWebcil(reason) if reason.contains("invalid cli header size")
        ));
    }

    #[test]
    fn synthesized_sections_preserve_virtual_layout() {
        let payload: Vec<u8> = build_webcil_payload();
        let header: WebcilHeader = parse_webcil_header(&payload).expect("header");
        let image: Vec<u8> = unwrap_webcil(&payload).expect("unwrap");
        let pe: usize = le_u32(&image, 0x3C).unwrap() as usize;
        let optional_header_size: usize = usize::from(le_u16(&image, pe + 20).unwrap());
        let sections_start: usize = pe + 24 + optional_header_size;
        for (index, section) in header.sections.iter().enumerate() {
            let entry: usize = sections_start + index * PE_SECTION_ENTRY_LEN;
            assert_eq!(le_u32(&image, entry + 8).unwrap(), section.virtual_size);
            assert_eq!(le_u32(&image, entry + 12).unwrap(), section.virtual_address);
            assert_eq!(le_u32(&image, entry + 16).unwrap(), section.raw_size);
        }
    }

    #[test]
    fn unwraps_wasm_wrapped_webcil() {
        let payload: Vec<u8> = build_webcil_payload();
        let wasm: Vec<u8> = wrap_in_wasm(&payload);
        assert!(wasm.starts_with(WASM_MAGIC));
        let located: &[u8] = locate_webcil_payload(&wasm).expect("locate");
        assert!(located.starts_with(WEBCIL_MAGIC));
        let raw_image: Vec<u8> = unwrap_webcil(&payload).expect("raw");
        let wasm_image: Vec<u8> = unwrap_webcil(&wasm).expect("wasm");
        assert_eq!(raw_image, wasm_image);
    }

    #[test]
    fn wasm_and_raw_streams_match() {
        let payload: Vec<u8> = build_webcil_payload();
        let raw_streams: BTreeMap<String, Vec<u8>> =
            read_streams(&unwrap_webcil(&payload).unwrap());
        let wasm_streams: BTreeMap<String, Vec<u8>> =
            read_streams(&unwrap_webcil(&wrap_in_wasm(&payload)).unwrap());
        assert_eq!(raw_streams, wasm_streams);
        assert!(raw_streams.contains_key("#~"));
        assert!(raw_streams.contains_key("#Strings"));
        assert_eq!(raw_streams.len(), 5);
    }

    fn boot_json() -> String {
        let payload: Vec<u8> = build_webcil_payload();
        let wasm: Vec<u8> = wrap_in_wasm(&payload);
        let digest: [u8; 32] = sha256(&wasm);
        let hash: String = format!(
            "{}{}",
            SHA256_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        format!(
            "{{\"mainAssemblyName\":\"Sample\",\"resources\":{{\"fingerprinting\":{{\"Sample.aaaa1111.wasm\":\"Sample.wasm\"}},\"assembly\":{{\"Sample.aaaa1111.wasm\":\"{hash}\"}}}}}}"
        )
    }

    #[test]
    fn extracts_and_verifies_fingerprinted_assembly() {
        let payload: Vec<u8> = build_webcil_payload();
        let wasm: Vec<u8> = wrap_in_wasm(&payload);
        let boot: String = boot_json();
        let files: Vec<BlazorFile<'_>> = vec![
            BlazorFile {
                name: "_framework/blazor.boot.json",
                data: boot.as_bytes(),
            },
            BlazorFile {
                name: "_framework/Sample.aaaa1111.wasm",
                data: &wasm,
            },
        ];
        let entries: Vec<DotnetBundleEntry> =
            extract_blazor_bundle(&files, ExtractionQuota::default_safe()).expect("extract");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative_path, "Sample.dll");
        assert_eq!(entries[0].file_type, BundleFileType::Assembly);
        validate_managed_pe(&entries[0].data).expect("valid managed pe");
    }

    #[test]
    fn rejects_assembly_with_wrong_integrity() {
        let payload: Vec<u8> = build_webcil_payload();
        let wasm: Vec<u8> = wrap_in_wasm(&payload);
        let boot: String = format!(
            "{{\"resources\":{{\"assembly\":{{\"Sample.aaaa1111.wasm\":\"{SHA256_PREFIX}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}}}}}}"
        );
        let files: Vec<BlazorFile<'_>> = vec![
            BlazorFile {
                name: "blazor.boot.json",
                data: boot.as_bytes(),
            },
            BlazorFile {
                name: "Sample.aaaa1111.wasm",
                data: &wasm,
            },
        ];
        let entries: Vec<DotnetBundleEntry> =
            extract_blazor_bundle(&files, ExtractionQuota::default_safe()).expect("extract");
        assert!(entries.is_empty());
    }

    #[test]
    fn passes_through_raw_managed_pe() {
        let payload: Vec<u8> = build_webcil_payload();
        let synthesized: Vec<u8> = unwrap_webcil(&payload).expect("synth");
        let again: Vec<u8> = unwrap_webcil(&synthesized).expect("passthrough");
        assert_eq!(synthesized, again);
    }

    #[test]
    fn detects_boot_manifest() {
        let boot: String = boot_json();
        assert!(detect_blazor_boot(boot.as_bytes()));
        assert!(!detect_blazor_boot(b"{\"resources\":{}}"));
        assert!(!detect_blazor_boot(b"not json at all"));
    }

    #[test]
    fn truncated_inputs_do_not_panic() {
        let payload: Vec<u8> = build_webcil_payload();
        let wasm: Vec<u8> = wrap_in_wasm(&payload);
        let boot: String = boot_json();
        for cut in (0..wasm.len()).step_by(7) {
            let _ = locate_webcil_payload(&wasm[..cut]);
            let _ = unwrap_webcil(&wasm[..cut]);
        }
        for cut in (0..payload.len()).step_by(5) {
            let _ = parse_webcil_header(&payload[..cut]);
            let _ = unwrap_webcil(&payload[..cut]);
        }
        for cut in (0..boot.len()).step_by(3) {
            let _ = parse_blazor_boot(&boot.as_bytes()[..cut]);
            let files: Vec<BlazorFile<'_>> = vec![BlazorFile {
                name: "blazor.boot.json",
                data: &boot.as_bytes()[..cut],
            }];
            let _ = extract_blazor_bundle(&files, ExtractionQuota::default_safe());
        }
    }

    fn blazor_fixture_dir() -> std::path::PathBuf {
        let mut dir: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop();
        dir.pop();
        dir.push("corpus");
        dir.push("binfmt");
        dir.push("blazor");
        dir
    }

    const BLAZOR_WEBCIL_FIXTURE: &str = "Bz.belq8bx71h.wasm";
    const BLAZOR_RAWDLL_FIXTURE: &str = "Bz.di7szpefj3.dll";

    #[test]
    fn real_sdk_metadata_streams_match_raw_dll() {
        let dir: std::path::PathBuf = blazor_fixture_dir();
        let webcil_bytes: Vec<u8> =
            std::fs::read(dir.join(BLAZOR_WEBCIL_FIXTURE)).expect("read committed webcil fixture");
        let rawdll_bytes: Vec<u8> =
            std::fs::read(dir.join(BLAZOR_RAWDLL_FIXTURE)).expect("read committed raw dll fixture");
        let synthesized: Vec<u8> = unwrap_webcil(&webcil_bytes).expect("unwrap real webcil");
        let synth_streams: BTreeMap<String, Vec<u8>> = read_streams(&synthesized);
        let raw_streams: BTreeMap<String, Vec<u8>> = read_streams(&rawdll_bytes);
        assert_eq!(
            synth_streams, raw_streams,
            "carved metadata streams must be byte-identical to the sdk raw dll"
        );
        assert!(synth_streams.contains_key("#~"));
        assert!(synth_streams.contains_key("#Strings"));
    }

    #[test]
    fn real_sdk_bundle_carves_and_integrity_verifies_app_assembly() {
        let dir: std::path::PathBuf = blazor_fixture_dir();
        let boot: Vec<u8> =
            std::fs::read(dir.join("blazor.boot.json")).expect("read committed boot manifest");
        let webcil: Vec<u8> =
            std::fs::read(dir.join(BLAZOR_WEBCIL_FIXTURE)).expect("read committed webcil fixture");
        let webcil_name: String = format!("_framework/{BLAZOR_WEBCIL_FIXTURE}");
        let files: Vec<BlazorFile<'_>> = vec![
            BlazorFile {
                name: "_framework/blazor.boot.json",
                data: &boot,
            },
            BlazorFile {
                name: &webcil_name,
                data: &webcil,
            },
        ];
        assert!(detect_blazor_bundle(&files), "must recognise a real bundle");
        let boot_parsed: BlazorBoot = parse_blazor_boot(&boot).expect("parse real boot manifest");
        assert_eq!(boot_parsed.main_assembly_name.as_deref(), Some("Bz"));
        let entries: Vec<DotnetBundleEntry> =
            extract_blazor_bundle(&files, ExtractionQuota::default_safe()).expect("extract bundle");
        assert_eq!(
            entries.len(),
            1,
            "only the committed app assembly resolves; runtime assemblies are absent and skipped"
        );
        assert_eq!(entries[0].relative_path, "Bz.dll");
        assert_eq!(entries[0].file_type, BundleFileType::Assembly);
        validate_managed_pe(&entries[0].data).expect("carved app assembly is a valid managed pe");
    }

    #[test]
    fn rejects_assembly_with_unparseable_integrity() {
        let payload: Vec<u8> = build_webcil_payload();
        let wasm: Vec<u8> = wrap_in_wasm(&payload);
        let boot: String = format!(
            "{{\"resources\":{{\"assembly\":{{\"Sample.aaaa1111.wasm\":\"{SHA256_PREFIX}not-valid-base64-@@@\"}}}}}}"
        );
        assert_eq!(
            parse_integrity(&format!("{SHA256_PREFIX}not-valid-base64-@@@")),
            BlazorIntegrity::Unparseable
        );
        let files: Vec<BlazorFile<'_>> = vec![
            BlazorFile {
                name: "blazor.boot.json",
                data: boot.as_bytes(),
            },
            BlazorFile {
                name: "Sample.aaaa1111.wasm",
                data: &wasm,
            },
        ];
        let entries: Vec<DotnetBundleEntry> =
            extract_blazor_bundle(&files, ExtractionQuota::default_safe()).expect("extract");
        assert!(
            entries.is_empty(),
            "an entry whose declared integrity string cannot be parsed must be rejected, not trusted"
        );
    }
}
