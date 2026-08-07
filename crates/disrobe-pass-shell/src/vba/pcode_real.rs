use std::io::Read;

use cfb::CompoundFile;
use disrobe_core::debug::DebugLog;
use serde::Serialize;

use crate::error::{Error, Result};

use super::pcode::{PCodeInstruction, PCodeStreamHeader, PCodeWall, PCodeWallDetail};

const VBA_PROJECT_MAGIC: u16 = 0x61CC;
const PCODE_MAGIC: u16 = 0xCAFE;
const BIG_ENDIAN_MARKER: u16 = 0x000E;
const MAX_CFB_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CFB_STREAM_RESERVE: usize = 4 * 1024 * 1024;
const MAX_OVBA_DECOMPRESSED_BYTES: usize = 64 * 1024 * 1024;
const MAX_FUNC_ARG_CHAIN: usize = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct RealPCodeReport {
    pub header: PCodeStreamHeader,
    pub identifiers: Vec<String>,
    pub modules: Vec<RealModuleDisasm>,
    pub walls: Vec<PCodeWallDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RealModuleDisasm {
    pub name: String,
    pub pcode_offset_in_stream: usize,
    pub num_lines: usize,
    pub lines: Vec<RealPCodeLine>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RealPCodeLine {
    pub line_index: usize,
    pub instructions: Vec<PCodeInstruction>,
    pub text: String,
}

pub fn disassemble_pcode_real(ole_bytes: &[u8]) -> Result<RealPCodeReport> {
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(ole_bytes);
    let mut comp: CompoundFile<std::io::Cursor<&[u8]>> =
        CompoundFile::open(cursor).map_err(|e: std::io::Error| Error::OleCfb(e.to_string()))?;
    let vba_project: Vec<u8> = read_stream(&mut comp, "/VBA/_VBA_PROJECT")?;
    let header: PCodeStreamHeader = parse_vba_project_header(&vba_project)?;
    let endian: Endian = if header.is_big_endian {
        Endian::Big
    } else {
        Endian::Little
    };
    let dir_compressed: Vec<u8> = read_stream(&mut comp, "/VBA/dir")?;
    let dir_data: Vec<u8> = decompress_ovba(&dir_compressed)?;
    let dir_parse: DirParse = parse_dir(&dir_data, endian);
    let identifiers: Vec<String> = extract_identifiers(&vba_project, header.version, endian)?;
    let vba_ver: u8 = if header.version >= 0x6B {
        if header.version >= 0x97 { 7 } else { 6 }
    } else {
        5
    };
    let is_64bit: bool = dir_parse.is_64bit;
    let mut modules_out: Vec<RealModuleDisasm> = Vec::with_capacity(dir_parse.modules.len());
    let mut walls: Vec<PCodeWallDetail> = Vec::new();
    for module_name in &dir_parse.modules {
        let stream_path: String = format!("/VBA/{module_name}");
        let module_bytes: Vec<u8> = match read_stream(&mut comp, &stream_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let module_offset: usize =
            find_module_text_offset(&dir_data, module_name, endian).unwrap_or(0);
        match disassemble_module(
            &module_bytes,
            &identifiers,
            vba_ver,
            is_64bit,
            module_name,
            module_offset,
        ) {
            Ok(m) => modules_out.push(m),
            Err(e) => walls.push(PCodeWallDetail {
                kind: PCodeWall::InsufficientStreamBytes,
                reason: format!("module {module_name}: {e}"),
            }),
        }
    }
    Ok(RealPCodeReport {
        header,
        identifiers,
        modules: modules_out,
        walls,
    })
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn parse_vba_project_header(buf: &[u8]) -> Result<PCodeStreamHeader> {
    if buf.len() < 8 {
        return Err(Error::VbaPcode {
            reason: "_VBA_PROJECT stream too short".to_owned(),
        });
    }
    let magic: u16 = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != VBA_PROJECT_MAGIC {
        return Err(Error::VbaPcode {
            reason: format!("_VBA_PROJECT magic mismatch: got {magic:#06x}"),
        });
    }
    let version: u16 = u16::from_le_bytes([buf[2], buf[3]]);
    let endian_marker: u16 = u16::from_le_bytes([buf[4], buf[5]]);
    let is_big_endian: bool = endian_marker == BIG_ENDIAN_MARKER;
    let language_id: u16 = u16::from_le_bytes([buf[6], buf[7]]);
    Ok(PCodeStreamHeader {
        magic,
        version,
        endian_marker,
        language_id,
        is_big_endian,
        bitness_hint: None,
        stream_bytes: buf.len(),
    })
}

fn read_stream<T: AsRef<[u8]>>(
    comp: &mut CompoundFile<std::io::Cursor<T>>,
    path: &str,
) -> Result<Vec<u8>> {
    let stream: cfb::Stream<std::io::Cursor<T>> = comp
        .open_stream(path)
        .map_err(|e: std::io::Error| Error::OleCfb(e.to_string()))?;
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_CFB_STREAM_RESERVE);
    let read: u64 = stream
        .take(MAX_CFB_STREAM_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .map(|n: usize| n as u64)
        .map_err(Error::Gzip)?;
    if read > MAX_CFB_STREAM_BYTES {
        return Err(Error::VbaPcode {
            reason: format!("OLE stream {path} exceeds {MAX_CFB_STREAM_BYTES}-byte cap"),
        });
    }
    Ok(buf)
}

pub(crate) fn decompress_ovba(data: &[u8]) -> Result<Vec<u8>> {
    decompress_ovba_bounded(data, MAX_OVBA_DECOMPRESSED_BYTES)
}

fn decompress_ovba_bounded(data: &[u8], max_output: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] != 0x01 {
        return Err(Error::VbaPcode {
            reason: format!("MS-OVBA signature byte must be 0x01, got {:#04x}", data[0]),
        });
    }
    let reserve: usize = data.len().saturating_mul(4).min(max_output);
    let mut out: Vec<u8> = Vec::with_capacity(reserve);
    let mut i: usize = 1;
    while i + 1 < data.len() {
        let sig: u16 = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;
        if sig & 0x7000 != 0x3000 {
            return Err(Error::VbaPcode {
                reason: format!("ChunkHeader signature high bits invalid: sig={sig:#06x}"),
            });
        }
        let block_len: usize = ((sig & 0x0FFF) + 3) as usize;
        let compressed: bool = (sig & 0x8000) != 0;
        let block_end: usize = (i - 2 + block_len).min(data.len());
        let chunk_start_decompressed: usize = out.len();
        if !compressed {
            ensure_ovba_output_room(out.len(), block_end - i, max_output)?;
            out.extend_from_slice(&data[i..block_end]);
            i = block_end;
            continue;
        }
        let mut p: usize = i;
        while p < block_end {
            let token_tag: u8 = data[p];
            p += 1;
            for bit in 0..8u8 {
                if p >= block_end {
                    break;
                }
                let is_copy: bool = (token_tag >> bit) & 1 == 1;
                if !is_copy {
                    ensure_ovba_output_room(out.len(), 1, max_output)?;
                    out.push(data[p]);
                    p += 1;
                    continue;
                }
                if p + 1 >= block_end {
                    return Err(Error::VbaPcode {
                        reason: "CopyToken truncated".to_owned(),
                    });
                }
                let raw: u16 = u16::from_le_bytes([data[p], data[p + 1]]);
                p += 2;
                let chunk_relative_pos: usize = out.len().saturating_sub(chunk_start_decompressed);
                let bit_count: u32 = copy_token_bit_count(chunk_relative_pos);
                let length_mask: u16 = copy_token_length_mask(chunk_relative_pos);
                let length: usize = ((raw & length_mask) + 3) as usize;
                let offset: usize = ((raw >> (16 - bit_count)) + 1) as usize;
                if offset == 0 || offset > out.len() - chunk_start_decompressed {
                    return Err(Error::VbaPcode {
                        reason: format!(
                            "CopyToken back-offset {offset} exceeds in-chunk window (chunk_rel_pos={chunk_relative_pos})"
                        ),
                    });
                }
                let copy_from: usize = out.len() - offset;
                ensure_ovba_output_room(out.len(), length, max_output)?;
                for k in 0..length {
                    let b: u8 = out[copy_from + k];
                    out.push(b);
                }
            }
        }
        i = block_end;
    }
    Ok(out)
}

fn ensure_ovba_output_room(current: usize, additional: usize, max_output: usize) -> Result<()> {
    let Some(next): Option<usize> = current.checked_add(additional) else {
        return Err(Error::VbaPcode {
            reason: "decompressed VBA stream size overflows usize".to_owned(),
        });
    };
    if next > max_output {
        return Err(Error::VbaPcode {
            reason: format!("decompressed VBA stream exceeds {max_output}-byte cap"),
        });
    }
    Ok(())
}

fn copy_token_bit_count(difference: usize) -> u32 {
    let ceil_log2: u32 = if difference <= 1 {
        0
    } else {
        usize::BITS - (difference - 1).leading_zeros()
    };
    ceil_log2.max(4)
}

fn copy_token_length_mask(difference: usize) -> u16 {
    0xFFFFu16 >> copy_token_bit_count(difference)
}

#[derive(Debug, Clone)]
struct DirParse {
    modules: Vec<String>,
    is_64bit: bool,
}

fn parse_dir(dir: &[u8], endian: Endian) -> DirParse {
    let mut modules: Vec<String> = Vec::new();
    let mut is_64bit: bool = false;
    let mut codepage_codec: CodepageCodec = CodepageCodec::Latin1;
    let mut offset: usize = 0;
    while offset + 6 <= dir.len() {
        let tag: u16 = read_u16(dir, offset, endian);
        let mut w_length: u32 = read_u16(dir, offset + 2, endian) as u32;
        if tag == 9 {
            w_length = 6;
        } else if tag == 3 {
            w_length = 2;
        }
        offset += 6;
        let payload_end: usize = offset.saturating_add(w_length as usize);
        if payload_end > dir.len() {
            break;
        }
        match tag {
            1 if w_length >= 4 => {
                let sys_kind: u32 = read_u32(dir, offset, endian);
                if sys_kind == 3 {
                    is_64bit = true;
                }
            }
            3 if w_length >= 2 => {
                let cp: u16 = read_u16(dir, offset, endian);
                codepage_codec = CodepageCodec::from_codepage(cp);
            }
            50 => {
                let unicode_name: String = decode_utf16le(&dir[offset..payload_end]);
                if !unicode_name.is_empty() {
                    modules.push(unicode_name);
                }
            }
            _ => {}
        }
        offset = payload_end;
    }
    let _ = codepage_codec;
    DirParse { modules, is_64bit }
}

fn find_module_text_offset(dir: &[u8], module_name: &str, endian: Endian) -> Option<usize> {
    let mut current_name: Option<String> = None;
    let mut offset: usize = 0;
    while offset + 6 <= dir.len() {
        let tag: u16 = read_u16(dir, offset, endian);
        let mut w_length: u32 = read_u16(dir, offset + 2, endian) as u32;
        if tag == 9 {
            w_length = 6;
        } else if tag == 3 {
            w_length = 2;
        }
        offset += 6;
        let payload_end: usize = offset.saturating_add(w_length as usize);
        if payload_end > dir.len() {
            break;
        }
        match tag {
            50 => {
                current_name = Some(decode_utf16le(&dir[offset..payload_end]));
            }
            49 if w_length >= 4 && current_name.as_deref() == Some(module_name) => {
                return Some(read_u32(dir, offset, endian) as usize);
            }
            _ => {}
        }
        offset = payload_end;
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum CodepageCodec {
    Latin1,
    Cp1252,
}

impl CodepageCodec {
    fn from_codepage(cp: u16) -> Self {
        match cp {
            1252 => Self::Cp1252,
            _ => Self::Latin1,
        }
    }
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words)
}

fn read_u16(buf: &[u8], at: usize, endian: Endian) -> u16 {
    let pair: [u8; 2] = [buf[at], buf[at + 1]];
    match endian {
        Endian::Little => u16::from_le_bytes(pair),
        Endian::Big => u16::from_be_bytes(pair),
    }
}

fn read_u32(buf: &[u8], at: usize, endian: Endian) -> u32 {
    let quad: [u8; 4] = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
    match endian {
        Endian::Little => u32::from_le_bytes(quad),
        Endian::Big => u32::from_be_bytes(quad),
    }
}

fn extract_identifiers(vba_project: &[u8], version: u16, endian: Endian) -> Result<Vec<String>> {
    let mut idents: Vec<String> = Vec::new();
    let unicode_ref: bool =
        (version >= 0x5B && !matches!(version, 0x60 | 0x62 | 0x63)) || version == 0x4E;
    let unicode_name: bool =
        (version >= 0x59 && !matches!(version, 0x60 | 0x62 | 0x63)) || version == 0x4E;
    let non_unicode_name: bool = version <= 0x59 && version != 0x4E;
    let mut offset: usize = 0x1E;
    let (offset_n, num_refs): (usize, u16) = read_var_word(vba_project, offset, endian);
    offset = offset_n + 2;
    for _ in 0..num_refs {
        let (next_o, ref_length): (usize, u16) = read_var_word(vba_project, offset, endian);
        offset = next_o;
        if ref_length == 0 {
            offset += 6;
        } else if (unicode_ref && ref_length < 5) || (!unicode_ref && ref_length < 3) {
            offset += ref_length as usize;
        } else {
            let c_offset: usize = if unicode_ref { offset + 4 } else { offset + 2 };
            if c_offset >= vba_project.len() {
                return Err(Error::VbaPcode {
                    reason: "ref name parse out of range".to_owned(),
                });
            }
            let c: u8 = vba_project[c_offset];
            offset += ref_length as usize;
            if c == b'C' || c == b'D' {
                offset = skip_structure(vba_project, offset, endian, false, 1, false)?;
            }
        }
        offset += 10;
        let (next_o, w): (usize, u16) = read_var_word(vba_project, offset, endian);
        offset = next_o;
        if w != 0 {
            offset = skip_structure(vba_project, offset, endian, false, 1, false)?;
            let (next_o, w_length): (usize, u16) = read_var_word(vba_project, offset, endian);
            offset = next_o;
            if w_length != 0 {
                offset += 2;
            }
            offset += w_length as usize + 30;
        }
    }
    offset = skip_structure(vba_project, offset, endian, false, 2, false)?;
    offset = skip_structure(vba_project, offset, endian, false, 4, false)?;
    offset += 2;
    offset = skip_structure(vba_project, offset, endian, false, 1, true)?;
    offset = skip_structure(vba_project, offset, endian, false, 1, true)?;
    offset = skip_structure(vba_project, offset, endian, false, 1, true)?;
    offset += 0x64;
    let (next_o, num_projects): (usize, u16) = read_var_word(vba_project, offset, endian);
    offset = next_o;
    for _ in 0..num_projects {
        let (next_o, w_length): (usize, u16) = read_var_word(vba_project, offset, endian);
        offset = next_o;
        if unicode_name {
            offset += w_length as usize;
        }
        if non_unicode_name {
            let wl: u16 = if w_length != 0 {
                let (n_o, w2): (usize, u16) = read_var_word(vba_project, offset, endian);
                offset = n_o;
                w2
            } else {
                w_length
            };
            offset += wl as usize;
        }
        offset = skip_structure(vba_project, offset, endian, false, 1, false)?;
        offset = skip_structure(vba_project, offset, endian, false, 1, true)?;
        let (n_o, _): (usize, u16) = read_var_word(vba_project, offset, endian);
        offset = n_o;
        if version >= 0x6B {
            offset = skip_structure(vba_project, offset, endian, false, 1, true)?;
        }
        offset = skip_structure(vba_project, offset, endian, false, 1, true)?;
        offset += 2;
        if version != 0x51 {
            offset += 4;
        }
        offset = skip_structure(vba_project, offset, endian, false, 8, false)?;
        offset += 11;
    }
    offset += 6;
    offset = skip_structure(vba_project, offset, endian, true, 1, false)?;
    offset += 6;
    let (n_o, w0): (usize, u16) = read_var_word(vba_project, offset, endian);
    offset = n_o;
    let (n_o, num_ids): (usize, u16) = read_var_word(vba_project, offset, endian);
    offset = n_o;
    let (n_o, w1): (usize, u16) = read_var_word(vba_project, offset, endian);
    offset = n_o;
    offset += 4;
    let num_junk: i32 = num_ids as i32 + w1 as i32 - w0 as i32;
    let true_num_ids: i32 = w0 as i32 - w1 as i32;
    for _ in 0..num_junk.max(0) {
        offset += 4;
        let (id_type, id_length): (u8, u8) = read_type_length(vba_project, offset, endian);
        offset += 2;
        if id_type > 0x7F {
            offset += 6;
        }
        offset += id_length as usize;
        if offset > vba_project.len() {
            return Err(Error::VbaPcode {
                reason: "ident-junk parse overran buffer".to_owned(),
            });
        }
    }
    for _ in 0..true_num_ids.max(0) {
        let (first_type, first_length): (u8, u8) = read_type_length(vba_project, offset, endian);
        offset += 2;
        let (id_type, id_length, is_kwd): (u8, u8, bool) = if first_length == 0 && first_type == 0 {
            offset += 2;
            let (t2, l2): (u8, u8) = read_type_length(vba_project, offset, endian);
            offset += 2;
            (t2, l2, true)
        } else {
            (first_type, first_length, false)
        };
        if id_type & 0x80 != 0 {
            offset += 6;
        }
        if id_length != 0 {
            let end: usize = offset + id_length as usize;
            if end > vba_project.len() {
                break;
            }
            let raw: &[u8] = &vba_project[offset..end];
            idents.push(decode_codepage_latin1(raw));
            offset = end;
        }
        if !is_kwd {
            offset += 4;
        }
        if offset > vba_project.len() {
            break;
        }
    }
    Ok(idents)
}

fn decode_codepage_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b: &u8| *b as char).collect()
}

fn read_var_word(buf: &[u8], at: usize, endian: Endian) -> (usize, u16) {
    if at + 2 > buf.len() {
        return (at, 0);
    }
    (at + 2, read_u16(buf, at, endian))
}

fn read_type_length(buf: &[u8], at: usize, endian: Endian) -> (u8, u8) {
    if at + 2 > buf.len() {
        return (0, 0);
    }
    match endian {
        Endian::Big => (buf[at], buf[at + 1]),
        Endian::Little => (buf[at + 1], buf[at]),
    }
}

fn skip_structure(
    buf: &[u8],
    offset: usize,
    endian: Endian,
    is_length_dw: bool,
    element_size: usize,
    check_for_minus_one: bool,
) -> Result<usize> {
    let mut o: usize = offset;
    let length: u64 = if is_length_dw {
        if o + 4 > buf.len() {
            return Err(Error::VbaPcode {
                reason: "skip_structure: dword length truncated".to_owned(),
            });
        }
        let v: u32 = read_u32(buf, o, endian);
        o += 4;
        v as u64
    } else {
        if o + 2 > buf.len() {
            return Err(Error::VbaPcode {
                reason: "skip_structure: word length truncated".to_owned(),
            });
        }
        let v: u16 = read_u16(buf, o, endian);
        o += 2;
        v as u64
    };
    let skip: bool = check_for_minus_one
        && ((is_length_dw && length == 0xFFFF_FFFF) || (!is_length_dw && length == 0xFFFF));
    if !skip {
        o = o.saturating_add((length as usize).saturating_mul(element_size));
    }
    Ok(o)
}

#[derive(Debug, Clone, Copy)]
struct ModuleTables<'a> {
    indirect: &'a [u8],
    object: &'a [u8],
    declaration: &'a [u8],
}

impl ModuleTables<'_> {
    const EMPTY: ModuleTables<'static> = ModuleTables {
        indirect: &[],
        object: &[],
        declaration: &[],
    };
}

fn slice_table(buf: &[u8], start: usize, length: usize) -> &[u8] {
    let end: usize = start.saturating_add(length).min(buf.len());
    if start >= buf.len() || end <= start {
        return &[];
    }
    &buf[start..end]
}

fn extract_module_tables(
    module: &[u8],
    vba_ver: u8,
    is_64bit: bool,
    endian: Endian,
) -> ModuleTables<'_> {
    if vba_ver < 6 {
        return extract_module_tables_v5(module, endian);
    }
    if 0x0011 + 4 > module.len() {
        return ModuleTables::EMPTY;
    }
    let dw_length: usize = read_u32(module, 0x0011, endian) as usize;
    let (table_base, decl_len_off, decl_off): (usize, usize, usize) = if is_64bit {
        (dw_length + 12, 0x0043, 0x0047)
    } else {
        (dw_length + 10, 0x003F, 0x0043)
    };
    if table_base + 4 > module.len() {
        return ModuleTables::EMPTY;
    }
    let indirect_len: usize = read_u32(module, table_base, endian) as usize;
    let indirect: &[u8] = slice_table(module, table_base + 4, indirect_len);
    let decl_len: usize = if decl_len_off + 4 <= module.len() {
        read_u32(module, decl_len_off, endian) as usize
    } else {
        0
    };
    let declaration: &[u8] = slice_table(module, decl_off, decl_len);
    let object: &[u8] = extract_object_table(module, endian);
    ModuleTables {
        indirect,
        object,
        declaration,
    }
}

fn extract_object_table(module: &[u8], endian: Endian) -> &[u8] {
    if 0x0005 + 4 > module.len() {
        return &[];
    }
    let dw_length: usize = read_u32(module, 0x0005, endian) as usize;
    let dw_length2: usize = dw_length + 0x8A;
    if dw_length2 + 4 > module.len() {
        return &[];
    }
    let obj_len: usize = read_u32(module, dw_length2, endian) as usize;
    slice_table(module, dw_length2 + 4, obj_len)
}

fn extract_module_tables_v5(module: &[u8], endian: Endian) -> ModuleTables<'_> {
    let mut offset: usize = 11;
    if offset + 4 > module.len() {
        return ModuleTables::EMPTY;
    }
    let decl_len: usize = read_u32(module, offset, endian) as usize;
    let declaration: &[u8] = slice_table(module, offset + 4, decl_len);
    let Ok(mut o): Result<usize> = skip_structure(module, offset, endian, true, 1, false) else {
        return ModuleTables::EMPTY;
    };
    o += 64;
    let Ok(o2): Result<usize> = skip_structure(module, o, endian, false, 16, false) else {
        return ModuleTables::EMPTY;
    };
    let Ok(o3): Result<usize> = skip_structure(module, o2, endian, true, 1, false) else {
        return ModuleTables::EMPTY;
    };
    o = o3 + 6;
    let Ok(o4): Result<usize> = skip_structure(module, o, endian, true, 1, false) else {
        return ModuleTables::EMPTY;
    };
    offset = o4;
    let offs_indirect_len: usize = offset + 8;
    if offs_indirect_len + 4 > module.len() {
        return ModuleTables::EMPTY;
    }
    let dw_length: usize = read_u32(module, offs_indirect_len, endian) as usize;
    let table_start: usize = dw_length + 14;
    let offs2: usize = dw_length + 10;
    if offs2 + 4 > module.len() {
        return ModuleTables::EMPTY;
    }
    let indirect_len: usize = read_u32(module, offs2, endian) as usize;
    let indirect: &[u8] = slice_table(module, table_start, indirect_len);
    if offset + 4 > module.len() {
        return ModuleTables::EMPTY;
    }
    let dw_length_obj: usize = read_u32(module, offset, endian) as usize;
    let offs_obj: usize = dw_length_obj + 0x8A;
    if offs_obj + 4 > module.len() {
        return ModuleTables {
            indirect,
            object: &[],
            declaration,
        };
    }
    let obj_len: usize = read_u32(module, offs_obj, endian) as usize;
    let object: &[u8] = slice_table(module, offs_obj + 4, obj_len);
    ModuleTables {
        indirect,
        object,
        declaration,
    }
}

fn disassemble_module(
    module: &[u8],
    identifiers: &[String],
    vba_ver: u8,
    is_64bit: bool,
    name: &str,
    text_offset_hint: usize,
) -> Result<RealModuleDisasm> {
    let _ = text_offset_hint;
    if module.len() < 0x100 {
        return Err(Error::VbaPcode {
            reason: format!("module {name} too short ({} bytes)", module.len()),
        });
    }
    let endian: Endian = if read_u16(module, 2, Endian::Little) > 0xFF {
        Endian::Big
    } else {
        Endian::Little
    };
    let dw_length_off: usize = 0x0011;
    if dw_length_off + 4 > module.len() {
        return Err(Error::VbaPcode {
            reason: "module: cannot read tableStart length".to_owned(),
        });
    }
    let dw_length: u32 = read_u32(module, dw_length_off, endian);
    let table_start: usize = dw_length as usize + if is_64bit { 12 } else { 10 };
    if table_start + 4 > module.len() {
        return Err(Error::VbaPcode {
            reason: format!(
                "module {name}: indirect-table start past end (table_start={table_start} module_len={})",
                module.len()
            ),
        });
    }
    let tables: ModuleTables = extract_module_tables(module, vba_ver, is_64bit, endian);
    let anchor: usize = if vba_ver >= 6 {
        0x0019
    } else {
        module_anchor_v5(module, endian)
    };
    let mut offset: usize = anchor;
    if offset + 4 > module.len() {
        return Err(Error::VbaPcode {
            reason: "module: pcode-anchor truncated".to_owned(),
        });
    }
    let dw_length: u32 = read_u32(module, offset, endian);
    offset = (dw_length as usize).saturating_add(0x003C);
    if offset + 2 > module.len() {
        return Err(Error::VbaPcode {
            reason: "module: magic 0xCAFE offset past end".to_owned(),
        });
    }
    let magic: u16 = read_u16(module, offset, endian);
    offset += 2;
    if magic != PCODE_MAGIC {
        return Err(Error::VbaPcode {
            reason: format!(
                "module {name}: expected p-code magic 0xCAFE, got {magic:#06x} at offset {offset}"
            ),
        });
    }
    offset += 2;
    if offset + 2 > module.len() {
        return Err(Error::VbaPcode {
            reason: "module: num_lines word truncated".to_owned(),
        });
    }
    let num_lines: usize = read_u16(module, offset, endian) as usize;
    offset += 2;
    let pcode_start: usize = offset.saturating_add(num_lines * 12).saturating_add(10);
    let mut lines: Vec<RealPCodeLine> = Vec::with_capacity(num_lines);
    for line_idx in 0..num_lines {
        offset += 4;
        if offset + 2 > module.len() {
            break;
        }
        let line_length: u16 = read_u16(module, offset, endian);
        offset += 2;
        offset += 2;
        if offset + 4 > module.len() {
            break;
        }
        let line_off: u32 = read_u32(module, offset, endian);
        offset += 4;
        let line_start: usize = pcode_start.saturating_add(line_off as usize);
        let line_end: usize = line_start
            .saturating_add(line_length as usize)
            .min(module.len());
        if line_start >= module.len() || line_end <= line_start {
            lines.push(RealPCodeLine {
                line_index: line_idx,
                instructions: Vec::new(),
                text: format!("Line #{line_idx}: <empty>"),
            });
            continue;
        }
        let ctx: LineContext = LineContext {
            identifiers,
            tables,
            vba_ver,
            is_64bit,
            endian,
        };
        let (instructions, text): (Vec<PCodeInstruction>, String) =
            walk_pcode_line(&module[line_start..line_end], line_start, &ctx);
        lines.push(RealPCodeLine {
            line_index: line_idx,
            instructions,
            text,
        });
    }
    Ok(RealModuleDisasm {
        name: name.to_owned(),
        pcode_offset_in_stream: pcode_start,
        num_lines,
        lines,
    })
}

fn module_anchor_v5(module: &[u8], endian: Endian) -> usize {
    let mut offset: usize = 11;
    let Ok(o): Result<usize> = skip_structure(module, offset, endian, true, 1, false) else {
        return 0x0019;
    };
    offset = o + 64;
    let Ok(o2): Result<usize> = skip_structure(module, offset, endian, false, 16, false) else {
        return 0x0019;
    };
    let Ok(o3): Result<usize> = skip_structure(module, o2, endian, true, 1, false) else {
        return 0x0019;
    };
    offset = o3 + 6;
    let Ok(o4): Result<usize> = skip_structure(module, offset, endian, true, 1, false) else {
        return 0x0019;
    };
    o4 + 77
}

#[derive(Debug, Clone, Copy)]
struct LineContext<'a> {
    identifiers: &'a [String],
    tables: ModuleTables<'a>,
    vba_ver: u8,
    is_64bit: bool,
    endian: Endian,
}

fn walk_pcode_line(
    line: &[u8],
    abs_start: usize,
    ctx: &LineContext,
) -> (Vec<PCodeInstruction>, String) {
    let endian: Endian = ctx.endian;
    let mut out: Vec<PCodeInstruction> = Vec::new();
    let mut text: String = String::new();
    let mut o: usize = 0;
    while o + 2 <= line.len() {
        let opcode_raw: u16 = read_u16(line, o, endian);
        o += 2;
        let op_type: u16 = (opcode_raw & !0x03FF) >> 10;
        let opcode_low: u16 = opcode_raw & 0x03FF;
        let translated: u16 = translate_opcode(opcode_low, ctx.vba_ver, ctx.is_64bit);
        let info: Option<&OpcodeInfo> = lookup_opcode(translated);
        let Some(opc): Option<&OpcodeInfo> = info else {
            out.push(PCodeInstruction {
                offset: abs_start + o,
                opcode_raw,
                mnemonic: format!("Unknown_{translated:04X}"),
            });
            text.push_str(&format!(
                "Unknown_{translated:04X} (raw=0x{opcode_raw:04X}, opType=0x{op_type:X})\n"
            ));
            break;
        };
        let mut mnem_text: String = opc.mnem.to_owned();
        let mut effective_optype: u16 = op_type;
        let mut truncated: bool = false;
        if let Some(decoration) = optype_decoration(opc.mnem, &mut effective_optype) {
            mnem_text.push_str(&decoration);
        }
        for arg in opc.args {
            if o + 2 > line.len() {
                truncated = true;
                break;
            }
            match *arg {
                OpArg::Name => {
                    let w: u16 = read_u16(line, o, endian);
                    o += 2;
                    mnem_text.push(' ');
                    mnem_text.push_str(disasm_name(w, opc.mnem, effective_optype, ctx).trim_end());
                }
                OpArg::Hex16 => {
                    let w: u16 = read_u16(line, o, endian);
                    o += 2;
                    mnem_text.push_str(&format!(" 0x{w:04X}"));
                }
                OpArg::Imp => {
                    let w: u16 = read_u16(line, o, endian);
                    o += 2;
                    mnem_text.push(' ');
                    mnem_text.push_str(disasm_imp(*arg, w, opc.mnem, ctx).trim_end());
                }
                OpArg::Func => {
                    if o + 4 > line.len() {
                        truncated = true;
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push(' ');
                    mnem_text.push_str(disasm_func(dw, effective_optype, ctx).trim_end());
                }
                OpArg::Var => {
                    if o + 4 > line.len() {
                        truncated = true;
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    if effective_optype & 0x20 != 0 {
                        mnem_text.push_str(" (WithEvents)");
                    }
                    mnem_text.push(' ');
                    mnem_text.push_str(disasm_var(dw, ctx).trim_end());
                    if effective_optype & 0x10 != 0 {
                        if o + 2 > line.len() {
                            truncated = true;
                            break;
                        }
                        let w: u16 = read_u16(line, o, endian);
                        o += 2;
                        mnem_text.push_str(&format!(" 0x{w:04X}"));
                    }
                }
                OpArg::Rec => {
                    if o + 4 > line.len() {
                        truncated = true;
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push(' ');
                    mnem_text.push_str(disasm_rec(dw, ctx).trim_end());
                }
                OpArg::Type => {
                    if o + 4 > line.len() {
                        truncated = true;
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&disasm_type_arg(dw, ctx));
                }
                OpArg::Context => {
                    if o + 4 > line.len() {
                        truncated = true;
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&format!(" context_{dw:08X}"));
                    if ctx.is_64bit {
                        if o + 4 > line.len() {
                            truncated = true;
                            break;
                        }
                        let dw2: u32 = read_u32(line, o, endian);
                        o += 4;
                        mnem_text.push_str(&format!(" {dw2:08X}"));
                    }
                }
            }
        }
        if opc.varg {
            if o + 2 > line.len() {
                truncated = true;
            } else {
                let w_length: u16 = read_u16(line, o, endian);
                o += 2;
                let wanted: usize = w_length as usize;
                let available: usize = line.len().saturating_sub(o);
                let take: usize = wanted.min(available);
                let payload: &[u8] = &line[o..o + take];
                let varg_text: String = disasm_varg(opc.mnem, w_length, payload, ctx);
                mnem_text.push(' ');
                mnem_text.push_str(&varg_text);
                o += take;
                if take < wanted {
                    truncated = true;
                    o = line.len();
                } else if w_length & 1 == 1 {
                    if o < line.len() {
                        o += 1;
                    } else {
                        truncated = true;
                    }
                }
            }
        }
        if truncated {
            mnem_text.push_str(" <truncated>");
        }
        out.push(PCodeInstruction {
            offset: abs_start + o,
            opcode_raw,
            mnemonic: opc.mnem.to_owned(),
        });
        text.push_str(mnem_text.trim_end());
        text.push('\n');
    }
    (out, text)
}

const VAR_TYPE_SIGILS: [&str; 14] = [
    "", "?", "%", "&", "!", "#", "@", "?", "$", "?", "?", "?", "?", "?",
];

const VAR_TYPES_LONG: [&str; 13] = [
    "Var", "?", "Int", "Lng", "Sng", "Dbl", "Cur", "Date", "Str", "Obj", "Err", "Bool", "Var",
];

const DIM_TYPES: [&str; 18] = [
    "", "Null", "Integer", "Long", "Single", "Double", "Currency", "Date", "String", "Object",
    "Error", "Boolean", "Variant", "", "Decimal", "", "", "Byte",
];

const LIT_SPECIALS: [&str; 4] = ["False", "True", "Null", "Empty"];

const OPTION_NAMES: [&str; 6] = [
    "Base 0",
    "Base 1",
    "Compare Text",
    "Compare Binary",
    "Explicit",
    "Private Module",
];

fn optype_decoration(mnem: &str, op_type: &mut u16) -> Option<String> {
    match mnem {
        "Coerce" | "CoerceVar" | "DefType" => {
            let t: usize = *op_type as usize;
            if t < VAR_TYPES_LONG.len() {
                Some(format!(" ({})", VAR_TYPES_LONG[t]))
            } else if t == 17 {
                Some(" (Byte)".to_owned())
            } else {
                Some(format!(" ({t})"))
            }
        }
        "Dim" | "DimImplicit" | "Type" => {
            let mut parts: Vec<&str> = Vec::new();
            if *op_type & 0x04 != 0 {
                parts.push("Global");
            } else if *op_type & 0x08 != 0 {
                parts.push("Public");
            } else if *op_type & 0x10 != 0 {
                parts.push("Private");
            } else if *op_type & 0x20 != 0 {
                parts.push("Static");
            }
            if *op_type & 0x01 != 0 && mnem != "Type" {
                parts.push("Const");
            }
            if parts.is_empty() {
                None
            } else {
                Some(format!(" ({})", parts.join(" ")))
            }
        }
        "LitVarSpecial" => {
            let t: usize = *op_type as usize;
            LIT_SPECIALS.get(t).map(|s: &&str| format!(" ({s})"))
        }
        "ArgsCall" | "ArgsMemCall" | "ArgsMemCallWith" => {
            if *op_type < 16 {
                Some(" (Call)".to_owned())
            } else {
                *op_type -= 16;
                None
            }
        }
        "Option" => {
            let t: usize = *op_type as usize;
            OPTION_NAMES.get(t).map(|s: &&str| format!(" ({s})"))
        }
        "Redim" | "RedimAs" => {
            if *op_type & 16 != 0 {
                Some(" (Preserve)".to_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn disasm_name(word: u16, mnem: &str, op_type: u16, ctx: &LineContext) -> String {
    let mut var_name: String = resolve_identifier(word, ctx.identifiers, ctx.vba_ver, ctx.is_64bit);
    let t: usize = op_type as usize;
    let mut sigil: &str = if t < VAR_TYPE_SIGILS.len() {
        VAR_TYPE_SIGILS[t]
    } else {
        ""
    };
    if t >= VAR_TYPE_SIGILS.len() {
        sigil = "";
        if op_type == 32 {
            var_name = format!("[{var_name}]");
        }
    }
    let mut sigil_owned: String = sigil.to_owned();
    if mnem == "OnError" {
        sigil_owned.clear();
        if op_type == 1 {
            var_name = "(Resume Next)".to_owned();
        } else if op_type == 2 {
            var_name = "(GoTo 0)".to_owned();
        }
    } else if mnem == "Resume" {
        sigil_owned.clear();
        if op_type == 1 {
            var_name = "(Next)".to_owned();
        } else if op_type != 0 {
            var_name = String::new();
        }
    }
    format!("{var_name}{sigil_owned} ")
}

fn read_name_at(table: &[u8], offset: usize, ctx: &LineContext) -> String {
    if !has_range(table, offset, 2) {
        return String::new();
    }
    let id: u16 = read_u16(table, offset, ctx.endian);
    resolve_identifier(id, ctx.identifiers, ctx.vba_ver, ctx.is_64bit)
}

fn has_range(buf: &[u8], offset: usize, len: usize) -> bool {
    offset
        .checked_add(len)
        .is_some_and(|end: usize| end <= buf.len())
}

fn disasm_imp(arg: OpArg, word: u16, mnem: &str, ctx: &LineContext) -> String {
    if mnem != "Open" {
        let object: &[u8] = ctx.tables.object;
        let offs: usize = if ctx.is_64bit {
            object_entry_offset(word as usize, ctx)
        } else {
            word as usize
        };
        if matches!(arg, OpArg::Imp) && has_range(object, offs, 8) {
            format!("{} ", read_name_at(object, offs + 6, ctx))
        } else {
            format!("imp_{word:04X} ")
        }
    } else {
        let access_mode: [&str; 3] = ["Read", "Write", "Read Write"];
        let lock_mode: [&str; 3] = ["Read Write", "Write", "Read"];
        let mode: u16 = word & 0x00FF;
        let access: u16 = (word & 0x0F00) >> 8;
        let lock: u16 = (word & 0xF000) >> 12;
        let mut imp_name: String = "(For ".to_owned();
        if mode & 0x01 != 0 {
            imp_name.push_str("Input");
        } else if mode & 0x02 != 0 {
            imp_name.push_str("Output");
        } else if mode & 0x04 != 0 {
            imp_name.push_str("Random");
        } else if mode & 0x08 != 0 {
            imp_name.push_str("Append");
        } else if mode == 0x20 {
            imp_name.push_str("Binary");
        }
        if access != 0 && (access as usize) <= access_mode.len() {
            imp_name.push_str(" Access ");
            imp_name.push_str(access_mode[access as usize - 1]);
        }
        if lock != 0 {
            if lock & 0x04 != 0 {
                imp_name.push_str(" Shared");
            } else if (lock as usize) <= access_mode.len() {
                imp_name.push_str(" Lock ");
                imp_name.push_str(lock_mode[lock as usize - 1]);
            }
        }
        imp_name.push(')');
        imp_name
    }
}

fn type_name_from_id(type_id: u8) -> String {
    let type_flags: u8 = type_id & 0xE0;
    let base: usize = (type_id & !0xE0) as usize;
    let mut name: String = if base < DIM_TYPES.len() {
        DIM_TYPES[base].to_owned()
    } else {
        String::new()
    };
    if type_flags & 0x80 != 0 {
        name.push_str("Ptr");
    }
    name
}

fn disasm_type(indirect: &[u8], dword: usize) -> String {
    if !has_range(indirect, dword, 7) {
        return format!("type_{dword:08X}");
    }
    let type_id: usize = indirect[dword + 6] as usize;
    if type_id < DIM_TYPES.len() {
        DIM_TYPES[type_id].to_owned()
    } else {
        format!("type_{dword:08X}")
    }
}

fn disasm_type_arg(dword: u32, ctx: &LineContext) -> String {
    let indirect: &[u8] = ctx.tables.indirect;
    let d: usize = dword as usize;
    if has_range(indirect, d, 7) {
        format!(" (As {})", disasm_type(indirect, d))
    } else {
        format!(" type_{dword:08X}")
    }
}

const OBJECT_TABLE_ENTRY_BYTES: usize = 10;
const MAX_TYPE_DESCRIPTOR_DEPTH: usize = 8;

fn named_type_from_descriptor(type_desc: usize, ctx: &LineContext, depth: usize) -> String {
    let indirect: &[u8] = ctx.tables.indirect;
    if depth >= MAX_TYPE_DESCRIPTOR_DEPTH || !has_range(indirect, type_desc, 8) {
        return String::new();
    }
    let flags: u16 = read_u16(indirect, type_desc, ctx.endian);
    if flags & 0x02 != 0 {
        let element_desc: usize = type_desc + 6;
        let element_id: usize = indirect[element_desc] as usize;
        let element: String = match DIM_TYPES.get(element_id) {
            Some(name) if !name.is_empty() => (*name).to_owned(),
            _ => named_type_from_descriptor(element_desc, ctx, depth + 1),
        };
        return if element.is_empty() {
            String::new()
        } else {
            format!("{element}()")
        };
    }
    let word: usize = read_u16(indirect, type_desc + 2, ctx.endian) as usize;
    if word == 0 && !ctx.is_64bit {
        return String::new();
    }
    let offs: usize = object_entry_offset(word, ctx);
    let object: &[u8] = ctx.tables.object;
    if !has_range(object, offs, 8) {
        return String::new();
    }
    read_name_at(object, offs + 6, ctx)
}

const fn object_entry_offset(word: usize, ctx: &LineContext) -> usize {
    let entry_stride_shift: usize = if ctx.is_64bit { 3 } else { 2 };
    (word >> entry_stride_shift) * OBJECT_TABLE_ENTRY_BYTES
}

fn named_type_from_slot(type_dword: u32, ctx: &LineContext) -> String {
    if type_dword & 0xFFFF_0000 == 0xFFFF_0000 {
        return type_name_from_id((type_dword & 0x0000_00FF) as u8);
    }
    named_type_from_descriptor(type_dword as usize, ctx, 0)
}

fn disasm_object(indirect: &[u8], offset: usize, ctx: &LineContext) -> String {
    if !has_range(indirect, offset, 4) {
        return String::new();
    }
    let type_desc: usize = read_u32(indirect, offset, ctx.endian) as usize;
    named_type_from_descriptor(type_desc, ctx, 0)
}

fn disasm_rec(dword: u32, ctx: &LineContext) -> String {
    let indirect: &[u8] = ctx.tables.indirect;
    let d: usize = dword as usize;
    if !has_range(indirect, d, 20) {
        return format!("rec_{dword:08X}");
    }
    let mut object_name: String = read_name_at(indirect, d + 2, ctx);
    let options: u16 = read_u16(indirect, d + 18, ctx.endian);
    if options & 1 == 0 {
        object_name = format!("(Private) {object_name}");
    }
    object_name
}

fn disasm_var(dword: u32, ctx: &LineContext) -> String {
    let indirect: &[u8] = ctx.tables.indirect;
    let d: usize = dword as usize;
    if !has_range(indirect, d, 16) {
        return format!("var_{dword:08X}");
    }
    let b_flag1: u8 = indirect[d];
    let b_flag2: u8 = indirect[d + 1];
    let has_as: bool = b_flag1 & 0x20 != 0;
    let has_new: bool = b_flag2 & 0x20 != 0;
    let mut var_name: String = read_name_at(indirect, d + 2, ctx);
    if has_new || has_as {
        let mut var_type: String = String::new();
        if has_new {
            var_type.push_str("New");
            if has_as {
                var_type.push(' ');
            }
        }
        if has_as {
            let offs: usize = if ctx.is_64bit { 16 } else { 12 };
            if let Some(type_base) = d
                .checked_add(offs)
                .filter(|base: &usize| has_range(indirect, *base, 4))
            {
                let word: u16 = read_u16(indirect, type_base + 2, ctx.endian);
                let type_name: String = if word == 0xFFFF {
                    let type_id: u8 = indirect[type_base];
                    type_name_from_id(type_id)
                } else {
                    disasm_object(indirect, type_base, ctx)
                };
                if !type_name.is_empty() {
                    var_type.push_str("As ");
                    var_type.push_str(&type_name);
                }
            }
        }
        if !var_type.is_empty() {
            var_name.push_str(&format!(" ({var_type})"));
        }
    }
    var_name
}

const fn arg_record_offs(ctx: &LineContext) -> usize {
    if ctx.is_64bit { 4 } else { 0 }
}

fn disasm_arg(indirect: &[u8], arg_offset: usize, ctx: &LineContext) -> String {
    if !has_range(indirect, arg_offset, 2) {
        return String::new();
    }
    let flags: u16 = read_u16(indirect, arg_offset, ctx.endian);
    let offs: usize = arg_record_offs(ctx);
    let mut arg_name: String = arg_offset
        .checked_add(2)
        .map_or_else(String::new, |offset: usize| {
            read_name_at(indirect, offset, ctx)
        });
    let arg_type: u32 = if let Some(type_pos) = arg_offset
        .checked_add(offs + 12)
        .filter(|pos: &usize| has_range(indirect, *pos, 4))
    {
        read_u32(indirect, type_pos, ctx.endian)
    } else {
        0
    };
    let arg_opts: u16 = if let Some(opts_pos) = arg_offset
        .checked_add(offs + 24)
        .filter(|pos: &usize| has_range(indirect, *pos, 2))
    {
        read_u16(indirect, opts_pos, ctx.endian)
    } else {
        0
    };
    if arg_opts & 0x0004 != 0 {
        arg_name = format!("ByVal {arg_name}");
    }
    if arg_opts & 0x0002 != 0 {
        arg_name = format!("ByRef {arg_name}");
    }
    if arg_opts & 0x0106 == 0x0100 {
        arg_name = format!("ParamArray {arg_name}");
    }
    if arg_opts & 0x0200 != 0 {
        arg_name = format!("Optional {arg_name}");
    }
    if flags & 0x0020 != 0 {
        let type_name: String = named_type_from_slot(arg_type, ctx);
        if let Some(element) = type_name.strip_suffix("()") {
            arg_name.push_str("() As ");
            arg_name.push_str(element);
        } else if !type_name.is_empty() {
            arg_name.push_str(" As ");
            arg_name.push_str(&type_name);
        }
    }
    arg_name
}

fn disasm_func(dword: u32, op_type: u16, ctx: &LineContext) -> String {
    let indirect: &[u8] = ctx.tables.indirect;
    let d: usize = dword as usize;
    if !has_range(indirect, d, 61) {
        return format!("func_{dword:08X}");
    }
    let mut func_decl: String = "(".to_owned();
    let flags: u16 = read_u16(indirect, d, ctx.endian);
    let sub_name: String = read_name_at(indirect, d + 2, ctx);
    let mut offs2: usize = if ctx.vba_ver > 5 { 4 } else { 0 };
    if ctx.is_64bit {
        offs2 += 16;
    }
    let Some(arg_offset_pos): Option<usize> = d.checked_add(offs2 + 36) else {
        return format!("func_{dword:08X}");
    };
    let Some(ret_type_pos): Option<usize> = d.checked_add(offs2 + 40) else {
        return format!("func_{dword:08X}");
    };
    let Some(decl_offset_pos): Option<usize> = d.checked_add(offs2 + 44) else {
        return format!("func_{dword:08X}");
    };
    let Some(c_options_pos): Option<usize> = d.checked_add(offs2 + 54) else {
        return format!("func_{dword:08X}");
    };
    let Some(new_flags_pos): Option<usize> = d.checked_add(offs2 + 57) else {
        return format!("func_{dword:08X}");
    };
    if !has_range(indirect, arg_offset_pos, 4)
        || !has_range(indirect, ret_type_pos, 4)
        || !has_range(indirect, decl_offset_pos, 2)
        || !has_range(indirect, c_options_pos, 1)
        || !has_range(indirect, new_flags_pos, 1)
    {
        return format!("func_{dword:08X}");
    }
    let mut arg_offset: u32 = read_u32(indirect, arg_offset_pos, ctx.endian);
    let ret_type: u32 = read_u32(indirect, ret_type_pos, ctx.endian);
    let decl_offset: u16 = read_u16(indirect, decl_offset_pos, ctx.endian);
    let c_options: u8 = indirect[c_options_pos];
    let new_flags: u8 = indirect[new_flags_pos];
    let mut has_declare: bool = false;
    if ctx.vba_ver > 5 {
        if new_flags & 0x0002 == 0 && !ctx.is_64bit {
            func_decl.push_str("Private ");
        }
        if new_flags & 0x0004 != 0 {
            func_decl.push_str("Friend ");
        }
    } else if flags & 0x0008 == 0 {
        func_decl.push_str("Private ");
    }
    if op_type & 0x04 != 0 {
        func_decl.push_str("Public ");
    }
    if flags & 0x0080 != 0 {
        func_decl.push_str("Static ");
    }
    if c_options & 0x90 == 0 && decl_offset != 0xFFFF && !ctx.is_64bit {
        has_declare = true;
        func_decl.push_str("Declare ");
    }
    if ctx.vba_ver > 5 && new_flags & 0x20 != 0 {
        func_decl.push_str("PtrSafe ");
    }
    let has_as: bool = flags & 0x0020 != 0;
    if flags & 0x1000 != 0 {
        if op_type == 2 || op_type == 6 {
            func_decl.push_str("Function ");
        } else {
            func_decl.push_str("Sub ");
        }
    } else if flags & 0x2000 != 0 {
        func_decl.push_str("Property Get ");
    } else if flags & 0x4000 != 0 {
        func_decl.push_str("Property Let ");
    } else if flags & 0x8000 != 0 {
        func_decl.push_str("Property Set ");
    }
    func_decl.push_str(&sub_name);
    if has_declare {
        let lib_name: String = read_name_at(ctx.tables.declaration, decl_offset as usize + 2, ctx);
        func_decl.push_str(&format!(" Lib \"{lib_name}\" "));
    }
    let arg_offs: usize = arg_record_offs(ctx);
    let mut arg_list: Vec<String> = Vec::new();
    let mut seen_arg_bases: Vec<u32> = Vec::new();
    while arg_offset != 0xFFFF_FFFF
        && arg_offset != 0
        && arg_list.len() < MAX_FUNC_ARG_CHAIN
        && !seen_arg_bases.contains(&arg_offset)
        && has_range(indirect, arg_offset as usize, arg_offs + 26)
    {
        seen_arg_bases.push(arg_offset);
        let arg_base: usize = arg_offset as usize;
        arg_list.push(disasm_arg(indirect, arg_base, ctx));
        let Some(next_pos): Option<usize> = arg_base
            .checked_add(arg_offs + 20)
            .filter(|pos: &usize| has_range(indirect, *pos, 4))
        else {
            break;
        };
        arg_offset = read_u32(indirect, next_pos, ctx.endian);
    }
    func_decl.push('(');
    func_decl.push_str(&arg_list.join(", "));
    func_decl.push(')');
    if has_as {
        let ret_name: String = named_type_from_slot(ret_type, ctx);
        if !ret_name.is_empty() {
            func_decl.push_str(" As ");
            func_decl.push_str(&ret_name);
        }
    }
    func_decl.push(')');
    func_decl
}

fn disasm_varg(mnem: &str, w_length: u16, payload: &[u8], ctx: &LineContext) -> String {
    match mnem {
        "LitStr" | "QuoteRem" | "Rem" | "Reparse" => {
            format!("0x{w_length:04X} \"{}\"", decode_codepage_latin1(payload))
        }
        "OnGosub" | "OnGoto" => {
            let mut vars: Vec<String> = Vec::new();
            let mut p: usize = 0;
            while p + 2 <= payload.len() {
                let word: u16 = read_u16(payload, p, ctx.endian);
                p += 2;
                vars.push(resolve_identifier(
                    word,
                    ctx.identifiers,
                    ctx.vba_ver,
                    ctx.is_64bit,
                ));
            }
            format!("0x{w_length:04X} {}", vars.join(", "))
        }
        _ => {
            let hex: String = payload
                .iter()
                .map(|b: &u8| format!("{b:02X}"))
                .collect::<Vec<String>>()
                .join(" ");
            format!("0x{w_length:04X} {hex}")
        }
    }
}

fn resolve_identifier(id_code: u16, identifiers: &[String], vba_ver: u8, is_64bit: bool) -> String {
    let orig_code: u16 = id_code;
    let mut idx: i32 = (id_code >> 1) as i32;
    if idx >= 0x100 {
        idx -= 0x100;
        if vba_ver >= 7 {
            idx -= 4;
            if is_64bit {
                idx -= 3;
            }
        }
        if idx >= 0 && (idx as usize) < identifiers.len() {
            DebugLog::for_scope("shell").kv("resolved-identifier-index", || idx.to_string());
            return identifiers[idx as usize].clone();
        }
        return format!("id_{orig_code:04X}");
    }
    if vba_ver >= 7 && idx >= 0xC3 {
        idx -= 1;
    }
    INTERNAL_NAMES
        .get(idx as usize)
        .map(|s: &&str| (*s).to_owned())
        .unwrap_or_else(|| format!("id_{orig_code:04X}"))
}

fn translate_opcode(opcode: u16, vba_ver: u8, is_64bit: bool) -> u16 {
    match vba_ver {
        3 => translate_v3(opcode),
        5 => translate_v5(opcode),
        _ if !is_64bit => translate_v6or7_32(opcode),
        _ => opcode,
    }
}

fn translate_v3(o: u16) -> u16 {
    match o {
        0..=67 => o,
        68..=70 => o + 2,
        71..=111 => o + 4,
        112..=150 => o + 8,
        151..=164 => o + 9,
        165..=166 => o + 10,
        167..=169 => o + 11,
        170..=238 => o + 12,
        _ => o + 24,
    }
}

fn translate_v5(o: u16) -> u16 {
    match o {
        0..=68 => o,
        69..=71 => o + 1,
        72..=112 => o + 3,
        113..=151 => o + 7,
        152..=165 => o + 8,
        166..=167 => o + 9,
        168..=170 => o + 10,
        _ => o + 11,
    }
}

fn translate_v6or7_32(o: u16) -> u16 {
    match o {
        0..=173 => o,
        174..=175 => o + 1,
        176..=178 => o + 2,
        _ => o + 3,
    }
}

fn lookup_opcode(translated: u16) -> Option<&'static OpcodeInfo> {
    let idx: usize = translated as usize;
    if idx >= OPCODES.len() {
        return None;
    }
    let entry: &OpcodeInfo = &OPCODES[idx];
    if entry.mnem.is_empty() {
        None
    } else {
        Some(entry)
    }
}

#[derive(Debug, Clone, Copy)]
enum OpArg {
    Name,
    Hex16,
    Imp,
    Func,
    Var,
    Rec,
    Type,
    Context,
}

#[derive(Debug, Clone, Copy)]
struct OpcodeInfo {
    mnem: &'static str,
    args: &'static [OpArg],
    varg: bool,
}

const NA: &[OpArg] = &[];
const A_NAME: &[OpArg] = &[OpArg::Name];
const A_HEX: &[OpArg] = &[OpArg::Hex16];
const A_NAME_HEX: &[OpArg] = &[OpArg::Name, OpArg::Hex16];
const A_IMP: &[OpArg] = &[OpArg::Imp];
const A_CTX: &[OpArg] = &[OpArg::Context];
const A_FUNC: &[OpArg] = &[OpArg::Func];
const A_VAR: &[OpArg] = &[OpArg::Var];
const A_REC: &[OpArg] = &[OpArg::Rec];
const A_NAME_HEX_TYPE: &[OpArg] = &[OpArg::Name, OpArg::Hex16, OpArg::Type];
const A_4HEX: &[OpArg] = &[OpArg::Hex16, OpArg::Hex16, OpArg::Hex16, OpArg::Hex16];
const A_2HEX: &[OpArg] = &[OpArg::Hex16, OpArg::Hex16];

const fn op(mnem: &'static str, args: &'static [OpArg], varg: bool) -> OpcodeInfo {
    OpcodeInfo { mnem, args, varg }
}

static OPCODES: [OpcodeInfo; 264] = [
    op("Imp", NA, false),
    op("Eqv", NA, false),
    op("Xor", NA, false),
    op("Or", NA, false),
    op("And", NA, false),
    op("Eq", NA, false),
    op("Ne", NA, false),
    op("Le", NA, false),
    op("Ge", NA, false),
    op("Lt", NA, false),
    op("Gt", NA, false),
    op("Add", NA, false),
    op("Sub", NA, false),
    op("Mod", NA, false),
    op("IDiv", NA, false),
    op("Mul", NA, false),
    op("Div", NA, false),
    op("Concat", NA, false),
    op("Like", NA, false),
    op("Pwr", NA, false),
    op("Is", NA, false),
    op("Not", NA, false),
    op("UMi", NA, false),
    op("FnAbs", NA, false),
    op("FnFix", NA, false),
    op("FnInt", NA, false),
    op("FnSgn", NA, false),
    op("FnLen", NA, false),
    op("FnLenB", NA, false),
    op("Paren", NA, false),
    op("Sharp", NA, false),
    op("LdLHS", A_NAME, false),
    op("Ld", A_NAME, false),
    op("MemLd", A_NAME, false),
    op("DictLd", A_NAME, false),
    op("IndexLd", A_HEX, false),
    op("ArgsLd", A_NAME_HEX, false),
    op("ArgsMemLd", A_NAME_HEX, false),
    op("ArgsDictLd", A_NAME_HEX, false),
    op("St", A_NAME, false),
    op("MemSt", A_NAME, false),
    op("DictSt", A_NAME, false),
    op("IndexSt", A_HEX, false),
    op("ArgsSt", A_NAME_HEX, false),
    op("ArgsMemSt", A_NAME_HEX, false),
    op("ArgsDictSt", A_NAME_HEX, false),
    op("Set", A_NAME, false),
    op("Memset", A_NAME, false),
    op("Dictset", A_NAME, false),
    op("Indexset", A_HEX, false),
    op("ArgsSet", A_NAME_HEX, false),
    op("ArgsMemSet", A_NAME_HEX, false),
    op("ArgsDictSet", A_NAME_HEX, false),
    op("MemLdWith", A_NAME, false),
    op("DictLdWith", A_NAME, false),
    op("ArgsMemLdWith", A_NAME_HEX, false),
    op("ArgsDictLdWith", A_NAME_HEX, false),
    op("MemStWith", A_NAME, false),
    op("DictStWith", A_NAME, false),
    op("ArgsMemStWith", A_NAME_HEX, false),
    op("ArgsDictStWith", A_NAME_HEX, false),
    op("MemSetWith", A_NAME, false),
    op("DictSetWith", A_NAME, false),
    op("ArgsMemSetWith", A_NAME_HEX, false),
    op("ArgsDictSetWith", A_NAME_HEX, false),
    op("ArgsCall", A_NAME_HEX, false),
    op("ArgsMemCall", A_NAME_HEX, false),
    op("ArgsMemCallWith", A_NAME_HEX, false),
    op("ArgsArray", A_NAME_HEX, false),
    op("Assert", NA, false),
    op("BoS", A_HEX, false),
    op("BoSImplicit", NA, false),
    op("BoL", NA, false),
    op("LdAddressOf", A_NAME, false),
    op("MemAddressOf", A_NAME, false),
    op("Case", NA, false),
    op("CaseTo", NA, false),
    op("CaseGt", NA, false),
    op("CaseLt", NA, false),
    op("CaseGe", NA, false),
    op("CaseLe", NA, false),
    op("CaseNe", NA, false),
    op("CaseEq", NA, false),
    op("CaseElse", NA, false),
    op("CaseDone", NA, false),
    op("Circle", A_HEX, false),
    op("Close", A_HEX, false),
    op("CloseAll", NA, false),
    op("Coerce", NA, false),
    op("CoerceVar", NA, false),
    op("Context", A_CTX, false),
    op("Debug", NA, false),
    op("DefType", A_2HEX, false),
    op("Dim", NA, false),
    op("DimImplicit", NA, false),
    op("Do", NA, false),
    op("DoEvents", NA, false),
    op("DoUnitil", NA, false),
    op("DoWhile", NA, false),
    op("Else", NA, false),
    op("ElseBlock", NA, false),
    op("ElseIfBlock", NA, false),
    op("ElseIfTypeBlock", A_IMP, false),
    op("End", NA, false),
    op("EndContext", NA, false),
    op("EndFunc", NA, false),
    op("EndIf", NA, false),
    op("EndIfBlock", NA, false),
    op("EndImmediate", NA, false),
    op("EndProp", NA, false),
    op("EndSelect", NA, false),
    op("EndSub", NA, false),
    op("EndType", NA, false),
    op("EndWith", NA, false),
    op("Erase", A_HEX, false),
    op("Error", NA, false),
    op("EventDecl", A_FUNC, false),
    op("RaiseEvent", A_NAME_HEX, false),
    op("ArgsMemRaiseEvent", A_NAME_HEX, false),
    op("ArgsMemRaiseEventWith", A_NAME_HEX, false),
    op("ExitDo", NA, false),
    op("ExitFor", NA, false),
    op("ExitFunc", NA, false),
    op("ExitProp", NA, false),
    op("ExitSub", NA, false),
    op("FnCurDir", NA, false),
    op("FnDir", NA, false),
    op("Empty0", NA, false),
    op("Empty1", NA, false),
    op("FnError", NA, false),
    op("FnFormat", NA, false),
    op("FnFreeFile", NA, false),
    op("FnInStr", NA, false),
    op("FnInStr3", NA, false),
    op("FnInStr4", NA, false),
    op("FnInStrB", NA, false),
    op("FnInStrB3", NA, false),
    op("FnInStrB4", NA, false),
    op("FnLBound", A_HEX, false),
    op("FnMid", NA, false),
    op("FnMidB", NA, false),
    op("FnStrComp", NA, false),
    op("FnStrComp3", NA, false),
    op("FnStringVar", NA, false),
    op("FnStringStr", NA, false),
    op("FnUBound", A_HEX, false),
    op("For", NA, false),
    op("ForEach", NA, false),
    op("ForEachAs", A_IMP, false),
    op("ForStep", NA, false),
    op("FuncDefn", A_FUNC, false),
    op("FuncDefnSave", A_FUNC, false),
    op("GetRec", NA, false),
    op("GoSub", A_NAME, false),
    op("GoTo", A_NAME, false),
    op("If", NA, false),
    op("IfBlock", NA, false),
    op("TypeOf", A_IMP, false),
    op("IfTypeBlock", A_IMP, false),
    op("Implements", A_4HEX, false),
    op("Input", NA, false),
    op("InputDone", NA, false),
    op("InputItem", NA, false),
    op("Label", A_NAME, false),
    op("Let", NA, false),
    op("Line", A_HEX, false),
    op("LineCont", NA, true),
    op("LineInput", NA, false),
    op("LineNum", A_NAME, false),
    op("LitCy", A_4HEX, false),
    op("LitDate", A_4HEX, false),
    op("LitDefault", NA, false),
    op("LitDI2", A_HEX, false),
    op("LitDI4", A_2HEX, false),
    op("LitDI8", A_4HEX, false),
    op("LitHI2", A_HEX, false),
    op("LitHI4", A_2HEX, false),
    op("LitHI8", A_4HEX, false),
    op("LitNothing", NA, false),
    op("LitOI2", A_HEX, false),
    op("LitOI4", A_2HEX, false),
    op("LitOI8", A_4HEX, false),
    op("LitR4", A_2HEX, false),
    op("LitR8", A_4HEX, false),
    op("LitSmallI2", NA, false),
    op("LitStr", NA, true),
    op("LitVarSpecial", NA, false),
    op("Lock", NA, false),
    op("Loop", NA, false),
    op("LoopUntil", NA, false),
    op("LoopWhile", NA, false),
    op("LSet", NA, false),
    op("Me", NA, false),
    op("MeImplicit", NA, false),
    op("MemRedim", A_NAME_HEX_TYPE, false),
    op("MemRedimWith", A_NAME_HEX_TYPE, false),
    op("MemRedimAs", A_NAME_HEX_TYPE, false),
    op("MemRedimAsWith", A_NAME_HEX_TYPE, false),
    op("Mid", NA, false),
    op("MidB", NA, false),
    op("Name", NA, false),
    op("New", A_IMP, false),
    op("Next", NA, false),
    op("NextVar", NA, false),
    op("OnError", A_NAME, false),
    op("OnGosub", NA, true),
    op("OnGoto", NA, true),
    op("Open", A_IMP, false),
    op("Option", NA, false),
    op("OptionBase", NA, false),
    op("ParamByVal", NA, false),
    op("ParamOmitted", NA, false),
    op("ParamNamed", A_NAME, false),
    op("PrintChan", NA, false),
    op("PrintComma", NA, false),
    op("PrintEoS", NA, false),
    op("PrintItemComma", NA, false),
    op("PrintItemNL", NA, false),
    op("PrintItemSemi", NA, false),
    op("PrintNL", NA, false),
    op("PrintObj", NA, false),
    op("PrintSemi", NA, false),
    op("PrintSpc", NA, false),
    op("PrintTab", NA, false),
    op("PrintTabComma", NA, false),
    op("PSet", A_HEX, false),
    op("PutRec", NA, false),
    op("QuoteRem", A_HEX, true),
    op("Redim", A_NAME_HEX_TYPE, false),
    op("RedimAs", A_NAME_HEX_TYPE, false),
    op("Reparse", NA, true),
    op("Rem", NA, true),
    op("Resume", A_NAME, false),
    op("Return", NA, false),
    op("RSet", NA, false),
    op("Scale", A_HEX, false),
    op("Seek", NA, false),
    op("SelectCase", NA, false),
    op("SelectIs", A_IMP, false),
    op("SelectType", NA, false),
    op("SetStmt", NA, false),
    op("Stack", A_2HEX, false),
    op("Stop", NA, false),
    op("Type", A_REC, false),
    op("Unlock", NA, false),
    op("VarDefn", A_VAR, false),
    op("Wend", NA, false),
    op("While", NA, false),
    op("With", NA, false),
    op("WriteChan", NA, false),
    op("ConstFuncExpr", NA, false),
    op("LbConst", A_NAME, false),
    op("LbIf", NA, false),
    op("LbElse", NA, false),
    op("LbElseIf", NA, false),
    op("LbEndIf", NA, false),
    op("LbMark", NA, false),
    op("EndForVariable", NA, false),
    op("StartForVariable", NA, false),
    op("NewRedim", NA, false),
    op("StartWithExpr", NA, false),
    op("SetOrSt", A_NAME, false),
    op("EndEnum", NA, false),
    op("Illegal", NA, false),
];

static INTERNAL_NAMES: &[&str] = &[
    "<crash>",
    "0",
    "Abs",
    "Access",
    "AddressOf",
    "Alias",
    "And",
    "Any",
    "Append",
    "Array",
    "As",
    "Assert",
    "B",
    "Base",
    "BF",
    "Binary",
    "Boolean",
    "ByRef",
    "Byte",
    "ByVal",
    "Call",
    "Case",
    "CBool",
    "CByte",
    "CCur",
    "CDate",
    "CDec",
    "CDbl",
    "CDecl",
    "ChDir",
    "CInt",
    "Circle",
    "CLng",
    "Close",
    "Compare",
    "Const",
    "CSng",
    "CStr",
    "CurDir",
    "CurDir$",
    "CVar",
    "CVDate",
    "CVErr",
    "Currency",
    "Database",
    "Date",
    "Date$",
    "Debug",
    "Decimal",
    "Declare",
    "DefBool",
    "DefByte",
    "DefCur",
    "DefDate",
    "DefDec",
    "DefDbl",
    "DefInt",
    "DefLng",
    "DefObj",
    "DefSng",
    "DefStr",
    "DefVar",
    "Dim",
    "Dir",
    "Dir$",
    "Do",
    "DoEvents",
    "Double",
    "Each",
    "Else",
    "ElseIf",
    "Empty",
    "End",
    "EndIf",
    "Enum",
    "Eqv",
    "Erase",
    "Error",
    "Error$",
    "Event",
    "WithEvents",
    "Explicit",
    "F",
    "False",
    "Fix",
    "For",
    "Format",
    "Format$",
    "FreeFile",
    "Friend",
    "Function",
    "Get",
    "Global",
    "Go",
    "GoSub",
    "Goto",
    "If",
    "Imp",
    "Implements",
    "In",
    "Input",
    "Input$",
    "InputB",
    "InputB",
    "InStr",
    "InputB$",
    "Int",
    "InStrB",
    "Is",
    "Integer",
    "Left",
    "LBound",
    "LenB",
    "Len",
    "Lib",
    "Let",
    "Line",
    "Like",
    "Load",
    "Local",
    "Lock",
    "Long",
    "Loop",
    "LSet",
    "Me",
    "Mid",
    "Mid$",
    "MidB",
    "MidB$",
    "Mod",
    "Module",
    "Name",
    "New",
    "Next",
    "Not",
    "Nothing",
    "Null",
    "Object",
    "On",
    "Open",
    "Option",
    "Optional",
    "Or",
    "Output",
    "ParamArray",
    "Preserve",
    "Print",
    "Private",
    "Property",
    "PSet",
    "Public",
    "Put",
    "RaiseEvent",
    "Random",
    "Randomize",
    "Read",
    "ReDim",
    "Rem",
    "Resume",
    "Return",
    "RGB",
    "RSet",
    "Scale",
    "Seek",
    "Select",
    "Set",
    "Sgn",
    "Shared",
    "Single",
    "Spc",
    "Static",
    "Step",
    "Stop",
    "StrComp",
    "String",
    "String$",
    "Sub",
    "Tab",
    "Text",
    "Then",
    "To",
    "True",
    "Type",
    "TypeOf",
    "UBound",
    "Unload",
    "Unlock",
    "Unknown",
    "Until",
    "Variant",
    "WEnd",
    "While",
    "Width",
    "With",
    "Write",
    "Xor",
    "#Const",
    "#Else",
    "#ElseIf",
    "#End",
    "#If",
    "Attribute",
    "VB_Base",
    "VB_Control",
    "VB_Creatable",
    "VB_Customizable",
    "VB_Description",
    "VB_Exposed",
    "VB_Ext_Key",
    "VB_HelpID",
    "VB_Invoke_Func",
    "VB_Invoke_Property",
    "VB_Invoke_PropertyPut",
    "VB_Invoke_PropertyPutRef",
    "VB_MemberFlags",
    "VB_Name",
    "VB_PredecraredID",
    "VB_ProcData",
    "VB_TemplateDerived",
    "VB_VarDescription",
    "VB_VarHelpID",
    "VB_VarMemberFlags",
    "VB_VarProcData",
    "VB_UserMemID",
    "VB_VarUserMemID",
    "VB_GlobalNameSpace",
    ",",
    ".",
    "\"",
    "_",
    "!",
    "#",
    "&",
    "'",
    "(",
    ")",
    "*",
    "+",
    "-",
    " /",
    ":",
    ";",
    "<",
    "<=",
    "<>",
    "=",
    "=<",
    "=>",
    ">",
    "><",
    ">=",
    "?",
    "\\",
    "^",
    ":=",
];

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn copy_token_mask_at_zero_is_12bit_length_4bit_offset() {
        let m: u16 = copy_token_length_mask(0);
        assert_eq!(m, 0x0FFF);
        assert_eq!(copy_token_bit_count(0), 4);
    }

    #[test]
    fn copy_token_mask_at_16_stays_4bit_offset() {
        assert_eq!(copy_token_length_mask(16), 0x0FFF);
        assert_eq!(copy_token_bit_count(16), 4);
    }

    #[test]
    fn copy_token_mask_at_17_drops_to_5_offset_bits() {
        assert_eq!(copy_token_length_mask(17), 0x07FF);
        assert_eq!(copy_token_bit_count(17), 5);
    }

    #[test]
    fn decompress_minimal_chunk() {
        let data: &[u8] = &[0x01, 0x03, 0xB0, 0x00, b'H', b'i'];
        let out: Vec<u8> = decompress_ovba(data).expect("decompress");
        assert_eq!(out, b"Hi");
    }

    #[test]
    fn decompress_rejects_output_past_cap() {
        let data: &[u8] = &[0x01, 0x03, 0xB0, 0x00, b'H', b'i'];
        let Err(err): Result<Vec<u8>> = decompress_ovba_bounded(data, 1) else {
            panic!("bounded decompression must reject oversized output");
        };
        assert!(err.to_string().contains("decompressed VBA stream exceeds"));
    }

    #[test]
    fn decompress_rejects_copytoken_self_reference_expansion_past_cap() {
        let data: &[u8] = &[0x01, 0x05, 0xB0, 0x08, b'a', b'b', b'c', 0x03, 0x20];
        let Err(err): Result<Vec<u8>> = decompress_ovba_bounded(data, 5) else {
            panic!(
                "the same 3-byte-to-9-byte self-referential CopyToken expansion that \
                 decompress_chunk_with_copytoken_roundtrip proves correct must be rejected, \
                 not grown unbounded, once it crosses a 5-byte cap"
            );
        };
        assert!(err.to_string().contains("decompressed VBA stream exceeds"));
    }

    #[test]
    fn decompress_chunk_with_copytoken_roundtrip() {
        let data: &[u8] = &[0x01, 0x05, 0xB0, 0x08, b'a', b'b', b'c', 0x03, 0x20];
        let out: Vec<u8> = decompress_ovba(data).expect("decompress");
        assert_eq!(out, b"abcabcabc");
    }

    #[test]
    fn decompress_raw_chunk_copies_verbatim() {
        let mut data: Vec<u8> = vec![0x01, 0xFF, 0x3F];
        data.extend_from_slice(b"verbatim");
        let out: Vec<u8> = decompress_ovba(&data).expect("decompress");
        assert_eq!(out, b"verbatim");
    }

    const OP_LD: u16 = 32;
    const OP_ST: u16 = 39;
    const OP_ADD: u16 = 11;
    const OP_DIM: u16 = 93;
    const OP_ARGSCALL: u16 = 65;
    const OP_FUNCDEFN: u16 = 150;
    const OP_ENDSUB: u16 = 111;
    const OP_FOR: u16 = 146;
    const OP_NEXT: u16 = 202;
    const OP_LITDI2: u16 = 172;
    const OP_LITSTR: u16 = 185;

    fn invert_v6or7_32(table_index: u16) -> u16 {
        let raw: u16 = match table_index {
            0..=173 => table_index,
            175..=176 => table_index - 1,
            178..=180 => table_index - 2,
            _ => table_index - 3,
        };
        assert_eq!(
            translate_v6or7_32(raw),
            table_index,
            "encoder inverse must round-trip table index {table_index}"
        );
        raw
    }

    struct PCodeAsm {
        bytes: Vec<u8>,
    }

    impl PCodeAsm {
        fn new() -> Self {
            Self { bytes: Vec::new() }
        }

        fn opcode(&mut self, table_index: u16) -> &mut Self {
            self.bytes
                .extend_from_slice(&invert_v6or7_32(table_index).to_le_bytes());
            self
        }

        fn opcode_optype(&mut self, table_index: u16, op_type: u16) -> &mut Self {
            let raw: u16 = invert_v6or7_32(table_index) | (op_type << 10);
            self.bytes.extend_from_slice(&raw.to_le_bytes());
            self
        }

        fn word(&mut self, w: u16) -> &mut Self {
            self.bytes.extend_from_slice(&w.to_le_bytes());
            self
        }

        fn dword(&mut self, d: u32) -> &mut Self {
            self.bytes.extend_from_slice(&d.to_le_bytes());
            self
        }

        fn internal_name(&mut self, internal_index: u16) -> &mut Self {
            self.word(internal_index << 1)
        }

        fn custom_name(&mut self, custom_index: u16) -> &mut Self {
            self.word((custom_index + 0x100) << 1)
        }

        fn lit_str(&mut self, payload: &[u8]) -> &mut Self {
            self.opcode(OP_LITSTR);
            self.word(payload.len() as u16);
            self.bytes.extend_from_slice(payload);
            if payload.len() & 1 == 1 {
                self.bytes.push(0);
            }
            self
        }

        fn finish(&self) -> &[u8] {
            &self.bytes
        }
    }

    fn disasm_line(asm: &PCodeAsm, idents: &[String], vba_ver: u8, is_64bit: bool) -> String {
        let ctx: LineContext = LineContext {
            identifiers: idents,
            tables: ModuleTables::EMPTY,
            vba_ver,
            is_64bit,
            endian: Endian::Little,
        };
        let (_, text): (Vec<PCodeInstruction>, String) = walk_pcode_line(asm.finish(), 0, &ctx);
        text
    }

    #[test]
    fn oracle_decodes_internal_name_load() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LD).internal_name(0x42);
        let expected: &str = INTERNAL_NAMES[0x42];
        let text: String = disasm_line(&asm, &[], 6, false);
        assert_eq!(text, format!("Ld {expected}\n"));
    }

    #[test]
    fn oracle_resolves_custom_identifier_by_index() {
        let idents: Vec<String> = vec!["alpha".to_owned(), "Beta".to_owned(), "gamma".to_owned()];
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LD).custom_name(1);
        let text: String = disasm_line(&asm, &idents, 6, false);
        assert_eq!(text, "Ld Beta\n");
    }

    #[test]
    fn oracle_decodes_litstr_varg_with_odd_padding() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.lit_str(b"hello world");
        let text: String = disasm_line(&asm, &[], 6, false);
        assert_eq!(text, "LitStr 0x000B \"hello world\"\n");
    }

    #[test]
    fn oracle_decodes_litstr_even_length_no_padding() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.lit_str(b"ab").opcode(OP_ST).custom_name(0);
        let idents: Vec<String> = vec!["dest".to_owned()];
        let text: String = disasm_line(&asm, &idents, 6, false);
        assert_eq!(text, "LitStr 0x0002 \"ab\"\nSt dest\n");
    }

    #[test]
    fn truncated_fixed_operand_is_annotated() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LD);
        let text: String = disasm_line(&asm, &[], 6, false);
        assert!(
            text.contains("<truncated>") && text != "Ld\n",
            "truncated operand must not look complete: {text}"
        );
    }

    #[test]
    fn truncated_litstr_payload_is_annotated() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LITSTR).word(0x0010);
        asm.bytes.push(b'A');
        let text: String = disasm_line(&asm, &[], 6, false);
        assert!(
            text.contains("LitStr 0x0010 \"A\" <truncated>"),
            "truncated LitStr must surface truncation: {text}"
        );
    }

    #[test]
    fn range_probe_rejects_overflowing_offsets() {
        let bytes: [u8; 4] = [0, 0, 0, 0];
        assert!(has_range(&bytes, 0, 4));
        assert!(!has_range(&bytes, usize::MAX - 3, 4));
        assert!(!has_range(&bytes, usize::MAX, 1));
    }

    #[test]
    fn oracle_decodes_litdi2_hex_operand() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LITDI2).word(0x002A);
        let text: String = disasm_line(&asm, &[], 6, false);
        assert_eq!(text, "LitDI2 0x002A\n");
    }

    #[test]
    fn oracle_decodes_argscall_name_and_argcount() {
        let idents: Vec<String> = vec!["MsgBox".to_owned()];
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_ARGSCALL).custom_name(0).word(0x0001);
        let text: String = disasm_line(&asm, &idents, 6, false);
        assert_eq!(text, "ArgsCall (Call) MsgBox 0x0001\n");
    }

    #[test]
    fn oracle_argscall_high_optype_suppresses_call_marker() {
        let idents: Vec<String> = vec!["MsgBox".to_owned()];
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode_optype(OP_ARGSCALL, 16)
            .custom_name(0)
            .word(0x0001);
        let text: String = disasm_line(&asm, &idents, 6, false);
        assert_eq!(text, "ArgsCall MsgBox 0x0001\n");
    }

    #[test]
    fn oracle_decodes_funcdefn_dword_operand() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_FUNCDEFN).dword(0xDEAD_BEEF);
        let text: String = disasm_line(&asm, &[], 6, false);
        assert_eq!(text, "FuncDefn func_DEADBEEF\n");
    }

    #[test]
    fn cyclic_func_arg_chain_terminates_bounded() {
        let mut indirect: Vec<u8> = vec![0u8; 64];
        indirect[6..8].copy_from_slice(&(0x100u16 << 1).to_le_bytes());
        indirect[40..44].copy_from_slice(&4u32.to_le_bytes());
        indirect[24..28].copy_from_slice(&4u32.to_le_bytes());
        let identifiers: Vec<String> = vec!["ARG".to_owned()];
        let tables: ModuleTables = ModuleTables {
            indirect: &indirect,
            object: &[],
            declaration: &[],
        };
        let ctx: LineContext = LineContext {
            identifiers: &identifiers,
            tables,
            vba_ver: 6,
            is_64bit: false,
            endian: Endian::Little,
        };
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_FUNCDEFN).dword(0);
        let (_, text): (Vec<PCodeInstruction>, String) = walk_pcode_line(asm.finish(), 0, &ctx);
        assert_eq!(
            text.matches("ARG").count(),
            1,
            "a self-referential arg chain must render each record once, not walk forever"
        );
        assert!(text.len() < 1 << 20, "capped arg chain must stay bounded");
    }

    fn identifier_code_64bit(index: u16) -> u16 {
        (index + 0x100 + 4 + 3) * 2
    }

    #[test]
    fn every_parameter_in_a_64_bit_arg_chain_is_rendered() {
        let mut indirect: Vec<u8> = vec![0u8; 256];
        indirect[0..2].copy_from_slice(&0x1000u16.to_le_bytes());
        indirect[2..4].copy_from_slice(&identifier_code_64bit(0).to_le_bytes());
        indirect[56..60].copy_from_slice(&128u32.to_le_bytes());
        indirect[60..64].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        indirect[64..66].copy_from_slice(&0xFFFFu16.to_le_bytes());
        for (record, index, next) in [(128usize, 1u16, 160u32), (160, 2, 0xFFFF_FFFF)] {
            indirect[record..record + 2].copy_from_slice(&0x0020u16.to_le_bytes());
            indirect[record + 2..record + 4]
                .copy_from_slice(&identifier_code_64bit(index).to_le_bytes());
            indirect[record + 16..record + 20].copy_from_slice(&0xFFFF_0008u32.to_le_bytes());
            indirect[record + 24..record + 28].copy_from_slice(&next.to_le_bytes());
        }
        let identifiers: Vec<String> =
            vec!["OWNER".to_owned(), "FIRST".to_owned(), "SECOND".to_owned()];
        let ctx: LineContext = LineContext {
            identifiers: &identifiers,
            tables: ModuleTables {
                indirect: &indirect,
                object: &[],
                declaration: &[],
            },
            vba_ver: 7,
            is_64bit: true,
            endian: Endian::Little,
        };
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_FUNCDEFN).dword(0);
        let (_, text): (Vec<PCodeInstruction>, String) = walk_pcode_line(asm.finish(), 0, &ctx);
        assert!(
            text.contains("OWNER(FIRST As String, SECOND As String)"),
            "both parameters of a 64-bit arg chain must appear; got {text}"
        );
    }

    #[test]
    fn oracle_round_trips_full_program() {
        let idents: Vec<String> = vec!["result".to_owned(), "MsgBox".to_owned(), "i".to_owned()];
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_FUNCDEFN).dword(0);
        asm.opcode(OP_DIM);
        asm.opcode(OP_LD).custom_name(0);
        asm.opcode(OP_LITDI2).word(0x0003);
        asm.opcode(OP_ADD);
        asm.opcode(OP_ST).custom_name(0);
        asm.lit_str(b"done");
        asm.opcode(OP_ARGSCALL).custom_name(1).word(0x0001);
        asm.opcode(OP_LD).custom_name(2);
        asm.opcode(OP_LITDI2).word(0x0001);
        asm.opcode(OP_LITDI2).word(0x000A);
        asm.opcode(OP_FOR);
        asm.opcode(OP_NEXT);
        asm.opcode(OP_ENDSUB);
        let text: String = disasm_line(&asm, &idents, 6, false);
        let expected: &str = concat!(
            "FuncDefn func_00000000\n",
            "Dim\n",
            "Ld result\n",
            "LitDI2 0x0003\n",
            "Add\n",
            "St result\n",
            "LitStr 0x0004 \"done\"\n",
            "ArgsCall (Call) MsgBox 0x0001\n",
            "Ld i\n",
            "LitDI2 0x0001\n",
            "LitDI2 0x000A\n",
            "For\n",
            "Next\n",
            "EndSub\n",
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn oracle_negative_unknown_opcode_not_silently_decoded() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(0x03FE);
        let text: String = disasm_line(&asm, &[], 6, false);
        assert!(
            text.starts_with("Unknown_"),
            "unknown opcode must surface as Unknown_, got: {text}"
        );
        assert!(!text.contains("Ld "));
    }

    #[test]
    fn oracle_negative_version_skew_changes_resolution() {
        let idents: Vec<String> = vec![
            "aa".to_owned(),
            "bb".to_owned(),
            "cc".to_owned(),
            "dd".to_owned(),
            "ee".to_owned(),
            "ff".to_owned(),
        ];
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LD).custom_name(5);
        let as_v6: String = disasm_line(&asm, &idents, 6, false);
        let as_v7: String = disasm_line(&asm, &idents, 7, false);
        assert_eq!(as_v6, "Ld ff\n");
        assert_ne!(
            as_v6, as_v7,
            "vba7 identifier-index shift must alter resolution: {as_v6:?} vs {as_v7:?}"
        );
    }

    #[test]
    fn oracle_negative_out_of_range_custom_index_is_marked_not_faked() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.opcode(OP_LD).custom_name(99);
        let text: String = disasm_line(&asm, &[], 6, false);
        assert!(
            text.contains("id_"),
            "unresolvable index must be id_<code>, not fabricated: {text}"
        );
    }

    #[test]
    fn oracle_round_trips_translated_opcode_via_v3_table() {
        let mut asm: PCodeAsm = PCodeAsm::new();
        asm.word(67);
        let text: String = disasm_line(&asm, &[], 3, false);
        let translated: u16 = translate_opcode(67, 3, false);
        let info: &OpcodeInfo = lookup_opcode(translated).expect("opcode 67 must map under v3");
        assert!(text.starts_with(info.mnem), "v3 translation: {text}");
    }

    fn empty_ctx(vba_ver: u8, is_64bit: bool) -> LineContext<'static> {
        LineContext {
            identifiers: &[],
            tables: ModuleTables::EMPTY,
            vba_ver,
            is_64bit,
            endian: Endian::Little,
        }
    }

    #[test]
    fn open_mode_words_match_pcodedmp() {
        let ctx: LineContext = empty_ctx(7, false);
        let cases: [(u16, &str); 6] = [
            (0x0001, "(For Input)"),
            (0x0002, "(For Output)"),
            (0x0020, "(For Binary)"),
            (0x0101, "(For Input Access Read)"),
            (0x1001, "(For Input Lock Read Write)"),
            (0x0301, "(For Input Access Read Write)"),
        ];
        for (word, expected) in cases {
            assert_eq!(disasm_imp(OpArg::Hex16, word, "Open", &ctx), expected);
        }
    }

    #[test]
    fn type_name_from_id_matches_pcodedmp() {
        let cases: [(u8, &str); 7] = [
            (2, "Integer"),
            (3, "Long"),
            (8, "String"),
            (11, "Boolean"),
            (17, "Byte"),
            (0x83, "LongPtr"),
            (0x88, "StringPtr"),
        ];
        for (id, expected) in cases {
            assert_eq!(type_name_from_id(id), expected);
        }
    }

    #[test]
    fn optype_decorations_match_pcodedmp() {
        let mut t: u16 = 0;
        assert_eq!(optype_decoration("Dim", &mut t), None);
        let mut t: u16 = 0x08;
        assert_eq!(
            optype_decoration("Dim", &mut t).as_deref(),
            Some(" (Public)")
        );
        let mut t: u16 = 0x11;
        assert_eq!(
            optype_decoration("Dim", &mut t).as_deref(),
            Some(" (Private Const)")
        );
        let mut t: u16 = 2;
        assert_eq!(
            optype_decoration("Coerce", &mut t).as_deref(),
            Some(" (Int)")
        );
        let mut t: u16 = 17;
        assert_eq!(
            optype_decoration("Coerce", &mut t).as_deref(),
            Some(" (Byte)")
        );
        let mut t: u16 = 1;
        assert_eq!(
            optype_decoration("LitVarSpecial", &mut t).as_deref(),
            Some(" (True)")
        );
        let mut t: u16 = 4;
        assert_eq!(
            optype_decoration("Option", &mut t).as_deref(),
            Some(" (Explicit)")
        );
        let mut t: u16 = 16;
        assert_eq!(
            optype_decoration("Redim", &mut t).as_deref(),
            Some(" (Preserve)")
        );
        let mut t: u16 = 20;
        assert_eq!(optype_decoration("ArgsCall", &mut t), None);
        assert_eq!(t, 4, "ArgsCall opType >= 16 must be reduced by 16");
    }

    #[test]
    fn onerror_and_resume_name_forms_match_pcodedmp() {
        let ctx: LineContext = empty_ctx(7, false);
        assert_eq!(
            disasm_name(0, "OnError", 1, &ctx).trim_end(),
            "(Resume Next)"
        );
        assert_eq!(disasm_name(0, "OnError", 2, &ctx).trim_end(), "(GoTo 0)");
        assert_eq!(disasm_name(0, "Resume", 1, &ctx).trim_end(), "(Next)");
    }

    #[test]
    fn var_type_sigil_appended_by_optype() {
        let idents: Vec<String> = vec!["counter".to_owned()];
        let ctx: LineContext = LineContext {
            identifiers: &idents,
            tables: ModuleTables::EMPTY,
            vba_ver: 6,
            is_64bit: false,
            endian: Endian::Little,
        };
        let word: u16 = 0x100 << 1;
        assert_eq!(disasm_name(word, "Ld", 3, &ctx).trim_end(), "counter&");
        assert_eq!(disasm_name(word, "Ld", 8, &ctx).trim_end(), "counter$");
    }

    fn config_translate(tag: &str, raw: u16) -> u16 {
        match tag {
            "v3_x86" => translate_opcode(raw, 3, false),
            "v5_x86" => translate_opcode(raw, 5, false),
            "v6_x86" => translate_opcode(raw, 6, false),
            "v7_x86" => translate_opcode(raw, 7, false),
            "v6_x64" => translate_opcode(raw, 6, true),
            "v7_x64" => translate_opcode(raw, 7, true),
            other => panic!("unknown config tag {other}"),
        }
    }

    #[test]
    fn per_version_translation_matches_pcodedmp_reference() {
        let manifest_dir: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixture: std::path::PathBuf = manifest_dir
            .join("tests")
            .join("pcodedmp_translate_reference.txt");
        let text: String = std::fs::read_to_string(&fixture)
            .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", fixture.display()));
        let mut configs_checked: usize = 0;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let tag: &str = parts.next().expect("config tag");
            let reference: Vec<u16> = parts
                .map(|t: &str| t.parse::<u16>().expect("u16 value"))
                .collect();
            assert_eq!(
                reference.len(),
                264,
                "config {tag} must have 264 reference values"
            );
            for (raw, expected) in reference.iter().enumerate() {
                let got: u16 = config_translate(tag, raw as u16);
                assert_eq!(
                    got, *expected,
                    "translate mismatch for {tag} raw-opcode {raw}: disrobe={got} pcodedmp={expected}"
                );
            }
            configs_checked += 1;
        }
        assert_eq!(
            configs_checked, 6,
            "expected all 6 per-version configs (v3/v5/v6/v7 x x86/x64) graded against pcodedmp"
        );
    }
}
