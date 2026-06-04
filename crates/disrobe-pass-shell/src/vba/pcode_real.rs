use std::io::Read;

use cfb::CompoundFile;
use serde::Serialize;

use crate::error::{Error, Result};

use super::pcode::{PCodeInstruction, PCodeStreamHeader, PCodeWall, PCodeWallDetail};

const VBA_PROJECT_MAGIC: u16 = 0x61CC;
const PCODE_MAGIC: u16 = 0xCAFE;
const BIG_ENDIAN_MARKER: u16 = 0x000E;

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
    let mut stream: cfb::Stream<std::io::Cursor<T>> = comp
        .open_stream(path)
        .map_err(|e: std::io::Error| Error::OleCfb(e.to_string()))?;
    let mut buf: Vec<u8> = Vec::new();
    stream.read_to_end(&mut buf).map_err(Error::Gzip)?;
    Ok(buf)
}

pub(crate) fn decompress_ovba(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if data[0] != 0x01 {
        return Err(Error::VbaPcode {
            reason: format!("MS-OVBA signature byte must be 0x01, got {:#04x}", data[0]),
        });
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 4);
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

fn disassemble_module(
    module: &[u8],
    identifiers: &[String],
    vba_ver: u8,
    is_64bit: bool,
    name: &str,
    text_offset_hint: usize,
) -> Result<RealModuleDisasm> {
    let _ = text_offset_hint;
    let endian: Endian = if read_u16(module, 2, Endian::Little) > 0xFF {
        Endian::Big
    } else {
        Endian::Little
    };
    if module.len() < 0x100 {
        return Err(Error::VbaPcode {
            reason: format!("module {name} too short ({} bytes)", module.len()),
        });
    }
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
    let mut offset: usize = 0x0019;
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
        let (instructions, text): (Vec<PCodeInstruction>, String) = walk_pcode_line(
            &module[line_start..line_end],
            line_start,
            identifiers,
            vba_ver,
            is_64bit,
            endian,
        );
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

fn walk_pcode_line(
    line: &[u8],
    abs_start: usize,
    identifiers: &[String],
    vba_ver: u8,
    is_64bit: bool,
    endian: Endian,
) -> (Vec<PCodeInstruction>, String) {
    let mut out: Vec<PCodeInstruction> = Vec::new();
    let mut text: String = String::new();
    let mut o: usize = 0;
    while o + 2 <= line.len() {
        let opcode_raw: u16 = read_u16(line, o, endian);
        o += 2;
        let op_type: u16 = (opcode_raw & !0x03FF) >> 10;
        let opcode_low: u16 = opcode_raw & 0x03FF;
        let translated: u16 = translate_opcode(opcode_low, vba_ver, is_64bit);
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
        for arg in opc.args {
            if o + 2 > line.len() {
                break;
            }
            match *arg {
                OpArg::Name => {
                    let w: u16 = read_u16(line, o, endian);
                    o += 2;
                    mnem_text.push(' ');
                    mnem_text.push_str(&resolve_identifier(w, identifiers, vba_ver, is_64bit));
                }
                OpArg::Hex16 => {
                    let w: u16 = read_u16(line, o, endian);
                    o += 2;
                    mnem_text.push_str(&format!(" 0x{w:04X}"));
                }
                OpArg::Imp => {
                    let w: u16 = read_u16(line, o, endian);
                    o += 2;
                    mnem_text.push_str(&format!(" imp_{w:04X}"));
                }
                OpArg::Func => {
                    if o + 4 > line.len() {
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&format!(" func_{dw:08X}"));
                }
                OpArg::Var => {
                    if o + 4 > line.len() {
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&format!(" var_{dw:08X}"));
                }
                OpArg::Rec => {
                    if o + 4 > line.len() {
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&format!(" rec_{dw:08X}"));
                }
                OpArg::Type => {
                    if o + 4 > line.len() {
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&format!(" type_{dw:08X}"));
                }
                OpArg::Context => {
                    if o + 4 > line.len() {
                        break;
                    }
                    let dw: u32 = read_u32(line, o, endian);
                    o += 4;
                    mnem_text.push_str(&format!(" context_{dw:08X}"));
                    if is_64bit {
                        if o + 4 > line.len() {
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
                break;
            }
            let w_length: u16 = read_u16(line, o, endian);
            o += 2;
            let take: usize = (w_length as usize).min(line.len().saturating_sub(o));
            let payload: &[u8] = &line[o..o + take];
            let varg_text: String = match opc.mnem {
                "LitStr" | "QuoteRem" | "Rem" | "Reparse" => {
                    format!("0x{w_length:04X} \"{}\"", decode_codepage_latin1(payload))
                }
                _ => {
                    let hex: String = payload
                        .iter()
                        .map(|b: &u8| format!("{b:02X}"))
                        .collect::<Vec<String>>()
                        .join(" ");
                    format!("0x{w_length:04X} {hex}")
                }
            };
            mnem_text.push(' ');
            mnem_text.push_str(&varg_text);
            o += take;
            if w_length & 1 == 1 {
                o += 1;
            }
        }
        out.push(PCodeInstruction {
            offset: abs_start + o,
            opcode_raw,
            mnemonic: opc.mnem.to_owned(),
        });
        text.push_str(&mnem_text);
        text.push('\n');
    }
    (out, text)
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
            if idx > 0xBE {
                idx -= 1;
            }
        }
        if idx >= 0 && (idx as usize) < identifiers.len() {
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
    op("Open", A_HEX, false),
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// MS-OVBA 2.4.1.3.19.3 (`CopyToken` Help): at `DifferenceDecompressed` 0,
    /// `BitCount = max(ceil(log2(0)), 4) = 4`, so `LengthMask = 0xFFFF >> 4 = 0x0FFF`
    /// (12 length bits, 4 offset bits). The prior `0x000F` expectation inverted the
    /// length/offset split and contradicted the spec.
    #[test]
    fn copy_token_mask_at_zero_is_12bit_length_4bit_offset() {
        let m: u16 = copy_token_length_mask(0);
        assert_eq!(m, 0x0FFF);
        assert_eq!(copy_token_bit_count(0), 4);
    }

    /// MS-OVBA 2.4.1.3.19.3: `ceil(log2(16)) = 4`, so at `DifferenceDecompressed` 16
    /// `BitCount` is still 4 and `LengthMask = 0x0FFF`. The boundary where `BitCount`
    /// increments is 17 (`ceil(log2(17)) = 5`), not 16; the loop-based implementation
    /// over-shifted at exact powers of two.
    #[test]
    fn copy_token_mask_at_16_stays_4bit_offset() {
        assert_eq!(copy_token_length_mask(16), 0x0FFF);
        assert_eq!(copy_token_bit_count(16), 4);
    }

    /// MS-OVBA 2.4.1.3.19.3: `ceil(log2(17)) = 5`, so at `DifferenceDecompressed` 17
    /// `BitCount = 5` and `LengthMask = 0xFFFF >> 5 = 0x07FF` (11 length bits).
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

    /// Hand-built per MS-OVBA 2.4.1 from plaintext "abcabcabc": a `CompressedChunk`
    /// (header 0xB005 = size 8 - 3) whose body is `FlagByte` 0x08 (token #4 is a
    /// `CopyToken`), the three literals 'a','b','c', then `CopyToken` 0x2003
    /// (`Offset` 3, `Length` 6) which overlap-copies the run. Proves `CopyToken`
    /// decode, `CopyTokenHelp` bit math, and overlapping copy beyond the minimal chunk.
    #[test]
    fn decompress_chunk_with_copytoken_roundtrip() {
        let data: &[u8] = &[0x01, 0x05, 0xB0, 0x08, b'a', b'b', b'c', 0x03, 0x20];
        let out: Vec<u8> = decompress_ovba(data).expect("decompress");
        assert_eq!(out, b"abcabcabc");
    }

    /// MS-OVBA 2.4.1.1.5: an uncompressed `CompressedChunk` (`CompressedChunkFlag` 0b0)
    /// MUST carry `CompressedChunkSize` 4095, i.e. header 0x3FFF, and the body is the
    /// raw bytes copied verbatim with no token decoding.
    #[test]
    fn decompress_raw_chunk_copies_verbatim() {
        let mut data: Vec<u8> = vec![0x01, 0xFF, 0x3F];
        data.extend_from_slice(b"verbatim");
        let out: Vec<u8> = decompress_ovba(&data).expect("decompress");
        assert_eq!(out, b"verbatim");
    }
}
