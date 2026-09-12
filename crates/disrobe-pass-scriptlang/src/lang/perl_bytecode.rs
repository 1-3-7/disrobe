use serde::Serialize;

use disrobe_bytes::{ByteReadError, ByteReader};

use crate::error::{Error, Result};
use crate::lang::perl::{PerlOp, PerlOpTree, PerlSub};

const MAGIC_NATIVE: u32 = 0x43424c50;
const MAGIC_LE_BYTES: [u8; 4] = [0x50, 0x4c, 0x42, 0x43];
const MAGIC_BE_BYTES: [u8; 4] = [0x43, 0x42, 0x4c, 0x50];
const SHEBANG_USE_BYTELOADER: &[u8] = b"use ByteLoader";
const MAX_OPS: usize = 2_000_000usize;
const MAX_BYTECODE_TEXT_BYTES: usize = 1usize << 20;
const DEFAULT_IVSIZE: u32 = 8u32;
const DEFAULT_PTRSIZE: u32 = 8u32;

const OP_RET: u8 = 0u8;
const OP_DATA: u8 = 142u8;
const DEFAULT_INTSIZE: u32 = 4u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgType {
    None,
    U8,
    U16,
    U32,
    I32,
    Iv,
    Nv,
    Pv,
    StrConst,
    PvContents,
    SvIndex,
    OpIndex,
    PvIndex,
    PadOffset,
    Long,
    Svtype,
    OpTrArray,
    CommentT,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BytecodeHeader {
    pub byte_order: ByteOrder,
    pub archname: Option<String>,
    pub byteloader_version: Option<String>,
    pub ivsize: Option<u32>,
    pub ptrsize: Option<u32>,
}

#[must_use]
pub fn is_bytecode(bytes: &[u8]) -> bool {
    find_magic(bytes).is_some()
}

fn find_magic(bytes: &[u8]) -> Option<(usize, ByteOrder)> {
    let scan_limit: usize = bytes.len().min(4096);
    let window: &[u8] = &bytes[..scan_limit];
    window
        .windows(4)
        .enumerate()
        .find_map(|(i, w): (usize, &[u8])| {
            if w == MAGIC_LE_BYTES {
                Some((i, ByteOrder::Little))
            } else if w == MAGIC_BE_BYTES {
                Some((i, ByteOrder::Big))
            } else {
                None
            }
        })
}

struct Cursor<'a> {
    reader: ByteReader<'a>,
    order: ByteOrder,
    ivsize: u32,
    ptrsize: u32,
    intsize: u32,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], pos: usize, order: ByteOrder) -> Result<Self> {
        let mut reader: ByteReader<'a> = ByteReader::new(bytes);
        reader.seek(pos).map_err(Self::truncated)?;
        Ok(Self {
            reader,
            order,
            ivsize: DEFAULT_IVSIZE,
            ptrsize: DEFAULT_PTRSIZE,
            intsize: DEFAULT_INTSIZE,
        })
    }

    fn truncated(error: ByteReadError) -> Error {
        Error::PerlBytecodeTruncated(error.offset)
    }

    fn u8(&mut self) -> Result<u8> {
        self.reader.read_u8().map_err(Self::truncated)
    }

    fn u16(&mut self) -> Result<u16> {
        match self.order {
            ByteOrder::Little => self.reader.read_u16_le(),
            ByteOrder::Big => self.reader.read_u16_be(),
        }
        .map_err(Self::truncated)
    }

    fn u32(&mut self) -> Result<u32> {
        match self.order {
            ByteOrder::Little => self.reader.read_u32_le(),
            ByteOrder::Big => self.reader.read_u32_be(),
        }
        .map_err(Self::truncated)
    }

    fn i32(&mut self) -> Result<i32> {
        match self.order {
            ByteOrder::Little => self.reader.read_i32_le(),
            ByteOrder::Big => self.reader.read_i32_be(),
        }
        .map_err(Self::truncated)
    }

    fn u64_val(&mut self) -> Result<u64> {
        match self.order {
            ByteOrder::Little => self.reader.read_u64_le(),
            ByteOrder::Big => self.reader.read_u64_be(),
        }
        .map_err(Self::truncated)
    }

    fn uptr(&mut self) -> Result<u64> {
        if self.ptrsize == 8 {
            self.u64_val()
        } else {
            Ok(u64::from(self.u32()?))
        }
    }

    fn svtype(&mut self) -> Result<u64> {
        if self.intsize == 8 {
            self.u64_val()
        } else {
            Ok(u64::from(self.u32()?))
        }
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.reader.skip(n).map_err(Self::truncated)
    }

    fn pv(&mut self) -> Result<Vec<u8>> {
        let declared: u32 = self.u32()?;
        let len: usize =
            usize::try_from(declared).map_err(|_| Error::PerlBytecodeValueTooLarge {
                field: "pv",
                len: usize::MAX,
                max: MAX_BYTECODE_TEXT_BYTES,
            })?;
        if len > MAX_BYTECODE_TEXT_BYTES {
            return Err(Error::PerlBytecodeValueTooLarge {
                field: "pv",
                len,
                max: MAX_BYTECODE_TEXT_BYTES,
            });
        }
        let out: Vec<u8> = self
            .reader
            .read_bytes(len)
            .map_err(Self::truncated)?
            .to_vec();
        Ok(out)
    }

    fn asciiz(&mut self) -> Result<String> {
        let start: usize = self.reader.position();
        let remaining: usize = self.reader.remaining();
        let scan_len: usize = remaining.min(MAX_BYTECODE_TEXT_BYTES.saturating_add(1usize));
        let bytes: &[u8] = self.reader.peek_bytes(scan_len).map_err(Self::truncated)?;
        let delimiter: Option<usize> = bytes.iter().position(|byte: &u8| *byte == 0u8);
        let len: usize = match delimiter {
            Some(value) if value <= MAX_BYTECODE_TEXT_BYTES => value,
            Some(_) => {
                return Err(Error::PerlBytecodeValueTooLarge {
                    field: "asciiz",
                    len: MAX_BYTECODE_TEXT_BYTES.saturating_add(1usize),
                    max: MAX_BYTECODE_TEXT_BYTES,
                });
            }
            None if bytes.len() > MAX_BYTECODE_TEXT_BYTES => {
                return Err(Error::PerlBytecodeValueTooLarge {
                    field: "asciiz",
                    len: MAX_BYTECODE_TEXT_BYTES.saturating_add(1usize),
                    max: MAX_BYTECODE_TEXT_BYTES,
                });
            }
            None => return Err(Error::PerlBytecodeTruncated(start)),
        };
        let raw: &[u8] = self.reader.read_bytes(len).map_err(Self::truncated)?;
        let s: String = String::from_utf8_lossy(raw).into_owned();
        self.reader.skip(1usize).map_err(Self::truncated)?;
        Ok(s)
    }

    fn strconst(&mut self) -> Result<String> {
        self.asciiz()
    }

    fn comment(&mut self) -> Result<String> {
        let remaining: usize = self.reader.remaining();
        let scan_len: usize = remaining.min(MAX_BYTECODE_TEXT_BYTES.saturating_add(1usize));
        let bytes: &[u8] = self.reader.peek_bytes(scan_len).map_err(Self::truncated)?;
        let delimiter: Option<usize> = bytes.iter().position(|byte: &u8| *byte == b'\n');
        let len: usize = delimiter.unwrap_or(bytes.len());
        if len > MAX_BYTECODE_TEXT_BYTES {
            return Err(Error::PerlBytecodeValueTooLarge {
                field: "comment",
                len: MAX_BYTECODE_TEXT_BYTES.saturating_add(1usize),
                max: MAX_BYTECODE_TEXT_BYTES,
            });
        }
        let raw: &[u8] = self.reader.read_bytes(len).map_err(Self::truncated)?;
        let s: String = String::from_utf8_lossy(raw).into_owned();
        if delimiter.is_some() {
            self.reader.skip(1usize).map_err(Self::truncated)?;
        }
        Ok(s)
    }

    fn op_tr_array(&mut self) -> Result<()> {
        let len: u16 = self.u16()?;
        self.skip(usize::from(len) * 2)
    }

    fn remaining(&self) -> usize {
        self.reader.remaining()
    }
}

const fn insn_info(opcode: u8) -> Option<(&'static str, ArgType)> {
    let entry: (&'static str, ArgType) = match opcode {
        0 => ("ret", ArgType::None),
        1 => ("ldsv", ArgType::SvIndex),
        2 => ("ldop", ArgType::OpIndex),
        3 => ("stsv", ArgType::U32),
        4 => ("stop", ArgType::U32),
        5 => ("stpv", ArgType::U32),
        6 => ("ldspecsv", ArgType::U8),
        7 => ("ldspecsvx", ArgType::U8),
        8 => ("newsv", ArgType::Svtype),
        9 => ("newsvx", ArgType::Svtype),
        10 => ("nop", ArgType::None),
        11 => ("newop", ArgType::U8),
        12 => ("newopx", ArgType::U16),
        13 => ("newopn", ArgType::U8),
        14 => ("newpv", ArgType::Pv),
        15 => ("pv_cur", ArgType::PadOffset),
        16 => ("pv_free", ArgType::None),
        17 => ("sv_upgrade", ArgType::Svtype),
        18 => ("sv_refcnt", ArgType::U32),
        19 => ("sv_refcnt_add", ArgType::I32),
        20 => ("sv_flags", ArgType::U32),
        21 => ("xrv", ArgType::SvIndex),
        22 => ("xpv", ArgType::None),
        23 => ("xpv_cur", ArgType::PadOffset),
        24 => ("xpv_len", ArgType::PadOffset),
        25 => ("xiv", ArgType::Iv),
        26 => ("xnv", ArgType::Nv),
        27 => ("xlv_targoff", ArgType::PadOffset),
        28 => ("xlv_targlen", ArgType::PadOffset),
        29 => ("xlv_targ", ArgType::SvIndex),
        30 => ("xlv_type", ArgType::U8),
        31 => ("xbm_useful", ArgType::I32),
        32 => ("xbm_previous", ArgType::U16),
        33 => ("xbm_rare", ArgType::U8),
        34 => ("xfm_lines", ArgType::Iv),
        35 => ("comment", ArgType::CommentT),
        36 => ("xio_lines", ArgType::Iv),
        37 => ("xio_page", ArgType::Iv),
        38 => ("xio_page_len", ArgType::Iv),
        39 => ("xio_lines_left", ArgType::Iv),
        40 => ("xio_top_name", ArgType::PvIndex),
        41 => ("xio_top_gv", ArgType::SvIndex),
        42 => ("xio_fmt_name", ArgType::PvIndex),
        43 => ("xio_fmt_gv", ArgType::SvIndex),
        44 => ("xio_bottom_name", ArgType::PvIndex),
        45 => ("xio_bottom_gv", ArgType::SvIndex),
        46 => ("xio_subprocess", ArgType::U16),
        47 => ("xio_type", ArgType::U8),
        48 => ("xio_flags", ArgType::U8),
        49 => ("xcv_xsubany", ArgType::SvIndex),
        50 => ("xcv_stash", ArgType::SvIndex),
        51 => ("xcv_start", ArgType::OpIndex),
        52 => ("xcv_root", ArgType::OpIndex),
        53 => ("xcv_gv", ArgType::SvIndex),
        54 => ("xcv_file", ArgType::PvIndex),
        55 => ("xcv_depth", ArgType::Long),
        56 => ("xcv_padlist", ArgType::SvIndex),
        57 => ("xcv_outside", ArgType::SvIndex),
        58 => ("xcv_outside_seq", ArgType::U32),
        59 => ("xcv_flags", ArgType::U16),
        60 => ("av_extend", ArgType::PadOffset),
        61 => ("av_pushx", ArgType::SvIndex),
        62 => ("av_push", ArgType::SvIndex),
        63 => ("xav_fill", ArgType::PadOffset),
        64 => ("xav_max", ArgType::PadOffset),
        65 => ("xav_flags", ArgType::U8),
        66 => ("xhv_riter", ArgType::I32),
        67 => ("xhv_name", ArgType::PvIndex),
        68 => ("xhv_pmroot", ArgType::OpIndex),
        69 => ("hv_store", ArgType::SvIndex),
        70 => ("sv_magic", ArgType::U8),
        71 => ("mg_obj", ArgType::SvIndex),
        72 => ("mg_private", ArgType::U16),
        73 => ("mg_flags", ArgType::U8),
        74 => ("mg_name", ArgType::PvContents),
        75 => ("mg_namex", ArgType::SvIndex),
        76 => ("xmg_stash", ArgType::SvIndex),
        77 => ("gv_fetchpv", ArgType::StrConst),
        78 => ("gv_fetchpvx", ArgType::StrConst),
        79 => ("gv_stashpv", ArgType::StrConst),
        80 => ("gv_stashpvx", ArgType::StrConst),
        81 => ("gp_sv", ArgType::SvIndex),
        82 => ("gp_refcnt", ArgType::U32),
        83 => ("gp_refcnt_add", ArgType::I32),
        84 => ("gp_av", ArgType::SvIndex),
        85 => ("gp_hv", ArgType::SvIndex),
        86 => ("gp_cv", ArgType::SvIndex),
        87 => ("gp_file", ArgType::PvIndex),
        88 => ("gp_io", ArgType::SvIndex),
        89 => ("gp_form", ArgType::SvIndex),
        90 => ("gp_cvgen", ArgType::U32),
        91 => ("gp_line", ArgType::U32),
        92 => ("gp_share", ArgType::SvIndex),
        93 => ("xgv_flags", ArgType::U8),
        94 => ("op_next", ArgType::OpIndex),
        95 => ("op_sibling", ArgType::OpIndex),
        96 => ("op_ppaddr", ArgType::StrConst),
        97 => ("op_targ", ArgType::PadOffset),
        98 => ("op_type", ArgType::U16),
        99 => ("op_seq", ArgType::U16),
        100 => ("op_flags", ArgType::U8),
        101 => ("op_private", ArgType::U8),
        102 => ("op_first", ArgType::OpIndex),
        103 => ("op_last", ArgType::OpIndex),
        104 => ("op_other", ArgType::OpIndex),
        105 => ("op_pmreplroot", ArgType::OpIndex),
        106 => ("op_pmreplstart", ArgType::OpIndex),
        107 => ("op_pmnext", ArgType::OpIndex),
        108 => ("op_pmstashpv", ArgType::PvIndex),
        109 => ("op_pmreplrootpo", ArgType::PadOffset),
        110 => ("op_pmstash", ArgType::SvIndex),
        111 => ("op_pmreplrootgv", ArgType::SvIndex),
        112 => ("pregcomp", ArgType::PvContents),
        113 => ("op_pmflags", ArgType::U16),
        114 => ("op_pmpermflags", ArgType::U16),
        115 => ("op_pmdynflags", ArgType::U8),
        116 => ("op_sv", ArgType::SvIndex),
        117 => ("op_padix", ArgType::PadOffset),
        118 => ("op_pv", ArgType::PvContents),
        119 => ("op_pv_tr", ArgType::OpTrArray),
        120 => ("op_redoop", ArgType::OpIndex),
        121 => ("op_nextop", ArgType::OpIndex),
        122 => ("op_lastop", ArgType::OpIndex),
        123 => ("cop_label", ArgType::PvIndex),
        124 => ("cop_stashpv", ArgType::PvIndex),
        125 => ("cop_file", ArgType::PvIndex),
        126 => ("cop_stash", ArgType::SvIndex),
        127 => ("cop_filegv", ArgType::SvIndex),
        128 => ("cop_seq", ArgType::U32),
        129 => ("cop_arybase", ArgType::I32),
        130 => ("cop_line", ArgType::U32),
        131 => ("cop_io", ArgType::SvIndex),
        132 => ("cop_warnings", ArgType::SvIndex),
        133 => ("main_start", ArgType::OpIndex),
        134 => ("main_root", ArgType::OpIndex),
        135 => ("main_cv", ArgType::SvIndex),
        136 => ("curpad", ArgType::SvIndex),
        137 => ("push_begin", ArgType::SvIndex),
        138 => ("push_init", ArgType::SvIndex),
        139 => ("push_end", ArgType::SvIndex),
        140 => ("curstash", ArgType::SvIndex),
        141 => ("defstash", ArgType::SvIndex),
        142 => ("data", ArgType::U8),
        143 => ("incav", ArgType::SvIndex),
        144 => ("load_glob", ArgType::SvIndex),
        145 => ("regex_padav", ArgType::SvIndex),
        146 => ("dowarn", ArgType::U8),
        147 => ("comppad_name", ArgType::SvIndex),
        148 => ("xgv_stash", ArgType::SvIndex),
        149 => ("signal", ArgType::StrConst),
        150 => ("formfeed", ArgType::SvIndex),
        151 => ("op_latefree", ArgType::U8),
        152 => ("op_latefreed", ArgType::U8),
        153 => ("op_attached", ArgType::U8),
        154 => ("op_reflags", ArgType::U32),
        155 => ("cop_seq_low", ArgType::U32),
        156 => ("cop_seq_high", ArgType::U32),
        _ => return None,
    };
    Some(entry)
}

pub fn read_bytecode(bytes: &[u8]) -> Result<PerlOpTree> {
    let (magic_off, order): (usize, ByteOrder) = find_magic(bytes).ok_or(Error::NotPerlBytecode)?;
    let mut c: Cursor<'_> = Cursor::new(bytes, magic_off, order)?;
    let magic: u32 = c.u32()?;
    if magic != MAGIC_NATIVE && magic.swap_bytes() != MAGIC_NATIVE {
        return Err(Error::NotPerlBytecode);
    }

    let header: BytecodeHeader = read_header(&mut c)?;
    if let Some(iv) = header.ivsize.filter(|v: &u32| *v == 4 || *v == 8) {
        c.ivsize = iv;
    }
    if let Some(pt) = header.ptrsize.filter(|v: &u32| *v == 4 || *v == 8) {
        c.ptrsize = pt;
    }
    let source_hint: Option<String> = header.archname;

    let mut ops: Vec<PerlOp> = Vec::new();
    let mut pvs: Vec<String> = Vec::new();
    let mut called_subs: Vec<String> = Vec::new();
    let mut op_count: usize = 0usize;

    while c.remaining() > 0 && op_count < MAX_OPS {
        let opcode: u8 = c.u8()?;
        let (name, detail): (&'static str, Option<String>) =
            decode_insn(&mut c, opcode, &mut pvs, &mut called_subs)?;
        ops.push(PerlOp {
            seq: op_count.to_string(),
            name: name.to_owned(),
            flags: String::new(),
            detail,
        });
        op_count += 1;
        if opcode == OP_RET || opcode == OP_DATA {
            break;
        }
    }

    if op_count == 0 {
        return Err(Error::PerlBytecodeEmpty);
    }

    let mut constants: Vec<String> = pvs;
    constants.sort_unstable();
    constants.dedup();
    called_subs.sort_unstable();
    called_subs.dedup();

    let sub: PerlSub = PerlSub {
        name: "main program".to_owned(),
        is_main_program: true,
        ops,
        pad_vars: Vec::new(),
        constants,
        called_subs,
    };

    Ok(PerlOpTree {
        source_hint,
        subs: vec![sub],
        op_count,
    })
}

fn read_header(c: &mut Cursor<'_>) -> Result<BytecodeHeader> {
    let archname_raw: String = c.asciiz()?;
    let byteloader_version_raw: String = c.asciiz()?;
    let archname: Option<String> = (!archname_raw.is_empty()).then_some(archname_raw);
    let byteloader_version: Option<String> =
        (!byteloader_version_raw.is_empty()).then_some(byteloader_version_raw);
    let ivsize: u32 = c.u32()?;
    let ptrsize: u32 = c.u32()?;
    Ok(BytecodeHeader {
        byte_order: c.order,
        archname,
        byteloader_version,
        ivsize: Some(ivsize),
        ptrsize: Some(ptrsize),
    })
}

fn decode_insn(
    c: &mut Cursor<'_>,
    opcode: u8,
    pvs: &mut Vec<String>,
    called_subs: &mut Vec<String>,
) -> Result<(&'static str, Option<String>)> {
    let (name, arg): (&'static str, ArgType) =
        insn_info(opcode).ok_or(Error::PerlBytecodeUnknownOp(opcode))?;
    let detail: Option<String> = read_arg(c, name, arg, pvs, called_subs)?;
    Ok((name, detail))
}

fn read_arg(
    c: &mut Cursor<'_>,
    name: &str,
    arg: ArgType,
    pvs: &mut Vec<String>,
    called_subs: &mut Vec<String>,
) -> Result<Option<String>> {
    let detail: Option<String> = match arg {
        ArgType::None => None,
        ArgType::U8 => Some(format!("{}", c.u8()?)),
        ArgType::U16 => Some(format!("{}", c.u16()?)),
        ArgType::U32 | ArgType::SvIndex | ArgType::OpIndex | ArgType::PvIndex => {
            Some(format!("{}", c.u32()?))
        }
        ArgType::I32 => Some(format!("{}", c.i32()?)),
        ArgType::PadOffset | ArgType::Long => Some(format!("{}", c.uptr()?)),
        ArgType::Svtype => Some(format!("{}", c.svtype()?)),
        ArgType::Iv => {
            let n: usize = c.ivsize as usize;
            c.skip(n)?;
            None
        }
        ArgType::Nv => {
            let s: String = c.strconst()?;
            Some(s).filter(|s: &String| !s.is_empty())
        }
        ArgType::Pv => {
            let raw: Vec<u8> = c.pv()?;
            let s: String = String::from_utf8_lossy(&raw).into_owned();
            let trimmed: &str = s.trim_end_matches('\0');
            if !trimmed.is_empty() {
                pvs.push(trimmed.to_owned());
            }
            Some(format!("PV \"{trimmed}\""))
        }
        ArgType::StrConst | ArgType::PvContents => {
            let s: String = if arg == ArgType::PvContents {
                c.pv().map(|raw: Vec<u8>| {
                    String::from_utf8_lossy(&raw)
                        .trim_end_matches('\0')
                        .to_owned()
                })?
            } else {
                c.strconst()?
            };
            harvest_name(name, &s, pvs, called_subs);
            Some(s).filter(|s: &String| !s.is_empty())
        }
        ArgType::OpTrArray => {
            c.op_tr_array()?;
            None
        }
        ArgType::CommentT => {
            let s: String = c.comment()?;
            Some(s).filter(|s: &String| !s.is_empty())
        }
    };
    Ok(detail)
}

fn harvest_name(insn: &str, value: &str, pvs: &mut Vec<String>, called_subs: &mut Vec<String>) {
    if value.is_empty() {
        return;
    }
    match insn {
        "gv_fetchpv" | "gv_fetchpvx" | "gv_stashpv" | "gv_stashpvx" => {
            let trimmed: &str = value.trim_start_matches('&').trim_start_matches('*');
            if !trimmed.is_empty() && trimmed != "main::" {
                called_subs.push(trimmed.to_owned());
            }
        }
        "op_pv" | "mg_name" => pvs.push(value.to_owned()),
        _ => {}
    }
}

#[must_use]
pub fn looks_like_byteloader_script(bytes: &[u8]) -> bool {
    let head: &[u8] = &bytes[..bytes.len().min(256)];
    head.windows(SHEBANG_USE_BYTELOADER.len())
        .any(|w: &[u8]| w == SHEBANG_USE_BYTELOADER)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const OP_NEWPV: u8 = 14u8;

    fn put_u32(out: &mut Vec<u8>, v: u32, order: ByteOrder) {
        match order {
            ByteOrder::Little => out.extend_from_slice(&v.to_le_bytes()),
            ByteOrder::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put_u16(out: &mut Vec<u8>, v: u16, order: ByteOrder) {
        match order {
            ByteOrder::Little => out.extend_from_slice(&v.to_le_bytes()),
            ByteOrder::Big => out.extend_from_slice(&v.to_be_bytes()),
        }
    }

    fn put_asciiz(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }

    fn put_pv(out: &mut Vec<u8>, s: &str, order: ByteOrder) {
        put_u32(out, s.len() as u32, order);
        out.extend_from_slice(s.as_bytes());
    }

    fn header_bytes(out: &mut Vec<u8>, order: ByteOrder, ivsize: u32, ptrsize: u32) {
        put_u32(out, MAGIC_NATIVE, order);
        put_asciiz(out, "x86_64-linux");
        put_asciiz(out, "0.06");
        put_u32(out, ivsize, order);
        put_u32(out, ptrsize, order);
    }

    fn minimal_bytecode(order: ByteOrder) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"#! /usr/bin/perl\nuse ByteLoader 0.06;\n");
        header_bytes(&mut out, order, 8, 8);

        out.push(9u8);
        put_u32(&mut out, 0x0c, order);
        out.push(OP_NEWPV);
        put_pv(&mut out, "Hello, disrobe!", order);
        out.push(15u8);
        put_u32(&mut out, 0u32, order);
        put_u32(&mut out, 15u32, order);
        out.push(OP_NEWPV);
        put_pv(&mut out, "main::greet", order);
        out.push(OP_RET);
        out
    }

    #[test]
    fn detects_le_and_be_magic() {
        assert!(is_bytecode(&minimal_bytecode(ByteOrder::Little)));
        assert!(is_bytecode(&minimal_bytecode(ByteOrder::Big)));
    }

    #[test]
    fn rejects_concise_text() {
        assert!(!is_bytecode(b"hello.pl syntax OK\nmain program:\n"));
    }

    #[test]
    fn parses_header_le() {
        let bc: Vec<u8> = minimal_bytecode(ByteOrder::Little);
        let tree: PerlOpTree = read_bytecode(&bc).expect("parse le");
        assert_eq!(tree.subs.len(), 1);
        assert!(tree.subs[0].is_main_program);
        assert_eq!(tree.source_hint.as_deref(), Some("x86_64-linux"));
    }

    #[test]
    fn recovers_pv_constants_both_orders() {
        for order in [ByteOrder::Little, ByteOrder::Big] {
            let bc: Vec<u8> = minimal_bytecode(order);
            let tree: PerlOpTree = read_bytecode(&bc).expect("parse");
            let main: &PerlSub = &tree.subs[0];
            assert!(
                main.constants
                    .iter()
                    .any(|c: &String| c == "Hello, disrobe!"),
                "PV must be recovered for {order:?}: {:?}",
                main.constants
            );
            assert!(
                main.constants.iter().any(|c: &String| c == "main::greet"),
                "sub-name PV must be recovered for {order:?}: {:?}",
                main.constants
            );
        }
    }

    #[test]
    fn walks_full_op_stream_to_ret() {
        let bc: Vec<u8> = minimal_bytecode(ByteOrder::Little);
        let tree: PerlOpTree = read_bytecode(&bc).expect("parse");
        assert_eq!(tree.op_count, 5);
        assert_eq!(
            tree.subs[0].ops.last().map(|o| o.name.as_str()),
            Some("ret")
        );
    }

    #[test]
    fn unknown_opcode_fails_fast() {
        let mut bc: Vec<u8> = Vec::new();
        header_bytes(&mut bc, ByteOrder::Little, 8, 8);
        bc.push(200u8);
        assert!(matches!(
            read_bytecode(&bc),
            Err(Error::PerlBytecodeUnknownOp(200))
        ));
    }

    #[test]
    fn truncated_header_after_magic_fails_fast() {
        let order: ByteOrder = ByteOrder::Little;
        let mut bc: Vec<u8> = Vec::new();
        put_u32(&mut bc, MAGIC_NATIVE, order);
        put_asciiz(&mut bc, "x86_64-linux");
        put_asciiz(&mut bc, "0.06");
        bc.extend_from_slice(&[8u8, 0u8]);
        assert!(matches!(
            read_bytecode(&bc),
            Err(Error::PerlBytecodeTruncated(_))
        ));
    }

    #[test]
    fn oversized_pv_declared_length_fails_before_payload_copy() {
        let order: ByteOrder = ByteOrder::Little;
        let mut bc: Vec<u8> = Vec::new();
        header_bytes(&mut bc, order, 8, 8);
        bc.push(OP_NEWPV);
        put_u32(&mut bc, MAX_BYTECODE_TEXT_BYTES as u32 + 1u32, order);
        assert!(matches!(
            read_bytecode(&bc),
            Err(Error::PerlBytecodeValueTooLarge { field: "pv", .. })
        ));
    }

    #[test]
    fn oversized_comment_fails_before_string_copy() {
        let order: ByteOrder = ByteOrder::Little;
        let mut bc: Vec<u8> = Vec::with_capacity(MAX_BYTECODE_TEXT_BYTES + 32usize);
        header_bytes(&mut bc, order, 8, 8);
        bc.push(35u8);
        bc.extend(std::iter::repeat_n(b'a', MAX_BYTECODE_TEXT_BYTES + 1usize));
        assert!(matches!(
            read_bytecode(&bc),
            Err(Error::PerlBytecodeValueTooLarge {
                field: "comment",
                ..
            })
        ));
    }

    #[test]
    fn decodes_full_opcode_table_arg_widths() {
        let order: ByteOrder = ByteOrder::Little;
        let mut bc: Vec<u8> = Vec::new();
        header_bytes(&mut bc, order, 8, 8);
        bc.push(77u8);
        put_asciiz(&mut bc, "main::compute");
        bc.push(98u8);
        put_u16(&mut bc, 178u16, order);
        bc.push(97u8);
        put_u32(&mut bc, 0u32, order);
        put_u32(&mut bc, 4u32, order);
        bc.push(130u8);
        put_u32(&mut bc, 42u32, order);
        bc.push(26u8);
        put_asciiz(&mut bc, "3.14159");
        bc.push(OP_RET);
        let tree: PerlOpTree = read_bytecode(&bc).expect("full table parse");
        let main: &PerlSub = &tree.subs[0];
        assert!(
            main.called_subs
                .iter()
                .any(|s: &String| s == "main::compute"),
            "gv_fetchpv name must be harvested: {:?}",
            main.called_subs
        );
        assert!(
            main.ops.iter().any(|o: &PerlOp| o.name == "op_type"),
            "op_type (U16) must decode: {:?}",
            main.ops.iter().map(|o| &o.name).collect::<Vec<_>>()
        );
        assert!(main.ops.iter().any(|o: &PerlOp| o.name == "cop_line"));
        assert!(main.ops.iter().any(|o: &PerlOp| o.name == "xnv"));
    }

    #[test]
    fn ptrsize_four_reads_padoffset_as_u32() {
        let order: ByteOrder = ByteOrder::Little;
        let mut bc: Vec<u8> = Vec::new();
        header_bytes(&mut bc, order, 4, 4);
        bc.push(97u8);
        put_u32(&mut bc, 7u32, order);
        bc.push(OP_RET);
        let tree: PerlOpTree = read_bytecode(&bc).expect("ptrsize=4 parse");
        assert_eq!(
            tree.subs[0].ops.first().map(|o| o.name.as_str()),
            Some("op_targ")
        );
        assert_eq!(tree.subs[0].ops[0].detail.as_deref(), Some("7"));
    }

    #[test]
    fn detects_byteloader_script_marker() {
        assert!(looks_like_byteloader_script(
            b"#!/usr/bin/perl\nuse ByteLoader 0.06;\n"
        ));
        assert!(!looks_like_byteloader_script(
            b"#!/usr/bin/perl\nprint 1;\n"
        ));
    }
}
