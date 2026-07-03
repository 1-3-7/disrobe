use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DalvikOp {
    pub mnemonic: &'static str,
    pub units: u8,
}

#[inline]
#[must_use]
pub const fn opcode(op: u8) -> DalvikOp {
    macro_rules! d {
        ($m:literal, $u:literal) => {
            DalvikOp {
                mnemonic: $m,
                units: $u,
            }
        };
    }
    match op {
        0x00 => d!("nop", 1),
        0x01 => d!("move", 1),
        0x02 => d!("move/from16", 2),
        0x03 => d!("move/16", 3),
        0x04 => d!("move-wide", 1),
        0x05 => d!("move-wide/from16", 2),
        0x06 => d!("move-wide/16", 3),
        0x07 => d!("move-object", 1),
        0x08 => d!("move-object/from16", 2),
        0x09 => d!("move-object/16", 3),
        0x0A => d!("move-result", 1),
        0x0B => d!("move-result-wide", 1),
        0x0C => d!("move-result-object", 1),
        0x0D => d!("move-exception", 1),
        0x0E => d!("return-void", 1),
        0x0F => d!("return", 1),
        0x10 => d!("return-wide", 1),
        0x11 => d!("return-object", 1),
        0x12 => d!("const/4", 1),
        0x13 => d!("const/16", 2),
        0x14 => d!("const", 3),
        0x15 => d!("const/high16", 2),
        0x16 => d!("const-wide/16", 2),
        0x17 => d!("const-wide/32", 3),
        0x18 => d!("const-wide", 5),
        0x19 => d!("const-wide/high16", 2),
        0x1A => d!("const-string", 2),
        0x1B => d!("const-string/jumbo", 3),
        0x1C => d!("const-class", 2),
        0x1D => d!("monitor-enter", 1),
        0x1E => d!("monitor-exit", 1),
        0x1F => d!("check-cast", 2),
        0x20 => d!("instance-of", 2),
        0x21 => d!("array-length", 1),
        0x22 => d!("new-instance", 2),
        0x23 => d!("new-array", 2),
        0x24 => d!("filled-new-array", 3),
        0x25 => d!("filled-new-array/range", 3),
        0x26 => d!("fill-array-data", 3),
        0x27 => d!("throw", 1),
        0x28 => d!("goto", 1),
        0x29 => d!("goto/16", 2),
        0x2A => d!("goto/32", 3),
        0x2B => d!("packed-switch", 3),
        0x2C => d!("sparse-switch", 3),
        0x2D => d!("cmpl-float", 2),
        0x2E => d!("cmpg-float", 2),
        0x2F => d!("cmpl-double", 2),
        0x30 => d!("cmpg-double", 2),
        0x31 => d!("cmp-long", 2),
        0x32 => d!("if-eq", 2),
        0x33 => d!("if-ne", 2),
        0x34 => d!("if-lt", 2),
        0x35 => d!("if-ge", 2),
        0x36 => d!("if-gt", 2),
        0x37 => d!("if-le", 2),
        0x38 => d!("if-eqz", 2),
        0x39 => d!("if-nez", 2),
        0x3A => d!("if-ltz", 2),
        0x3B => d!("if-gez", 2),
        0x3C => d!("if-gtz", 2),
        0x3D => d!("if-lez", 2),
        0x3E..=0x43 => d!("unused", 1),
        0x44 => d!("aget", 2),
        0x45 => d!("aget-wide", 2),
        0x46 => d!("aget-object", 2),
        0x47 => d!("aget-boolean", 2),
        0x48 => d!("aget-byte", 2),
        0x49 => d!("aget-char", 2),
        0x4A => d!("aget-short", 2),
        0x4B => d!("aput", 2),
        0x4C => d!("aput-wide", 2),
        0x4D => d!("aput-object", 2),
        0x4E => d!("aput-boolean", 2),
        0x4F => d!("aput-byte", 2),
        0x50 => d!("aput-char", 2),
        0x51 => d!("aput-short", 2),
        0x52 => d!("iget", 2),
        0x53 => d!("iget-wide", 2),
        0x54 => d!("iget-object", 2),
        0x55 => d!("iget-boolean", 2),
        0x56 => d!("iget-byte", 2),
        0x57 => d!("iget-char", 2),
        0x58 => d!("iget-short", 2),
        0x59 => d!("iput", 2),
        0x5A => d!("iput-wide", 2),
        0x5B => d!("iput-object", 2),
        0x5C => d!("iput-boolean", 2),
        0x5D => d!("iput-byte", 2),
        0x5E => d!("iput-char", 2),
        0x5F => d!("iput-short", 2),
        0x60 => d!("sget", 2),
        0x61 => d!("sget-wide", 2),
        0x62 => d!("sget-object", 2),
        0x63 => d!("sget-boolean", 2),
        0x64 => d!("sget-byte", 2),
        0x65 => d!("sget-char", 2),
        0x66 => d!("sget-short", 2),
        0x67 => d!("sput", 2),
        0x68 => d!("sput-wide", 2),
        0x69 => d!("sput-object", 2),
        0x6A => d!("sput-boolean", 2),
        0x6B => d!("sput-byte", 2),
        0x6C => d!("sput-char", 2),
        0x6D => d!("sput-short", 2),
        0x6E => d!("invoke-virtual", 3),
        0x6F => d!("invoke-super", 3),
        0x70 => d!("invoke-direct", 3),
        0x71 => d!("invoke-static", 3),
        0x72 => d!("invoke-interface", 3),
        0x73 => d!("unused", 1),
        0x74 => d!("invoke-virtual/range", 3),
        0x75 => d!("invoke-super/range", 3),
        0x76 => d!("invoke-direct/range", 3),
        0x77 => d!("invoke-static/range", 3),
        0x78 => d!("invoke-interface/range", 3),
        0x79 | 0x7A => d!("unused", 1),
        0x7B => d!("neg-int", 1),
        0x7C => d!("not-int", 1),
        0x7D => d!("neg-long", 1),
        0x7E => d!("not-long", 1),
        0x7F => d!("neg-float", 1),
        0x80 => d!("neg-double", 1),
        0x81 => d!("int-to-long", 1),
        0x82 => d!("int-to-float", 1),
        0x83 => d!("int-to-double", 1),
        0x84 => d!("long-to-int", 1),
        0x85 => d!("long-to-float", 1),
        0x86 => d!("long-to-double", 1),
        0x87 => d!("float-to-int", 1),
        0x88 => d!("float-to-long", 1),
        0x89 => d!("float-to-double", 1),
        0x8A => d!("double-to-int", 1),
        0x8B => d!("double-to-long", 1),
        0x8C => d!("double-to-float", 1),
        0x8D => d!("int-to-byte", 1),
        0x8E => d!("int-to-char", 1),
        0x8F => d!("int-to-short", 1),
        0x90 => d!("add-int", 2),
        0x91 => d!("sub-int", 2),
        0x92 => d!("mul-int", 2),
        0x93 => d!("div-int", 2),
        0x94 => d!("rem-int", 2),
        0x95 => d!("and-int", 2),
        0x96 => d!("or-int", 2),
        0x97 => d!("xor-int", 2),
        0x98 => d!("shl-int", 2),
        0x99 => d!("shr-int", 2),
        0x9A => d!("ushr-int", 2),
        0x9B => d!("add-long", 2),
        0x9C => d!("sub-long", 2),
        0x9D => d!("mul-long", 2),
        0x9E => d!("div-long", 2),
        0x9F => d!("rem-long", 2),
        0xA0 => d!("and-long", 2),
        0xA1 => d!("or-long", 2),
        0xA2 => d!("xor-long", 2),
        0xA3 => d!("shl-long", 2),
        0xA4 => d!("shr-long", 2),
        0xA5 => d!("ushr-long", 2),
        0xA6 => d!("add-float", 2),
        0xA7 => d!("sub-float", 2),
        0xA8 => d!("mul-float", 2),
        0xA9 => d!("div-float", 2),
        0xAA => d!("rem-float", 2),
        0xAB => d!("add-double", 2),
        0xAC => d!("sub-double", 2),
        0xAD => d!("mul-double", 2),
        0xAE => d!("div-double", 2),
        0xAF => d!("rem-double", 2),
        0xB0 => d!("add-int/2addr", 1),
        0xB1 => d!("sub-int/2addr", 1),
        0xB2 => d!("mul-int/2addr", 1),
        0xB3 => d!("div-int/2addr", 1),
        0xB4 => d!("rem-int/2addr", 1),
        0xB5 => d!("and-int/2addr", 1),
        0xB6 => d!("or-int/2addr", 1),
        0xB7 => d!("xor-int/2addr", 1),
        0xB8 => d!("shl-int/2addr", 1),
        0xB9 => d!("shr-int/2addr", 1),
        0xBA => d!("ushr-int/2addr", 1),
        0xBB => d!("add-long/2addr", 1),
        0xBC => d!("sub-long/2addr", 1),
        0xBD => d!("mul-long/2addr", 1),
        0xBE => d!("div-long/2addr", 1),
        0xBF => d!("rem-long/2addr", 1),
        0xC0 => d!("and-long/2addr", 1),
        0xC1 => d!("or-long/2addr", 1),
        0xC2 => d!("xor-long/2addr", 1),
        0xC3 => d!("shl-long/2addr", 1),
        0xC4 => d!("shr-long/2addr", 1),
        0xC5 => d!("ushr-long/2addr", 1),
        0xC6 => d!("add-float/2addr", 1),
        0xC7 => d!("sub-float/2addr", 1),
        0xC8 => d!("mul-float/2addr", 1),
        0xC9 => d!("div-float/2addr", 1),
        0xCA => d!("rem-float/2addr", 1),
        0xCB => d!("add-double/2addr", 1),
        0xCC => d!("sub-double/2addr", 1),
        0xCD => d!("mul-double/2addr", 1),
        0xCE => d!("div-double/2addr", 1),
        0xCF => d!("rem-double/2addr", 1),
        0xD0 => d!("add-int/lit16", 2),
        0xD1 => d!("rsub-int", 2),
        0xD2 => d!("mul-int/lit16", 2),
        0xD3 => d!("div-int/lit16", 2),
        0xD4 => d!("rem-int/lit16", 2),
        0xD5 => d!("and-int/lit16", 2),
        0xD6 => d!("or-int/lit16", 2),
        0xD7 => d!("xor-int/lit16", 2),
        0xD8 => d!("add-int/lit8", 2),
        0xD9 => d!("rsub-int/lit8", 2),
        0xDA => d!("mul-int/lit8", 2),
        0xDB => d!("div-int/lit8", 2),
        0xDC => d!("rem-int/lit8", 2),
        0xDD => d!("and-int/lit8", 2),
        0xDE => d!("or-int/lit8", 2),
        0xDF => d!("xor-int/lit8", 2),
        0xE0 => d!("shl-int/lit8", 2),
        0xE1 => d!("shr-int/lit8", 2),
        0xE2 => d!("ushr-int/lit8", 2),
        0xE3 => d!("iget-volatile", 2),
        0xE4 => d!("iput-volatile", 2),
        0xE5 => d!("sget-volatile", 2),
        0xE6 => d!("sput-volatile", 2),
        0xE7 => d!("iget-object-volatile", 2),
        0xE8 => d!("iget-wide-volatile", 2),
        0xE9 => d!("iput-wide-volatile", 2),
        0xEA => d!("sget-wide-volatile", 2),
        0xEB => d!("sput-wide-volatile", 2),
        0xEC => d!("breakpoint", 1),
        0xED => d!("throw-verification-error", 2),
        0xEE => d!("execute-inline", 3),
        0xEF => d!("execute-inline/range", 3),
        0xF0 => d!("invoke-object-init/range", 3),
        0xF1 => d!("return-void-barrier", 1),
        0xF2 => d!("iget-quick", 2),
        0xF3 => d!("iget-wide-quick", 2),
        0xF4 => d!("iget-object-quick", 2),
        0xF5 => d!("iput-quick", 2),
        0xF6 => d!("iput-wide-quick", 2),
        0xF7 => d!("iput-object-quick", 2),
        0xF8 => d!("invoke-virtual-quick", 3),
        0xF9 => d!("invoke-virtual-quick/range", 3),
        0xFA => d!("invoke-polymorphic", 4),
        0xFB => d!("invoke-polymorphic/range", 4),
        0xFC => d!("invoke-custom", 3),
        0xFD => d!("invoke-custom/range", 3),
        0xFE => d!("const-method-handle", 2),
        0xFF => d!("const-method-type", 2),
    }
}

#[must_use]
pub fn disassemble_units(code: &[u16]) -> Vec<(u32, &'static str)> {
    let mut out: Vec<(u32, &'static str)> = Vec::new();
    let mut i: usize = 0;
    while i < code.len() {
        let unit: u16 = code[i];
        let op: u8 = (unit & 0xFF) as u8;
        let info: DalvikOp = opcode(op);
        out.push((i as u32, info.mnemonic));
        let default_width: usize = usize::from(info.units);
        let width: usize = payload_width(code, i, op).unwrap_or(default_width);
        i += width.max(1);
    }
    out
}

fn payload_width(code: &[u16], i: usize, op: u8) -> Option<usize> {
    let unit: u16 = *code.get(i)?;
    match op {
        0x00 => match unit >> 8 {
            0x01 => {
                let size: usize = usize::from(*code.get(i + 1)?);
                Some(size * 2 + 4)
            }
            0x02 => {
                let size: usize = usize::from(*code.get(i + 1)?);
                Some(size * 4 + 2)
            }
            0x03 => {
                let element_width: usize = usize::from(*code.get(i + 1)?);
                let count: usize =
                    usize::from(*code.get(i + 2)?) | (usize::from(*code.get(i + 3)?) << 16);
                let bytes: usize = element_width * count;
                Some(4 + bytes.div_ceil(2))
            }
            _ => Some(1),
        },
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InsnFormat {
    Fmt10x,
    Fmt12x,
    Fmt11n,
    Fmt11x,
    Fmt10t,
    Fmt20t,
    Fmt22x,
    Fmt21t,
    Fmt21s,
    Fmt21h,
    Fmt21c,
    Fmt23x,
    Fmt22b,
    Fmt22t,
    Fmt22s,
    Fmt22c,
    Fmt30t,
    Fmt32x,
    Fmt31i,
    Fmt31t,
    Fmt31c,
    Fmt35c,
    Fmt3rc,
    Fmt45cc,
    Fmt4rcc,
    Fmt51l,
    Fmt22cs,
    Fmt35mi,
    Fmt35ms,
    Fmt3rmi,
    Fmt3rms,
    PackedSwitchPayload,
    SparseSwitchPayload,
    FillArrayDataPayload,
}

#[inline]
#[must_use]
pub const fn dalvik_format(op: u8) -> InsnFormat {
    match op {
        0x00 => InsnFormat::Fmt10x,
        0x01 | 0x04 | 0x07 => InsnFormat::Fmt12x,
        0x02 | 0x05 | 0x08 => InsnFormat::Fmt22x,
        0x03 | 0x06 | 0x09 => InsnFormat::Fmt32x,
        0x0A..=0x0D => InsnFormat::Fmt11x,
        0x0E => InsnFormat::Fmt10x,
        0x0F..=0x11 => InsnFormat::Fmt11x,
        0x12 => InsnFormat::Fmt11n,
        0x13 | 0x16 => InsnFormat::Fmt21s,
        0x14 | 0x17 => InsnFormat::Fmt31i,
        0x15 | 0x19 => InsnFormat::Fmt21h,
        0x18 => InsnFormat::Fmt51l,
        0x1A => InsnFormat::Fmt21c,
        0x1B => InsnFormat::Fmt31c,
        0x1C | 0x1F | 0x22 => InsnFormat::Fmt21c,
        0x1D | 0x1E => InsnFormat::Fmt11x,
        0x20 | 0x23 => InsnFormat::Fmt22c,
        0x21 => InsnFormat::Fmt12x,
        0x24 => InsnFormat::Fmt35c,
        0x25 => InsnFormat::Fmt3rc,
        0x26 => InsnFormat::Fmt31t,
        0x27 => InsnFormat::Fmt11x,
        0x28 => InsnFormat::Fmt10t,
        0x29 => InsnFormat::Fmt20t,
        0x2A => InsnFormat::Fmt30t,
        0x2B | 0x2C => InsnFormat::Fmt31t,
        0x2D..=0x31 => InsnFormat::Fmt23x,
        0x32..=0x37 => InsnFormat::Fmt22t,
        0x38..=0x3D => InsnFormat::Fmt21t,
        0x3E..=0x43 => InsnFormat::Fmt10x,
        0x44..=0x51 => InsnFormat::Fmt23x,
        0x52..=0x5F => InsnFormat::Fmt22c,
        0x60..=0x6D => InsnFormat::Fmt21c,
        0x6E..=0x72 => InsnFormat::Fmt35c,
        0x73 => InsnFormat::Fmt10x,
        0x74..=0x78 => InsnFormat::Fmt3rc,
        0x79 | 0x7A => InsnFormat::Fmt10x,
        0x7B..=0x8F => InsnFormat::Fmt12x,
        0x90..=0xAF => InsnFormat::Fmt23x,
        0xB0..=0xCF => InsnFormat::Fmt12x,
        0xD0..=0xD7 => InsnFormat::Fmt22s,
        0xD8..=0xE2 => InsnFormat::Fmt22b,
        0xE3..=0xE7 => InsnFormat::Fmt22c,
        0xE8 => InsnFormat::Fmt22cs,
        0xE9 | 0xEA => InsnFormat::Fmt22cs,
        0xEB => InsnFormat::Fmt22cs,
        0xEC => InsnFormat::Fmt10x,
        0xED => InsnFormat::Fmt20t,
        0xEE => InsnFormat::Fmt35mi,
        0xEF => InsnFormat::Fmt3rmi,
        0xF0 => InsnFormat::Fmt35c,
        0xF1 => InsnFormat::Fmt10x,
        0xF2..=0xF7 => InsnFormat::Fmt22cs,
        0xF8 => InsnFormat::Fmt35ms,
        0xF9 => InsnFormat::Fmt3rms,
        0xFA => InsnFormat::Fmt45cc,
        0xFB => InsnFormat::Fmt4rcc,
        0xFC => InsnFormat::Fmt35c,
        0xFD => InsnFormat::Fmt3rc,
        0xFE | 0xFF => InsnFormat::Fmt21c,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DalvikInsn {
    pub pc: u32,
    pub op: u8,
    pub mnemonic: &'static str,
    pub width: u8,
    pub format: InsnFormat,
    pub regs: Vec<u16>,
    pub literal: Option<i64>,
    pub index: Option<u32>,
    pub branch: Option<i32>,
    pub payload_off: Option<u32>,
}

impl DalvikInsn {
    #[inline]
    #[must_use]
    pub fn branch_target_pc(&self) -> Option<u32> {
        self.branch
            .map(|off: i32| (i64::from(self.pc) + i64::from(off)) as u32)
    }

    #[inline]
    #[must_use]
    pub const fn is_unconditional_goto(&self) -> bool {
        matches!(self.op, 0x28..=0x2A)
    }

    #[inline]
    #[must_use]
    pub const fn is_conditional_branch(&self) -> bool {
        matches!(self.op, 0x32..=0x3D)
    }

    #[inline]
    #[must_use]
    pub const fn is_switch(&self) -> bool {
        matches!(self.op, 0x2B | 0x2C)
    }

    #[inline]
    #[must_use]
    pub const fn is_return(&self) -> bool {
        matches!(self.op, 0x0E..=0x11)
    }

    #[inline]
    #[must_use]
    pub const fn is_throw(&self) -> bool {
        self.op == 0x27
    }

    #[inline]
    #[must_use]
    pub const fn is_terminator(&self) -> bool {
        self.is_return()
            || self.is_throw()
            || self.is_unconditional_goto()
            || self.is_conditional_branch()
            || self.is_switch()
    }
}

#[inline]
const fn nibble_low(unit: u16) -> u16 {
    (unit >> 8) & 0x0F
}

#[inline]
const fn nibble_high(unit: u16) -> u16 {
    (unit >> 12) & 0x0F
}

#[inline]
const fn byte_bb(unit: u16) -> u16 {
    unit >> 8
}

#[inline]
fn sign_extend_nibble(n: u16) -> i64 {
    let v: i64 = i64::from(n & 0x0F);
    if v >= 8 { v - 16 } else { v }
}

#[inline]
fn sign_extend_byte(b: u16) -> i64 {
    let v: i64 = i64::from(b & 0xFF);
    if v >= 0x80 { v - 0x100 } else { v }
}

#[inline]
const fn sign_extend_short(s: u16) -> i64 {
    (s as i16) as i64
}

#[must_use]
pub fn decode_method(code: &[u16]) -> Vec<DalvikInsn> {
    let mut out: Vec<DalvikInsn> = Vec::with_capacity(code.len());
    let mut i: usize = 0;
    while i < code.len() {
        let unit: u16 = code[i];
        let op: u8 = (unit & 0xFF) as u8;
        if op == 0x00 && (unit >> 8) != 0 {
            let width: usize = payload_width(code, i, op).unwrap_or(1).max(1);
            i += width;
            continue;
        }
        let info: DalvikOp = opcode(op);
        let format: InsnFormat = dalvik_format(op);
        let decoded: DalvikInsn = decode_one(code, i, op, info.mnemonic, format);
        let width: usize = usize::from(decoded.width).max(1);
        out.push(decoded);
        i += width;
    }
    out
}

fn decode_one(
    code: &[u16],
    unit_off: usize,
    op: u8,
    mnemonic: &'static str,
    format: InsnFormat,
) -> DalvikInsn {
    let pc: u32 = unit_off as u32;
    let u0: u16 = code[unit_off];
    let u1: Option<u16> = code.get(unit_off + 1).copied();
    let u2: Option<u16> = code.get(unit_off + 2).copied();
    let u3: Option<u16> = code.get(unit_off + 3).copied();
    let u4: Option<u16> = code.get(unit_off + 4).copied();
    let mut regs: Vec<u16> = Vec::new();
    let mut literal: Option<i64> = None;
    let mut index: Option<u32> = None;
    let mut branch: Option<i32> = None;
    let mut payload_off: Option<u32> = None;
    let width: u8 = match format {
        InsnFormat::Fmt10x => 1,
        InsnFormat::Fmt12x => {
            regs.push(nibble_low(u0));
            regs.push(nibble_high(u0));
            1
        }
        InsnFormat::Fmt11n => {
            regs.push(nibble_low(u0));
            literal = Some(sign_extend_nibble(nibble_high(u0)));
            1
        }
        InsnFormat::Fmt11x => {
            regs.push(byte_bb(u0));
            1
        }
        InsnFormat::Fmt10t => {
            branch = Some(i32::from(sign_extend_byte(byte_bb(u0)) as i16));
            1
        }
        InsnFormat::Fmt20t => {
            branch = u1.map(|b: u16| i32::from(b as i16));
            2
        }
        InsnFormat::Fmt22x => {
            regs.push(byte_bb(u0));
            if let Some(b) = u1 {
                regs.push(b);
            }
            2
        }
        InsnFormat::Fmt21t => {
            regs.push(byte_bb(u0));
            branch = u1.map(|b: u16| i32::from(b as i16));
            2
        }
        InsnFormat::Fmt21s => {
            regs.push(byte_bb(u0));
            literal = u1.map(sign_extend_short);
            2
        }
        InsnFormat::Fmt21h => {
            regs.push(byte_bb(u0));
            literal = u1.map(|b: u16| i64::from(b as i16));
            2
        }
        InsnFormat::Fmt21c => {
            regs.push(byte_bb(u0));
            index = u1.map(u32::from);
            2
        }
        InsnFormat::Fmt23x => {
            regs.push(byte_bb(u0));
            if let Some(b) = u1 {
                regs.push(b & 0xFF);
                regs.push(b >> 8);
            }
            2
        }
        InsnFormat::Fmt22b => {
            regs.push(byte_bb(u0));
            if let Some(b) = u1 {
                regs.push(b & 0xFF);
                literal = Some(sign_extend_byte(b >> 8));
            }
            2
        }
        InsnFormat::Fmt22t => {
            regs.push(nibble_low(u0));
            regs.push(nibble_high(u0));
            branch = u1.map(|b: u16| i32::from(b as i16));
            2
        }
        InsnFormat::Fmt22s => {
            regs.push(nibble_low(u0));
            regs.push(nibble_high(u0));
            literal = u1.map(sign_extend_short);
            2
        }
        InsnFormat::Fmt22c | InsnFormat::Fmt22cs => {
            regs.push(nibble_low(u0));
            regs.push(nibble_high(u0));
            index = u1.map(u32::from);
            2
        }
        InsnFormat::Fmt30t => {
            branch = match (u1, u2) {
                (Some(lo), Some(hi)) => Some((u32::from(lo) | (u32::from(hi) << 16)) as i32),
                _ => None,
            };
            3
        }
        InsnFormat::Fmt32x => {
            if let Some(a) = u1 {
                regs.push(a);
            }
            if let Some(b) = u2 {
                regs.push(b);
            }
            3
        }
        InsnFormat::Fmt31i => {
            regs.push(byte_bb(u0));
            literal = match (u1, u2) {
                (Some(lo), Some(hi)) => {
                    Some(i64::from((u32::from(lo) | (u32::from(hi) << 16)) as i32))
                }
                _ => None,
            };
            3
        }
        InsnFormat::Fmt31t => {
            regs.push(byte_bb(u0));
            payload_off = match (u1, u2) {
                (Some(lo), Some(hi)) => {
                    let rel: i32 = (u32::from(lo) | (u32::from(hi) << 16)) as i32;
                    Some((i64::from(pc) + i64::from(rel)) as u32)
                }
                _ => None,
            };
            3
        }
        InsnFormat::Fmt31c => {
            regs.push(byte_bb(u0));
            index = match (u1, u2) {
                (Some(lo), Some(hi)) => Some(u32::from(lo) | (u32::from(hi) << 16)),
                _ => None,
            };
            3
        }
        InsnFormat::Fmt35c | InsnFormat::Fmt35mi | InsnFormat::Fmt35ms => {
            let count: u16 = nibble_high(u0);
            index = u1.map(u32::from);
            if let Some(packed) = u2 {
                let last_reg: u16 = nibble_low(u0);
                let nibbles: [u16; 5] = [
                    packed & 0xF,
                    (packed >> 4) & 0xF,
                    (packed >> 8) & 0xF,
                    (packed >> 12) & 0xF,
                    last_reg,
                ];
                regs.extend(nibbles.into_iter().take(usize::from(count.min(5))));
            }
            3
        }
        InsnFormat::Fmt3rc | InsnFormat::Fmt3rmi | InsnFormat::Fmt3rms => {
            let count: u16 = byte_bb(u0);
            index = u1.map(u32::from);
            if let Some(start) = u2 {
                for k in 0..count {
                    regs.push(start.wrapping_add(k));
                }
            }
            3
        }
        InsnFormat::Fmt45cc => {
            let count: u16 = nibble_high(u0);
            index = u1.map(u32::from);
            if let Some(packed) = u2 {
                let last_reg: u16 = nibble_low(u0);
                let nibbles: [u16; 5] = [
                    packed & 0xF,
                    (packed >> 4) & 0xF,
                    (packed >> 8) & 0xF,
                    (packed >> 12) & 0xF,
                    last_reg,
                ];
                regs.extend(nibbles.into_iter().take(usize::from(count.min(5))));
            }
            4
        }
        InsnFormat::Fmt4rcc => {
            let count: u16 = byte_bb(u0);
            index = u1.map(u32::from);
            if let Some(start) = u2 {
                for k in 0..count {
                    regs.push(start.wrapping_add(k));
                }
            }
            4
        }
        InsnFormat::Fmt51l => {
            regs.push(byte_bb(u0));
            literal = match (u1, u2, u3, u4) {
                (Some(w0), Some(w1), Some(w2), Some(w3)) => {
                    let value: u64 = u64::from(w0)
                        | (u64::from(w1) << 16)
                        | (u64::from(w2) << 32)
                        | (u64::from(w3) << 48);
                    Some(value as i64)
                }
                _ => None,
            };
            5
        }
        InsnFormat::PackedSwitchPayload
        | InsnFormat::SparseSwitchPayload
        | InsnFormat::FillArrayDataPayload => 1,
    };
    DalvikInsn {
        pc,
        op,
        mnemonic,
        width,
        format,
        regs,
        literal,
        index,
        branch,
        payload_off,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchPayload {
    pub keys: Vec<i32>,
    pub targets: Vec<u32>,
}

#[must_use]
pub fn parse_packed_switch(
    code: &[u16],
    switch_pc: u32,
    payload_off: u32,
) -> Option<SwitchPayload> {
    let base: usize = payload_off as usize;
    if *code.get(base)? != 0x0100 {
        return None;
    }
    let size: usize = usize::from(*code.get(base + 1)?);
    let first_key: i32 =
        (u32::from(*code.get(base + 2)?) | (u32::from(*code.get(base + 3)?) << 16)) as i32;
    let mut keys: Vec<i32> = Vec::with_capacity(size);
    let mut targets: Vec<u32> = Vec::with_capacity(size);
    for k in 0..size {
        let lo: u16 = *code.get(base + 4 + k * 2)?;
        let hi: u16 = *code.get(base + 4 + k * 2 + 1)?;
        let rel: i32 = (u32::from(lo) | (u32::from(hi) << 16)) as i32;
        keys.push(first_key.wrapping_add(k as i32));
        targets.push((i64::from(switch_pc) + i64::from(rel)) as u32);
    }
    Some(SwitchPayload { keys, targets })
}

#[must_use]
pub fn parse_sparse_switch(
    code: &[u16],
    switch_pc: u32,
    payload_off: u32,
) -> Option<SwitchPayload> {
    let base: usize = payload_off as usize;
    if *code.get(base)? != 0x0200 {
        return None;
    }
    let size: usize = usize::from(*code.get(base + 1)?);
    let keys_off: usize = base + 2;
    let targets_off: usize = keys_off + size * 2;
    let mut keys: Vec<i32> = Vec::with_capacity(size);
    let mut targets: Vec<u32> = Vec::with_capacity(size);
    for k in 0..size {
        let klo: u16 = *code.get(keys_off + k * 2)?;
        let khi: u16 = *code.get(keys_off + k * 2 + 1)?;
        keys.push((u32::from(klo) | (u32::from(khi) << 16)) as i32);
    }
    for k in 0..size {
        let tlo: u16 = *code.get(targets_off + k * 2)?;
        let thi: u16 = *code.get(targets_off + k * 2 + 1)?;
        let rel: i32 = (u32::from(tlo) | (u32::from(thi) << 16)) as i32;
        targets.push((i64::from(switch_pc) + i64::from(rel)) as u32);
    }
    Some(SwitchPayload { keys, targets })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn covers_full_opcode_space() {
        for op in 0u16..=0xFFu16 {
            let info: DalvikOp = opcode(op as u8);
            assert!(info.units >= 1);
        }
    }

    #[test]
    fn known_opcodes_have_correct_widths() {
        assert_eq!(opcode(0x0E).mnemonic, "return-void");
        assert_eq!(opcode(0x0E).units, 1);
        assert_eq!(opcode(0x6E).mnemonic, "invoke-virtual");
        assert_eq!(opcode(0x6E).units, 3);
        assert_eq!(opcode(0x18).mnemonic, "const-wide");
        assert_eq!(opcode(0x18).units, 5);
    }

    #[test]
    fn disassembles_simple_unit_stream() {
        let code: Vec<u16> = vec![0x000E, 0x0012, 0x000F];
        let insns: Vec<(u32, &'static str)> = disassemble_units(&code);
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].1, "return-void");
        assert_eq!(insns[1].1, "const/4");
        assert_eq!(insns[2].1, "return");
    }

    #[test]
    fn packed_switch_payload_width() {
        let code: Vec<u16> = vec![0x0100, 0x0003];
        let insns: Vec<(u32, &'static str)> = disassemble_units(&code);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].1, "nop");
    }
}
