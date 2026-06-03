use serde::{Deserialize, Serialize};

use crate::dalvik::{instruction_width, opcode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DalvikFormat {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F30t,
    F31t,
    F31i,
    F31c,
    F32x,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
    FPayload,
    FUnused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndexKind {
    None,
    String,
    Type,
    Field,
    Method,
    Proto,
    MethodAndProto,
    CallSite,
    MethodHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operands {
    None,
    RegA {
        a: u8,
    },
    RegAB {
        a: u8,
        b: u8,
    },
    RegALitB {
        a: u8,
        b: i32,
    },
    RegABLitC {
        a: u8,
        b: u8,
        c: i32,
    },
    RegABC {
        a: u8,
        b: u8,
        c: u8,
    },
    BranchA {
        a: i32,
    },
    RegABranch {
        a: u8,
        target: i32,
    },
    RegABBranch {
        a: u8,
        b: u8,
        target: i32,
    },
    RegAIndex {
        a: u8,
        index: u32,
    },
    RegABIndex {
        a: u8,
        b: u8,
        index: u32,
    },
    RegAWide {
        a: u8,
        literal: i64,
    },
    Index {
        index: u32,
    },
    Invoke {
        arg_count: u8,
        index: u32,
        args: [u8; 5],
    },
    InvokeRange {
        arg_count: u8,
        index: u32,
        first_reg: u16,
    },
    InvokePoly {
        arg_count: u8,
        method_index: u32,
        proto_index: u32,
        args: [u8; 5],
    },
    InvokePolyRange {
        arg_count: u8,
        method_index: u32,
        proto_index: u32,
        first_reg: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedInsn {
    pub offset: u32,
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub format: DalvikFormat,
    pub index_kind: IndexKind,
    pub width: u16,
    pub operands: Operands,
}

#[inline]
#[must_use]
pub const fn format_of(op: u8) -> DalvikFormat {
    match op {
        0x00 => DalvikFormat::F10x,
        0x01 => DalvikFormat::F12x,
        0x02 => DalvikFormat::F22x,
        0x03 => DalvikFormat::F32x,
        0x04 => DalvikFormat::F12x,
        0x05 => DalvikFormat::F22x,
        0x06 => DalvikFormat::F32x,
        0x07 => DalvikFormat::F12x,
        0x08 => DalvikFormat::F22x,
        0x09 => DalvikFormat::F32x,
        0x0A..=0x0D => DalvikFormat::F11x,
        0x0E => DalvikFormat::F10x,
        0x0F..=0x11 => DalvikFormat::F11x,
        0x12 => DalvikFormat::F11n,
        0x13 => DalvikFormat::F21s,
        0x14 => DalvikFormat::F31i,
        0x15 => DalvikFormat::F21h,
        0x16 => DalvikFormat::F21s,
        0x17 => DalvikFormat::F31i,
        0x18 => DalvikFormat::F51l,
        0x19 => DalvikFormat::F21h,
        0x1A => DalvikFormat::F21c,
        0x1B => DalvikFormat::F31c,
        0x1C => DalvikFormat::F21c,
        0x1D | 0x1E => DalvikFormat::F11x,
        0x1F => DalvikFormat::F21c,
        0x20 => DalvikFormat::F22c,
        0x21 => DalvikFormat::F12x,
        0x22 => DalvikFormat::F21c,
        0x23 => DalvikFormat::F22c,
        0x24 => DalvikFormat::F35c,
        0x25 => DalvikFormat::F3rc,
        0x26 => DalvikFormat::F31t,
        0x27 => DalvikFormat::F11x,
        0x28 => DalvikFormat::F10t,
        0x29 => DalvikFormat::F20t,
        0x2A => DalvikFormat::F30t,
        0x2B | 0x2C => DalvikFormat::F31t,
        0x2D..=0x31 => DalvikFormat::F23x,
        0x32..=0x37 => DalvikFormat::F22t,
        0x38..=0x3D => DalvikFormat::F21t,
        0x3E..=0x43 => DalvikFormat::FUnused,
        0x44..=0x51 => DalvikFormat::F23x,
        0x52..=0x5F => DalvikFormat::F22c,
        0x60..=0x6D => DalvikFormat::F21c,
        0x6E..=0x72 => DalvikFormat::F35c,
        0x73 => DalvikFormat::FUnused,
        0x74..=0x78 => DalvikFormat::F3rc,
        0x79 | 0x7A => DalvikFormat::FUnused,
        0x7B..=0x8F => DalvikFormat::F12x,
        0x90..=0xAF => DalvikFormat::F23x,
        0xB0..=0xCF => DalvikFormat::F12x,
        0xD0..=0xD7 => DalvikFormat::F22s,
        0xD8..=0xE2 => DalvikFormat::F22b,
        0xFA => DalvikFormat::F45cc,
        0xFB => DalvikFormat::F4rcc,
        0xFC | 0xFD => DalvikFormat::F35c,
        0xFE | 0xFF => DalvikFormat::F21c,
        _ => DalvikFormat::FUnused,
    }
}

#[inline]
#[must_use]
pub const fn index_kind_of(op: u8) -> IndexKind {
    match op {
        0x1A | 0x1B => IndexKind::String,
        0x1C | 0x1F | 0x20 | 0x22 | 0x23 | 0x24 | 0x25 => IndexKind::Type,
        0x52..=0x6D => IndexKind::Field,
        0x6E..=0x72 | 0x74..=0x78 => IndexKind::Method,
        0xFA | 0xFB => IndexKind::MethodAndProto,
        0xFC | 0xFD => IndexKind::CallSite,
        0xFE => IndexKind::MethodHandle,
        0xFF => IndexKind::Proto,
        _ => IndexKind::None,
    }
}

#[inline]
const fn nib_high(b: u16) -> u8 {
    ((b >> 4) & 0x0F) as u8
}

#[inline]
fn sign_extend_nibble(v: u8) -> i32 {
    let n: i32 = i32::from(v);
    if n & 0x8 != 0 { n - 16 } else { n }
}

#[inline]
fn at(code: &[u16], i: usize) -> u16 {
    code.get(i).copied().unwrap_or(0)
}

#[allow(clippy::many_single_char_names)]
fn extract_invoke(code: &[u16], i: usize) -> Operands {
    let unit0: u16 = at(code, i);
    let arg_count: u8 = ((unit0 >> 12) & 0x0F) as u8;
    let g: u8 = ((unit0 >> 8) & 0x0F) as u8;
    let index: u32 = u32::from(at(code, i + 1));
    let ccrr: u16 = at(code, i + 2);
    let c: u8 = (ccrr & 0x0F) as u8;
    let d: u8 = ((ccrr >> 4) & 0x0F) as u8;
    let e: u8 = ((ccrr >> 8) & 0x0F) as u8;
    let f: u8 = ((ccrr >> 12) & 0x0F) as u8;
    Operands::Invoke {
        arg_count,
        index,
        args: [c, d, e, f, g],
    }
}

fn extract_invoke_range(code: &[u16], i: usize) -> Operands {
    let unit0: u16 = at(code, i);
    let arg_count: u8 = ((unit0 >> 8) & 0xFF) as u8;
    let index: u32 = u32::from(at(code, i + 1));
    let first_reg: u16 = at(code, i + 2);
    Operands::InvokeRange {
        arg_count,
        index,
        first_reg,
    }
}

#[allow(clippy::many_single_char_names)]
fn extract_operands(code: &[u16], i: usize, op: u8, format: DalvikFormat) -> Operands {
    let unit0: u16 = at(code, i);
    let bb_high: u8 = ((unit0 >> 8) & 0xFF) as u8;
    let a_nib: u8 = nib_high(unit0 >> 8);
    let b_nib: u8 = ((unit0 >> 12) & 0x0F) as u8;
    match format {
        DalvikFormat::F10x | DalvikFormat::FUnused | DalvikFormat::FPayload => Operands::None,
        DalvikFormat::F12x => Operands::RegAB { a: a_nib, b: b_nib },
        DalvikFormat::F11n => Operands::RegALitB {
            a: a_nib,
            b: sign_extend_nibble(b_nib),
        },
        DalvikFormat::F11x => Operands::RegA { a: bb_high },
        DalvikFormat::F10t => Operands::BranchA {
            a: i32::from(bb_high as i8),
        },
        DalvikFormat::F20t => Operands::BranchA {
            a: i32::from(at(code, i + 1) as i16),
        },
        DalvikFormat::F22x => Operands::RegAB {
            a: bb_high,
            b: (at(code, i + 1) & 0xFF) as u8,
        },
        DalvikFormat::F21t => Operands::RegABranch {
            a: bb_high,
            target: i32::from(at(code, i + 1) as i16),
        },
        DalvikFormat::F21s => Operands::RegALitB {
            a: bb_high,
            b: i32::from(at(code, i + 1) as i16),
        },
        DalvikFormat::F21h => {
            let raw: i32 = i32::from(at(code, i + 1) as i16);
            let shifted: i32 = if op == 0x15 { raw << 16 } else { raw };
            Operands::RegALitB {
                a: bb_high,
                b: shifted,
            }
        }
        DalvikFormat::F21c => Operands::RegAIndex {
            a: bb_high,
            index: u32::from(at(code, i + 1)),
        },
        DalvikFormat::F23x => {
            let bc: u16 = at(code, i + 1);
            Operands::RegABC {
                a: bb_high,
                b: (bc & 0xFF) as u8,
                c: ((bc >> 8) & 0xFF) as u8,
            }
        }
        DalvikFormat::F22b => {
            let bc: u16 = at(code, i + 1);
            Operands::RegABLitC {
                a: bb_high,
                b: (bc & 0xFF) as u8,
                c: i32::from((bc >> 8) as i8),
            }
        }
        DalvikFormat::F22t => Operands::RegABBranch {
            a: a_nib,
            b: b_nib,
            target: i32::from(at(code, i + 1) as i16),
        },
        DalvikFormat::F22s => Operands::RegABLitC {
            a: a_nib,
            b: b_nib,
            c: i32::from(at(code, i + 1) as i16),
        },
        DalvikFormat::F22c => Operands::RegABIndex {
            a: a_nib,
            b: b_nib,
            index: u32::from(at(code, i + 1)),
        },
        DalvikFormat::F30t => {
            let lo: u32 = u32::from(at(code, i + 1));
            let hi: u32 = u32::from(at(code, i + 2));
            Operands::BranchA {
                a: (lo | (hi << 16)) as i32,
            }
        }
        DalvikFormat::F31t => {
            let lo: u32 = u32::from(at(code, i + 1));
            let hi: u32 = u32::from(at(code, i + 2));
            Operands::RegABranch {
                a: bb_high,
                target: (lo | (hi << 16)) as i32,
            }
        }
        DalvikFormat::F31i => {
            let lo: u32 = u32::from(at(code, i + 1));
            let hi: u32 = u32::from(at(code, i + 2));
            Operands::RegALitB {
                a: bb_high,
                b: (lo | (hi << 16)) as i32,
            }
        }
        DalvikFormat::F31c => {
            let lo: u32 = u32::from(at(code, i + 1));
            let hi: u32 = u32::from(at(code, i + 2));
            Operands::RegAIndex {
                a: bb_high,
                index: lo | (hi << 16),
            }
        }
        DalvikFormat::F32x => Operands::RegAB {
            a: (at(code, i + 1) & 0xFF) as u8,
            b: (at(code, i + 2) & 0xFF) as u8,
        },
        DalvikFormat::F35c => extract_invoke(code, i),
        DalvikFormat::F3rc => extract_invoke_range(code, i),
        DalvikFormat::F45cc => {
            let unit0_a: u8 = ((unit0 >> 12) & 0x0F) as u8;
            let g: u8 = ((unit0 >> 8) & 0x0F) as u8;
            let method_index: u32 = u32::from(at(code, i + 1));
            let ccrr: u16 = at(code, i + 2);
            let c: u8 = (ccrr & 0x0F) as u8;
            let d: u8 = ((ccrr >> 4) & 0x0F) as u8;
            let e: u8 = ((ccrr >> 8) & 0x0F) as u8;
            let f: u8 = ((ccrr >> 12) & 0x0F) as u8;
            let proto_index: u32 = u32::from(at(code, i + 3));
            Operands::InvokePoly {
                arg_count: unit0_a,
                method_index,
                proto_index,
                args: [c, d, e, f, g],
            }
        }
        DalvikFormat::F4rcc => {
            let arg_count: u8 = ((unit0 >> 8) & 0xFF) as u8;
            let method_index: u32 = u32::from(at(code, i + 1));
            let first_reg: u16 = at(code, i + 2);
            let proto_index: u32 = u32::from(at(code, i + 3));
            Operands::InvokePolyRange {
                arg_count,
                method_index,
                proto_index,
                first_reg,
            }
        }
        DalvikFormat::F51l => {
            let mut literal: u64 = 0;
            for k in 0..4 {
                literal |= u64::from(at(code, i + 1 + k)) << (16 * k);
            }
            Operands::RegAWide {
                a: bb_high,
                literal: literal as i64,
            }
        }
    }
}

#[must_use]
pub fn decode_one(code: &[u16], i: usize) -> Option<DecodedInsn> {
    let unit0: u16 = *code.get(i)?;
    let op: u8 = (unit0 & 0xFF) as u8;
    let mnemonic: &'static str = opcode(op).mnemonic;
    let width_units: usize = instruction_width(code, i, op);
    let is_payload: bool = op == 0x00 && (unit0 >> 8) != 0;
    let format: DalvikFormat = if is_payload {
        DalvikFormat::FPayload
    } else {
        format_of(op)
    };
    let index_kind: IndexKind = if is_payload {
        IndexKind::None
    } else {
        index_kind_of(op)
    };
    let operands: Operands = if is_payload {
        Operands::None
    } else {
        extract_operands(code, i, op, format)
    };
    Some(DecodedInsn {
        offset: i as u32,
        opcode: op,
        mnemonic,
        format,
        index_kind,
        width: width_units as u16,
        operands,
    })
}

#[must_use]
pub fn decode_all(code: &[u16]) -> Vec<DecodedInsn> {
    let mut out: Vec<DecodedInsn> = Vec::new();
    let mut i: usize = 0;
    while i < code.len() {
        let Some(insn): Option<DecodedInsn> = decode_one(code, i) else {
            break;
        };
        let width: usize = usize::from(insn.width).max(1);
        out.push(insn);
        i += width;
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn format_map_is_total_over_opcode_space() {
        for op in 0u16..=0xFFu16 {
            let _f: DalvikFormat = format_of(op as u8);
            let _k: IndexKind = index_kind_of(op as u8);
        }
    }

    #[test]
    fn invoke_direct_extracts_method_index_and_args() {
        let code: Vec<u16> = vec![0x1070, 0x0007, 0x0000, 0x000E];
        let insn: DecodedInsn = decode_one(&code, 0).expect("decode");
        assert_eq!(insn.opcode, 0x70);
        assert_eq!(insn.format, DalvikFormat::F35c);
        assert_eq!(insn.index_kind, IndexKind::Method);
        let Operands::Invoke {
            arg_count,
            index,
            args,
        }: Operands = insn.operands
        else {
            panic!("expected invoke operands");
        };
        assert_eq!(arg_count, 1);
        assert_eq!(index, 7);
        assert_eq!(args[0], 0);
    }

    #[test]
    fn const_string_is_string_index_kind() {
        let code: Vec<u16> = vec![0x001A, 0x0005];
        let insn: DecodedInsn = decode_one(&code, 0).expect("decode");
        assert_eq!(insn.format, DalvikFormat::F21c);
        assert_eq!(insn.index_kind, IndexKind::String);
        let Operands::RegAIndex { a, index }: Operands = insn.operands else {
            panic!("expected reg+index");
        };
        assert_eq!(a, 0);
        assert_eq!(index, 5);
    }
}
