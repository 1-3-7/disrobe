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

#[inline]
#[must_use]
pub fn instruction_width(code: &[u16], i: usize, op: u8) -> usize {
    let default_width: usize = usize::from(opcode(op).units);
    payload_width(code, i, op).unwrap_or(default_width).max(1)
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
        let width: usize = instruction_width(code, i, op);
        i += width;
    }
    out
}

#[must_use]
pub fn payload_width(code: &[u16], i: usize, op: u8) -> Option<usize> {
    let unit: u16 = *code.get(i)?;
    match op {
        0x00 => match unit >> 8 {
            0x01 => {
                let size: usize = usize::from(*code.get(i + 1)?);
                Some(4 + size * 2)
            }
            0x02 => {
                let size: usize = usize::from(*code.get(i + 1)?);
                Some(2 + size * 4)
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
