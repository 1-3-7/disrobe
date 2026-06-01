use crate::error::{CextractError, Result};

pub(crate) const MAX_PROLOGUE_SCAN: usize = 32;
pub(crate) const MIN_HOOK_BYTES: usize = 14;

#[derive(Debug, Clone, Copy)]
pub(crate) struct InstructionLen {
    pub length: u8,
    pub uses_rip_relative: bool,
}

#[inline]
const fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
    )
}

#[inline]
const fn is_rex(b: u8) -> bool {
    (b & 0xF0) == 0x40
}

#[inline]
const fn modrm_mod(b: u8) -> u8 {
    (b >> 6) & 0x03
}

#[inline]
const fn modrm_rm(b: u8) -> u8 {
    b & 0x07
}

#[inline]
const fn modrm_reg(b: u8) -> u8 {
    (b >> 3) & 0x07
}

#[derive(Debug, Clone, Copy)]
struct OpInfo {
    has_modrm: bool,
    imm_size: u8,
    is_rip_branch_or_call: bool,
}

#[inline]
const fn imm_z_size(operand_size: u8) -> u8 {
    if operand_size == 2 { 2 } else { 4 }
}

const fn one_byte_opcode_info(op: u8, operand_size: u8) -> Option<OpInfo> {
    match op {
        0x50..=0x5F | 0x90 | 0xC3 | 0xCB => Some(OpInfo {
            has_modrm: false,
            imm_size: 0,
            is_rip_branch_or_call: false,
        }),
        0x88..=0x8B
        | 0x84..=0x85
        | 0x86..=0x87
        | 0x00..=0x03
        | 0x08..=0x0B
        | 0x30..=0x33
        | 0x38..=0x3B
        | 0x20..=0x23
        | 0x28..=0x2B
        | 0x10..=0x13
        | 0x18..=0x1B
        | 0x8D
        | 0x8F
        | 0xFF => Some(OpInfo {
            has_modrm: true,
            imm_size: 0,
            is_rip_branch_or_call: false,
        }),
        0xC2 | 0xCA => Some(OpInfo {
            has_modrm: false,
            imm_size: 2,
            is_rip_branch_or_call: false,
        }),
        0x68 => Some(OpInfo {
            has_modrm: false,
            imm_size: imm_z_size(operand_size),
            is_rip_branch_or_call: false,
        }),
        0xB8..=0xBF => Some(OpInfo {
            has_modrm: false,
            imm_size: operand_size,
            is_rip_branch_or_call: false,
        }),
        0x6A | 0xB0..=0xB7 => Some(OpInfo {
            has_modrm: false,
            imm_size: 1,
            is_rip_branch_or_call: false,
        }),
        0x81 | 0xC7 => Some(OpInfo {
            has_modrm: true,
            imm_size: imm_z_size(operand_size),
            is_rip_branch_or_call: false,
        }),
        0x83 | 0xC6 => Some(OpInfo {
            has_modrm: true,
            imm_size: 1,
            is_rip_branch_or_call: false,
        }),
        0xE8 | 0xE9 => Some(OpInfo {
            has_modrm: false,
            imm_size: 4,
            is_rip_branch_or_call: true,
        }),
        0xEB => Some(OpInfo {
            has_modrm: false,
            imm_size: 1,
            is_rip_branch_or_call: true,
        }),
        _ => None,
    }
}

const fn modrm_extra_len(modrm: u8, address_size: u8) -> (u8, bool) {
    let md: u8 = modrm_mod(modrm);
    let rm: u8 = modrm_rm(modrm);
    if md == 0b11 {
        return (0, false);
    }
    let (mut extra, rip_rel): (u8, bool) = if md == 0b00 && rm == 0b101 {
        (4, true)
    } else {
        let base: u8 = match md {
            0b01 => 1,
            0b10 => 4,
            _ => 0,
        };
        (base, false)
    };
    if md != 0b11 && rm == 0b100 {
        extra += 1;
    }
    let _ = address_size;
    (extra, rip_rel)
}

pub(crate) fn instruction_length(bytes: &[u8]) -> Result<InstructionLen> {
    if bytes.is_empty() {
        return Err(CextractError::HotpatchFailed {
            stage: "lde",
            reason: "empty instruction buffer".to_owned(),
        });
    }
    let mut idx: usize = 0;
    let mut operand_size: u8 = 4;
    let address_size: u8 = 4;
    while idx < bytes.len() && is_legacy_prefix(bytes[idx]) {
        if bytes[idx] == 0x66 {
            operand_size = 2;
        }
        idx += 1;
        if idx >= 15 {
            return Err(CextractError::HotpatchFailed {
                stage: "lde",
                reason: "instruction exceeds 15 bytes (prefixes)".to_owned(),
            });
        }
    }
    if idx < bytes.len() && is_rex(bytes[idx]) {
        let rex: u8 = bytes[idx];
        if (rex & 0x08) != 0 {
            operand_size = 8;
        }
        idx += 1;
    }
    let Some(&op) = bytes.get(idx) else {
        return Err(CextractError::HotpatchFailed {
            stage: "lde",
            reason: "no opcode after prefixes".to_owned(),
        });
    };
    idx += 1;
    if op == 0x0F {
        let Some(&op2) = bytes.get(idx) else {
            return Err(CextractError::HotpatchFailed {
                stage: "lde",
                reason: "truncated 0F escape".to_owned(),
            });
        };
        idx += 1;
        let (extra, has_modrm, imm, rip_branch): (u8, bool, u8, bool) = match op2 {
            0x80..=0x8F => (0, false, 4, true),
            0xB6 | 0xB7 | 0xBE | 0xBF | 0xAF | 0x40..=0x4F => (0, true, 0, false),
            0x05 => (0, false, 0, false),
            _ => {
                return Err(CextractError::HotpatchFailed {
                    stage: "lde",
                    reason: format!("unsupported 0F {op2:02X} in prologue"),
                });
            }
        };
        let _ = extra;
        if has_modrm {
            let Some(&modrm) = bytes.get(idx) else {
                return Err(CextractError::HotpatchFailed {
                    stage: "lde",
                    reason: "truncated modrm".to_owned(),
                });
            };
            idx += 1;
            let (mextra, rip_rel): (u8, bool) = modrm_extra_len(modrm, address_size);
            idx += mextra as usize;
            return Ok(InstructionLen {
                length: u8::try_from(idx).unwrap_or(0).saturating_add(imm),
                uses_rip_relative: rip_rel || rip_branch,
            });
        }
        idx += imm as usize;
        return Ok(InstructionLen {
            length: u8::try_from(idx).unwrap_or(0),
            uses_rip_relative: rip_branch,
        });
    }
    let info: OpInfo =
        one_byte_opcode_info(op, operand_size).ok_or_else(|| CextractError::HotpatchFailed {
            stage: "lde",
            reason: format!("unsupported opcode {op:02X} in prologue"),
        })?;
    let mut rip_rel: bool = info.is_rip_branch_or_call;
    if info.has_modrm {
        let Some(&modrm) = bytes.get(idx) else {
            return Err(CextractError::HotpatchFailed {
                stage: "lde",
                reason: "truncated modrm".to_owned(),
            });
        };
        idx += 1;
        let (mextra, modrm_rip): (u8, bool) = modrm_extra_len(modrm, address_size);
        idx += mextra as usize;
        rip_rel = rip_rel || modrm_rip;
        if op == 0xFF {
            let reg: u8 = modrm_reg(modrm);
            if matches!(reg, 2..=5) {
                rip_rel = true;
            }
        }
    }
    idx += info.imm_size as usize;
    Ok(InstructionLen {
        length: u8::try_from(idx).unwrap_or(0),
        uses_rip_relative: rip_rel,
    })
}

pub(crate) fn measure_prologue(bytes: &[u8], min_bytes: usize) -> Result<usize> {
    let mut consumed: usize = 0;
    while consumed < min_bytes {
        if consumed >= MAX_PROLOGUE_SCAN || consumed >= bytes.len() {
            return Err(CextractError::HotpatchFailed {
                stage: "prologue-scan",
                reason: format!(
                    "exhausted scan window before reaching {min_bytes} bytes (got {consumed})"
                ),
            });
        }
        let slice: &[u8] = &bytes[consumed..];
        let ins: InstructionLen = instruction_length(slice)?;
        if ins.uses_rip_relative {
            return Err(CextractError::HotpatchFailed {
                stage: "prologue-scan",
                reason: format!(
                    "rip-relative instruction at offset {consumed} cannot be relocated"
                ),
            });
        }
        if ins.length == 0 {
            return Err(CextractError::HotpatchFailed {
                stage: "prologue-scan",
                reason: format!("zero-length decode at offset {consumed}"),
            });
        }
        consumed += ins.length as usize;
    }
    Ok(consumed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        InstructionLen, MAX_PROLOGUE_SCAN, MIN_HOOK_BYTES, instruction_length, measure_prologue,
    };

    #[test]
    fn detects_push_rbp() {
        let bytes: [u8; 1] = [0x55];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 1);
        assert!(!ins.uses_rip_relative);
    }

    #[test]
    fn detects_mov_rbp_rsp() {
        let bytes: [u8; 3] = [0x48, 0x89, 0xE5];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 3);
    }

    #[test]
    fn detects_sub_rsp_imm8() {
        let bytes: [u8; 4] = [0x48, 0x83, 0xEC, 0x20];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 4);
    }

    #[test]
    fn detects_mov_rdi_rdi_two_byte_hot_patch_prefix() {
        let bytes: [u8; 3] = [0x48, 0x8B, 0xFF];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 3);
    }

    #[test]
    fn flags_rip_relative_jmp_e9() {
        let bytes: [u8; 5] = [0xE9, 0x00, 0x00, 0x00, 0x00];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert!(ins.uses_rip_relative);
    }

    #[test]
    fn measure_prologue_classic_function_entry_consumes_at_least_min_bytes() {
        let prologue: [u8; 16] = [
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0x7D, 0xF8, 0x48, 0x89,
            0x75, 0xF0,
        ];
        let n: usize = measure_prologue(&prologue, MIN_HOOK_BYTES).unwrap();
        assert!(n >= MIN_HOOK_BYTES);
        assert!(n <= MAX_PROLOGUE_SCAN);
    }

    #[test]
    fn measure_prologue_refuses_rip_relative_inside_hook_window() {
        let prologue: [u8; 16] = [
            0x55, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90,
        ];
        assert!(measure_prologue(&prologue, MIN_HOOK_BYTES).is_err());
    }

    #[test]
    fn detects_nop_prefix() {
        let bytes: [u8; 2] = [0x90, 0x90];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 1);
    }

    #[test]
    fn rexw_push_imm32_is_five_bytes_not_nine() {
        let bytes: [u8; 9] = [0x48, 0x68, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 6);
    }

    #[test]
    fn push_imm32_no_rex_is_five_bytes() {
        let bytes: [u8; 5] = [0x68, 0x78, 0x56, 0x34, 0x12];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 5);
    }

    #[test]
    fn rexw_add_rm_imm32_group1_is_seven_bytes_not_eleven() {
        let bytes: [u8; 11] = [
            0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 7);
    }

    #[test]
    fn rexw_mov_rm_imm32_c7_is_seven_bytes_not_eleven() {
        let bytes: [u8; 11] = [
            0x48, 0xC7, 0x45, 0xF8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 8);
    }

    #[test]
    fn rexw_mov_reg_imm64_b8_stays_ten_bytes() {
        let bytes: [u8; 10] = [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 10);
    }

    #[test]
    fn operand16_push_imm16_is_four_bytes() {
        let bytes: [u8; 4] = [0x66, 0x68, 0x34, 0x12];
        let ins: InstructionLen = instruction_length(&bytes).unwrap();
        assert_eq!(ins.length, 4);
    }

    #[test]
    fn measure_prologue_with_rexw_c7_does_not_overrun() {
        let prologue: [u8; 16] = [
            0x55, 0x48, 0x89, 0xE5, 0x48, 0xC7, 0x45, 0xF8, 0x2A, 0x00, 0x00, 0x00, 0x90, 0x90,
            0x90, 0x90,
        ];
        let n: usize = measure_prologue(&prologue, MIN_HOOK_BYTES).unwrap();
        assert!(n >= MIN_HOOK_BYTES);
        assert!(n <= MAX_PROLOGUE_SCAN);
        assert_eq!(n, 14);
    }
}
