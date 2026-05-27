use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::static_unpack::decrypt_v8;
use crate::static_unpack::runtime::RuntimeInfoSummary;
use crate::static_unpack::{DecryptStatus, UnpackConfig, VersionedOutcome};

pub(crate) fn run(
    bytes: &[u8],
    detection: &Detection,
    runtime: Option<&RuntimeInfoSummary>,
    cfg: &UnpackConfig,
) -> Result<VersionedOutcome> {
    let Some(runtime_info): Option<&RuntimeInfoSummary> = runtime else {
        if cfg.strict {
            return Err(Error::RuntimeNotFound {
                searched: vec!["<runtime not supplied to unpack_static_with_config>".to_owned()],
            });
        }
        return Ok(VersionedOutcome {
            plaintext: Vec::new(),
            original_bytecode: None,
            bcc_blobs: Vec::new(),
            encrypted_funcs_recovered: 0,
            inner_cipher_stats: crate::static_unpack::InnerCipherStats::empty(),
            status: DecryptStatus::DetectOnly,
            diagnostics: vec![
                "DR-PYARM-STATIC: v9 detect-only (no runtime supplied; pass UnpackConfig.runtime_bytes for full decrypt)"
                    .to_owned(),
            ],
        });
    };

    let base_status: DecryptStatus = DecryptStatus::Functional;
    let mut outcome: VersionedOutcome =
        decrypt_v8::decrypt_with_runtime_key(bytes, &runtime_info.aes_key, base_status)?;

    if let Some(mask) = recover_inner_nonce_xor_mask(&outcome.plaintext) {
        outcome.diagnostics.push(format!(
            "DR-PYARM-STATIC: v9 RFT/BCC nonce-XOR microVM ran, mask={}",
            hex_short(&mask)
        ));
    }

    if !outcome.bcc_blobs.is_empty() && !cfg.allow_bcc {
        outcome
            .diagnostics
            .push("DR-PYARM-STATIC: BCC blobs present; native lift gated behind allow_bcc=true + ghidra-headless".to_owned());
    }

    let _ = detection;
    Ok(outcome)
}

fn recover_inner_nonce_xor_mask(plaintext: &[u8]) -> Option<[u8; 12]> {
    if plaintext.len() < 8 {
        return None;
    }
    let code_object_offset: usize = u32_le_at(plaintext, 0)?;
    let xor_key_procedure_length: usize = u32_le_at(plaintext, 4)?;
    if xor_key_procedure_length == 0 {
        return None;
    }
    let proc_start: usize = code_object_offset.checked_sub(xor_key_procedure_length)?;
    let proc_end: usize = proc_start.checked_add(xor_key_procedure_length)?;
    if proc_end > plaintext.len() {
        return None;
    }
    let procedure: &[u8] = &plaintext[proc_start..proc_end];
    let mut mask: [u8; 12] = [0u8; 12];
    run_xor_microvm(procedure, &mut mask);
    Some(mask)
}

fn u32_le_at(buf: &[u8], offset: usize) -> Option<usize> {
    let end: usize = offset.checked_add(4)?;
    let slice: &[u8] = buf.get(offset..end)?;
    let value: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    usize::try_from(value).ok()
}

fn hex_short(b: &[u8]) -> String {
    let mut s: String = String::with_capacity(b.len() * 2);
    for byte in b {
        let upper: u8 = (byte >> 4) & 0x0f;
        let lower: u8 = byte & 0x0f;
        s.push(nibble_to_char(upper));
        s.push(nibble_to_char(lower));
    }
    s
}

const fn nibble_to_char(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

const VALID_REG_INDEX: [i8; 16] = [0, 1, 2, 3, 4, 5, -1, 7, -1, -1, -1, -1, -1, -1, -1, -1];

#[inline]
const fn low32_of(value: i64) -> u32 {
    let unsigned: u64 = value.cast_unsigned();
    (unsigned & 0xffff_ffff) as u32
}

#[derive(Debug, Default)]
struct MicroVmState {
    registers: [i64; 8],
}

fn run_xor_microvm(procedure: &[u8], out: &mut [u8; 12]) {
    if procedure.len() <= 16 {
        return;
    }
    let mut state: MicroVmState = MicroVmState::default();
    let mut cur: usize = 16;
    while cur < procedure.len() {
        let opcode: u8 = procedure[cur];
        let advanced: Option<usize> = step(&mut state, procedure, cur, opcode, out);
        match advanced {
            Some(next) if next > cur => cur = next,
            _ => return,
        }
    }
}

fn step(
    state: &mut MicroVmState,
    procedure: &[u8],
    cur: usize,
    opcode: u8,
    out: &mut [u8; 12],
) -> Option<usize> {
    match opcode {
        1u8 => Some(cur + 1),
        2u8..=7u8 => {
            let (operand2, advance): (i64, usize) = read_operand2(state, procedure, cur)?;
            let high: usize = ((procedure.get(cur + 1).copied()? >> 4) & 0x0f) as usize;
            let reg: &mut i64 = state.registers.get_mut(high)?;
            match opcode {
                2u8 => *reg = reg.wrapping_add(operand2),
                3u8 => *reg = reg.wrapping_sub(operand2),
                4u8 => *reg = reg.wrapping_mul(operand2),
                5u8 => {
                    if operand2 != 0 {
                        *reg = reg.wrapping_div(operand2);
                    }
                    let after_div: i64 = *reg;
                    state.registers[0] = after_div;
                }
                6u8 => *reg ^= operand2,
                7u8 => *reg = operand2,
                _ => return None,
            }
            Some(cur + advance)
        }
        8u8 => Some(cur + 2),
        9u8 => {
            let reg_index: usize = (procedure.get(cur + 1).copied()? & 0x07) as usize;
            let value: u32 = low32_of(state.registers.get(reg_index).copied()?);
            out[..4].copy_from_slice(&value.to_le_bytes());
            Some(cur + 2)
        }
        0xau8 => Some(cur + 6),
        0xbu8 => {
            let reg_index: usize = (procedure.get(cur + 1).copied()? & 0x07) as usize;
            let offset: usize = procedure.get(cur + 2).copied()? as usize;
            let end: usize = offset.checked_add(4)?;
            if end > out.len() {
                return Some(cur + 3);
            }
            let value: u32 = low32_of(state.registers.get(reg_index).copied()?);
            out[offset..end].copy_from_slice(&value.to_le_bytes());
            Some(cur + 3)
        }
        _ => None,
    }
}

fn read_operand2(state: &MicroVmState, procedure: &[u8], cur: usize) -> Option<(i64, usize)> {
    let nibble: u8 = procedure.get(cur + 1).copied()? & 0x0f;
    let mapped_idx: i8 = VALID_REG_INDEX.get(nibble as usize).copied()?;
    if mapped_idx >= 0 {
        let reg_index: usize = usize::try_from(mapped_idx).ok()?;
        let value: i64 = state.registers.get(reg_index).copied()?;
        return Some((value, 2));
    }
    let inside_size: u8 = nibble & 0x07;
    match inside_size {
        1u8 => {
            let raw: u8 = procedure.get(cur + 2).copied()?;
            let byte: i8 = raw.cast_signed();
            Some((i64::from(byte), 3))
        }
        2u8 => {
            let low: u8 = procedure.get(cur + 2).copied()?;
            let high: u8 = procedure.get(cur + 3).copied()?;
            let val: i16 = i16::from_le_bytes([low, high]);
            Some((i64::from(val), 4))
        }
        _ => {
            let b0: u8 = procedure.get(cur + 2).copied()?;
            let b1: u8 = procedure.get(cur + 3).copied()?;
            let b2: u8 = procedure.get(cur + 4).copied()?;
            let b3: u8 = procedure.get(cur + 5).copied()?;
            let val: i32 = i32::from_le_bytes([b0, b1, b2, b3]);
            Some((i64::from(val), 6))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn microvm_no_procedure_returns_zero_mask() {
        let mut out: [u8; 12] = [0xffu8; 12];
        run_xor_microvm(&[0u8; 16], &mut out);
        assert_eq!(out, [0xffu8; 12]);
    }

    #[test]
    fn microvm_op7_set_and_op9_store_first4() {
        let mut procedure: Vec<u8> = vec![0u8; 16];
        procedure.push(7u8);
        procedure.push(0x08u8);
        procedure.push(0xefu8);
        procedure.push(0xbeu8);
        procedure.push(0xadu8);
        procedure.push(0xdeu8);
        procedure.push(9u8);
        procedure.push(0u8);
        procedure.push(1u8);
        let mut out: [u8; 12] = [0u8; 12];
        run_xor_microvm(&procedure, &mut out);
        assert_eq!(&out[..4], &[0xef, 0xbe, 0xad, 0xde]);
    }

    #[test]
    fn microvm_op7_op2_op6_chain_and_opb_store_at_offset_4() {
        let mut procedure: Vec<u8> = vec![0u8; 16];
        procedure.push(7u8);
        procedure.push(0x18u8);
        procedure.push(0x10u8);
        procedure.push(0u8);
        procedure.push(0u8);
        procedure.push(0u8);
        procedure.push(2u8);
        procedure.push(0x18u8);
        procedure.push(0x05u8);
        procedure.push(0u8);
        procedure.push(0u8);
        procedure.push(0u8);
        procedure.push(6u8);
        procedure.push(0x18u8);
        procedure.push(0x0fu8);
        procedure.push(0u8);
        procedure.push(0u8);
        procedure.push(0u8);
        procedure.push(0xbu8);
        procedure.push(0x01u8);
        procedure.push(4u8);
        procedure.push(1u8);
        let mut out: [u8; 12] = [0u8; 12];
        run_xor_microvm(&procedure, &mut out);
        let expected_value: i32 = (0x10i32 + 0x05i32) ^ 0x0fi32;
        assert_eq!(&out[4..8], &expected_value.to_le_bytes());
    }

    #[test]
    fn hex_short_lowercase() {
        let s: String = hex_short(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s, "deadbeef");
    }
}
