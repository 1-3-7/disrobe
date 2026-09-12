use std::fmt::Arguments;

use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

use crate::debug::{dbg_kv, dbg_section};

const ARM64_INSN_LEN: usize = 4;

const ARM64_RET_ENCODING: u32 = 0xd65f_03c0;

const MAX_FUNCTION_INSNS: usize = 1 << 16;

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arm64FlowKind {
    Sequential,
    DirectCall,
    IndirectCall,
    DirectBranch,
    ConditionalBranch,
    IndirectBranch,
    Return,
    DecodeError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64Instruction {
    pub address: u64,
    pub bytes: u32,
    pub text: String,
    pub flow: Arm64FlowKind,
    pub branch_target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64Function {
    pub entry_offset: usize,
    pub name: Option<String>,
    pub instructions: Vec<Arm64Instruction>,
    pub call_targets: Vec<u64>,
    pub branch_targets: Vec<u64>,
    pub ends_in_return: bool,
    pub decoded_instruction_count: usize,
}

#[must_use]
fn classify(insn: &Instruction, address: u64) -> (Arm64FlowKind, Option<u64>) {
    let pc_target = || -> Option<u64> {
        for operand in &insn.operands {
            if let Operand::PCOffset(offset) = operand {
                return Some(address.wrapping_add_signed(*offset));
            }
        }
        None
    };
    match insn.opcode {
        Opcode::BL => (Arm64FlowKind::DirectCall, pc_target()),
        Opcode::BLR => (Arm64FlowKind::IndirectCall, None),
        Opcode::B => (Arm64FlowKind::DirectBranch, pc_target()),
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            (Arm64FlowKind::ConditionalBranch, pc_target())
        }
        Opcode::BR => (Arm64FlowKind::IndirectBranch, None),
        Opcode::RET => (Arm64FlowKind::Return, None),
        _ => (Arm64FlowKind::Sequential, None),
    }
}

#[must_use]
pub fn disassemble_function(
    instructions: &[u8],
    base: u64,
    entry_offset: usize,
    limit_offset: usize,
    name: Option<String>,
) -> Arm64Function {
    let decoder: InstDecoder = InstDecoder::default();
    let mut decoded: Vec<Arm64Instruction> = Vec::new();
    let mut call_targets: Vec<u64> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();
    let mut ends_in_return: bool = false;

    let hard_end: usize = limit_offset.min(instructions.len());
    let mut offset: usize = entry_offset;
    while offset + ARM64_INSN_LEN <= hard_end && decoded.len() < MAX_FUNCTION_INSNS {
        let window: &[u8] = &instructions[offset..offset + ARM64_INSN_LEN];
        let raw: u32 = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
        let address: u64 = base + offset as u64;
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        match decoder.decode(&mut reader) {
            Ok(insn) => {
                let (flow, target): (Arm64FlowKind, Option<u64>) = classify(&insn, address);
                match flow {
                    Arm64FlowKind::DirectCall => {
                        if let Some(t) = target {
                            call_targets.push(t);
                        }
                    }
                    Arm64FlowKind::DirectBranch | Arm64FlowKind::ConditionalBranch => {
                        if let Some(t) = target {
                            branch_targets.push(t);
                        }
                    }
                    _ => {}
                }
                let is_return: bool = matches!(flow, Arm64FlowKind::Return);
                decoded.push(Arm64Instruction {
                    address,
                    bytes: raw,
                    text: format!("{insn}"),
                    flow,
                    branch_target: target,
                });
                offset += ARM64_INSN_LEN;
                if is_return {
                    ends_in_return = true;
                    break;
                }
            }
            Err(_) => {
                decoded.push(Arm64Instruction {
                    address,
                    bytes: raw,
                    text: "(bad)".to_owned(),
                    flow: Arm64FlowKind::DecodeError,
                    branch_target: None,
                });
                offset += ARM64_INSN_LEN;
                if raw == ARM64_RET_ENCODING {
                    ends_in_return = true;
                    break;
                }
            }
        }
    }

    call_targets.sort_unstable();
    call_targets.dedup();
    branch_targets.sort_unstable();
    branch_targets.dedup();
    let decoded_instruction_count: usize = decoded
        .iter()
        .filter(|i: &&Arm64Instruction| i.flow != Arm64FlowKind::DecodeError)
        .count();

    Arm64Function {
        entry_offset,
        name,
        instructions: decoded,
        call_targets,
        branch_targets,
        ends_in_return,
        decoded_instruction_count,
    }
}

#[must_use]
pub fn disassemble_range(
    instructions: &[u8],
    base: u64,
    entry_offset: usize,
    limit_offset: usize,
    name: Option<String>,
) -> Arm64Function {
    let decoder: InstDecoder = InstDecoder::default();
    let mut decoded: Vec<Arm64Instruction> = Vec::new();
    let mut call_targets: Vec<u64> = Vec::new();
    let mut branch_targets: Vec<u64> = Vec::new();
    let mut ends_in_return: bool = false;

    let hard_end: usize = limit_offset.min(instructions.len());
    let mut offset: usize = entry_offset;
    while offset + ARM64_INSN_LEN <= hard_end && decoded.len() < MAX_FUNCTION_INSNS {
        let window: &[u8] = &instructions[offset..offset + ARM64_INSN_LEN];
        let raw: u32 = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
        let address: u64 = base + offset as u64;
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        match decoder.decode(&mut reader) {
            Ok(insn) => {
                let (flow, target): (Arm64FlowKind, Option<u64>) = classify(&insn, address);
                match flow {
                    Arm64FlowKind::DirectCall => {
                        if let Some(t) = target {
                            call_targets.push(t);
                        }
                    }
                    Arm64FlowKind::DirectBranch | Arm64FlowKind::ConditionalBranch => {
                        if let Some(t) = target {
                            branch_targets.push(t);
                        }
                    }
                    Arm64FlowKind::Return => ends_in_return = true,
                    _ => {}
                }
                decoded.push(Arm64Instruction {
                    address,
                    bytes: raw,
                    text: format!("{insn}"),
                    flow,
                    branch_target: target,
                });
            }
            Err(_) => {
                decoded.push(Arm64Instruction {
                    address,
                    bytes: raw,
                    text: "(bad)".to_owned(),
                    flow: Arm64FlowKind::DecodeError,
                    branch_target: None,
                });
                if raw == ARM64_RET_ENCODING {
                    ends_in_return = true;
                }
            }
        }
        offset += ARM64_INSN_LEN;
    }

    call_targets.sort_unstable();
    call_targets.dedup();
    branch_targets.sort_unstable();
    branch_targets.dedup();
    let decoded_instruction_count: usize = decoded
        .iter()
        .filter(|i: &&Arm64Instruction| i.flow != Arm64FlowKind::DecodeError)
        .count();

    Arm64Function {
        entry_offset,
        name,
        instructions: decoded,
        call_targets,
        branch_targets,
        ends_in_return,
        decoded_instruction_count,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Arm64Disassembly {
    pub function_count: usize,
    pub functions: Vec<Arm64Function>,
    pub total_instructions: usize,
}

#[must_use]
pub fn disassemble_functions(
    instructions: &[u8],
    base: u64,
    entry_offsets: &[usize],
    names: &[Option<String>],
) -> Arm64Disassembly {
    dbg_section("dart.arm64-disasm");
    dbg_kv("entry_offsets", || entry_offsets.len().to_string());
    let mut entries: Vec<(usize, Option<String>)> = entry_offsets
        .iter()
        .enumerate()
        .map(|(idx, entry): (usize, &usize)| (*entry, names.get(idx).cloned().flatten()))
        .collect();
    entries.sort_unstable_by_key(|(entry, _): &(usize, Option<String>)| *entry);
    entries.dedup_by(|a: &mut (usize, Option<String>), b: &mut (usize, Option<String>)| a.0 == b.0);
    dbg_kv("functions_to_decode", || entries.len().to_string());

    let mut functions: Vec<Arm64Function> = Vec::with_capacity(entries.len());
    for (idx, (entry, name)) in entries.iter().enumerate() {
        let limit: usize = entries
            .get(idx + 1)
            .map_or(instructions.len(), |(next, _): &(usize, Option<String>)| {
                *next
            });
        functions.push(disassemble_function(
            instructions,
            base,
            *entry,
            limit,
            name.clone(),
        ));
    }
    let total_instructions: usize = functions
        .iter()
        .map(|f: &Arm64Function| f.decoded_instruction_count)
        .sum::<usize>();
    Arm64Disassembly {
        function_count: functions.len(),
        functions,
        total_instructions,
    }
}

impl Arm64Function {
    #[must_use]
    pub fn to_listing(&self) -> String {
        let mut out: String = String::new();
        match &self.name {
            Some(n) => {
                push_line!(out, "{n}:");
            }
            None => {
                push_line!(out, "sub_{:#010x}:", self.entry_offset);
            }
        }
        for insn in &self.instructions {
            let target: String = match insn.branch_target {
                Some(t) => format!("  -> {t:#x}"),
                None => String::new(),
            };
            push_line!(
                out,
                "  {:#010x}:  {:08x}  {}{}",
                insn.address,
                insn.bytes,
                insn.text,
                target
            );
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn words(ws: &[u32]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(ws.len() * 4);
        for w in ws {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    fn bl(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        0x9400_0000 | ((imm as u32) & 0x03ff_ffff)
    }

    #[test]
    fn disassembles_real_prologue_to_text() {
        let bytes: Vec<u8> = words(&[0xa9bf_7bfd, 0x9100_03fd, 0xd65f_03c0]);
        let func: Arm64Function = disassemble_function(&bytes, 0x1000, 0, bytes.len(), None);
        assert_eq!(func.instructions.len(), 3);
        assert!(func.ends_in_return, "must stop at ret");
        assert_eq!(func.instructions[0].address, 0x1000);
        assert!(
            func.instructions[0].text.contains("stp"),
            "push fp/lr decodes to stp, got {}",
            func.instructions[0].text
        );
        assert_eq!(func.instructions[2].flow, Arm64FlowKind::Return);
    }

    #[test]
    fn resolves_direct_call_target() {
        let bytes: Vec<u8> = words(&[bl(0x2000, 0x2040), 0xd65f_03c0]);
        let func: Arm64Function = disassemble_function(&bytes, 0x2000, 0, bytes.len(), None);
        assert_eq!(func.instructions[0].flow, Arm64FlowKind::DirectCall);
        assert_eq!(func.instructions[0].branch_target, Some(0x2040));
        assert!(func.call_targets.contains(&0x2040));
    }

    #[test]
    fn listing_renders_addresses_and_mnemonics() {
        let bytes: Vec<u8> = words(&[0xd503_201f, 0xd65f_03c0]);
        let func: Arm64Function = disassemble_function(
            &bytes,
            0x3000,
            0,
            bytes.len(),
            Some("MyClass.build".to_owned()),
        );
        let listing: String = func.to_listing();
        assert!(listing.starts_with("MyClass.build:\n"));
        assert!(listing.contains("0x00003000"));
        assert!(listing.contains("nop"));
    }

    #[test]
    fn stops_at_next_function_boundary() {
        let bytes: Vec<u8> = words(&[0xd503_201f, 0xd503_201f, 0xd503_201f, 0xd503_201f]);
        let func: Arm64Function = disassemble_function(&bytes, 0, 0, 8, None);
        assert_eq!(
            func.instructions.len(),
            2,
            "limit_offset of 8 means only the first two instructions belong to this function"
        );
    }

    #[test]
    fn multi_function_split_uses_boundaries_as_limits() {
        let bytes: Vec<u8> = words(&[0xd503_201f, 0xd65f_03c0, 0xd503_201f, 0xd65f_03c0]);
        let disasm: Arm64Disassembly = disassemble_functions(&bytes, 0, &[0, 8], &[None, None]);
        assert_eq!(disasm.function_count, 2);
        assert!(disasm.functions[0].ends_in_return);
        assert!(disasm.functions[1].ends_in_return);
        assert_eq!(disasm.total_instructions, 4);
    }

    #[test]
    fn empty_input_yields_empty_function() {
        let func: Arm64Function = disassemble_function(&[], 0, 0, 0, None);
        assert!(func.instructions.is_empty());
        assert!(!func.ends_in_return);
    }
}
