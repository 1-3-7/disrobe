use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use yaxpeax_arch::Decoder as _;
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand};

const ARM64_INSN_LEN: u64 = 4;

const TRAVERSAL_INSN_BUDGET: usize = 1 << 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Arm64UnresolvedKind {
    IndirectBranch,
    IndirectCall,
    Return,
    DecodeError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64Unresolved {
    pub address: u64,
    pub kind: Arm64UnresolvedKind,
    pub mnemonic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64TraversalReport {
    pub entry_count: usize,
    pub reachable_instruction_count: usize,
    pub direct_call_targets: Vec<u64>,
    pub resolved_branch_targets: Vec<u64>,
    pub unresolved: Vec<Arm64Unresolved>,
    pub linear_decode_count: usize,
}

impl Arm64TraversalReport {
    #[must_use]
    pub fn indirect_target_count(&self) -> usize {
        self.unresolved
            .iter()
            .filter(|u: &&Arm64Unresolved| {
                matches!(
                    u.kind,
                    Arm64UnresolvedKind::IndirectBranch | Arm64UnresolvedKind::IndirectCall
                )
            })
            .count()
    }
}

#[must_use]
pub fn traverse(base: u64, instructions: &[u8], entries: &[u64]) -> Arm64TraversalReport {
    let decoder: InstDecoder = InstDecoder::default();
    let end_addr: u64 = base.saturating_add(instructions.len() as u64);

    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut direct_calls: BTreeSet<u64> = BTreeSet::new();
    let mut resolved_branches: BTreeSet<u64> = BTreeSet::new();
    let mut unresolved: BTreeMap<u64, Arm64Unresolved> = BTreeMap::new();

    let valid_entries: Vec<u64> = entries
        .iter()
        .copied()
        .filter(|addr: &u64| {
            *addr >= base && *addr < end_addr && (addr - base) % ARM64_INSN_LEN == 0
        })
        .collect::<Vec<u64>>();
    let mut queue: VecDeque<u64> = valid_entries.iter().copied().collect::<VecDeque<u64>>();
    let entry_count: usize = valid_entries.len();

    let mut decoded: usize = 0;
    while let Some(address) = queue.pop_front() {
        if decoded >= TRAVERSAL_INSN_BUDGET {
            break;
        }
        if address < base || address >= end_addr {
            continue;
        }
        if (address - base) % ARM64_INSN_LEN != 0 {
            continue;
        }
        if !visited.insert(address) {
            continue;
        }
        let offset: usize = (address - base) as usize;
        let Some(window): Option<&[u8]> =
            instructions.get(offset..offset + ARM64_INSN_LEN as usize)
        else {
            continue;
        };
        decoded += 1;
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        let Ok(insn): Result<Instruction, _> = decoder.decode(&mut reader) else {
            unresolved
                .entry(address)
                .or_insert_with(|| Arm64Unresolved {
                    address,
                    kind: Arm64UnresolvedKind::DecodeError,
                    mnemonic: "(bad)".to_owned(),
                });
            continue;
        };

        let fallthrough: u64 = address.saturating_add(ARM64_INSN_LEN);
        classify_flow(
            &insn,
            address,
            fallthrough,
            base,
            end_addr,
            &mut queue,
            &mut direct_calls,
            &mut resolved_branches,
            &mut unresolved,
        );
    }

    let linear_decode_count: usize = linear_decode(decoder, instructions);

    Arm64TraversalReport {
        entry_count,
        reachable_instruction_count: visited.len(),
        direct_call_targets: direct_calls.into_iter().collect(),
        resolved_branch_targets: resolved_branches.into_iter().collect(),
        unresolved: unresolved.into_values().collect(),
        linear_decode_count,
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_flow(
    insn: &Instruction,
    address: u64,
    fallthrough: u64,
    base: u64,
    end_addr: u64,
    queue: &mut VecDeque<u64>,
    direct_calls: &mut BTreeSet<u64>,
    resolved_branches: &mut BTreeSet<u64>,
    unresolved: &mut BTreeMap<u64, Arm64Unresolved>,
) {
    let in_range = |target: u64| target >= base && target < end_addr;
    match insn.opcode {
        Opcode::BL => {
            if let Some(target) = pc_relative_target(insn, address) {
                direct_calls.insert(target);
                if in_range(target) {
                    queue.push_back(target);
                }
            } else {
                unresolved
                    .entry(address)
                    .or_insert_with(|| Arm64Unresolved {
                        address,
                        kind: Arm64UnresolvedKind::IndirectCall,
                        mnemonic: "bl".to_owned(),
                    });
            }
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        Opcode::B => {
            if let Some(target) = pc_relative_target(insn, address) {
                resolved_branches.insert(target);
                if in_range(target) {
                    queue.push_back(target);
                }
            }
        }
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => {
            if let Some(target) = pc_relative_target(insn, address) {
                resolved_branches.insert(target);
                if in_range(target) {
                    queue.push_back(target);
                }
            }
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        Opcode::BLR => {
            unresolved
                .entry(address)
                .or_insert_with(|| Arm64Unresolved {
                    address,
                    kind: Arm64UnresolvedKind::IndirectCall,
                    mnemonic: "blr".to_owned(),
                });
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
        Opcode::BR => {
            unresolved
                .entry(address)
                .or_insert_with(|| Arm64Unresolved {
                    address,
                    kind: Arm64UnresolvedKind::IndirectBranch,
                    mnemonic: "br".to_owned(),
                });
        }
        Opcode::RET => {
            unresolved
                .entry(address)
                .or_insert_with(|| Arm64Unresolved {
                    address,
                    kind: Arm64UnresolvedKind::Return,
                    mnemonic: "ret".to_owned(),
                });
        }
        _ => {
            if in_range(fallthrough) {
                queue.push_back(fallthrough);
            }
        }
    }
}

#[must_use]
fn pc_relative_target(insn: &Instruction, address: u64) -> Option<u64> {
    for operand in &insn.operands {
        if let Operand::PCOffset(offset) = operand {
            return Some(address.wrapping_add_signed(*offset));
        }
    }
    None
}

#[must_use]
fn linear_decode(decoder: InstDecoder, instructions: &[u8]) -> usize {
    let mut count: usize = 0;
    let mut idx: usize = 0;
    while idx + ARM64_INSN_LEN as usize <= instructions.len() {
        let window: &[u8] = &instructions[idx..idx + ARM64_INSN_LEN as usize];
        let mut reader: yaxpeax_arch::U8Reader<'_> = yaxpeax_arch::U8Reader::new(window);
        if decoder.decode(&mut reader).is_ok() {
            count += 1;
        }
        idx += ARM64_INSN_LEN as usize;
    }
    count
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn bl(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        let imm26: u32 = (imm as u32) & 0x03ff_ffff;
        0x9400_0000 | imm26
    }

    fn b(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        let imm26: u32 = (imm as u32) & 0x03ff_ffff;
        0x1400_0000 | imm26
    }

    fn ret() -> u32 {
        0xd65f_03c0
    }

    fn blr(reg: u32) -> u32 {
        0xd63f_0000 | (reg << 5)
    }

    fn br(reg: u32) -> u32 {
        0xd61f_0000 | (reg << 5)
    }

    fn nop() -> u32 {
        0xd503_201f
    }

    fn assemble(words: &[u32]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(words.len() * 4);
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    #[test]
    fn direct_call_target_is_resolved() {
        let base: u64 = 0x1000;
        let words: Vec<u32> = vec![bl(0x1000, 0x1010), nop(), nop(), nop(), nop()];
        let bytes: Vec<u8> = assemble(&words);
        let report: Arm64TraversalReport = traverse(base, &bytes, &[0x1000]);
        assert!(
            report.direct_call_targets.contains(&0x1010),
            "bl target 0x1010 not resolved: {:?}",
            report.direct_call_targets
        );
    }

    #[test]
    fn ret_is_surfaced_not_followed() {
        let base: u64 = 0x2000;
        let words: Vec<u32> = vec![nop(), ret(), nop()];
        let bytes: Vec<u8> = assemble(&words);
        let report: Arm64TraversalReport = traverse(base, &bytes, &[0x2000]);
        assert!(
            report
                .unresolved
                .iter()
                .any(|u: &Arm64Unresolved| u.kind == Arm64UnresolvedKind::Return),
            "ret must be surfaced: {:?}",
            report.unresolved
        );
        assert_eq!(
            report.reachable_instruction_count, 2,
            "must stop at ret, not decode past it"
        );
    }

    #[test]
    fn indirect_branch_is_flagged_not_guessed() {
        let base: u64 = 0x3000;
        let words: Vec<u32> = vec![br(8), nop()];
        let bytes: Vec<u8> = assemble(&words);
        let report: Arm64TraversalReport = traverse(base, &bytes, &[0x3000]);
        assert!(
            report
                .unresolved
                .iter()
                .any(|u: &Arm64Unresolved| u.kind == Arm64UnresolvedKind::IndirectBranch),
            "br x8 must be an unresolved indirect branch: {:?}",
            report.unresolved
        );
        assert_eq!(report.indirect_target_count(), 1);
    }

    #[test]
    fn indirect_call_flagged_but_fallthrough_followed() {
        let base: u64 = 0x4000;
        let words: Vec<u32> = vec![blr(9), nop(), ret()];
        let bytes: Vec<u8> = assemble(&words);
        let report: Arm64TraversalReport = traverse(base, &bytes, &[0x4000]);
        assert!(
            report
                .unresolved
                .iter()
                .any(|u: &Arm64Unresolved| u.kind == Arm64UnresolvedKind::IndirectCall),
            "blr must be flagged indirect call"
        );
        assert_eq!(
            report.reachable_instruction_count, 3,
            "fallthrough past blr must be decoded"
        );
    }

    #[test]
    fn branch_over_data_skips_uncovered_bytes() {
        let base: u64 = 0x5000;
        let words: Vec<u32> = vec![b(0x5000, 0x5008), 0xdead_beef, ret()];
        let bytes: Vec<u8> = assemble(&words);
        let report: Arm64TraversalReport = traverse(base, &bytes, &[0x5000]);
        assert!(report.resolved_branch_targets.contains(&0x5008));
        assert_eq!(
            report.reachable_instruction_count, 2,
            "the b and the ret are reachable; the data word in the middle is not"
        );
    }

    #[test]
    fn entry_outside_range_yields_no_entries() {
        let base: u64 = 0x6000;
        let bytes: Vec<u8> = assemble(&[nop(), ret()]);
        let report: Arm64TraversalReport = traverse(base, &bytes, &[0x9000]);
        assert_eq!(report.entry_count, 0);
        assert_eq!(report.reachable_instruction_count, 0);
    }

    #[test]
    fn empty_instructions_do_not_panic() {
        let report: Arm64TraversalReport = traverse(0, &[], &[0]);
        assert_eq!(report.reachable_instruction_count, 0);
        assert_eq!(report.linear_decode_count, 0);
    }
}
