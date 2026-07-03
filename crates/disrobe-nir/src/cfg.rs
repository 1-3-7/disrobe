use disrobe_core::{Cfg, cyclomatic_complexity};
use serde::Serialize;

use crate::types::{NirClass, NirFunction, NirInstr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockKind {
    FallThrough,
    Conditional,
    Jump,
    Return,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NirBlock {
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<NirInstr>,
    pub successors: Vec<u64>,
    pub kind: BlockKind,
}

fn effective_end(function: &NirFunction) -> u64 {
    let last_address: u64 = function
        .instructions
        .last()
        .map_or(function.end, |i: &NirInstr| i.address);
    function.end.max(last_address.saturating_add(1))
}

#[must_use]
pub fn basic_blocks(function: &NirFunction) -> Vec<NirBlock> {
    if function.instructions.is_empty() {
        return Vec::new();
    }
    let end: u64 = effective_end(function);
    let leaders: Vec<u64> = block_leaders(function);
    let mut blocks: Vec<NirBlock> = Vec::with_capacity(leaders.len());
    for (idx, leader) in leaders.iter().enumerate() {
        let next_leader: Option<u64> = leaders.get(idx + 1).copied();
        let block_end: u64 = next_leader.unwrap_or(end);
        let mut insns: Vec<NirInstr> = function
            .instructions
            .iter()
            .filter(|i: &&NirInstr| address_in_block(i.address, *leader, next_leader, end))
            .cloned()
            .collect();
        insns.sort_by_key(|i: &NirInstr| i.address);
        let Some(last): Option<&NirInstr> = insns.last() else {
            continue;
        };
        let fallthrough: Option<u64> = next_leader;
        let (kind, successors): (BlockKind, Vec<u64>) =
            terminator_edges(last, fallthrough, &leaders);
        blocks.push(NirBlock {
            start: *leader,
            end: block_end,
            instructions: insns,
            successors,
            kind,
        });
    }
    blocks
}

fn block_leaders(function: &NirFunction) -> Vec<u64> {
    let end: u64 = effective_end(function);
    let in_function =
        |address: u64| address >= function.address && address_is_before_end(address, end);
    let mut starts: Vec<u64> = Vec::new();
    if let Some(first) = function.instructions.first() {
        starts.push(first.address);
    }
    for (idx, insn) in function.instructions.iter().enumerate() {
        match insn.class() {
            NirClass::ConditionalJump | NirClass::UnconditionalJump => {
                if let Some(target) = insn.direct_target()
                    && in_function(target)
                {
                    starts.push(target);
                }
                if let Some(next) = function.instructions.get(idx + 1) {
                    starts.push(next.address);
                }
            }
            NirClass::Return => {
                if let Some(next) = function.instructions.get(idx + 1) {
                    starts.push(next.address);
                }
            }
            NirClass::Call | NirClass::Other => {}
        }
    }
    starts.retain(|s: &u64| in_function(*s));
    starts.sort_unstable();
    starts.dedup();
    starts
}

const fn address_in_block(address: u64, leader: u64, next_leader: Option<u64>, end: u64) -> bool {
    if address < leader {
        return false;
    }
    match next_leader {
        Some(next) => address < next,
        None => address_is_before_end(address, end),
    }
}

const fn address_is_before_end(address: u64, end: u64) -> bool {
    address < end || (end == u64::MAX && address == u64::MAX)
}

fn terminator_edges(
    last: &NirInstr,
    fallthrough: Option<u64>,
    leaders: &[u64],
) -> (BlockKind, Vec<u64>) {
    let in_function = |addr: u64| leaders.binary_search(&addr).is_ok();
    match last.class() {
        NirClass::ConditionalJump => {
            let mut succ: Vec<u64> = Vec::new();
            if let Some(target) = last.direct_target().filter(|t: &u64| in_function(*t)) {
                succ.push(target);
            }
            if let Some(next) = fallthrough.filter(|n: &u64| in_function(*n)) {
                succ.push(next);
            }
            succ.sort_unstable();
            succ.dedup();
            (BlockKind::Conditional, succ)
        }
        NirClass::UnconditionalJump => match last.direct_target() {
            Some(target) if in_function(target) => (BlockKind::Jump, vec![target]),
            Some(_) => (BlockKind::Jump, Vec::new()),
            None => (BlockKind::Indirect, Vec::new()),
        },
        NirClass::Return => (BlockKind::Return, Vec::new()),
        NirClass::Call | NirClass::Other => {
            let succ: Vec<u64> = fallthrough
                .filter(|n: &u64| in_function(*n))
                .map(|next: u64| vec![next])
                .unwrap_or_default();
            (BlockKind::FallThrough, succ)
        }
    }
}

#[must_use]
pub fn control_flow_graph(function: &NirFunction) -> Cfg {
    let blocks: Vec<NirBlock> = basic_blocks(function);
    let starts: Vec<u64> = blocks.iter().map(|b: &NirBlock| b.start).collect();
    let nodes: u32 = u32::try_from(blocks.len().max(1)).unwrap_or(u32::MAX);
    let mut edges: u32 = 0;
    for block in &blocks {
        for succ in &block.successors {
            if starts.binary_search(succ).is_ok() {
                edges = edges.saturating_add(1);
            }
        }
    }
    Cfg::from_counts(nodes, edges)
}

#[must_use]
pub fn complexity(function: &NirFunction) -> u32 {
    cyclomatic_complexity(&control_flow_graph(function))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NirOp, SourceLang, SourceRef};

    fn instr(address: u64, op: NirOp) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: Vec::new(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn branchy() -> NirFunction {
        NirFunction {
            name: "branchy".to_owned(),
            address: 0x0,
            end: 0x7,
            is_export: false,
            instructions: vec![
                instr(0x0, NirOp::Nop),
                instr(0x2, NirOp::CondBranch { target: Some(0x6) }),
                instr(0x4, NirOp::Nop),
                instr(0x6, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        }
    }

    #[test]
    fn straight_line_is_complexity_one() {
        let f: NirFunction = NirFunction {
            name: "f".to_owned(),
            address: 0x0,
            end: 0x3,
            is_export: false,
            instructions: vec![
                instr(0x0, NirOp::Nop),
                instr(0x1, NirOp::Nop),
                instr(0x2, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        };
        assert_eq!(complexity(&f), 1);
        let blocks: Vec<NirBlock> = basic_blocks(&f);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, BlockKind::Return);
    }

    #[test]
    fn single_branch_is_complexity_two() {
        let f: NirFunction = branchy();
        assert_eq!(complexity(&f), 2);
    }

    #[test]
    fn branchy_blocks_match_hand_verified_edges() {
        let f: NirFunction = branchy();
        let blocks: Vec<NirBlock> = basic_blocks(&f);
        assert_eq!(blocks.len(), 3, "entry, arm, ret: {blocks:?}");
        assert_eq!(blocks[0].start, 0x0);
        assert_eq!(blocks[0].kind, BlockKind::Conditional);
        assert_eq!(blocks[0].successors, vec![0x4, 0x6]);
        assert_eq!(blocks[1].start, 0x4);
        assert_eq!(blocks[1].successors, vec![0x6]);
        assert_eq!(blocks[2].start, 0x6);
        assert_eq!(blocks[2].kind, BlockKind::Return);
        assert!(blocks[2].successors.is_empty());
    }

    #[test]
    fn blocks_reassemble_to_linear_listing() {
        let f: NirFunction = branchy();
        let reassembled: Vec<u64> = basic_blocks(&f)
            .iter()
            .flat_map(|b: &NirBlock| b.instructions.iter().map(|i: &NirInstr| i.address))
            .collect();
        let linear: Vec<u64> = f
            .instructions
            .iter()
            .map(|i: &NirInstr| i.address)
            .collect();
        assert_eq!(reassembled, linear);
    }

    #[test]
    fn too_small_end_does_not_drop_trailing_instructions() {
        let f: NirFunction = NirFunction {
            name: "bad_end".to_owned(),
            address: 0x0,
            end: 0x4,
            is_export: false,
            instructions: vec![
                instr(0x0, NirOp::Nop),
                instr(0x2, NirOp::Nop),
                instr(0x6, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        };
        let addrs: Vec<u64> = basic_blocks(&f)
            .iter()
            .flat_map(|b: &NirBlock| b.instructions.iter().map(|i: &NirInstr| i.address))
            .collect();
        assert_eq!(
            addrs,
            vec![0x0, 0x2, 0x6],
            "a function.end that does not bound the instructions must not drop the tail"
        );
    }

    #[test]
    fn unconditional_jump_before_dead_code_keeps_jump_edge() {
        let f: NirFunction = NirFunction {
            name: "jump_dead".to_owned(),
            address: 0x0,
            end: 0x12,
            is_export: false,
            instructions: vec![
                instr(0x0, NirOp::Branch { target: Some(0x10) }),
                instr(0x2, NirOp::Nop),
                instr(0x10, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        };
        let blocks: Vec<NirBlock> = basic_blocks(&f);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].start, 0x0);
        assert_eq!(blocks[0].kind, BlockKind::Jump);
        assert_eq!(blocks[0].successors, vec![0x10]);
        assert_eq!(blocks[1].start, 0x2);
        assert_eq!(blocks[1].kind, BlockKind::FallThrough);
        assert_eq!(blocks[1].successors, vec![0x10]);
        assert_eq!(blocks[2].kind, BlockKind::Return);
    }

    #[test]
    fn return_before_dead_code_keeps_return_terminator() {
        let f: NirFunction = NirFunction {
            name: "return_dead".to_owned(),
            address: 0x0,
            end: 0x5,
            is_export: false,
            instructions: vec![
                instr(0x0, NirOp::Return),
                instr(0x2, NirOp::Nop),
                instr(0x4, NirOp::Return),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x0),
        };
        let blocks: Vec<NirBlock> = basic_blocks(&f);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].start, 0x0);
        assert_eq!(blocks[0].kind, BlockKind::Return);
        assert!(blocks[0].successors.is_empty());
        assert_eq!(blocks[1].start, 0x2);
        assert_eq!(blocks[1].kind, BlockKind::Return);
    }

    #[test]
    fn inverted_end_still_produces_a_block() {
        let f: NirFunction = NirFunction {
            name: "inverted".to_owned(),
            address: 0x10,
            end: 0x10,
            is_export: false,
            instructions: vec![instr(0x10, NirOp::Nop), instr(0x12, NirOp::Return)],
            source: SourceRef::new(SourceLang::NativeX86, 0x10),
        };
        assert!(
            !basic_blocks(&f).is_empty(),
            "an inverted or empty function.end must still yield a block for a non-empty function"
        );
    }

    #[test]
    fn max_address_instruction_is_not_dropped() {
        let f: NirFunction = NirFunction {
            name: "max_addr".to_owned(),
            address: u64::MAX,
            end: u64::MAX,
            is_export: false,
            instructions: vec![instr(u64::MAX, NirOp::Return)],
            source: SourceRef::new(SourceLang::NativeX86, u64::MAX),
        };
        let blocks: Vec<NirBlock> = basic_blocks(&f);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].instructions.len(), 1);
        assert_eq!(blocks[0].instructions[0].address, u64::MAX);
        assert_eq!(blocks[0].kind, BlockKind::Return);
    }
}
