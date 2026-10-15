use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::disasm::{JumpDests, push_value};
use crate::opcode::{self, JUMP, JUMPDEST, JUMPI};
use crate::u256::U256;

const STACK_LIMIT: usize = 1024;
const CONTEXT_VALUE_LIMIT: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgLimits {
    pub blocks: usize,
    pub contexts_per_block: usize,
    pub steps: usize,
}

impl Default for CfgLimits {
    fn default() -> Self {
        Self {
            blocks: 1 << 16,
            contexts_per_block: 32,
            steps: 4_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockEnd {
    Jump,
    JumpI,
    FallThrough,
    Stop,
    Return,
    Revert,
    Invalid,
    SelfDestruct,
    Undefined,
    CodeEnd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    pub last_pc: usize,
    pub instructions: usize,
    pub jumpdest: bool,
    pub exit: BlockEnd,
    pub stack_needed: u32,
    pub stack_delta: i32,
    pub reachable: bool,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub entry_heights: BTreeSet<u32>,
    pub successors: BTreeSet<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unresolved_jump: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cfg {
    pub blocks: Vec<Block>,
    pub jumpdests: usize,
    pub edges: usize,
    pub reachable_blocks: usize,
    pub unresolved_jumps: BTreeSet<usize>,
    pub invalid_jump_targets: BTreeMap<usize, String>,
    pub stack_underflows: BTreeSet<usize>,
    pub stack_overflows: BTreeSet<usize>,
    pub max_stack_height: u32,
    pub complete: bool,
}

impl Cfg {
    #[must_use]
    pub fn block_index(&self, pc: usize) -> Option<usize> {
        self.blocks
            .binary_search_by(|block: &Block| {
                if pc < block.start {
                    std::cmp::Ordering::Greater
                } else if pc >= block.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
    }
}

const fn exit_kind(byte: u8) -> BlockEnd {
    match byte {
        0x00 => BlockEnd::Stop,
        JUMP => BlockEnd::Jump,
        JUMPI => BlockEnd::JumpI,
        0xf3 => BlockEnd::Return,
        0xfd => BlockEnd::Revert,
        0xfe => BlockEnd::Invalid,
        0xff => BlockEnd::SelfDestruct,
        _ if opcode::info(byte).is_none() => BlockEnd::Undefined,
        _ => BlockEnd::FallThrough,
    }
}

fn split_blocks(code: &[u8], code_end: usize, limit: usize) -> (Vec<Block>, bool) {
    let mut blocks: Vec<Block> = Vec::new();
    let mut pc: usize = 0;
    let mut start: usize = 0;
    let mut count: usize = 0;
    let mut height: i32 = 0;
    let mut needed: i32 = 0;
    let mut last_pc: usize = 0;
    while pc < code_end {
        let byte: u8 = code[pc];
        if byte == JUMPDEST && pc != start {
            blocks.push(Block {
                start,
                end: pc,
                last_pc,
                instructions: count,
                jumpdest: code[start] == JUMPDEST,
                exit: BlockEnd::FallThrough,
                stack_needed: needed as u32,
                stack_delta: height,
                reachable: false,
                entry_heights: BTreeSet::new(),
                successors: BTreeSet::new(),
                unresolved_jump: false,
            });
            if blocks.len() >= limit {
                return (blocks, false);
            }
            start = pc;
            count = 0;
            height = 0;
            needed = 0;
        }
        let (inputs, outputs): (i32, i32) =
            opcode::info(byte).map_or((0, 0), |op| (i32::from(op.inputs), i32::from(op.outputs)));
        needed = needed.max(inputs - height);
        height += outputs - inputs;
        count += 1;
        last_pc = pc;
        let next: usize = pc + 1 + opcode::immediate_len(byte);
        if opcode::ends_block(byte) || next >= code_end {
            let exit: BlockEnd = if opcode::ends_block(byte) {
                exit_kind(byte)
            } else {
                BlockEnd::CodeEnd
            };
            blocks.push(Block {
                start,
                end: next.min(code.len()),
                last_pc: pc,
                instructions: count,
                jumpdest: code[start] == JUMPDEST,
                exit,
                stack_needed: needed as u32,
                stack_delta: height,
                reachable: false,
                entry_heights: BTreeSet::new(),
                successors: BTreeSet::new(),
                unresolved_jump: false,
            });
            if blocks.len() >= limit {
                return (blocks, next >= code_end);
            }
            start = next;
            count = 0;
            height = 0;
            needed = 0;
        }
        pc = next;
    }
    (blocks, true)
}

type Abstract = Option<U256>;

fn fold(byte: u8, args: &[Abstract]) -> Abstract {
    let a: U256 = args.first().copied().flatten()?;
    let b: Option<U256> = args.get(1).copied().flatten();
    let both = |f: fn(U256, U256) -> U256| b.map(|b: U256| f(a, b));
    match byte {
        0x01 => both(U256::wrapping_add),
        0x02 => both(U256::wrapping_mul),
        0x03 => both(U256::wrapping_sub),
        0x04 => both(|a, b| a.div_rem(b).0),
        0x06 => both(|a, b| a.div_rem(b).1),
        0x0a => both(U256::wrapping_pow),
        0x10 => both(|a, b| U256::from_bool(a < b)),
        0x11 => both(|a, b| U256::from_bool(a > b)),
        0x14 => both(|a, b| U256::from_bool(a == b)),
        0x15 => Some(U256::from_bool(a.is_zero())),
        0x16 => both(|a, b| a & b),
        0x17 => both(|a, b| a | b),
        0x18 => both(|a, b| a ^ b),
        0x19 => Some(!a),
        0x1b => both(|a, b| b.shift_left(a.shift_amount())),
        0x1c => both(|a, b| b.shift_right(a.shift_amount())),
        _ => None,
    }
}

fn context_key(stack: &[Abstract]) -> Vec<Abstract> {
    stack
        .iter()
        .map(|value: &Abstract| {
            value.filter(|v: &U256| {
                v.to_u64()
                    .is_some_and(|small: u64| small < CONTEXT_VALUE_LIMIT)
            })
        })
        .collect()
}

struct Builder<'a> {
    code: &'a [u8],
    dests: &'a JumpDests,
    observed: &'a BTreeMap<usize, BTreeSet<usize>>,
    cfg: Cfg,
    seen: Vec<BTreeSet<Vec<Abstract>>>,
    steps: usize,
    limits: CfgLimits,
}

impl Builder<'_> {
    fn run(&mut self) {
        let mut work: Vec<(usize, Vec<Abstract>)> = vec![(0, Vec::new())];
        while let Some((index, stack)) = work.pop() {
            let key: Vec<Abstract> = context_key(&stack);
            if self.seen[index].contains(&key) {
                continue;
            }
            if self.seen[index].len() >= self.limits.contexts_per_block {
                self.cfg.complete = false;
                continue;
            }
            self.seen[index].insert(key.clone());
            let block: &mut Block = &mut self.cfg.blocks[index];
            block.reachable = true;
            block.entry_heights.insert(stack.len() as u32);
            let (start, end, exit) = (block.start, block.end, block.exit);
            let mut stack: Vec<Abstract> = key;
            let mut pc: usize = start;
            let mut halted: bool = false;
            while pc < end {
                self.steps += 1;
                if self.steps > self.limits.steps {
                    self.cfg.complete = false;
                    return;
                }
                let byte: u8 = self.code[pc];
                let Some(info) = opcode::info(byte) else {
                    halted = true;
                    break;
                };
                let inputs: usize = usize::from(info.inputs);
                if stack.len() < inputs {
                    self.cfg.stack_underflows.insert(pc);
                    halted = true;
                    break;
                }
                match byte {
                    0x5f..=0x7f => stack.push(Some(if byte == 0x5f {
                        U256::ZERO
                    } else {
                        push_value(self.code, pc).0
                    })),
                    0x80..=0x8f => {
                        let value: Abstract = stack[stack.len() - inputs];
                        stack.push(value);
                    }
                    0x90..=0x9f => {
                        let top: usize = stack.len() - 1;
                        stack.swap(top, top + 1 - inputs);
                    }
                    0x58 => stack.push(Some(U256::from_u64(pc as u64))),
                    JUMP | JUMPI => {
                        let target: Abstract = stack.pop().flatten();
                        let condition: Abstract = if byte == JUMPI {
                            stack.pop().flatten()
                        } else {
                            Some(U256::ONE)
                        };
                        let taken: bool = condition.is_none_or(|c: U256| !c.is_zero());
                        let falls: bool =
                            byte == JUMPI && condition.is_none_or(|c: U256| c.is_zero());
                        if taken {
                            self.follow_jump(index, pc, target, &stack, &mut work);
                        }
                        if falls {
                            self.follow_fallthrough(index, end, &stack, &mut work);
                        }
                        halted = true;
                        break;
                    }
                    _ => {
                        let base: usize = stack.len() - inputs;
                        let args: Vec<Abstract> = stack[base..].iter().rev().copied().collect();
                        stack.truncate(base);
                        if info.outputs == 1 {
                            stack.push(fold(byte, &args));
                        }
                    }
                }
                if stack.len() > STACK_LIMIT {
                    self.cfg.stack_overflows.insert(pc);
                    halted = true;
                    break;
                }
                let height: u32 = stack.len() as u32;
                self.cfg.max_stack_height = self.cfg.max_stack_height.max(height);
                pc += 1 + opcode::immediate_len(byte);
            }
            if !halted && matches!(exit, BlockEnd::FallThrough) {
                self.follow_fallthrough(index, end, &stack, &mut work);
            }
        }
    }

    fn follow_jump(
        &mut self,
        index: usize,
        pc: usize,
        target: Abstract,
        stack: &[Abstract],
        work: &mut Vec<(usize, Vec<Abstract>)>,
    ) {
        let Some(value) = target else {
            if let Some(targets) = self.observed.get(&pc) {
                for dest in targets {
                    if let Some(next) = self.cfg.block_index(*dest) {
                        self.cfg.blocks[index].successors.insert(*dest);
                        work.push((next, stack.to_vec()));
                    }
                }
            } else {
                self.cfg.blocks[index].unresolved_jump = true;
                self.cfg.unresolved_jumps.insert(pc);
            }
            return;
        };
        if let Some(dest) = self.dests.valid_target(value) {
            if let Some(next) = self.cfg.block_index(dest) {
                self.cfg.blocks[index].successors.insert(dest);
                work.push((next, stack.to_vec()));
            }
        } else {
            self.cfg.invalid_jump_targets.insert(pc, value.to_string());
        }
    }

    fn follow_fallthrough(
        &mut self,
        index: usize,
        end: usize,
        stack: &[Abstract],
        work: &mut Vec<(usize, Vec<Abstract>)>,
    ) {
        if let Some(next) = self.cfg.block_index(end) {
            self.cfg.blocks[index].successors.insert(end);
            work.push((next, stack.to_vec()));
        }
    }
}

#[must_use]
pub fn build(
    code: &[u8],
    code_end: usize,
    dests: &JumpDests,
    limits: CfgLimits,
    observed: &BTreeMap<usize, BTreeSet<usize>>,
) -> Cfg {
    let (blocks, split_complete) = split_blocks(code, code_end.min(code.len()), limits.blocks);
    let count: usize = blocks.len();
    let mut builder: Builder<'_> = Builder {
        code,
        dests,
        observed,
        cfg: Cfg {
            blocks,
            jumpdests: dests.count(),
            edges: 0,
            reachable_blocks: 0,
            unresolved_jumps: BTreeSet::new(),
            invalid_jump_targets: BTreeMap::new(),
            stack_underflows: BTreeSet::new(),
            stack_overflows: BTreeSet::new(),
            max_stack_height: 0,
            complete: split_complete,
        },
        seen: vec![BTreeSet::new(); count],
        steps: 0,
        limits,
    };
    if count > 0 {
        builder.run();
    }
    let mut cfg: Cfg = builder.cfg;
    cfg.edges = cfg
        .blocks
        .iter()
        .map(|block: &Block| block.successors.len())
        .sum();
    cfg.reachable_blocks = cfg
        .blocks
        .iter()
        .filter(|block: &&Block| block.reachable)
        .count();
    cfg
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{BlockEnd, CfgLimits, build};
    use crate::disasm::JumpDests;

    #[test]
    fn return_addresses_resolve_through_an_internal_call() {
        let code: [u8; 14] = [
            0x60, 0x08, 0x60, 0x0b, 0x56, 0x00, 0x00, 0x00, 0x5b, 0x00, 0xfe, 0x5b, 0x56, 0xfe,
        ];
        let dests: JumpDests = JumpDests::analyse(&code);
        let cfg = build(
            &code,
            code.len(),
            &dests,
            CfgLimits::default(),
            &BTreeMap::new(),
        );
        let callee = cfg.block_index(11).map(|index| &cfg.blocks[index]);
        assert_eq!(
            callee.map(|block| block.successors.contains(&8)),
            Some(true)
        );
        assert!(cfg.unresolved_jumps.is_empty());
        let caller = cfg.block_index(0).map(|index| &cfg.blocks[index]);
        assert_eq!(caller.map(|block| block.exit), Some(BlockEnd::Jump));
        let returned = cfg.block_index(8).map(|index| cfg.blocks[index].reachable);
        assert_eq!(returned, Some(true));
        let dead = cfg.block_index(5).map(|index| cfg.blocks[index].reachable);
        assert_eq!(dead, Some(false));
    }

    #[test]
    fn a_jump_into_push_data_is_invalid() {
        let code: [u8; 5] = [0x60, 0x01, 0x56, 0x5b, 0x00];
        let dests: JumpDests = JumpDests::analyse(&code);
        let cfg = build(
            &code,
            code.len(),
            &dests,
            CfgLimits::default(),
            &BTreeMap::new(),
        );
        assert!(cfg.invalid_jump_targets.contains_key(&2));
    }
}
