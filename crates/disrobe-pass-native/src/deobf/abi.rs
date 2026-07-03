use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register, UsedRegister,
};

const MAX_DECODE_INSNS: usize = 4096;
const MAX_BLOCKS: usize = 256;
const MAX_BLOCK_INSNS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallingConvention {
    SysV64,
    Microsoft64,
    Cdecl,
    Stdcall,
    Fastcall,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArgCount {
    Exact(u32),
    AtLeast(u32),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReturnKind {
    Void,
    Value,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AbiInference {
    pub address: u64,
    pub abi: CallingConvention,
    pub arg_count: ArgCount,
    pub returns_value: ReturnKind,
    pub param_regs: Vec<String>,
}

#[derive(Debug, Clone)]
struct BasicBlock {
    insns: std::ops::Range<usize>,
    successors: Vec<usize>,
    returns: bool,
}

#[derive(Debug, Clone, Default)]
struct LiveSets {
    use_set: BTreeSet<Register>,
    def_set: BTreeSet<Register>,
}

#[must_use]
pub fn infer(bitness: u32, base: u64, code: &[u8], entry: u64) -> Option<AbiInference> {
    let insns: Vec<Instruction> = decode_all(bitness, base, code);
    if insns.is_empty() {
        return None;
    }
    let index: BTreeMap<u64, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
        .collect();
    let start: usize = *index.get(&entry)?;

    let blocks: Vec<BasicBlock> = build_cfg(&insns, &index, start)?;
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();

    let live_in: BTreeSet<Register> = live_in_at_entry(&insns, &blocks, &mut factory);
    let returns_value: ReturnKind = classify_return(&insns, &blocks, &mut factory);

    let integer_live: BTreeSet<Register> = live_in
        .iter()
        .copied()
        .filter(|r: &Register| INTEGER_ARG_FULL.contains(r))
        .collect();
    let fp_args: Vec<Register> = ordered_fp_live_in(&live_in);

    let (abi, param_regs, arg_count): (CallingConvention, Vec<Register>, ArgCount) = match bitness {
        64 => classify_64(&integer_live, &fp_args),
        32 => classify_32(&insns, &blocks, &integer_live),
        _ => (CallingConvention::Unknown, Vec::new(), ArgCount::Unknown),
    };

    Some(AbiInference {
        address: entry,
        abi,
        arg_count,
        returns_value,
        param_regs: param_regs
            .iter()
            .map(|r: &Register| register_label(*r))
            .collect(),
    })
}

fn classify_64(
    integer_live: &BTreeSet<Register>,
    fp_args: &[Register],
) -> (CallingConvention, Vec<Register>, ArgCount) {
    if integer_live.is_empty() && fp_args.is_empty() {
        return (CallingConvention::Unknown, Vec::new(), ArgCount::Exact(0));
    }

    let sysv_prefix: Option<usize> = contiguous_prefix(integer_live, SYSV64_INTEGER);
    let ms_prefix: Option<usize> = contiguous_prefix(integer_live, MS64_INTEGER);

    match (sysv_prefix, ms_prefix) {
        (Some(used), None) => {
            let params: Vec<Register> = abi_param_sequence(SYSV64_INTEGER, used, fp_args);
            let count: u32 = params.len() as u32;
            (CallingConvention::SysV64, params, ArgCount::Exact(count))
        }
        (None, Some(used)) => {
            let params: Vec<Register> = abi_param_sequence(MS64_INTEGER, used, fp_args);
            let count: u32 = params.len() as u32;
            (
                CallingConvention::Microsoft64,
                params,
                ArgCount::Exact(count),
            )
        }
        _ => {
            if integer_live.is_empty() && !fp_args.is_empty() {
                return (
                    CallingConvention::Unknown,
                    fp_args.to_vec(),
                    ArgCount::AtLeast(fp_args.len() as u32),
                );
            }
            (CallingConvention::Unknown, Vec::new(), ArgCount::Unknown)
        }
    }
}

fn contiguous_prefix(live: &BTreeSet<Register>, table: &[Register]) -> Option<usize> {
    if live.is_empty() {
        return None;
    }
    let n: usize = live.len();
    if n > table.len() {
        return None;
    }
    let prefix_matches: bool = table.iter().take(n).all(|r: &Register| live.contains(r));
    let no_overflow: bool = live.iter().all(|r: &Register| {
        table
            .iter()
            .position(|t: &Register| t == r)
            .is_some_and(|pos: usize| pos < n)
    });
    (prefix_matches && no_overflow).then_some(n)
}

fn abi_param_sequence(table: &[Register], used: usize, fp_args: &[Register]) -> Vec<Register> {
    let mut params: Vec<Register> = table.iter().copied().take(used).collect();
    params.extend_from_slice(fp_args);
    params
}

fn classify_32(
    insns: &[Instruction],
    blocks: &[BasicBlock],
    integer_live: &BTreeSet<Register>,
) -> (CallingConvention, Vec<Register>, ArgCount) {
    let callee_cleanup: Option<bool> = callee_cleans_stack(insns, blocks);
    let stack_args: Option<u32> = count_stack_args(insns, blocks);

    let has_ecx: bool = integer_live.contains(&Register::RCX);
    let has_edx: bool = integer_live.contains(&Register::RDX);
    let uses_only_fastcall_regs: bool = !integer_live.is_empty()
        && integer_live
            .iter()
            .all(|r: &Register| matches!(*r, Register::RCX | Register::RDX));
    let has_stack_args: bool = matches!(stack_args, Some(n) if n > 0);
    let cleanup_consistent: bool = !has_stack_args || callee_cleanup == Some(true);

    if has_ecx && uses_only_fastcall_regs && cleanup_consistent {
        let reg_count: u32 = if has_edx { 2 } else { 1 };
        let params: Vec<Register> = FASTCALL_INTEGER32
            .iter()
            .copied()
            .take(reg_count as usize)
            .collect();
        let count: ArgCount = stack_args.map_or(ArgCount::AtLeast(reg_count), |stack: u32| {
            ArgCount::Exact(reg_count + stack)
        });
        return (CallingConvention::Fastcall, params, count);
    }

    if !integer_live.is_empty() {
        return (CallingConvention::Unknown, Vec::new(), ArgCount::Unknown);
    }

    let arg_count: ArgCount = stack_args.map_or(ArgCount::Unknown, ArgCount::Exact);
    match callee_cleanup {
        Some(true) => (CallingConvention::Stdcall, Vec::new(), arg_count),
        Some(false) => (CallingConvention::Cdecl, Vec::new(), arg_count),
        None => (CallingConvention::Unknown, Vec::new(), arg_count),
    }
}

fn callee_cleans_stack(insns: &[Instruction], blocks: &[BasicBlock]) -> Option<bool> {
    let mut saw_ret: bool = false;
    let mut imm_ret: bool = false;
    let mut bare_ret: bool = false;
    for block in blocks {
        if !block.returns {
            continue;
        }
        for insn in &insns[block.insns.clone()] {
            if insn.flow_control() != FlowControl::Return {
                continue;
            }
            if !matches!(insn.mnemonic(), Mnemonic::Ret | Mnemonic::Retf) {
                return None;
            }
            saw_ret = true;
            if insn.op_count() == 1 && matches!(insn.op0_kind(), OpKind::Immediate16) {
                imm_ret = true;
            } else {
                bare_ret = true;
            }
        }
    }
    if !saw_ret || (imm_ret && bare_ret) {
        return None;
    }
    Some(imm_ret)
}

fn count_stack_args(insns: &[Instruction], blocks: &[BasicBlock]) -> Option<u32> {
    let frame_base: Option<Register> = detect_frame_base(insns, blocks);
    let Some(base): Option<Register> = frame_base else {
        return Some(0);
    };
    let baseline: i64 = if base == Register::EBP { 8 } else { 4 };
    let mut max_disp: Option<i64> = None;
    for block in blocks {
        for insn in &insns[block.insns.clone()] {
            for op in 0..insn.op_count() {
                if insn.op_kind(op) != OpKind::Memory {
                    continue;
                }
                if insn.memory_base() != base || insn.memory_index() != Register::None {
                    continue;
                }
                let disp: i64 = insn.memory_displacement64().cast_signed();
                if disp >= baseline {
                    max_disp = Some(max_disp.map_or(disp, |m: i64| m.max(disp)));
                }
            }
        }
    }
    let top: i64 = max_disp?;
    if top < baseline {
        return Some(0);
    }
    let span: i64 = top - baseline;
    if span % 4 != 0 {
        return None;
    }
    u32::try_from((span / 4) + 1).ok()
}

fn detect_frame_base(insns: &[Instruction], blocks: &[BasicBlock]) -> Option<Register> {
    for block in blocks {
        for insn in &insns[block.insns.clone()] {
            if insn.mnemonic() == Mnemonic::Mov
                && insn.op0_kind() == OpKind::Register
                && insn.op0_register() == Register::EBP
                && insn.op1_kind() == OpKind::Register
                && insn.op1_register() == Register::ESP
            {
                return Some(Register::EBP);
            }
        }
    }
    let reads_ebp: bool = blocks.iter().any(|block: &BasicBlock| {
        insns[block.insns.clone()].iter().any(|insn: &Instruction| {
            (0..insn.op_count()).any(|op: u32| {
                insn.op_kind(op) == OpKind::Memory && insn.memory_base() == Register::EBP
            })
        })
    });
    if reads_ebp {
        return Some(Register::EBP);
    }
    let reads_esp: bool = blocks.iter().any(|block: &BasicBlock| {
        insns[block.insns.clone()].iter().any(|insn: &Instruction| {
            (0..insn.op_count()).any(|op: u32| {
                insn.op_kind(op) == OpKind::Memory && insn.memory_base() == Register::ESP
            })
        })
    });
    reads_esp.then_some(Register::ESP)
}

fn live_in_at_entry(
    insns: &[Instruction],
    blocks: &[BasicBlock],
    factory: &mut InstructionInfoFactory,
) -> BTreeSet<Register> {
    let count: usize = blocks.len();
    let local: Vec<LiveSets> = blocks
        .iter()
        .map(|block: &BasicBlock| block_use_def(insns, block, factory))
        .collect();

    let mut live_in: Vec<BTreeSet<Register>> = vec![BTreeSet::new(); count];
    let mut live_out: Vec<BTreeSet<Register>> = vec![BTreeSet::new(); count];

    let mut changed: bool = true;
    let mut iterations: usize = 0;
    while changed && iterations < count * 4 + 8 {
        changed = false;
        iterations += 1;
        for node in (0..count).rev() {
            let mut out: BTreeSet<Register> = BTreeSet::new();
            for &succ in &blocks[node].successors {
                for reg in &live_in[succ] {
                    out.insert(*reg);
                }
            }
            let mut new_in: BTreeSet<Register> = local[node].use_set.clone();
            for reg in &out {
                if !local[node].def_set.contains(reg) {
                    new_in.insert(*reg);
                }
            }
            if out != live_out[node] {
                live_out[node] = out;
                changed = true;
            }
            if new_in != live_in[node] {
                live_in[node] = new_in;
                changed = true;
            }
        }
    }

    live_in.first().cloned().unwrap_or_default()
}

fn block_use_def(
    insns: &[Instruction],
    block: &BasicBlock,
    factory: &mut InstructionInfoFactory,
) -> LiveSets {
    let mut sets: LiveSets = LiveSets::default();
    for insn in &insns[block.insns.clone()] {
        let info: &iced_x86::InstructionInfo = factory.info(insn);
        let mut reads: Vec<Register> = Vec::new();
        let mut writes: Vec<Register> = Vec::new();
        for used in info.used_registers() {
            collect_access(*used, &mut reads, &mut writes);
        }
        for base in memory_address_registers(insn) {
            reads.push(base);
        }
        for reg in reads {
            if argument_candidate(reg) && !sets.def_set.contains(&reg) {
                sets.use_set.insert(reg);
            }
        }
        for reg in writes {
            if argument_candidate(reg) {
                sets.def_set.insert(reg);
            }
        }
    }
    sets
}

fn collect_access(used: UsedRegister, reads: &mut Vec<Register>, writes: &mut Vec<Register>) {
    let reg: Register = canonical_argument_register(used.register());
    if reg == Register::None {
        return;
    }
    match used.access() {
        OpAccess::Read | OpAccess::CondRead => reads.push(reg),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
            reads.push(reg);
            writes.push(reg);
        }
        OpAccess::Write => writes.push(reg),
        OpAccess::CondWrite => {
            reads.push(reg);
            writes.push(reg);
        }
        OpAccess::None | OpAccess::NoMemAccess => {}
    }
}

fn memory_address_registers(insn: &Instruction) -> Vec<Register> {
    let mut out: Vec<Register> = Vec::new();
    let base: Register = canonical_argument_register(insn.memory_base());
    let index: Register = canonical_argument_register(insn.memory_index());
    if base != Register::None {
        out.push(base);
    }
    if index != Register::None {
        out.push(index);
    }
    out
}

fn classify_return(
    insns: &[Instruction],
    blocks: &[BasicBlock],
    factory: &mut InstructionInfoFactory,
) -> ReturnKind {
    let return_blocks: Vec<usize> = blocks
        .iter()
        .enumerate()
        .filter_map(|(i, block): (usize, &BasicBlock)| block.returns.then_some(i))
        .collect();
    if return_blocks.is_empty() {
        return ReturnKind::Unknown;
    }

    let preds: Vec<Vec<usize>> = predecessors(blocks);
    let mut verdicts: Vec<bool> = Vec::with_capacity(return_blocks.len());
    for &ret in &return_blocks {
        verdicts.push(rax_live_on_return_path(insns, blocks, &preds, ret, factory));
    }
    if verdicts.iter().all(|v: &bool| *v) {
        ReturnKind::Value
    } else if verdicts.iter().all(|v: &bool| !*v) {
        ReturnKind::Void
    } else {
        ReturnKind::Unknown
    }
}

fn rax_live_on_return_path(
    insns: &[Instruction],
    blocks: &[BasicBlock],
    preds: &[Vec<usize>],
    ret_block: usize,
    factory: &mut InstructionInfoFactory,
) -> bool {
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<usize> = vec![ret_block];
    while let Some(node) = stack.pop() {
        if !visited.insert(node) {
            continue;
        }
        match block_defines_return_reg(insns, &blocks[node], factory) {
            Some(true) => return true,
            Some(false) => {}
            None => {
                for &pred in &preds[node] {
                    stack.push(pred);
                }
            }
        }
    }
    false
}

fn block_defines_return_reg(
    insns: &[Instruction],
    block: &BasicBlock,
    factory: &mut InstructionInfoFactory,
) -> Option<bool> {
    for insn in insns[block.insns.clone()].iter().rev() {
        let info: &iced_x86::InstructionInfo = factory.info(insn);
        for used in info.used_registers() {
            if !is_return_register(used.register()) {
                continue;
            }
            match used.access() {
                OpAccess::Write | OpAccess::ReadWrite => return Some(true),
                OpAccess::Read | OpAccess::CondRead => return Some(true),
                OpAccess::CondWrite | OpAccess::ReadCondWrite => return Some(true),
                OpAccess::None | OpAccess::NoMemAccess => {}
            }
        }
    }
    None
}

fn predecessors(blocks: &[BasicBlock]) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (from, block) in blocks.iter().enumerate() {
        for &succ in &block.successors {
            if succ < preds.len() {
                preds[succ].push(from);
            }
        }
    }
    preds
}

fn build_cfg(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    start: usize,
) -> Option<Vec<BasicBlock>> {
    let leaders: BTreeSet<usize> = collect_leaders(insns, index, start)?;
    let leader_vec: Vec<usize> = leaders.iter().copied().collect();
    if leader_vec.len() > MAX_BLOCKS {
        return None;
    }
    let leader_to_block: BTreeMap<usize, usize> = leader_vec
        .iter()
        .enumerate()
        .map(|(i, leader): (usize, &usize)| (*leader, i))
        .collect();

    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(leader_vec.len());
    for (i, &leader) in leader_vec.iter().enumerate() {
        let next_leader: usize = leader_vec.get(i + 1).copied().unwrap_or(insns.len());
        blocks.push(build_block(
            insns,
            index,
            leader,
            next_leader,
            &leader_to_block,
        )?);
    }
    let start_block: usize = *leader_to_block.get(&start)?;
    if start_block != 0 {
        blocks.swap(0, start_block);
        let remap = |b: usize| -> usize {
            if b == 0 {
                start_block
            } else if b == start_block {
                0
            } else {
                b
            }
        };
        for block in &mut blocks {
            for succ in &mut block.successors {
                *succ = remap(*succ);
            }
        }
    }
    Some(blocks)
}

fn collect_leaders(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    start: usize,
) -> Option<BTreeSet<usize>> {
    let mut leaders: BTreeSet<usize> = BTreeSet::from([start]);
    let mut worklist: Vec<usize> = vec![start];
    let mut visited: BTreeSet<usize> = BTreeSet::new();

    while let Some(leader) = worklist.pop() {
        if !visited.insert(leader) {
            continue;
        }
        if visited.len() > MAX_BLOCKS {
            return None;
        }
        let mut cursor: usize = leader;
        let limit: usize = leader + MAX_BLOCK_INSNS;
        loop {
            if cursor >= insns.len() || cursor > limit {
                return None;
            }
            let insn: &Instruction = &insns[cursor];
            match insn.flow_control() {
                FlowControl::Next | FlowControl::Call => {
                    if insn.has_lock_prefix() {
                        return None;
                    }
                    cursor += 1;
                }
                FlowControl::Return | FlowControl::Interrupt => break,
                FlowControl::ConditionalBranch => {
                    let taken: usize = *index.get(&insn.near_branch_target())?;
                    let fallthrough: usize = cursor + 1;
                    if fallthrough >= insns.len() {
                        return None;
                    }
                    leaders.insert(taken);
                    leaders.insert(fallthrough);
                    worklist.push(taken);
                    worklist.push(fallthrough);
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    let target: usize = *index.get(&insn.near_branch_target())?;
                    leaders.insert(target);
                    worklist.push(target);
                    break;
                }
                _ => return None,
            }
        }
    }
    Some(leaders)
}

fn build_block(
    insns: &[Instruction],
    index: &BTreeMap<u64, usize>,
    leader: usize,
    next_leader: usize,
    leader_to_block: &BTreeMap<usize, usize>,
) -> Option<BasicBlock> {
    let mut cursor: usize = leader;
    let limit: usize = leader + MAX_BLOCK_INSNS;
    loop {
        if cursor >= insns.len() || cursor > limit {
            return None;
        }
        let insn: &Instruction = &insns[cursor];
        match insn.flow_control() {
            FlowControl::Next | FlowControl::Call => {
                if insn.has_lock_prefix() {
                    return None;
                }
                if cursor + 1 == next_leader {
                    let to: usize = *leader_to_block.get(&next_leader)?;
                    return Some(BasicBlock {
                        insns: leader..cursor + 1,
                        successors: vec![to],
                        returns: false,
                    });
                }
                cursor += 1;
            }
            FlowControl::Return | FlowControl::Interrupt => {
                return Some(BasicBlock {
                    insns: leader..cursor + 1,
                    successors: Vec::new(),
                    returns: matches!(insn.flow_control(), FlowControl::Return),
                });
            }
            FlowControl::ConditionalBranch => {
                let taken_insn: usize = *index.get(&insn.near_branch_target())?;
                let taken: usize = *leader_to_block.get(&taken_insn)?;
                let fallthrough: usize = *leader_to_block.get(&(cursor + 1))?;
                return Some(BasicBlock {
                    insns: leader..cursor + 1,
                    successors: vec![taken, fallthrough],
                    returns: false,
                });
            }
            FlowControl::UnconditionalBranch => {
                let target_insn: usize = *index.get(&insn.near_branch_target())?;
                let to: usize = *leader_to_block.get(&target_insn)?;
                return Some(BasicBlock {
                    insns: leader..cursor + 1,
                    successors: vec![to],
                    returns: false,
                });
            }
            _ => return None,
        }
    }
}

fn ordered_fp_live_in(live_in: &BTreeSet<Register>) -> Vec<Register> {
    XMM_ARGS
        .iter()
        .copied()
        .filter(|r: &Register| live_in.contains(r))
        .collect()
}

fn argument_candidate(reg: Register) -> bool {
    INTEGER_ARG_FULL.contains(&reg) || XMM_ARGS.contains(&reg)
}

fn canonical_argument_register(reg: Register) -> Register {
    if reg == Register::None {
        return Register::None;
    }
    if reg.is_xmm() {
        return if XMM_ARGS.contains(&reg) {
            reg
        } else {
            Register::None
        };
    }
    if !reg.is_gpr() {
        return Register::None;
    }
    let full: Register = reg.full_register();
    if INTEGER_ARG_FULL.contains(&full) {
        full
    } else {
        Register::None
    }
}

fn is_return_register(reg: Register) -> bool {
    if reg == Register::None {
        return false;
    }
    if reg.is_xmm() {
        return reg == Register::XMM0;
    }
    if !reg.is_gpr() {
        return false;
    }
    reg.full_register() == Register::RAX
}

fn register_label(reg: Register) -> String {
    format!("{reg:?}").to_ascii_lowercase()
}

const SYSV64_INTEGER: &[Register] = &[
    Register::RDI,
    Register::RSI,
    Register::RDX,
    Register::RCX,
    Register::R8,
    Register::R9,
];

const MS64_INTEGER: &[Register] = &[Register::RCX, Register::RDX, Register::R8, Register::R9];

const FASTCALL_INTEGER32: &[Register] = &[Register::ECX, Register::EDX];

const INTEGER_ARG_FULL: &[Register] = &[
    Register::RDI,
    Register::RSI,
    Register::RDX,
    Register::RCX,
    Register::R8,
    Register::R9,
];

const XMM_ARGS: &[Register] = &[
    Register::XMM0,
    Register::XMM1,
    Register::XMM2,
    Register::XMM3,
    Register::XMM4,
    Register::XMM5,
    Register::XMM6,
    Register::XMM7,
];

fn decode_all(bitness: u32, base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    while decoder.can_decode() && out.len() < MAX_DECODE_INSNS {
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
