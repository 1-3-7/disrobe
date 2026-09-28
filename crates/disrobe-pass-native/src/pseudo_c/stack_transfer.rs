use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register};

use crate::arch::{DisasmInsn, decode_one_x86};
use crate::error::{Error, Result};

use super::{
    Abi, Reg, RegRef, Source, Stmt, Width, Xmm, iced_register, iced_xmm_register,
    instruction_writes_register, instruction_writes_xmm, is_ms_x64_callee_saved_xmm_spill,
    parse_reg, parse_xmm,
};

const GPR_ORDER: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
const XMM_SHIFT: usize = 16;
const ALL_LIVE: u32 = u32::MAX;
const RETURN_LIVE: u32 = 0b101 | (0b11 << XMM_SHIFT);
const MS_X64_CALL_PRESERVED_XMM: u32 = 0xffc0 << XMM_SHIFT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    Branch {
        target: Option<usize>,
        conditional: bool,
    },
    Call,
    Return,
    Trap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InsnFacts {
    flow: Flow,
    uses: u32,
    kills: u32,
}

fn register_bit(register: Register) -> Option<u32> {
    if register.is_xmm() || register.is_ymm() || register.is_zmm() {
        let number: usize = register.number();
        return (number < 16).then(|| 1_u32 << (XMM_SHIFT + number));
    }
    if !register.is_gpr() {
        return None;
    }
    let full: Register = register.full_register();
    GPR_ORDER
        .iter()
        .position(|candidate: &Register| *candidate == full)
        .map(|index: usize| 1_u32 << index)
}

fn reg_bit(reg: Reg) -> Option<u32> {
    iced_register(reg).and_then(register_bit)
}

fn xmm_bit(xmm: Xmm) -> Option<u32> {
    iced_xmm_register(xmm).and_then(register_bit)
}

fn flow_of(decoded: &Instruction, by_address: &BTreeMap<u64, usize>) -> Flow {
    match decoded.flow_control() {
        FlowControl::Next => Flow::Next,
        control @ (FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch) => {
            Flow::Branch {
                target: by_address.get(&decoded.near_branch_target()).copied(),
                conditional: control == FlowControl::ConditionalBranch,
            }
        }
        FlowControl::Call => Flow::Call,
        FlowControl::Return => Flow::Return,
        FlowControl::Exception => Flow::Trap,
        FlowControl::Interrupt if decoded.mnemonic() == Mnemonic::Int3 => Flow::Trap,
        FlowControl::Interrupt
        | FlowControl::IndirectBranch
        | FlowControl::IndirectCall
        | FlowControl::XbeginXabortXend => Flow::Unknown,
    }
}

fn instruction_facts(
    factory: &mut InstructionInfoFactory,
    insn: &DisasmInsn,
    by_address: &BTreeMap<u64, usize>,
) -> InsnFacts {
    let Some(decoded): Option<Instruction> = decode_one_x86(64, insn.address, &insn.bytes) else {
        return InsnFacts {
            flow: Flow::Unknown,
            uses: ALL_LIVE,
            kills: 0,
        };
    };
    let mut uses: u32 = 0;
    let mut kills: u32 = 0;
    for used in factory.info(&decoded).used_registers() {
        let Some(bit): Option<u32> = register_bit(used.register()) else {
            continue;
        };
        match used.access() {
            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                uses |= bit;
            }
            OpAccess::Write if used.register().is_gpr() && used.register().size() >= 4 => {
                kills |= bit;
            }
            OpAccess::Write | OpAccess::CondWrite | OpAccess::None | OpAccess::NoMemAccess => {}
        }
    }
    InsnFacts {
        flow: flow_of(&decoded, by_address),
        uses,
        kills,
    }
}

struct FunctionFacts {
    facts: Vec<InsnFacts>,
    leaders: BTreeSet<usize>,
}

impl FunctionFacts {
    fn new(insns: &[DisasmInsn], extra_leaders: &[u64]) -> Self {
        let by_address: BTreeMap<u64, usize> = insns
            .iter()
            .enumerate()
            .map(|(index, insn): (usize, &DisasmInsn)| (insn.address, index))
            .collect();
        let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
        let facts: Vec<InsnFacts> = insns
            .iter()
            .map(|insn: &DisasmInsn| instruction_facts(&mut factory, insn, &by_address))
            .collect();
        let mut leaders: BTreeSet<usize> = extra_leaders
            .iter()
            .filter_map(|address: &u64| by_address.get(address).copied())
            .collect();
        for fact in &facts {
            if let Flow::Branch {
                target: Some(target),
                ..
            } = fact.flow
            {
                leaders.insert(target);
            }
        }
        Self { facts, leaders }
    }

    fn successors(&self, index: usize) -> Vec<usize> {
        let fallthrough: Option<usize> = (index + 1 < self.facts.len()).then_some(index + 1);
        match self.facts[index].flow {
            Flow::Next | Flow::Call => fallthrough.into_iter().collect(),
            Flow::Branch {
                target,
                conditional,
            } => target
                .into_iter()
                .chain(fallthrough.filter(|_: &usize| conditional))
                .collect(),
            Flow::Return | Flow::Trap | Flow::Unknown => Vec::new(),
        }
    }

    fn live_out(&self, index: usize, live_in: &[u32], abi: Abi) -> u32 {
        let next =
            |successor: usize| -> u32 { live_in.get(successor).copied().unwrap_or(ALL_LIVE) };
        match self.facts[index].flow {
            Flow::Next => next(index + 1),
            Flow::Branch {
                target,
                conditional,
            } => {
                let taken: u32 = target.map_or(ALL_LIVE, next);
                let fallthrough: u32 = if conditional { next(index + 1) } else { 0 };
                taken | fallthrough
            }
            Flow::Call => {
                if abi == Abi::MsX64 {
                    (ALL_LIVE & !MS_X64_CALL_PRESERVED_XMM)
                        | (next(index + 1) & MS_X64_CALL_PRESERVED_XMM)
                } else {
                    ALL_LIVE
                }
            }
            Flow::Return => RETURN_LIVE,
            Flow::Trap => 0,
            Flow::Unknown => ALL_LIVE,
        }
    }

    fn liveness(&self, abi: Abi) -> Vec<u32> {
        let count: usize = self.facts.len();
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
        for index in 0..count {
            for successor in self.successors(index) {
                predecessors[successor].push(index);
            }
        }
        let mut live_in: Vec<u32> = vec![0; count];
        let mut live_out: Vec<u32> = vec![0; count];
        let mut queued: Vec<bool> = vec![true; count];
        let mut pending: Vec<usize> = (0..count).collect();
        while let Some(index) = pending.pop() {
            queued[index] = false;
            let out: u32 = self.live_out(index, &live_in, abi);
            let facts: InsnFacts = self.facts[index];
            let incoming: u32 = facts.uses | (out & !facts.kills);
            live_out[index] = out;
            if incoming == live_in[index] {
                continue;
            }
            live_in[index] = incoming;
            for predecessor in &predecessors[index] {
                if !queued[*predecessor] {
                    queued[*predecessor] = true;
                    pending.push(*predecessor);
                }
            }
        }
        live_out
    }

    fn straight_line_predecessor(&self, index: usize) -> Option<usize> {
        let previous: usize = index.checked_sub(1)?;
        (!self.leaders.contains(&index) && self.facts[previous].flow == Flow::Next)
            .then_some(previous)
    }

    fn tainted_by_writes(&self, writers: &[usize]) -> Vec<bool> {
        let mut tainted: Vec<bool> = vec![false; self.facts.len()];
        let mut pending: Vec<usize> = Vec::new();
        for writer in writers {
            if self.facts[*writer].flow == Flow::Unknown {
                return vec![true; self.facts.len()];
            }
            pending.extend(self.successors(*writer));
        }
        while let Some(index) = pending.pop() {
            if tainted[index] {
                continue;
            }
            tainted[index] = true;
            if self.facts[index].flow == Flow::Unknown {
                return vec![true; self.facts.len()];
            }
            pending.extend(self.successors(index));
        }
        tainted
    }
}

fn stack_register(insn: &DisasmInsn) -> Option<RegRef> {
    parse_reg(insn.operands.trim()).filter(|register: &RegRef| register.width == Width::W64)
}

fn matching_push(
    insns: &[DisasmInsn],
    function: &FunctionFacts,
    pop_index: usize,
) -> Option<(usize, RegRef)> {
    let mut depth: usize = 0;
    let mut index: usize = pop_index;
    while let Some(previous) = function.straight_line_predecessor(index) {
        let insn: &DisasmInsn = &insns[previous];
        match insn.mnemonic.as_str() {
            "push" => {
                let pushed: RegRef = stack_register(insn)?;
                if depth == 0 {
                    return Some((previous, pushed));
                }
                depth -= 1;
            }
            "pop" => {
                stack_register(insn)?;
                depth += 1;
            }
            _ if instruction_writes_register(insn, Reg::Rsp) => return None,
            _ => {}
        }
        index = previous;
    }
    None
}

fn refuse_return_through_push(
    insns: &[DisasmInsn],
    function: &FunctionFacts,
    ret_index: usize,
) -> Result<()> {
    let mut depth: usize = 0;
    let mut index: usize = ret_index;
    while let Some(previous) = function.straight_line_predecessor(index) {
        let insn: &DisasmInsn = &insns[previous];
        match insn.mnemonic.as_str() {
            "push" if depth == 0 => {
                return Err(Error::LlvmIr(format!(
                    "`ret` at {:#x} returns through the value `push {}` stored at {:#x}; a return address built on the stack is not modelled",
                    insns[ret_index].address, insn.operands, insn.address
                )));
            }
            "push" => depth -= 1,
            "pop" => depth += 1,
            _ if instruction_writes_register(insn, Reg::Rsp) => return Ok(()),
            _ => {}
        }
        index = previous;
    }
    Ok(())
}

fn pop_move(
    insns: &[DisasmInsn],
    function: &FunctionFacts,
    live_out: &[u32],
    pop_index: usize,
) -> Result<Option<Stmt>> {
    let insn: &DisasmInsn = &insns[pop_index];
    let Some(dest): Option<RegRef> = stack_register(insn) else {
        return Ok(None);
    };
    if dest.reg == Reg::Rsp {
        return Err(Error::LlvmIr(format!(
            "`pop rsp` at {:#x} loads the stack pointer from memory; the resulting frame is not modelled",
            insn.address
        )));
    }
    let dest_bit: u32 = reg_bit(dest.reg).ok_or_else(|| {
        Error::LlvmIr(format!(
            "`pop {}` at {:#x} names a register outside the tracked set",
            insn.operands, insn.address
        ))
    })?;
    if live_out[pop_index] & dest_bit == 0 {
        return Ok(None);
    }
    let Some((push_index, pushed)): Option<(usize, RegRef)> =
        matching_push(insns, function, pop_index)
    else {
        return Err(Error::LlvmIr(format!(
            "`pop {}` at {:#x} is read afterwards but has no matching push in its block; a stack transfer outside the prologue and epilogue is not modelled",
            insn.operands, insn.address
        )));
    };
    let unchanged: bool = pushed.reg != Reg::Rsp
        && insns[push_index + 1..pop_index]
            .iter()
            .all(|between: &DisasmInsn| !instruction_writes_register(between, pushed.reg));
    if !unchanged {
        return Err(Error::LlvmIr(format!(
            "`pop {}` at {:#x} reloads the value `push {}` stored at {:#x} after the register changed; a stack round trip through a modified register is not modelled",
            insn.operands, insn.address, insns[push_index].operands, insns[push_index].address
        )));
    }
    if pushed.reg == dest.reg {
        return Ok(None);
    }
    Ok(Some(Stmt::Assign {
        dest,
        src: Source::Reg(pushed),
    }))
}

fn refuse_live_xmm_spills(
    insns: &[DisasmInsn],
    function: &FunctionFacts,
    live_out: &[u32],
) -> Result<()> {
    for (index, insn) in insns.iter().enumerate() {
        if !is_ms_x64_callee_saved_xmm_spill(&insn.mnemonic, &insn.operands, Abi::MsX64) {
            continue;
        }
        let Some((lhs, rhs)): Option<(&str, &str)> = insn.operands.split_once(',') else {
            continue;
        };
        if let Some(reloaded) = parse_xmm(lhs.trim()) {
            let live: bool = xmm_bit(reloaded).is_none_or(|bit: u32| live_out[index] & bit != 0);
            if live {
                return Err(Error::LlvmIr(format!(
                    "reload `{} {}` at {:#x} of a callee-saved xmm register is read afterwards; a mid-body xmm spill round trip is not modelled",
                    insn.mnemonic, insn.operands, insn.address
                )));
            }
            continue;
        }
        let Some(saved): Option<Xmm> = parse_xmm(rhs.trim()) else {
            continue;
        };
        let writers: Vec<usize> = insns
            .iter()
            .enumerate()
            .filter(|(_, candidate): &(usize, &DisasmInsn)| {
                instruction_writes_xmm(candidate, saved)
            })
            .map(|(writer, _): (usize, &DisasmInsn)| writer)
            .collect();
        if function.tainted_by_writes(&writers)[index] {
            return Err(Error::LlvmIr(format!(
                "spill `{} {}` at {:#x} stores a callee-saved xmm register after the body changed it; a mid-body xmm spill is not modelled",
                insn.mnemonic, insn.operands, insn.address
            )));
        }
    }
    Ok(())
}

pub(super) fn plan_stack_transfers(
    insns: &[DisasmInsn],
    abi: Abi,
    extra_leaders: &[u64],
) -> Result<BTreeMap<u64, Stmt>> {
    let has_stack_transfer: bool = insns
        .iter()
        .any(|insn: &DisasmInsn| matches!(insn.mnemonic.as_str(), "push" | "pop"));
    let has_xmm_spill: bool = abi == Abi::MsX64
        && insns.iter().any(|insn: &DisasmInsn| {
            is_ms_x64_callee_saved_xmm_spill(&insn.mnemonic, &insn.operands, abi)
        });
    let mut moves: BTreeMap<u64, Stmt> = BTreeMap::new();
    if !has_stack_transfer && !has_xmm_spill {
        return Ok(moves);
    }
    let function: FunctionFacts = FunctionFacts::new(insns, extra_leaders);
    let live_out: Vec<u32> = function.liveness(abi);
    if has_xmm_spill {
        refuse_live_xmm_spills(insns, &function, &live_out)?;
    }
    if !has_stack_transfer {
        return Ok(moves);
    }
    for (index, insn) in insns.iter().enumerate() {
        if function.facts[index].flow == Flow::Return {
            refuse_return_through_push(insns, &function, index)?;
        }
        if insn.mnemonic == "pop"
            && let Some(stmt) = pop_move(insns, &function, &live_out, index)?
        {
            moves.insert(insn.address, stmt);
        }
    }
    Ok(moves)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests;
