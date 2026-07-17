use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register, UsedMemory, UsedRegister,
};

use crate::cfg::{self, BasicBlock, Cfg};

const MAX_DECODE_INSNS: usize = 1 << 16;
const WIN64_SHADOW_BASE: i64 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Convention {
    SysVAmd64,
    Win64,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArgLocation {
    IntReg(u8),
    SseReg(u8),
    Stack(i64),
}

impl ArgLocation {
    #[must_use]
    pub fn int_register(convention: Convention, index: usize) -> Option<Self> {
        int_arg_registers(convention)
            .get(index)
            .map(|reg: &Register| Self::IntReg(int_arg_slot(*reg)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnKind {
    Void,
    IntRax,
    IntRdxRax,
    Sse,
    Sret,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredProto {
    pub convention: Convention,
    pub args: Vec<ArgLocation>,
    pub ret: ReturnKind,
    pub variadic: bool,
    pub sret: bool,
    pub preserved: Vec<Register>,
    pub clobbers: Vec<Register>,
    pub arg_confidence: SigConfidence,
    pub ret_confidence: SigConfidence,
}

impl RecoveredProto {
    #[must_use]
    pub fn arg_register_set(&self) -> BTreeSet<ArgLocation> {
        self.args
            .iter()
            .filter(|loc: &&ArgLocation| !matches!(loc, ArgLocation::Stack(_)))
            .copied()
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FunctionCode<'a> {
    pub low_pc: u64,
    pub bytes: &'a [u8],
}

#[must_use]
pub const fn int_arg_registers(convention: Convention) -> &'static [Register] {
    const SYSV: [Register; 6] = [
        Register::RDI,
        Register::RSI,
        Register::RDX,
        Register::RCX,
        Register::R8,
        Register::R9,
    ];
    const WIN64: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];
    match convention {
        Convention::SysVAmd64 => &SYSV,
        Convention::Win64 | Convention::Unknown => &WIN64,
    }
}

#[allow(clippy::missing_const_for_fn)]
fn int_arg_slot(reg: Register) -> u8 {
    match reg.full_register() {
        Register::RDI => 0,
        Register::RSI => 1,
        Register::RDX => 2,
        Register::RCX => 3,
        Register::R8 => 4,
        Register::R9 => 5,
        Register::RAX => 6,
        _ => u8::MAX,
    }
}

const fn first_int_arg_register(convention: Convention) -> Register {
    match convention {
        Convention::SysVAmd64 => Register::RDI,
        Convention::Win64 | Convention::Unknown => Register::RCX,
    }
}

fn int_bit(reg: Register) -> Option<u32> {
    match reg.full_register() {
        Register::RDI => Some(0),
        Register::RSI => Some(1),
        Register::RDX => Some(2),
        Register::RCX => Some(3),
        Register::R8 => Some(4),
        Register::R9 => Some(5),
        Register::RAX => Some(6),
        _ => None,
    }
}

const fn xmm_index(reg: Register) -> Option<u8> {
    Some(match reg {
        Register::XMM0 | Register::YMM0 | Register::ZMM0 => 0,
        Register::XMM1 | Register::YMM1 | Register::ZMM1 => 1,
        Register::XMM2 | Register::YMM2 | Register::ZMM2 => 2,
        Register::XMM3 | Register::YMM3 | Register::ZMM3 => 3,
        Register::XMM4 | Register::YMM4 | Register::ZMM4 => 4,
        Register::XMM5 | Register::YMM5 | Register::ZMM5 => 5,
        Register::XMM6 | Register::YMM6 | Register::ZMM6 => 6,
        Register::XMM7 | Register::YMM7 | Register::ZMM7 => 7,
        _ => return None,
    })
}

fn tracked_bit(reg: Register) -> Option<u32> {
    if let Some(index) = int_bit(reg) {
        return Some(index);
    }
    xmm_index(reg).map(|index: u8| 7 + u32::from(index))
}

const fn int_reg_mask(slot: u32) -> u32 {
    1 << slot
}

const fn xmm_mask(index: u8) -> u32 {
    1 << (7 + index as u32)
}

const RAX_MASK: u32 = int_reg_mask(6);
const XMM0_MASK: u32 = xmm_mask(0);

const fn is_read(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn is_kill_write(reg: Register, access: OpAccess) -> bool {
    if !matches!(access, OpAccess::Write | OpAccess::ReadWrite) {
        return false;
    }
    if xmm_index(reg).is_some() {
        return true;
    }
    reg.size() >= 4
}

fn zeroing_idiom_dest(insn: &Instruction) -> Option<Register> {
    let same: bool = insn.op0_kind() == OpKind::Register
        && insn.op1_kind() == OpKind::Register
        && insn.op_register(0) == insn.op_register(1);
    if !same {
        return None;
    }
    matches!(
        insn.mnemonic(),
        Mnemonic::Xor | Mnemonic::Sub | Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd
    )
    .then(|| insn.op_register(0))
}

fn use_def(insn: &Instruction, factory: &mut InstructionInfoFactory) -> (u32, u32) {
    if let Some(dest) = zeroing_idiom_dest(insn) {
        if let Some(bit) = tracked_bit(dest) {
            return (0, 1 << bit);
        }
        return (0, 0);
    }
    let info: &InstructionInfo = factory.info(insn);
    let mut uses: u32 = 0;
    let mut defs: u32 = 0;
    for ur in info.used_registers() {
        let ur: UsedRegister = *ur;
        let Some(bit): Option<u32> = tracked_bit(ur.register()) else {
            continue;
        };
        if is_read(ur.access()) {
            uses |= 1 << bit;
        }
        if is_kill_write(ur.register(), ur.access()) {
            defs |= 1 << bit;
        }
    }
    (uses, defs)
}

fn entry_live_in(instrs: &[Instruction], cfg: &Cfg, factory: &mut InstructionInfoFactory) -> u32 {
    let masks: Vec<(u32, u32)> = instrs
        .iter()
        .map(|insn: &Instruction| use_def(insn, factory))
        .collect();
    let block_count: usize = cfg.blocks.len();
    if block_count == 0 {
        return 0;
    }
    let mut live_in: Vec<u32> = vec![0; block_count];
    let budget: usize = block_count.saturating_mul(4).saturating_add(8);
    for _ in 0..budget {
        let mut changed: bool = false;
        for index in (0..block_count).rev() {
            let block: &BasicBlock = &cfg.blocks[index];
            let mut cur: u32 = block
                .succs
                .iter()
                .fold(0, |acc: u32, succ: &usize| acc | live_in[*succ]);
            for pos in (block.start..block.end).rev() {
                let (uses, defs): (u32, u32) = masks.get(pos).copied().unwrap_or((0, 0));
                cur = (cur & !defs) | uses;
            }
            if cur != live_in[index] {
                live_in[index] = cur;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    live_in.first().copied().unwrap_or(0)
}

const fn detect_convention(mask: u32) -> Convention {
    let sysv_only: u32 = int_reg_mask(0) | int_reg_mask(1);
    if mask & sysv_only != 0 {
        return Convention::SysVAmd64;
    }
    let win64_int: u32 = int_reg_mask(3) | int_reg_mask(2) | int_reg_mask(4) | int_reg_mask(5);
    if mask & (win64_int | sse_mask_all()) != 0 {
        return Convention::Win64;
    }
    Convention::Unknown
}

const fn sse_mask_all() -> u32 {
    let mut mask: u32 = 0;
    let mut index: u8 = 0;
    while index < 8 {
        mask |= xmm_mask(index);
        index += 1;
    }
    mask
}

fn register_args(mask: u32, convention: Convention) -> Vec<ArgLocation> {
    match convention {
        Convention::Win64 | Convention::Unknown => win64_register_args(mask),
        Convention::SysVAmd64 => sysv_register_args(mask),
    }
}

fn win64_register_args(mask: u32) -> Vec<ArgLocation> {
    const INT_SLOTS: [u32; 4] = [3, 2, 4, 5];
    let mut args: Vec<ArgLocation> = Vec::new();
    for position in 0..4u8 {
        let int_slot: u32 = INT_SLOTS[position as usize];
        let int_live: bool = mask & int_reg_mask(int_slot) != 0;
        let sse_live: bool = mask & xmm_mask(position) != 0;
        match (int_live, sse_live) {
            (true, false) => args.push(ArgLocation::IntReg(u8::try_from(int_slot).unwrap_or(0))),
            (false, true) => args.push(ArgLocation::SseReg(position)),
            (false, false) => break,
            (true, true) => {
                args.push(ArgLocation::IntReg(u8::try_from(int_slot).unwrap_or(0)));
            }
        }
    }
    args
}

fn sysv_register_args(mask: u32) -> Vec<ArgLocation> {
    const INT_SLOTS: [u32; 6] = [0, 1, 2, 3, 4, 5];
    let mut args: Vec<ArgLocation> = Vec::new();
    for slot in INT_SLOTS {
        if mask & int_reg_mask(slot) == 0 {
            break;
        }
        args.push(ArgLocation::IntReg(u8::try_from(slot).unwrap_or(0)));
    }
    for index in 0..8u8 {
        if mask & xmm_mask(index) == 0 {
            break;
        }
        args.push(ArgLocation::SseReg(index));
    }
    args
}

fn stack_args(instrs: &[Instruction], factory: &mut InstructionInfoFactory) -> Vec<ArgLocation> {
    let mut first_access: BTreeMap<i64, bool> = BTreeMap::new();
    for insn in instrs {
        let info: &InstructionInfo = factory.info(insn);
        for mem in info.used_memory() {
            let mem: UsedMemory = *mem;
            if mem.base() != Register::RBP || mem.index() != Register::None {
                continue;
            }
            let disp: i64 = i64::from_ne_bytes(mem.displacement().to_ne_bytes());
            if disp < WIN64_SHADOW_BASE {
                continue;
            }
            let is_write: bool = matches!(
                mem.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
            first_access.entry(disp).or_insert(!is_write);
        }
    }
    first_access
        .into_iter()
        .filter_map(|(disp, first_read): (i64, bool)| {
            first_read.then_some(ArgLocation::Stack(disp))
        })
        .collect()
}

fn spill_slot_of(
    instrs: &[Instruction],
    reg: Register,
    factory: &mut InstructionInfoFactory,
) -> Option<i64> {
    for insn in instrs {
        if insn.mnemonic() != Mnemonic::Mov
            || insn.op0_kind() != OpKind::Memory
            || insn.op1_kind() != OpKind::Register
        {
            continue;
        }
        if insn.op_register(1) != reg {
            continue;
        }
        let info: &InstructionInfo = factory.info(insn);
        for mem in info.used_memory() {
            let mem: UsedMemory = *mem;
            if mem.base() == Register::RBP && mem.index() == Register::None {
                return Some(i64::from_ne_bytes(mem.displacement().to_ne_bytes()));
            }
        }
    }
    None
}

fn detect_sret(
    instrs: &[Instruction],
    convention: Convention,
    factory: &mut InstructionInfoFactory,
) -> bool {
    let first_reg: Register = first_int_arg_register(convention);
    let Some(slot): Option<i64> = spill_slot_of(instrs, first_reg, factory) else {
        return false;
    };
    for (index, insn) in instrs.iter().enumerate() {
        if insn.flow_control() != FlowControl::Return {
            continue;
        }
        if returns_load_from_slot(instrs, index, slot, factory) {
            return true;
        }
    }
    false
}

fn returns_load_from_slot(
    instrs: &[Instruction],
    ret_index: usize,
    slot: i64,
    factory: &mut InstructionInfoFactory,
) -> bool {
    for pos in (0..ret_index).rev() {
        let insn: &Instruction = &instrs[pos];
        let (_, defs): (u32, u32) = use_def(insn, factory);
        if defs & RAX_MASK == 0 {
            continue;
        }
        if insn.mnemonic() != Mnemonic::Mov
            || insn.op0_kind() != OpKind::Register
            || insn.op1_kind() != OpKind::Memory
            || insn.op_register(0) != Register::RAX
        {
            return false;
        }
        return insn.memory_base() == Register::RBP
            && insn.memory_index() == Register::None
            && i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes()) == slot;
    }
    false
}

#[derive(Debug, Clone, Copy, Default)]
struct BodyReturn {
    int: bool,
    sse: bool,
}

fn body_return(instrs: &[Instruction], factory: &mut InstructionInfoFactory) -> BodyReturn {
    let mut out: BodyReturn = BodyReturn::default();
    for (index, insn) in instrs.iter().enumerate() {
        if insn.flow_control() != FlowControl::Return {
            continue;
        }
        if let Some(kind) = nearest_return_writer(instrs, index, factory) {
            match kind {
                ReturnWriter::Int => out.int = true,
                ReturnWriter::Sse => out.sse = true,
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy)]
enum ReturnWriter {
    Int,
    Sse,
}

fn nearest_return_writer(
    instrs: &[Instruction],
    ret_index: usize,
    factory: &mut InstructionInfoFactory,
) -> Option<ReturnWriter> {
    for pos in (0..ret_index).rev() {
        let insn: &Instruction = &instrs[pos];
        if insn.flow_control() == FlowControl::Call {
            return None;
        }
        let (_, defs): (u32, u32) = use_def(insn, factory);
        if defs & XMM0_MASK != 0 {
            return Some(ReturnWriter::Sse);
        }
        if defs & RAX_MASK != 0 {
            return Some(ReturnWriter::Int);
        }
    }
    None
}

fn preserved_registers(instrs: &[Instruction]) -> Vec<Register> {
    let mut pushed: BTreeSet<Register> = BTreeSet::new();
    let mut popped: BTreeSet<Register> = BTreeSet::new();
    for insn in instrs {
        if insn.op0_kind() != OpKind::Register {
            continue;
        }
        let reg: Register = insn.op_register(0).full_register();
        if !is_callee_saved(reg) {
            continue;
        }
        match insn.mnemonic() {
            Mnemonic::Push => {
                pushed.insert(reg);
            }
            Mnemonic::Pop => {
                popped.insert(reg);
            }
            _ => {}
        }
    }
    pushed.intersection(&popped).copied().collect()
}

fn clobbered_registers(
    instrs: &[Instruction],
    factory: &mut InstructionInfoFactory,
) -> Vec<Register> {
    let mut clobbers: BTreeSet<Register> = BTreeSet::new();
    for insn in instrs {
        let info: &InstructionInfo = factory.info(insn);
        for ur in info.used_registers() {
            let ur: UsedRegister = *ur;
            if !matches!(ur.access(), OpAccess::Write | OpAccess::ReadWrite) {
                continue;
            }
            let reg: Register = ur.register().full_register();
            if is_caller_saved(reg) {
                clobbers.insert(reg);
            }
        }
    }
    clobbers.into_iter().collect()
}

const fn is_callee_saved(reg: Register) -> bool {
    matches!(
        reg,
        Register::RBX
            | Register::RBP
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
            | Register::RDI
            | Register::RSI
    )
}

const fn is_caller_saved(reg: Register) -> bool {
    matches!(
        reg,
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
    )
}

#[derive(Debug, Clone)]
struct CalleeRaw {
    convention: Convention,
    args: Vec<ArgLocation>,
    sret: bool,
    preserved: Vec<Register>,
    clobbers: Vec<Register>,
    body: BodyReturn,
}

fn analyze_callee(
    instrs: &[Instruction],
    cfg: &Cfg,
    hint: Option<Convention>,
    factory: &mut InstructionInfoFactory,
) -> CalleeRaw {
    let mask: u32 = entry_live_in(instrs, cfg, factory);
    let convention: Convention = hint.unwrap_or_else(|| detect_convention(mask));
    let sret: bool = detect_sret(instrs, convention, factory);
    let mut args: Vec<ArgLocation> = register_args(mask, convention);
    if sret && !args.is_empty() {
        args.remove(0);
    }
    args.extend(stack_args(instrs, factory));
    CalleeRaw {
        convention,
        args,
        sret,
        preserved: preserved_registers(instrs),
        clobbers: clobbered_registers(instrs, factory),
        body: body_return(instrs, factory),
    }
}

#[derive(Debug, Clone, Default)]
struct CallSiteObs {
    int_args: BTreeSet<u32>,
    sse_args: BTreeSet<u8>,
    int_ret_used: bool,
    sse_ret_used: bool,
    variadic: bool,
}

fn scan_callsites(
    instrs: &[Instruction],
    factory: &mut InstructionInfoFactory,
) -> BTreeMap<u64, Vec<CallSiteObs>> {
    let mut out: BTreeMap<u64, Vec<CallSiteObs>> = BTreeMap::new();
    let mut int_args: BTreeSet<u32> = BTreeSet::new();
    let mut sse_args: BTreeSet<u8> = BTreeSet::new();
    let mut variadic: bool = false;
    for (index, insn) in instrs.iter().enumerate() {
        if insn.flow_control() == FlowControl::Call {
            if let Some(target) = call_target(insn) {
                let (int_used, sse_used): (bool, bool) = return_used(instrs, index, factory);
                out.entry(target).or_default().push(CallSiteObs {
                    int_args: int_args.clone(),
                    sse_args: sse_args.clone(),
                    int_ret_used: int_used,
                    sse_ret_used: sse_used,
                    variadic,
                });
            }
            int_args.clear();
            sse_args.clear();
            variadic = false;
            continue;
        }
        record_arg_writes(insn, factory, &mut int_args, &mut sse_args);
        if is_variadic_marker(insn) {
            variadic = true;
        }
    }
    out
}

fn call_target(insn: &Instruction) -> Option<u64> {
    matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| insn.near_branch_target())
}

fn record_arg_writes(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    int_args: &mut BTreeSet<u32>,
    sse_args: &mut BTreeSet<u8>,
) {
    let info: &InstructionInfo = factory.info(insn);
    for ur in info.used_registers() {
        let ur: UsedRegister = *ur;
        if !matches!(ur.access(), OpAccess::Write | OpAccess::ReadWrite) {
            continue;
        }
        let reg: Register = ur.register();
        if let Some(slot) = int_bit(reg) {
            if slot != 6 {
                int_args.insert(slot);
            }
        } else if let Some(index) = xmm_index(reg) {
            sse_args.insert(index);
        }
    }
}

fn is_variadic_marker(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Mov
        && insn.op0_kind() == OpKind::Register
        && insn.op_register(0) == Register::AL
        && matches!(insn.op1_kind(), OpKind::Immediate8)
}

fn return_used(
    instrs: &[Instruction],
    call_index: usize,
    factory: &mut InstructionInfoFactory,
) -> (bool, bool) {
    let mut int_used: bool = false;
    let mut sse_used: bool = false;
    let mut int_open: bool = true;
    let mut sse_open: bool = true;
    for insn in instrs.iter().skip(call_index + 1) {
        if insn.flow_control() == FlowControl::Call {
            break;
        }
        let (uses, defs): (u32, u32) = use_def(insn, factory);
        if int_open {
            if uses & RAX_MASK != 0 {
                int_used = true;
                int_open = false;
            } else if defs & RAX_MASK != 0 {
                int_open = false;
            }
        }
        if sse_open {
            if uses & XMM0_MASK != 0 {
                sse_used = true;
                sse_open = false;
            } else if defs & XMM0_MASK != 0 {
                sse_open = false;
            }
        }
        if !int_open && !sse_open {
            break;
        }
        if insn.flow_control() != FlowControl::Next {
            break;
        }
    }
    (int_used, sse_used)
}

fn unify(callee: &CalleeRaw, callsites: &[CallSiteObs]) -> RecoveredProto {
    let arg_confidence: SigConfidence = arg_confidence(callee, callsites);
    let (ret, ret_confidence): (ReturnKind, SigConfidence) = return_kind(callee, callsites);
    let variadic: bool = callsites.iter().any(|obs: &CallSiteObs| obs.variadic);
    RecoveredProto {
        convention: callee.convention,
        args: callee.args.clone(),
        ret,
        variadic,
        sret: callee.sret,
        preserved: callee.preserved.clone(),
        clobbers: callee.clobbers.clone(),
        arg_confidence,
        ret_confidence,
    }
}

fn arg_confidence(callee: &CalleeRaw, callsites: &[CallSiteObs]) -> SigConfidence {
    if callsites.is_empty() {
        return SigConfidence::Medium;
    }
    let mut required_int: BTreeSet<u32> = BTreeSet::new();
    let mut required_sse: BTreeSet<u8> = BTreeSet::new();
    for arg in &callee.args {
        match arg {
            ArgLocation::IntReg(slot) => {
                required_int.insert(u32::from(*slot));
            }
            ArgLocation::SseReg(index) => {
                required_sse.insert(*index);
            }
            ArgLocation::Stack(_) => {}
        }
    }
    let agrees: bool = callsites.iter().any(|obs: &CallSiteObs| {
        required_int.is_subset(&obs.int_args) && required_sse.is_subset(&obs.sse_args)
    });
    if agrees {
        SigConfidence::High
    } else {
        SigConfidence::Low
    }
}

fn return_kind(callee: &CalleeRaw, callsites: &[CallSiteObs]) -> (ReturnKind, SigConfidence) {
    if callee.sret {
        return (ReturnKind::Sret, SigConfidence::High);
    }
    let sse_used: bool = callsites.iter().any(|obs: &CallSiteObs| obs.sse_ret_used);
    let int_used: bool = callsites.iter().any(|obs: &CallSiteObs| obs.int_ret_used);
    if sse_used {
        return (ReturnKind::Sse, SigConfidence::High);
    }
    if int_used {
        return (ReturnKind::IntRax, SigConfidence::High);
    }
    if !callsites.is_empty() {
        return (ReturnKind::Void, SigConfidence::High);
    }
    if callee.body.sse {
        return (ReturnKind::Sse, SigConfidence::Low);
    }
    (ReturnKind::Unknown, SigConfidence::Low)
}

fn decode_all(bytes: &[u8], base: u64) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
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

#[must_use]
pub fn recover_proto(bytes: &[u8], base: u64) -> RecoveredProto {
    let instrs: Vec<Instruction> = decode_all(bytes, base);
    let cfg: Cfg = cfg::build(&instrs);
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let callee: CalleeRaw = analyze_callee(&instrs, &cfg, None, &mut factory);
    unify(&callee, &[])
}

#[must_use]
pub fn recover_protos(
    functions: &[FunctionCode<'_>],
    convention: Convention,
) -> Vec<RecoveredProto> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut callees: Vec<CalleeRaw> = Vec::with_capacity(functions.len());
    let mut callsites: BTreeMap<u64, Vec<CallSiteObs>> = BTreeMap::new();
    for function in functions {
        let instrs: Vec<Instruction> = decode_all(function.bytes, function.low_pc);
        let cfg: Cfg = cfg::build(&instrs);
        callees.push(analyze_callee(
            &instrs,
            &cfg,
            Some(convention),
            &mut factory,
        ));
        for (target, obs) in scan_callsites(&instrs, &mut factory) {
            callsites.entry(target).or_default().extend(obs);
        }
    }
    functions
        .iter()
        .zip(callees.iter())
        .map(|(function, callee): (&FunctionCode<'_>, &CalleeRaw)| {
            let empty: Vec<CallSiteObs> = Vec::new();
            let obs: &[CallSiteObs] = callsites
                .get(&function.low_pc)
                .map_or(empty.as_slice(), Vec::as_slice);
            unify(callee, obs)
        })
        .collect()
}

#[must_use]
pub fn called_targets(functions: &[FunctionCode<'_>]) -> BTreeSet<u64> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for function in functions {
        let instrs: Vec<Instruction> = decode_all(function.bytes, function.low_pc);
        for target in scan_callsites(&instrs, &mut factory).keys() {
            targets.insert(*target);
        }
    }
    targets
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn win64(a: u8) -> ArgLocation {
        ArgLocation::IntReg(a)
    }

    #[test]
    fn two_int_args_win64_from_entry_liveness() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x89, 0x4d, 0x10, 0x89, 0x55, 0x18, 0x8b, 0x45, 0x10, 0x03,
            0x45, 0x18, 0x5d, 0xc3,
        ];
        let proto: RecoveredProto = recover_proto(bytes, 0x1000);
        assert_eq!(proto.convention, Convention::Win64);
        assert_eq!(proto.args, vec![win64(3), win64(2)]);
        assert!(!proto.sret);
    }

    #[test]
    fn zero_args_when_first_write_precedes_read() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x5d, 0xc3,
        ];
        let proto: RecoveredProto = recover_proto(bytes, 0x1000);
        assert!(proto.args.is_empty());
    }

    #[test]
    fn zeroing_idiom_is_not_an_argument() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x31, 0xc9, 0x88, 0x4d, 0x10, 0x5d, 0xc3,
        ];
        let proto: RecoveredProto = recover_proto(bytes, 0x1000);
        assert!(
            proto.args.is_empty(),
            "xor ecx,ecx zeroes rcx; it is not a read-before-write argument: {:?}",
            proto.args,
        );
    }

    #[test]
    fn sysv_detection_from_rdi() {
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x89, 0x75, 0xf8, 0x8b, 0x45, 0xfc, 0x5d,
            0xc3,
        ];
        let proto: RecoveredProto = recover_proto(bytes, 0x1000);
        assert_eq!(proto.convention, Convention::SysVAmd64);
        assert_eq!(
            proto.args,
            vec![ArgLocation::IntReg(0), ArgLocation::IntReg(1)]
        );
    }

    #[test]
    fn return_used_confirms_int_return() {
        let callee: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x89, 0x4d, 0x10, 0x8b, 0x45, 0x10, 0x5d, 0xc3,
        ];
        let caller: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0xb9, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xe2, 0xff, 0xff, 0xff,
            0x89, 0x45, 0xfc, 0x5d, 0xc3,
        ];
        let functions: [FunctionCode<'_>; 2] = [
            FunctionCode {
                low_pc: 0x1000,
                bytes: callee,
            },
            FunctionCode {
                low_pc: 0x1010,
                bytes: caller,
            },
        ];
        let protos: Vec<RecoveredProto> = recover_protos(&functions, Convention::Win64);
        assert_eq!(protos[0].ret, ReturnKind::IntRax);
        assert_eq!(protos[0].arg_confidence, SigConfidence::High);
        assert_eq!(protos[0].args, vec![win64(3)]);
    }

    #[test]
    fn discarded_return_is_void() {
        let callee: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x89, 0x4d, 0x10, 0x8b, 0x45, 0x10, 0x5d, 0xc3,
        ];
        let caller: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0xb9, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xe2, 0xff, 0xff, 0xff,
            0x90, 0x5d, 0xc3,
        ];
        let functions: [FunctionCode<'_>; 2] = [
            FunctionCode {
                low_pc: 0x1000,
                bytes: callee,
            },
            FunctionCode {
                low_pc: 0x1010,
                bytes: caller,
            },
        ];
        let protos: Vec<RecoveredProto> = recover_protos(&functions, Convention::Win64);
        assert_eq!(protos[0].ret, ReturnKind::Void);
    }

    #[test]
    fn variadic_marker_is_detected() {
        let insns: &[u8] = &[0xb0, 0x02, 0xe8, 0x00, 0x00, 0x00, 0x00];
        let decoded: Vec<Instruction> = decode_all(insns, 0x1000);
        let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
        let sites: BTreeMap<u64, Vec<CallSiteObs>> = scan_callsites(&decoded, &mut factory);
        assert!(
            sites
                .values()
                .flatten()
                .any(|obs: &CallSiteObs| obs.variadic)
        );
    }
}
