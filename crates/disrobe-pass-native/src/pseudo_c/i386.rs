use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    CpuidFeature, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};

use crate::arch::{Arch, DisasmInsn, decode_one_x86, disassemble};
use crate::error::{Error, Result};

use super::{
    Abi, AggregatePlan, BinOp, Block, CallTarget, CondKind, EmptyObjectCallFacts, ExtSource, Flags,
    FnReturn, FnSignature, FramePlan, FrameShape, LeafItems, LeafRecovery, LifterCoverageTrace,
    MemRef, Node, ParameterBinding, RecoveredSignature, Reg, RegRef, ResolvedCall,
    RipRelativeLeaPolicy, Source, StackFrameBoundary, StackFrameExtent, Stmt, Structured, Width,
    annotate_calls_block, build_leaf_items, call_clobber, call_display_name, collect_call_targets,
    emit_c, infer_aggregate_plan, normalize_noreturn_guards, plan_frame,
    rewrite_incoming_stack_arguments, rewrite_incoming_stack_items, spilled_body, structure_items,
    x86_outgoing_argument_reg, x86_stack_argument_reg,
};

const WORD: i64 = 4;
const MAX_FUNCTION_INSTRUCTIONS: usize = 16_384;
const MAX_DATAFLOW_VISITS: usize = 1 << 20;
const MAX_CALLEE_INSTRUCTIONS: usize = 4_096;
const MAX_CALLEE_DEPTH: usize = 8;
const MAX_STACK_ARGUMENTS: usize = 8;
const MAX_FRAME_BYTES: i64 = 1 << 20;

const EAX: u8 = 0;
const ECX: u8 = 1;
const EDX: u8 = 2;
const EBX: u8 = 3;
const ESP: u8 = 4;
const EBP: u8 = 5;
const ESI: u8 = 6;
const EDI: u8 = 7;

const CALLEE_SAVED: [u8; 4] = [EBX, EBP, ESI, EDI];
const REGISTER_ARGUMENTS: [u8; 2] = [ECX, EDX];

const fn bit(gpr: u8) -> u8 {
    1 << gpr
}

const fn gpr_name(gpr: u8) -> &'static str {
    match gpr {
        EAX => "eax",
        ECX => "ecx",
        EDX => "edx",
        EBX => "ebx",
        ESP => "esp",
        EBP => "ebp",
        ESI => "esi",
        _ => "edi",
    }
}

const fn gpr_reg(gpr: u8) -> Reg {
    match gpr {
        EAX => Reg::Rax,
        ECX => Reg::Rcx,
        EDX => Reg::Rdx,
        EBX => Reg::Rbx,
        ESP => Reg::Rsp,
        EBP => Reg::Rbp,
        ESI => Reg::Rsi,
        _ => Reg::Rdi,
    }
}

const fn gpr_wide_name(gpr: u8) -> &'static str {
    match gpr {
        EAX => "rax",
        ECX => "rcx",
        EDX => "rdx",
        EBX => "rbx",
        ESP => "rsp",
        EBP => "rbp",
        ESI => "rsi",
        _ => "rdi",
    }
}

fn gpr_of(register: Register) -> Option<u8> {
    match register.full_register32() {
        Register::EAX => Some(EAX),
        Register::ECX => Some(ECX),
        Register::EDX => Some(EDX),
        Register::EBX => Some(EBX),
        Register::ESP => Some(ESP),
        Register::EBP => Some(EBP),
        Register::ESI => Some(ESI),
        Register::EDI => Some(EDI),
        _ => None,
    }
}

fn gpr32_of(register: Register) -> Option<u8> {
    if register.size() == 4 {
        gpr_of(register)
    } else {
        None
    }
}

fn refusal(address: u64, text: &str, why: &str) -> Error {
    Error::LlvmIr(format!("x86-32 `{text}` at {address:#x}: {why}"))
}

fn text(insn: &DisasmInsn) -> String {
    if insn.operands.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} {}", insn.mnemonic, insn.operands)
    }
}

const fn reads(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

const fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I386Convention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
}

impl I386Convention {
    pub const fn c_attribute(self) -> Option<&'static str> {
        match self {
            Self::Cdecl => None,
            Self::Stdcall => Some("__attribute__((stdcall))"),
            Self::Fastcall => Some("__attribute__((fastcall))"),
            Self::Thiscall => Some("__attribute__((thiscall))"),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Fastcall => "fastcall",
            Self::Thiscall => "thiscall",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I386Signature {
    pub convention: I386Convention,
    pub register_arguments: u8,
    pub stack_arguments: u8,
    pub callee_pop_bytes: u16,
    pub returns_edx_eax: bool,
}

impl I386Signature {
    pub(super) fn prototype(self, name: &str, return_width: Width) -> String {
        let count: usize =
            usize::from(self.register_arguments).saturating_add(usize::from(self.stack_arguments));
        let parameters: String = if count == 0 {
            "void".to_owned()
        } else {
            vec!["uint32_t"; count].join(", ")
        };
        let returned: &str = if self.returns_edx_eax {
            "uint64_t"
        } else {
            super::width_c_uint(return_width)
        };
        self.convention.c_attribute().map_or_else(
            || format!("extern {returned} {name}({parameters});"),
            |attribute: &str| format!("extern {returned} {attribute} {name}({parameters});"),
        )
    }
}

struct Image<'data> {
    sections: Vec<(u64, &'data [u8], bool)>,
}

impl<'data> Image<'data> {
    fn parse(object: &'data [u8]) -> Result<Option<Self>> {
        use object::{Object as _, ObjectSection as _};

        if object.is_empty() {
            return Ok(None);
        }
        let file: object::File<'data> = object::File::parse(object)
            .map_err(|error| Error::LlvmIr(format!("x86-32 image does not parse: {error}")))?;
        if file.architecture() != object::Architecture::I386 {
            return Err(Error::LlvmIr(format!(
                "x86-32 recovery needs an i386 image, not {:?}",
                file.architecture()
            )));
        }
        if !matches!(
            file.kind(),
            object::ObjectKind::Executable | object::ObjectKind::Dynamic
        ) {
            return Err(Error::LlvmIr(
                "x86-32 recovery needs a linked executable or shared library; call targets and global addresses in a relocatable object are only known through relocations"
                    .to_owned(),
            ));
        }
        let mut sections: Vec<(u64, &'data [u8], bool)> = Vec::new();
        for section in file.sections() {
            let Ok(data) = section.data() else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            let executable: bool = section.kind() == object::SectionKind::Text;
            sections.push((section.address(), data, executable));
        }
        Ok(Some(Self { sections }))
    }

    fn code_at(&self, address: u64) -> Option<&'data [u8]> {
        self.sections
            .iter()
            .filter(|(_, _, executable)| *executable)
            .find_map(|(start, data, _)| {
                let offset: usize = usize::try_from(address.checked_sub(*start)?).ok()?;
                data.get(offset..).filter(|rest: &&[u8]| !rest.is_empty())
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CalleeFacts {
    pop_bytes: u16,
    returns: bool,
    clobbers: u8,
    register_arguments: u8,
    xmm_clobbers: u32,
}

impl CalleeFacts {
    const fn writes_edx(self) -> bool {
        self.clobbers & bit(EDX) != 0
    }
}

struct CalleeScan<'image, 'data> {
    image: &'image Image<'data>,
    memo: BTreeMap<u64, Option<CalleeFacts>>,
    active: BTreeSet<u64>,
    factory: InstructionInfoFactory,
}

impl CalleeScan<'_, '_> {
    fn facts(&mut self, entry: u64, depth: usize) -> Option<CalleeFacts> {
        if let Some(known) = self.memo.get(&entry) {
            return *known;
        }
        if depth > MAX_CALLEE_DEPTH || !self.active.insert(entry) {
            return None;
        }
        let scanned: Option<CalleeFacts> = self.scan(entry, depth);
        self.active.remove(&entry);
        self.memo.insert(entry, scanned);
        scanned
    }

    fn scan(&mut self, entry: u64, depth: usize) -> Option<CalleeFacts> {
        let mut defined_at: BTreeMap<u64, u8> = BTreeMap::new();
        let mut pending: Vec<(u64, u8)> = vec![(entry, 0)];
        let mut visits: usize = 0;
        let mut pop_bytes: Option<u16> = None;
        let mut clobbers: u8 = 0;
        let mut register_arguments: u8 = 0;
        let mut xmm_clobbers: u32 = 0;
        while let Some((address, incoming)) = pending.pop() {
            visits = visits.checked_add(1)?;
            if visits > MAX_CALLEE_INSTRUCTIONS {
                return None;
            }
            let defined: u8 = match defined_at.get(&address) {
                Some(known) if known & incoming == *known => continue,
                Some(known) => known & incoming,
                None => incoming,
            };
            defined_at.insert(address, defined);
            let bytes: &[u8] = self.image.code_at(address)?;
            let decoded: Instruction = decode_one_x86(32, address, bytes)?;
            let info = self.factory.info(&decoded);
            let mut after: u8 = defined;
            for used in info.used_registers() {
                if let Some(gpr) = gpr_of(used.register()) {
                    if reads(used.access())
                        && REGISTER_ARGUMENTS.contains(&gpr)
                        && defined & bit(gpr) == 0
                    {
                        register_arguments |= bit(gpr);
                    }
                    if writes(used.access()) {
                        if matches!(gpr, EAX | ECX | EDX) {
                            clobbers |= bit(gpr);
                        }
                        after |= bit(gpr);
                    }
                } else if let Some(index) = xmm_index(used.register())
                    && writes(used.access())
                {
                    xmm_clobbers |= 1 << index;
                }
            }
            let next: u64 = decoded.next_ip32().into();
            match decoded.flow_control() {
                FlowControl::Next => pending.push((next, after)),
                FlowControl::Return => {
                    let popped: u16 = if decoded.op_count() == 1 {
                        decoded.immediate16()
                    } else {
                        0
                    };
                    if pop_bytes.is_some_and(|known: u16| known != popped) {
                        return None;
                    }
                    pop_bytes = Some(popped);
                }
                FlowControl::Call => {
                    let nested: CalleeFacts =
                        self.facts(decoded.near_branch_target(), depth.checked_add(1)?)?;
                    if !nested.returns {
                        continue;
                    }
                    if nested.register_arguments & !after != 0 {
                        register_arguments |= nested.register_arguments & !after;
                    }
                    clobbers |= nested.clobbers | bit(EAX);
                    xmm_clobbers |= nested.xmm_clobbers;
                    pending.push((next, (after | bit(EAX)) & !(nested.clobbers & !bit(EAX))));
                }
                FlowControl::UnconditionalBranch => {
                    pending.push((decoded.near_branch_target(), after));
                }
                FlowControl::ConditionalBranch => {
                    pending.push((decoded.near_branch_target(), after));
                    pending.push((next, after));
                }
                FlowControl::Exception | FlowControl::Interrupt => {}
                FlowControl::IndirectBranch
                | FlowControl::IndirectCall
                | FlowControl::XbeginXabortXend => return None,
            }
        }
        Some(CalleeFacts {
            pop_bytes: pop_bytes.unwrap_or(0),
            returns: pop_bytes.is_some(),
            clobbers,
            register_arguments,
            xmm_clobbers,
        })
    }
}

fn xmm_index(register: Register) -> Option<u32> {
    let full: Register = register.full_register();
    let index: u32 = (full as u32).checked_sub(Register::ZMM0 as u32)?;
    (index < 8).then_some(index)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    Free,
    At(i64),
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    depth: i64,
    anchor: Anchor,
    realigned: Option<i64>,
    defined: u8,
    written: u8,
    consts: [Option<u32>; 8],
}

impl State {
    const fn entry() -> Self {
        Self {
            depth: 0,
            anchor: Anchor::Free,
            realigned: None,
            defined: 0,
            written: 0,
            consts: [None; 8],
        }
    }

    fn join(&mut self, other: &Self, address: u64) -> Result<bool> {
        if self.depth != other.depth {
            return Err(Error::LlvmIr(format!(
                "x86-32 stack depth differs at the join {address:#x} ({} against {} bytes below the entry stack pointer), so no frame offset is constant there",
                -self.depth, -other.depth
            )));
        }
        if self.realigned != other.realigned {
            return Err(Error::LlvmIr(format!(
                "x86-32 stack is realigned on some paths into the join {address:#x} and not on others"
            )));
        }
        let before: Self = self.clone();
        if self.anchor != other.anchor {
            self.anchor = Anchor::Conflict;
        }
        self.defined &= other.defined;
        self.written |= other.written;
        for (mine, theirs) in self.consts.iter_mut().zip(other.consts.iter()) {
            if mine != theirs {
                *mine = None;
            }
        }
        Ok(*self != before)
    }

    fn write(&mut self, gpr: u8) {
        self.defined |= bit(gpr);
        self.written |= bit(gpr);
        if let Some(slot) = self.consts.get_mut(usize::from(gpr)) {
            *slot = None;
        }
        if gpr == EBP {
            self.anchor = Anchor::Free;
        }
    }

    fn set_const(&mut self, gpr: u8, value: u32) {
        self.write(gpr);
        if let Some(slot) = self.consts.get_mut(usize::from(gpr)) {
            *slot = Some(value);
        }
    }

    fn constant(&self, gpr: u8) -> Option<u32> {
        self.consts.get(usize::from(gpr)).copied().flatten()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PicIdiom {
    CallNext { register: u8, value: u32 },
    PopNext,
    Thunk { register: u8, value: u32 },
}

#[derive(Debug, Clone, Copy)]
struct CallSite {
    target: u64,
    facts: CalleeFacts,
    returns_edx_eax: bool,
    resolved_signature: Option<I386Signature>,
}

struct Decoded {
    insn: DisasmInsn,
    decoded: Instruction,
}

struct Analysis {
    before: Vec<Option<State>>,
    pop_bytes: Option<u16>,
    min_depth: i64,
    live_in: BTreeMap<u8, u64>,
    returns_edx_eax: bool,
    pic: BTreeMap<usize, PicIdiom>,
    calls: BTreeMap<usize, CallSite>,
    saves: BTreeMap<usize, i64>,
    restores: BTreeSet<usize>,
}

struct Function<'a> {
    code: Vec<Decoded>,
    index: BTreeMap<u64, usize>,
    start: u64,
    end: u64,
    image: Option<&'a Image<'a>>,
    resolved: &'a [ResolvedCall],
}

fn x87_or_mmx(decoded: &Instruction) -> Option<&'static str> {
    decoded
        .cpuid_features()
        .iter()
        .find_map(|feature| match feature {
            CpuidFeature::FPU | CpuidFeature::FPU287 | CpuidFeature::FPU387 => Some(
                "x87 floating point (st(0) returns and the x87 register stack) is not modelled",
            ),
            CpuidFeature::MMX => Some("MMX registers are not modelled"),
            _ => None,
        })
}

fn decode_function(base: u64, machine_code: &[u8]) -> Result<Vec<Decoded>> {
    let insns: Vec<DisasmInsn> = disassemble(Arch::X86, base, machine_code)?;
    if insns.is_empty() {
        return Err(Error::LlvmIr("no decodable instructions".to_owned()));
    }
    if insns.len() > MAX_FUNCTION_INSTRUCTIONS {
        return Err(Error::LlvmIr(format!(
            "x86-32 function has {} instructions, over the {MAX_FUNCTION_INSTRUCTIONS}-instruction lift bound",
            insns.len()
        )));
    }
    insns
        .into_iter()
        .map(|insn: DisasmInsn| {
            let decoded: Instruction = decode_one_x86(32, insn.address, &insn.bytes)
                .ok_or_else(|| refusal(insn.address, &text(&insn), "does not decode"))?;
            Ok(Decoded { insn, decoded })
        })
        .collect()
}

fn mov_register_from_esp_load(decoded: &Instruction) -> Option<u8> {
    (decoded.mnemonic() == Mnemonic::Mov
        && decoded.op_count() == 2
        && decoded.op0_kind() == OpKind::Register
        && decoded.op1_kind() == OpKind::Memory
        && decoded.memory_base() == Register::ESP
        && decoded.memory_index() == Register::None
        && decoded.memory_displacement32() == 0)
        .then(|| gpr32_of(decoded.op0_register()))
        .flatten()
}

fn thunk_register(image: &Image<'_>, target: u64) -> Option<u8> {
    let bytes: &[u8] = image.code_at(target)?;
    let first: Instruction = decode_one_x86(32, target, bytes)?;
    let register: u8 = mov_register_from_esp_load(&first)?;
    let next: u64 = first.next_ip32().into();
    let second: Instruction = decode_one_x86(32, next, image.code_at(next)?)?;
    (second.mnemonic() == Mnemonic::Ret && second.op_count() == 0).then_some(register)
}

fn ret_pop_bytes(decoded: &Instruction) -> u16 {
    if decoded.op_count() == 1 {
        decoded.immediate16()
    } else {
        0
    }
}

const fn register_mask(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => bit(ECX),
        _ => bit(ECX) | bit(EDX),
    }
}

const fn register_count(mask: u8) -> u8 {
    if mask & bit(EDX) != 0 {
        2
    } else if mask & bit(ECX) != 0 {
        1
    } else {
        0
    }
}

fn signature_facts(signature: I386Signature) -> CalleeFacts {
    CalleeFacts {
        pop_bytes: signature.callee_pop_bytes,
        returns: true,
        clobbers: bit(EAX) | bit(ECX) | bit(EDX),
        register_arguments: register_mask(signature.register_arguments),
        xmm_clobbers: 0xff,
    }
}

impl Function<'_> {
    fn position(&self, address: u64, from: u64) -> Result<usize> {
        self.index.get(&address).copied().ok_or_else(|| {
            Error::LlvmIr(format!(
                "x86-32 branch at {from:#x} lands at {address:#x}, which is not an instruction boundary of the linear decode"
            ))
        })
    }

    fn inside(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }

    fn resolved_signature(&self, target: u64) -> Option<I386Signature> {
        self.resolved
            .iter()
            .find(|call: &&ResolvedCall| call.target == target)
            .and_then(|call: &ResolvedCall| call.signature.i386)
    }

    fn call_site(&self, scan: &mut Option<CalleeScan<'_, '_>>, at: &Decoded) -> Result<CallSite> {
        let target: u64 = at.decoded.near_branch_target();
        let resolved: Option<I386Signature> = self.resolved_signature(target);
        let scanned: Option<CalleeFacts> = scan
            .as_mut()
            .and_then(|scan: &mut CalleeScan<'_, '_>| scan.facts(target, 0));
        let facts: CalleeFacts = match (scanned, resolved) {
            (Some(facts), _) => facts,
            (None, Some(signature)) => signature_facts(signature),
            (None, None) => {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "the callee's own code is not available to prove how many argument bytes it pops and which caller-saved registers it writes, so the stack depth after the call is not known",
                ));
            }
        };
        if !facts.returns {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "the callee has no reachable return instruction, and a call that does not return is not modelled for x86-32",
            ));
        }
        if let Some(signature) = resolved
            && signature.callee_pop_bytes != facts.pop_bytes
        {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "the resolved callee's signature and its own return instructions disagree on the argument bytes it pops",
            ));
        }
        let returns_edx_eax: bool = resolved.map_or_else(
            || facts.writes_edx(),
            |signature: I386Signature| signature.returns_edx_eax,
        );
        Ok(CallSite {
            target,
            facts,
            returns_edx_eax,
            resolved_signature: resolved,
        })
    }

    fn pic_idioms(&self) -> BTreeMap<usize, PicIdiom> {
        let mut idioms: BTreeMap<usize, PicIdiom> = BTreeMap::new();
        for (position, at) in self.code.iter().enumerate() {
            if at.decoded.flow_control() != FlowControl::Call
                || at.decoded.op0_kind() != OpKind::NearBranch32
            {
                continue;
            }
            let target: u64 = at.decoded.near_branch_target();
            let next: u64 = at.decoded.next_ip32().into();
            let Ok(value) = u32::try_from(next) else {
                continue;
            };
            if target == next
                && let Some(following) = self.code.get(position + 1)
                && following.decoded.mnemonic() == Mnemonic::Pop
                && following.decoded.op0_kind() == OpKind::Register
                && let Some(register) = gpr32_of(following.decoded.op0_register())
                && register != ESP
            {
                idioms.insert(position, PicIdiom::CallNext { register, value });
                idioms.insert(position + 1, PicIdiom::PopNext);
                continue;
            }
            if let Some(image) = self.image
                && let Some(register) = thunk_register(image, target)
                && register != ESP
            {
                idioms.insert(position, PicIdiom::Thunk { register, value });
            }
        }
        idioms
    }

    fn successors(&self, position: usize, at: &Decoded) -> Result<Vec<usize>> {
        let next = || -> Result<usize> {
            if position + 1 < self.code.len() {
                Ok(position + 1)
            } else {
                Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "execution falls through the end of the function body",
                ))
            }
        };
        match at.decoded.flow_control() {
            FlowControl::Next | FlowControl::Call => Ok(vec![next()?]),
            FlowControl::Return | FlowControl::Exception => Ok(Vec::new()),
            FlowControl::Interrupt => {
                if at.decoded.mnemonic() == Mnemonic::Int3 {
                    Ok(Vec::new())
                } else {
                    Err(refusal(
                        at.insn.address,
                        &text(&at.insn),
                        "a software interrupt is not modelled",
                    ))
                }
            }
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                let target: u64 = at.decoded.near_branch_target();
                if !self.inside(target) {
                    return Err(refusal(
                        at.insn.address,
                        &text(&at.insn),
                        "a jump out of the function (a tail call) is not modelled for x86-32",
                    ));
                }
                let mut out: Vec<usize> = vec![self.position(target, at.insn.address)?];
                if at.decoded.flow_control() == FlowControl::ConditionalBranch {
                    out.push(next()?);
                }
                Ok(out)
            }
            FlowControl::IndirectBranch => Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "an indirect jump (a switch table or a tail call through a pointer) is not modelled for x86-32",
            )),
            FlowControl::IndirectCall => Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "a call through memory or a register has no known x86-32 calling convention or argument count",
            )),
            FlowControl::XbeginXabortXend => Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "transactional memory is not modelled",
            )),
        }
    }
}

fn esp_write_refusal(at: &Decoded) -> Error {
    refusal(
        at.insn.address,
        &text(&at.insn),
        "the stack pointer is written in a way that is not a push, a pop, a constant adjustment or a frame-pointer restore, so no frame offset is constant after it",
    )
}

fn immediate_operand(decoded: &Instruction, operand: u32) -> Option<i64> {
    match decoded.op_kind(operand) {
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32 => Some(i64::from(decoded.immediate(operand) as u32 as i32)),
        _ => None,
    }
}

struct Transfer {
    after: State,
    successors: Vec<usize>,
}

fn stack_effect(
    at: &Decoded,
    state: &State,
    call: Option<&CallSite>,
    pic: Option<PicIdiom>,
) -> Result<Option<i64>> {
    let decoded: &Instruction = &at.decoded;
    if let Some(idiom) = pic {
        return Ok(Some(match idiom {
            PicIdiom::CallNext { .. } => state.depth - WORD,
            PicIdiom::PopNext => state.depth + WORD,
            PicIdiom::Thunk { .. } => state.depth,
        }));
    }
    let delta = |amount: i64| -> Option<i64> { state.depth.checked_add(amount) };
    let found: Option<i64> = match decoded.mnemonic() {
        Mnemonic::Push => {
            let fits: bool = match decoded.op0_kind() {
                OpKind::Register => gpr32_of(decoded.op0_register()).is_some(),
                OpKind::Immediate8to32 | OpKind::Immediate32 => true,
                OpKind::Memory => decoded.memory_size().size() == 4,
                _ => false,
            };
            if !fits {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "only four-byte pushes of a general register, an immediate or memory are modelled",
                ));
            }
            delta(-WORD)
        }
        Mnemonic::Pop => {
            if decoded.op0_kind() != OpKind::Register
                || gpr32_of(decoded.op0_register()).is_none_or(|gpr: u8| gpr == ESP)
            {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "only a pop into a general register other than esp is modelled",
                ));
            }
            delta(WORD)
        }
        Mnemonic::Sub | Mnemonic::Add
            if decoded.op0_kind() == OpKind::Register
                && decoded.op0_register() == Register::ESP =>
        {
            let amount: i64 = immediate_operand(decoded, 1).ok_or_else(|| esp_write_refusal(at))?;
            if decoded.mnemonic() == Mnemonic::Sub {
                delta(-amount)
            } else {
                delta(amount)
            }
        }
        Mnemonic::Lea
            if decoded.op0_kind() == OpKind::Register
                && decoded.op0_register() == Register::ESP =>
        {
            if decoded.memory_index() != Register::None {
                return Err(esp_write_refusal(at));
            }
            let displacement: i64 = i64::from(decoded.memory_displacement32() as i32);
            match (decoded.memory_base(), state.anchor) {
                (Register::ESP, _) => delta(displacement),
                (Register::EBP, Anchor::At(anchor)) => anchor.checked_add(displacement),
                _ => return Err(esp_write_refusal(at)),
            }
        }
        Mnemonic::Mov
            if decoded.op0_kind() == OpKind::Register
                && decoded.op0_register() == Register::ESP =>
        {
            match (decoded.op1_kind(), decoded.op1_register(), state.anchor) {
                (OpKind::Register, Register::EBP, Anchor::At(anchor)) => Some(anchor),
                _ => return Err(esp_write_refusal(at)),
            }
        }
        Mnemonic::Leave => match state.anchor {
            Anchor::At(anchor) => anchor.checked_add(WORD),
            Anchor::Free | Anchor::Conflict => {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "leave restores the stack pointer from ebp, which holds no proven frame anchor here",
                ));
            }
        },
        Mnemonic::Call => match call {
            Some(site) => delta(i64::from(site.facts.pop_bytes)),
            None => return Ok(None),
        },
        Mnemonic::Ret => {
            if state.depth != 0 {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    &format!(
                        "returns with the stack pointer {} bytes away from its entry value",
                        -state.depth
                    ),
                ));
            }
            Some(0)
        }
        Mnemonic::Enter
        | Mnemonic::Pushad
        | Mnemonic::Popad
        | Mnemonic::Pusha
        | Mnemonic::Popa
        | Mnemonic::Pushfd
        | Mnemonic::Popfd
        | Mnemonic::Pushf
        | Mnemonic::Popf => {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "enter, pusha, popa, pushf and popf are not modelled",
            ));
        }
        Mnemonic::And
            if decoded.op0_kind() == OpKind::Register
                && decoded.op0_register() == Register::ESP =>
        {
            let mask: i64 = immediate_operand(decoded, 1).ok_or_else(|| esp_write_refusal(at))?;
            let alignment: i64 = mask.checked_neg().unwrap_or(0);
            if !matches!(state.anchor, Anchor::At(_))
                || state.realigned.is_some()
                || !(4..=64).contains(&alignment)
                || alignment & (alignment - 1) != 0
            {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "the stack pointer is realigned by a mask without a frame pointer that restores it, so no frame offset is constant relative to entry",
                ));
            }
            Some(state.depth)
        }
        _ => {
            if writes_esp(decoded) {
                return Err(esp_write_refusal(at));
            }
            Some(state.depth)
        }
    };
    let depth: i64 = found.ok_or_else(|| esp_write_refusal(at))?;
    if !(-MAX_FRAME_BYTES..=0).contains(&depth) {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "moves the stack pointer outside the bounded frame of this function",
        ));
    }
    Ok(Some(depth))
}

fn is_register_nop(decoded: &Instruction, state: &State) -> bool {
    if decoded.op_count() != 2 || decoded.op0_kind() != OpKind::Register {
        return false;
    }
    let Some(register) = gpr32_of(decoded.op0_register()) else {
        return false;
    };
    let frame_register: bool =
        register == ESP || (register == EBP && matches!(state.anchor, Anchor::At(_)));
    match decoded.mnemonic() {
        Mnemonic::Mov => {
            decoded.op1_kind() == OpKind::Register
                && decoded.op1_register() == decoded.op0_register()
        }
        Mnemonic::Lea => {
            !frame_register
                && decoded.memory_index() == Register::None
                && decoded.memory_displacement32() == 0
                && gpr32_of(decoded.memory_base()) == Some(register)
        }
        _ => false,
    }
}

fn writes_esp(decoded: &Instruction) -> bool {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    factory
        .info(decoded)
        .used_registers()
        .iter()
        .any(|used| gpr_of(used.register()) == Some(ESP) && writes(used.access()))
}

fn constant_after(decoded: &Instruction, state: &State) -> Option<(u8, u32)> {
    if decoded.op_count() == 0 || decoded.op0_kind() != OpKind::Register {
        return None;
    }
    let register: u8 = gpr32_of(decoded.op0_register())?;
    match decoded.mnemonic() {
        Mnemonic::Mov => match decoded.op1_kind() {
            OpKind::Immediate32 => Some((register, decoded.immediate32())),
            OpKind::Register => {
                let source: u8 = gpr32_of(decoded.op1_register())?;
                Some((register, state.constant(source)?))
            }
            _ => None,
        },
        Mnemonic::Add | Mnemonic::Sub => {
            let current: u32 = state.constant(register)?;
            let amount: u32 = immediate_operand(decoded, 1)? as u32;
            Some((
                register,
                if decoded.mnemonic() == Mnemonic::Add {
                    current.wrapping_add(amount)
                } else {
                    current.wrapping_sub(amount)
                },
            ))
        }
        Mnemonic::Lea => {
            let base: u32 = match decoded.memory_base() {
                Register::None => 0,
                other => state.constant(gpr32_of(other)?)?,
            };
            let index: u32 = match decoded.memory_index() {
                Register::None => 0,
                other => state
                    .constant(gpr32_of(other)?)?
                    .wrapping_mul(decoded.memory_index_scale()),
            };
            Some((
                register,
                base.wrapping_add(index)
                    .wrapping_add(decoded.memory_displacement32()),
            ))
        }
        _ => None,
    }
}

fn transfer(
    function: &Function<'_>,
    factory: &mut InstructionInfoFactory,
    position: usize,
    state: &State,
    analysis: &Analysis,
    restores: &BTreeSet<usize>,
) -> Result<Transfer> {
    let at: &Decoded = &function.code[position];
    if let Some(why) = x87_or_mmx(&at.decoded) {
        return Err(refusal(at.insn.address, &text(&at.insn), why));
    }
    let pic: Option<PicIdiom> = analysis.pic.get(&position).copied();
    let call: Option<&CallSite> = analysis.calls.get(&position);
    let successors: Vec<usize> = function.successors(position, at)?;
    if pic.is_none() && at.decoded.flow_control() == FlowControl::Call && call.is_none() {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "the call's stack effect was not analysed",
        ));
    }
    let depth: i64 = stack_effect(at, state, call, pic)?.ok_or_else(|| {
        refusal(
            at.insn.address,
            &text(&at.insn),
            "the call's stack effect is unknown",
        )
    })?;
    let mut after: State = state.clone();
    after.depth = depth;
    let restores_from_anchor: bool = matches!(at.decoded.mnemonic(), Mnemonic::Leave)
        || (matches!(at.decoded.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
            && at.decoded.op0_kind() == OpKind::Register
            && at.decoded.op0_register() == Register::ESP);
    if at.decoded.mnemonic() == Mnemonic::And
        && at.decoded.op0_kind() == OpKind::Register
        && at.decoded.op0_register() == Register::ESP
    {
        after.realigned = Some(depth);
    } else if restores_from_anchor && state.realigned.is_some() {
        after.realigned = None;
    } else if let Some(point) = state.realigned
        && depth > point
    {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "the stack pointer moves back above the point where it was realigned without being restored from the frame pointer",
        ));
    }
    if at.decoded.mnemonic() == Mnemonic::Ret && state.realigned.is_some() {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "returns while the stack is still realigned",
        ));
    }
    if is_register_nop(&at.decoded, state) {
        return Ok(Transfer { after, successors });
    }
    match pic {
        Some(PicIdiom::CallNext { .. }) => {
            return Ok(Transfer {
                after,
                successors: vec![position + 1],
            });
        }
        Some(PicIdiom::PopNext) => {
            if let Some(PicIdiom::CallNext { register, value }) = position
                .checked_sub(1)
                .and_then(|prior| analysis.pic.get(&prior))
                .copied()
            {
                after.set_const(register, value);
            }
            return Ok(Transfer { after, successors });
        }
        Some(PicIdiom::Thunk { register, value }) => {
            after.set_const(register, value);
            return Ok(Transfer { after, successors });
        }
        None => {}
    }
    let decoded: &Instruction = &at.decoded;
    if let Some(site) = call {
        let clobbers: u8 = site.facts.clobbers;
        for gpr in [EAX, ECX, EDX] {
            let keeps: bool = clobbers & bit(gpr) == 0;
            if gpr == EAX || (gpr == EDX && site.returns_edx_eax) {
                after.write(gpr);
            } else if !keeps {
                after.defined &= !bit(gpr);
                after.written |= bit(gpr);
                after.consts[usize::from(gpr)] = None;
            }
        }
        return Ok(Transfer { after, successors });
    }
    if decoded.mnemonic() == Mnemonic::Mov
        && decoded.op0_kind() == OpKind::Register
        && decoded.op0_register() == Register::EBP
        && decoded.op1_kind() == OpKind::Register
        && decoded.op1_register() == Register::ESP
    {
        after.write(EBP);
        after.anchor = Anchor::At(state.depth);
        return Ok(Transfer { after, successors });
    }
    if decoded.mnemonic() == Mnemonic::Leave {
        if restores.contains(&position) {
            after.defined &= !bit(EBP);
        } else {
            after.defined |= bit(EBP);
        }
        after.written |= bit(EBP);
        after.consts[usize::from(EBP)] = None;
        after.anchor = Anchor::Free;
        return Ok(Transfer { after, successors });
    }
    let constant: Option<(u8, u32)> = constant_after(decoded, state);
    let info = factory.info(decoded);
    for used in info.used_registers() {
        let Some(gpr) = gpr_of(used.register()) else {
            continue;
        };
        if gpr == ESP || !writes(used.access()) {
            continue;
        }
        if used.access() == OpAccess::CondWrite || used.access() == OpAccess::ReadCondWrite {
            after.written |= bit(gpr);
            after.consts[usize::from(gpr)] = None;
            if gpr == EBP {
                after.anchor = Anchor::Free;
            }
            continue;
        }
        after.write(gpr);
    }
    if restores.contains(&position)
        && decoded.op0_kind() == OpKind::Register
        && let Some(gpr) = gpr32_of(decoded.op0_register())
    {
        after.defined &= !bit(gpr);
    }
    if let Some((register, value)) = constant {
        after.set_const(register, value);
    }
    Ok(Transfer { after, successors })
}

fn note_live_in(
    function: &Function<'_>,
    factory: &mut InstructionInfoFactory,
    position: usize,
    state: &State,
    analysis: &Analysis,
    live_in: &mut BTreeMap<u8, u64>,
) {
    let at: &Decoded = &function.code[position];
    if analysis.pic.contains_key(&position)
        || analysis.saves.contains_key(&position)
        || analysis.restores.contains(&position)
        || is_register_nop(&at.decoded, state)
    {
        return;
    }
    let mut note = |gpr: u8| {
        if gpr != ESP && state.defined & bit(gpr) == 0 {
            live_in.entry(gpr).or_insert(at.insn.address);
        }
    };
    if let Some(site) = analysis.calls.get(&position) {
        for gpr in REGISTER_ARGUMENTS {
            if site.facts.register_arguments & bit(gpr) != 0 {
                note(gpr);
            }
        }
        return;
    }
    let decoded: &Instruction = &at.decoded;
    if decoded.mnemonic() == Mnemonic::Push
        && decoded.op0_kind() == OpKind::Register
        && let Some(gpr) = gpr32_of(decoded.op0_register())
    {
        if state.defined & bit(gpr) == 0
            && (state.written & bit(gpr) != 0
                || pushed_value_read(function, analysis, position, state.depth - WORD))
        {
            note(gpr);
        }
        return;
    }
    if matches!(decoded.mnemonic(), Mnemonic::Sbb | Mnemonic::Adc)
        && decoded.op0_kind() == OpKind::Register
        && decoded.op1_kind() == OpKind::Register
        && decoded.op0_register() == decoded.op1_register()
    {
        return;
    }
    if decoded.mnemonic() == Mnemonic::Leave
        || (decoded.mnemonic() == Mnemonic::Mov
            && decoded.op0_kind() == OpKind::Register
            && decoded.op0_register() == Register::ESP)
    {
        return;
    }
    let info = factory.info(decoded);
    for used in info.used_registers() {
        if let Some(gpr) = gpr_of(used.register())
            && reads(used.access())
        {
            if gpr == EBP && matches!(state.anchor, Anchor::At(_)) {
                continue;
            }
            note(gpr);
        }
    }
}

fn pushed_value_read(function: &Function<'_>, analysis: &Analysis, push: usize, slot: i64) -> bool {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut pending: Vec<usize> = function
        .successors(push, &function.code[push])
        .unwrap_or_default();
    while let Some(position) = pending.pop() {
        if !seen.insert(position) {
            continue;
        }
        let Some(Some(state)) = analysis.before.get(position) else {
            continue;
        };
        if state.depth > slot {
            continue;
        }
        let at: &Decoded = &function.code[position];
        let decoded: &Instruction = &at.decoded;
        if analysis.calls.contains_key(&position) {
            return true;
        }
        if decoded.mnemonic() == Mnemonic::Pop && state.depth == slot {
            return true;
        }
        if decoded.mnemonic() == Mnemonic::Push && state.depth.saturating_sub(WORD) == slot {
            continue;
        }
        if let Some((start, end)) = memory_range(decoded, state)
            && start < slot.saturating_add(WORD)
            && slot < end
        {
            let info = factory.info(decoded);
            let overwrites: bool = start == slot
                && end == slot.saturating_add(WORD)
                && info
                    .used_memory()
                    .iter()
                    .all(|memory| memory.access() == OpAccess::Write);
            if overwrites {
                continue;
            }
            return true;
        }
        match function.successors(position, at) {
            Ok(next) => pending.extend(next),
            Err(_) => return true,
        }
    }
    false
}

fn analyse(function: &Function<'_>, scan: &mut Option<CalleeScan<'_, '_>>) -> Result<Analysis> {
    for at in &function.code {
        if let Some(why) = x87_or_mmx(&at.decoded) {
            return Err(refusal(at.insn.address, &text(&at.insn), why));
        }
    }
    let pic: BTreeMap<usize, PicIdiom> = function.pic_idioms();
    let mut calls: BTreeMap<usize, CallSite> = BTreeMap::new();
    for (position, at) in function.code.iter().enumerate() {
        if pic.contains_key(&position) || at.decoded.flow_control() != FlowControl::Call {
            continue;
        }
        if at.decoded.op0_kind() != OpKind::NearBranch32 {
            continue;
        }
        let target: u64 = at.decoded.near_branch_target();
        if function.inside(target) {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                if target == function.start {
                    "a recursive call to the function itself is not modelled for x86-32"
                } else {
                    "a call into the middle of the same function is not modelled"
                },
            ));
        }
        calls.insert(position, function.call_site(scan, at)?);
    }
    let mut analysis: Analysis = Analysis {
        before: Vec::new(),
        pop_bytes: None,
        min_depth: 0,
        live_in: BTreeMap::new(),
        returns_edx_eax: false,
        pic,
        calls,
        saves: BTreeMap::new(),
        restores: BTreeSet::new(),
    };
    analysis.before = run_dataflow(function, &analysis, &BTreeSet::new())?;
    classify_saves(function, &mut analysis)?;
    let restores: BTreeSet<usize> = analysis.restores.clone();
    analysis.before = run_dataflow(function, &analysis, &restores)?;
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut live_in: BTreeMap<u8, u64> = BTreeMap::new();
    let mut pop_bytes: Option<u16> = None;
    let mut every_return_defines_edx: bool = true;
    let mut min_depth: i64 = 0;
    for (position, state) in analysis.before.iter().enumerate() {
        let Some(state) = state else {
            continue;
        };
        min_depth = min_depth.min(state.depth);
        note_live_in(
            function,
            &mut factory,
            position,
            state,
            &analysis,
            &mut live_in,
        );
        let at: &Decoded = &function.code[position];
        if at.decoded.mnemonic() == Mnemonic::Ret {
            let popped: u16 = ret_pop_bytes(&at.decoded);
            if pop_bytes.is_some_and(|known: u16| known != popped) {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "the function's returns pop different numbers of argument bytes",
                ));
            }
            pop_bytes = Some(popped);
            if state.written & bit(EDX) == 0 || state.defined & bit(EDX) == 0 {
                every_return_defines_edx = false;
            }
        }
        if let Some(PicIdiom::CallNext { .. }) = analysis.pic.get(&position) {
            min_depth = min_depth.min(state.depth - WORD);
        }
    }
    if pop_bytes.is_none() {
        return Err(Error::LlvmIr(
            "no ret found; not a single-exit leaf".to_owned(),
        ));
    }
    analysis.pop_bytes = pop_bytes;
    analysis.min_depth = min_depth;
    analysis.live_in = live_in;
    analysis.returns_edx_eax = every_return_defines_edx;
    Ok(analysis)
}

fn run_dataflow(
    function: &Function<'_>,
    analysis: &Analysis,
    restores: &BTreeSet<usize>,
) -> Result<Vec<Option<State>>> {
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut before: Vec<Option<State>> = vec![None; function.code.len()];
    before[0] = Some(State::entry());
    let mut pending: BTreeSet<usize> = BTreeSet::from([0]);
    let mut visits: usize = 0;
    while let Some(position) = pending.pop_first() {
        visits += 1;
        if visits > MAX_DATAFLOW_VISITS {
            return Err(Error::LlvmIr(
                "x86-32 stack and register analysis did not converge within its bound".to_owned(),
            ));
        }
        let Some(state) = before[position].clone() else {
            continue;
        };
        let transfer: Transfer =
            transfer(function, &mut factory, position, &state, analysis, restores)?;
        for successor in transfer.successors {
            let address: u64 = function.code[successor].insn.address;
            let changed: bool = match &mut before[successor] {
                Some(existing) => existing.join(&transfer.after, address)?,
                slot @ None => {
                    *slot = Some(transfer.after.clone());
                    true
                }
            };
            if changed {
                pending.insert(successor);
            }
        }
    }
    Ok(before)
}

fn memory_range(decoded: &Instruction, state: &State) -> Option<(i64, i64)> {
    let operand_memory: bool =
        (0..decoded.op_count()).any(|operand: u32| decoded.op_kind(operand) == OpKind::Memory);
    if !operand_memory || decoded.mnemonic() == Mnemonic::Lea {
        return None;
    }
    let displacement: i64 = i64::from(decoded.memory_displacement32() as i32);
    let start: i64 = match (decoded.memory_base(), state.anchor) {
        (Register::ESP, _) => state.depth.checked_add(displacement)?,
        (Register::EBP, Anchor::At(anchor)) => anchor.checked_add(displacement)?,
        _ => return None,
    };
    let size: i64 = i64::try_from(decoded.memory_size().size()).ok()?;
    Some((start, start.checked_add(size.max(1))?))
}

fn classify_saves(function: &Function<'_>, analysis: &mut Analysis) -> Result<()> {
    let mut saves: BTreeMap<usize, (u8, i64)> = BTreeMap::new();
    for (position, state) in analysis.before.iter().enumerate() {
        let Some(state) = state else {
            continue;
        };
        let decoded: &Instruction = &function.code[position].decoded;
        if decoded.mnemonic() == Mnemonic::Push
            && decoded.op0_kind() == OpKind::Register
            && let Some(gpr) = gpr32_of(decoded.op0_register())
            && CALLEE_SAVED.contains(&gpr)
            && state.written & bit(gpr) == 0
        {
            saves.insert(position, (gpr, state.depth - WORD));
        }
    }
    let slots: BTreeMap<i64, u8> = saves.values().map(|(gpr, slot)| (*slot, *gpr)).collect();
    if slots.len() != saves.len() {
        return Err(Error::LlvmIr(
            "x86-32 callee-saved registers are saved to the same stack slot on different paths"
                .to_owned(),
        ));
    }
    let mut restores: BTreeSet<usize> = BTreeSet::new();
    for (position, state) in analysis.before.iter().enumerate() {
        let Some(state) = state else {
            continue;
        };
        let at: &Decoded = &function.code[position];
        let decoded: &Instruction = &at.decoded;
        if saves.contains_key(&position) || analysis.pic.contains_key(&position) {
            continue;
        }
        let restored: Option<(u8, i64)> = match decoded.mnemonic() {
            Mnemonic::Pop => gpr32_of(decoded.op0_register()).map(|gpr: u8| (gpr, state.depth)),
            Mnemonic::Mov
                if decoded.op0_kind() == OpKind::Register
                    && decoded.op1_kind() == OpKind::Memory =>
            {
                match (
                    gpr32_of(decoded.op0_register()),
                    memory_range(decoded, state),
                ) {
                    (Some(gpr), Some((start, end))) if end == start.saturating_add(WORD) => {
                        Some((gpr, start))
                    }
                    _ => None,
                }
            }
            Mnemonic::Leave => match state.anchor {
                Anchor::At(anchor) => Some((EBP, anchor)),
                Anchor::Free | Anchor::Conflict => None,
            },
            _ => None,
        };
        if let Some((gpr, slot)) = restored
            && slots.get(&slot) == Some(&gpr)
        {
            restores.insert(position);
            continue;
        }
        if let Some((start, end)) = memory_range(decoded, state)
            && slots
                .keys()
                .any(|slot: &i64| *slot < end && start < slot.saturating_add(WORD))
        {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "reads or writes the stack slot that holds a saved callee-saved register",
            ));
        }
    }
    analysis.saves = saves
        .into_iter()
        .map(|(position, (_, slot))| (position, slot))
        .collect();
    analysis.restores = restores;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Lowered {
    Replace { stmts: Vec<Stmt>, keeps_flags: bool },
    BeforeReturn(Vec<Stmt>),
}

#[derive(Debug)]
pub(super) struct Lowering {
    pub(super) insns: Vec<DisasmInsn>,
    pub(super) lowered: BTreeMap<u64, Lowered>,
    pub(super) shape: FrameShape,
    pub(super) signature: I386Signature,
    pub(super) register_parameters: Vec<Reg>,
    pub(super) callee_clobbers: BTreeMap<u64, call_clobber::CalleeClobbers>,
    pub(super) callees: BTreeMap<u64, I386Signature>,
}

const fn reg32(reg: Reg) -> RegRef {
    RegRef {
        reg,
        width: Width::W32,
    }
}

const fn reg64(reg: Reg) -> RegRef {
    RegRef {
        reg,
        width: Width::W64,
    }
}

const fn frame_slot(disp: i64) -> MemRef {
    MemRef {
        base: Some(Reg::Rsp),
        index: None,
        disp,
        width: Width::W32,
    }
}

fn format_address(base: Option<&str>, index: Option<(&str, u32)>, disp: i64) -> String {
    let mut terms: Vec<String> = Vec::with_capacity(2);
    if let Some(base) = base {
        terms.push(base.to_owned());
    }
    if let Some((index, scale)) = index {
        terms.push(format!("{index}*{scale}"));
    }
    if terms.is_empty() {
        return format!("[{:#x}]", disp as u32);
    }
    let registers: String = terms.join("+");
    match disp.cmp(&0) {
        std::cmp::Ordering::Greater => format!("[{registers}+{disp}]"),
        std::cmp::Ordering::Less => format!("[{registers}{disp}]"),
        std::cmp::Ordering::Equal => format!("[{registers}]"),
    }
}

fn rewritten_memory(at: &Decoded, state: &State) -> Result<Option<String>> {
    let decoded: &Instruction = &at.decoded;
    if !(0..decoded.op_count()).any(|operand: u32| decoded.op_kind(operand) == OpKind::Memory) {
        return Ok(None);
    }
    if matches!(decoded.segment_prefix(), Register::FS | Register::GS) {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "an fs or gs segment access (thread-local storage or the thread information block) is not modelled",
        ));
    }
    let displacement: i64 = i64::from(decoded.memory_displacement32() as i32);
    let index: Option<(u8, u32)> = match decoded.memory_index() {
        Register::None => None,
        other => {
            let gpr: u8 = gpr32_of(other).ok_or_else(|| {
                refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "the memory index is not a 32-bit general register",
                )
            })?;
            Some((gpr, decoded.memory_index_scale()))
        }
    };
    let base: Option<u8> = match decoded.memory_base() {
        Register::None => None,
        other => Some(gpr32_of(other).ok_or_else(|| {
            refusal(
                at.insn.address,
                &text(&at.insn),
                "the memory base is not a 32-bit general register",
            )
        })?),
    };
    let frame: Option<i64> = match (base, state.anchor) {
        (Some(ESP), _) => {
            Some(state.depth.checked_add(displacement).ok_or_else(|| {
                refusal(at.insn.address, &text(&at.insn), "frame offset overflows")
            })?)
        }
        (Some(EBP), Anchor::At(anchor)) => {
            Some(anchor.checked_add(displacement).ok_or_else(|| {
                refusal(at.insn.address, &text(&at.insn), "frame offset overflows")
            })?)
        }
        (Some(EBP), Anchor::Conflict) => {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "ebp is a frame anchor on some paths into this access and a general register on others",
            ));
        }
        _ => None,
    };
    if let (Some(point), Some(entry)) = (state.realigned, frame) {
        let across: bool = if base == Some(ESP) {
            entry >= point
        } else {
            entry < WORD
        };
        if across {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "a frame access crosses the padding the stack realignment inserted, whose size is only known at run time",
            ));
        }
    }
    if let Some((gpr, _)) = index
        && (gpr == ESP || (gpr == EBP && matches!(state.anchor, Anchor::At(_))))
    {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "the stack or frame pointer is used as a scaled index",
        ));
    }
    let index_text: Option<(&str, u32)> =
        index.map(|(gpr, scale): (u8, u32)| (gpr_wide_name(gpr), scale));
    if let Some(entry) = frame {
        return Ok(Some(format_address(Some("rsp"), index_text, entry)));
    }
    let constant_base: Option<u32> = base.and_then(|gpr: u8| state.constant(gpr));
    let constant_index: Option<u32> = match index {
        None => Some(0),
        Some((gpr, scale)) => state
            .constant(gpr)
            .map(|value: u32| value.wrapping_mul(scale)),
    };
    if let (Some(base_value), Some(index_value)) = (constant_base, constant_index) {
        let absolute: u32 = base_value
            .wrapping_add(index_value)
            .wrapping_add(displacement as u32);
        if absolute != 0 {
            return Ok(Some(format_address(None, None, i64::from(absolute))));
        }
    }
    if base.is_none() && index.is_none() {
        return Ok(Some(format_address(
            None,
            None,
            i64::from(displacement as u32),
        )));
    }
    let base_text: Option<&str> = base.map(gpr_wide_name);
    let disp: i64 = if base.is_none() {
        i64::from(displacement as u32)
    } else {
        displacement
    };
    Ok(Some(format_address(base_text, index_text, disp)))
}

fn frame_address_copy(decoded: &Instruction, state: &State) -> Option<String> {
    if decoded.mnemonic() != Mnemonic::Mov
        || decoded.op_count() != 2
        || decoded.op0_kind() != OpKind::Register
        || decoded.op1_kind() != OpKind::Register
    {
        return None;
    }
    let dest: u8 = gpr32_of(decoded.op0_register())?;
    let entry: i64 = match (decoded.op1_register(), state.anchor) {
        (Register::ESP, _) => state.depth,
        (Register::EBP, Anchor::At(anchor)) => anchor,
        _ => return None,
    };
    Some(format!(
        "{},{}",
        gpr_name(dest),
        format_address(Some("rsp"), None, entry)
    ))
}

fn replace_bracket(operands: &str, address: &str) -> Option<String> {
    let open: usize = operands.find('[')?;
    let close: usize = operands[open..].find(']')?.checked_add(open)?;
    Some(format!(
        "{}{}{}",
        &operands[..open],
        address,
        &operands[close + 1..]
    ))
}

fn mentions_register(operands: &str, name: &str) -> bool {
    operands
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token: &str| token == name)
}

fn source_operand(
    decoded: &Instruction,
    operand: u32,
    rewritten: Option<&MemRef>,
) -> Option<Source> {
    match decoded.op_kind(operand) {
        OpKind::Register => Some(Source::Reg(reg32(gpr_reg(gpr32_of(
            decoded.op_register(operand),
        )?)))),
        OpKind::Memory => rewritten.map(|mem: &MemRef| Source::Mem(*mem)),
        _ => immediate_operand(decoded, operand).map(Source::Imm),
    }
}

fn parsed_memory(operands: &str) -> Option<MemRef> {
    operands.split(',').find_map(|operand: &str| {
        let operand: &str = operand.trim();
        if !super::is_mem_token(operand) {
            return None;
        }
        super::parse_mem_access(operand, Some(Width::W32))
    })
}

struct Lowerer<'a> {
    function: &'a Function<'a>,
    analysis: &'a Analysis,
    insns: Vec<DisasmInsn>,
    lowered: BTreeMap<u64, Lowered>,
    pending_carry: BTreeSet<usize>,
    caller_pop_arguments: BTreeMap<u64, usize>,
}

fn argument_window(analysis: &Analysis, depth: i64) -> usize {
    let window_top: i64 = analysis
        .saves
        .values()
        .copied()
        .chain(std::iter::once(0))
        .filter(|slot: &i64| *slot >= depth)
        .min()
        .unwrap_or(0);
    usize::try_from(window_top.saturating_sub(depth) / WORD)
        .unwrap_or(0)
        .min(MAX_STACK_ARGUMENTS)
}

fn caller_pop_arguments(analysis: &Analysis) -> BTreeMap<u64, usize> {
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for (position, site) in &analysis.calls {
        if site.resolved_signature.is_some() || site.facts.pop_bytes > 0 {
            continue;
        }
        let Some(Some(state)) = analysis.before.get(*position) else {
            continue;
        };
        let available: usize = argument_window(analysis, state.depth);
        counts
            .entry(site.target)
            .and_modify(|known: &mut usize| *known = (*known).min(available))
            .or_insert(available);
    }
    counts
}

impl Lowerer<'_> {
    fn replace(&mut self, address: u64, stmts: Vec<Stmt>, keeps_flags: bool) {
        self.lowered
            .insert(address, Lowered::Replace { stmts, keeps_flags });
    }

    fn drop_instruction(&mut self, address: u64, keeps_flags: bool) {
        self.replace(address, Vec::new(), keeps_flags);
    }

    fn lower(&mut self) -> Result<()> {
        self.pair_carries()?;
        for position in 0..self.function.code.len() {
            self.lower_one(position)?;
        }
        Ok(())
    }

    fn pair_carries(&mut self) -> Result<()> {
        for (position, at) in self.function.code.iter().enumerate() {
            if self.analysis.before[position].is_none()
                || !matches!(at.decoded.mnemonic(), Mnemonic::Adc | Mnemonic::Sbb)
            {
                continue;
            }
            let producer: Option<usize> = (0..position).rev().find(|candidate: &usize| {
                let decoded: &Instruction = &self.function.code[*candidate].decoded;
                super::x86_mnemonic_writes_flags(&self.function.code[*candidate].insn.mnemonic)
                    || decoded.flow_control() != FlowControl::Next
            });
            let landing: bool = producer.is_some_and(|start: usize| {
                ((start + 1)..=position).any(|middle: usize| {
                    let address: u64 = self.function.code[middle].insn.address;
                    self.function.code.iter().any(|other: &Decoded| {
                        matches!(
                            other.decoded.flow_control(),
                            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                        ) && other.decoded.near_branch_target() == address
                    })
                })
            });
            let accepted: Option<usize> = producer.filter(|start: &usize| {
                let decoded: &Instruction = &self.function.code[*start].decoded;
                !landing
                    && matches!(
                        (at.decoded.mnemonic(), decoded.mnemonic()),
                        (Mnemonic::Adc, Mnemonic::Add)
                            | (Mnemonic::Sbb, Mnemonic::Sub | Mnemonic::Cmp)
                            | (Mnemonic::Adc | Mnemonic::Sbb, Mnemonic::Neg)
                    )
                    && decoded.op0_kind() == OpKind::Register
                    && gpr32_of(decoded.op0_register()).is_some()
            });
            let Some(start) = accepted else {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "the carry it consumes does not come from a 32-bit register add, sub, cmp or neg in the same block",
                ));
            };
            self.pending_carry.insert(start);
        }
        Ok(())
    }

    fn lower_one(&mut self, position: usize) -> Result<()> {
        let at: &Decoded = &self.function.code[position];
        let address: u64 = at.insn.address;
        let Some(state) = self.analysis.before[position].clone() else {
            self.drop_instruction(address, true);
            return Ok(());
        };
        let decoded: Instruction = at.decoded;
        if let Some(idiom) = self.analysis.pic.get(&position).copied() {
            match idiom {
                PicIdiom::CallNext { register, value } | PicIdiom::Thunk { register, value } => {
                    self.replace(
                        address,
                        vec![Stmt::Assign {
                            dest: reg32(gpr_reg(register)),
                            src: Source::Imm(i64::from(value)),
                        }],
                        true,
                    );
                }
                PicIdiom::PopNext => self.drop_instruction(address, true),
            }
            return Ok(());
        }
        if self.analysis.saves.contains_key(&position) || self.analysis.restores.contains(&position)
        {
            self.drop_instruction(address, true);
            return Ok(());
        }
        if decoded.op_count() > 0
            && decoded.op0_kind() == OpKind::Register
            && decoded.op0_register() == Register::ESP
            && matches!(
                decoded.mnemonic(),
                Mnemonic::Lea | Mnemonic::Mov | Mnemonic::Sub | Mnemonic::Add | Mnemonic::And
            )
        {
            let keeps_flags: bool = matches!(decoded.mnemonic(), Mnemonic::Lea | Mnemonic::Mov);
            self.drop_instruction(address, keeps_flags);
            return Ok(());
        }
        let memory: Option<String> = rewritten_memory(at, &state)?;
        let operands: String = match &memory {
            Some(address_text) => {
                replace_bracket(&at.insn.operands, address_text).ok_or_else(|| {
                    refusal(
                        address,
                        &text(&at.insn),
                        "the memory operand text has no brackets",
                    )
                })?
            }
            None => at.insn.operands.clone(),
        };
        let mem: Option<MemRef> = memory.as_ref().and_then(|_| parsed_memory(&operands));
        if let Some(site) = self.analysis.calls.get(&position).copied() {
            let stmts: Vec<Stmt> = self.call(at, &state, site)?;
            self.replace(address, stmts, false);
            return Ok(());
        }
        match decoded.mnemonic() {
            Mnemonic::Push => {
                let stmts: Vec<Stmt> = self.push(at, &state, mem.as_ref())?;
                self.replace(address, stmts, true);
                return Ok(());
            }
            Mnemonic::Pop => {
                let gpr: u8 = gpr32_of(decoded.op0_register())
                    .ok_or_else(|| refusal(address, &text(&at.insn), "pop target"))?;
                self.replace(
                    address,
                    vec![Stmt::Assign {
                        dest: reg32(gpr_reg(gpr)),
                        src: Source::Mem(frame_slot(state.depth)),
                    }],
                    true,
                );
                return Ok(());
            }
            Mnemonic::Leave => {
                self.replace(
                    address,
                    vec![Stmt::Assign {
                        dest: reg32(Reg::Rbp),
                        src: Source::Mem(frame_slot(match state.anchor {
                            Anchor::At(anchor) => anchor,
                            Anchor::Free | Anchor::Conflict => state.depth,
                        })),
                    }],
                    true,
                );
                return Ok(());
            }
            Mnemonic::Sub | Mnemonic::Add | Mnemonic::And
                if decoded.op0_kind() == OpKind::Register
                    && decoded.op0_register() == Register::ESP =>
            {
                self.drop_instruction(address, false);
                return Ok(());
            }
            Mnemonic::Lea | Mnemonic::Mov
                if decoded.op0_kind() == OpKind::Register
                    && decoded.op0_register() == Register::ESP =>
            {
                self.drop_instruction(address, true);
                return Ok(());
            }
            Mnemonic::Mov
                if decoded.op0_kind() == OpKind::Register
                    && decoded.op0_register() == Register::EBP
                    && decoded.op1_kind() == OpKind::Register
                    && decoded.op1_register() == Register::ESP =>
            {
                self.drop_instruction(address, true);
                return Ok(());
            }
            Mnemonic::Ret => {
                if self.analysis.returns_edx_eax {
                    self.lowered
                        .insert(address, Lowered::BeforeReturn(compose_edx_eax()));
                }
                self.insns.push(DisasmInsn {
                    address,
                    bytes: at.insn.bytes.clone(),
                    mnemonic: "ret".to_owned(),
                    operands: String::new(),
                });
                return Ok(());
            }
            Mnemonic::Adc | Mnemonic::Sbb => {
                let stmts: Vec<Stmt> = carry_consumer(at, mem.as_ref())?;
                self.replace(address, stmts, false);
                return Ok(());
            }
            Mnemonic::Mul | Mnemonic::Imul if decoded.op_count() == 1 => {
                let stmts: Vec<Stmt> = wide_multiply(at, mem.as_ref())?;
                self.replace(address, stmts, false);
                return Ok(());
            }
            Mnemonic::Shld | Mnemonic::Shrd => {
                let stmts: Vec<Stmt> = double_shift(at)?;
                self.replace(address, stmts, false);
                return Ok(());
            }
            _ if is_register_nop(&decoded, &state) => {
                self.drop_instruction(address, true);
                return Ok(());
            }
            _ => {}
        }
        if self.pending_carry.contains(&position) {
            let stmts: Vec<Stmt> = carry_producer(at, mem.as_ref())?;
            self.replace(address, stmts, false);
            return Ok(());
        }
        if let Some(frame_copy) = frame_address_copy(&decoded, &state) {
            self.insns.push(DisasmInsn {
                address,
                bytes: at.insn.bytes.clone(),
                mnemonic: "lea".to_owned(),
                operands: frame_copy,
            });
            return Ok(());
        }
        if mentions_register(&operands, "esp")
            || (matches!(state.anchor, Anchor::At(_)) && mentions_register(&operands, "ebp"))
        {
            return Err(refusal(
                address,
                &text(&at.insn),
                "the stack or frame pointer is used as a value",
            ));
        }
        self.insns.push(DisasmInsn {
            address,
            bytes: at.insn.bytes.clone(),
            mnemonic: at.insn.mnemonic.clone(),
            operands,
        });
        Ok(())
    }

    fn push(&self, at: &Decoded, state: &State, mem: Option<&MemRef>) -> Result<Vec<Stmt>> {
        let decoded: &Instruction = &at.decoded;
        let slot: MemRef = frame_slot(state.depth - WORD);
        match decoded.op0_kind() {
            OpKind::Register => {
                let gpr: u8 = gpr32_of(decoded.op0_register())
                    .ok_or_else(|| refusal(at.insn.address, &text(&at.insn), "push operand"))?;
                if gpr == ESP {
                    return Err(refusal(
                        at.insn.address,
                        &text(&at.insn),
                        "pushing the stack pointer stores a frame address as a value",
                    ));
                }
                let parameter: bool =
                    self.analysis.live_in.contains_key(&gpr) && REGISTER_ARGUMENTS.contains(&gpr);
                if state.defined & bit(gpr) != 0 || parameter {
                    return Ok(vec![Stmt::Store {
                        addr: slot,
                        src: Source::Reg(reg32(gpr_reg(gpr))),
                    }]);
                }
                if state.written & bit(gpr) == 0 && matches!(gpr, EAX | ECX | EDX) {
                    return Ok(Vec::new());
                }
                Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "pushes a register that holds no value the function defined on every path",
                ))
            }
            OpKind::Memory => {
                let mem: MemRef = *mem.ok_or_else(|| {
                    refusal(at.insn.address, &text(&at.insn), "push memory operand")
                })?;
                Ok(vec![
                    Stmt::Assign {
                        dest: reg32(Reg::X86Scratch),
                        src: Source::Mem(mem),
                    },
                    Stmt::Store {
                        addr: slot,
                        src: Source::Reg(reg32(Reg::X86Scratch)),
                    },
                ])
            }
            _ => {
                let value: i64 = immediate_operand(decoded, 0)
                    .ok_or_else(|| refusal(at.insn.address, &text(&at.insn), "push immediate"))?;
                Ok(vec![Stmt::Store {
                    addr: slot,
                    src: Source::Imm(value),
                }])
            }
        }
    }

    fn call(&self, at: &Decoded, state: &State, site: CallSite) -> Result<Vec<Stmt>> {
        let available: usize = argument_window(self.analysis, state.depth);
        let needed: usize = match site.resolved_signature {
            Some(signature) => usize::from(signature.stack_arguments),
            None if site.facts.pop_bytes > 0 => usize::from(site.facts.pop_bytes) / 4,
            None => self
                .caller_pop_arguments
                .get(&site.target)
                .copied()
                .unwrap_or(available),
        };
        if needed > available {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                &format!(
                    "the callee takes {needed} stack arguments but only {available} stack slots lie between the call and this function's saved registers"
                ),
            ));
        }
        let mut stmts: Vec<Stmt> = Vec::with_capacity(needed + 4);
        let mut args: Vec<Reg> = Vec::new();
        for gpr in REGISTER_ARGUMENTS {
            let mask: u8 = register_mask(site.resolved_signature.map_or_else(
                || register_count(site.facts.register_arguments),
                |signature: I386Signature| signature.register_arguments,
            ));
            let register_argument: bool = mask & bit(gpr) != 0;
            if register_argument {
                args.push(gpr_reg(gpr));
            }
        }
        for slot in 0..needed {
            let reg: Reg = x86_outgoing_argument_reg(slot).ok_or_else(|| {
                refusal(at.insn.address, &text(&at.insn), "outgoing argument slot")
            })?;
            let offset: i64 = i64::try_from(slot)
                .ok()
                .and_then(|slot: i64| slot.checked_mul(WORD))
                .and_then(|bytes: i64| state.depth.checked_add(bytes))
                .ok_or_else(|| refusal(at.insn.address, &text(&at.insn), "argument offset"))?;
            stmts.push(Stmt::Assign {
                dest: reg32(reg),
                src: Source::Mem(frame_slot(offset)),
            });
            args.push(reg);
        }
        stmts.push(Stmt::Call {
            target: CallTarget::Address(site.target),
            args,
            name: None,
        });
        if site.returns_edx_eax {
            stmts.push(Stmt::Assign {
                dest: reg64(Reg::Rdx),
                src: Source::Reg(reg64(Reg::Rax)),
            });
            stmts.push(Stmt::BinAssign {
                dest: reg64(Reg::Rdx),
                op: BinOp::Shr,
                src: Source::Imm(32),
            });
        }
        stmts.push(Stmt::Assign {
            dest: reg32(Reg::Rax),
            src: Source::Reg(reg32(Reg::Rax)),
        });
        Ok(stmts)
    }
}

fn compose_edx_eax() -> Vec<Stmt> {
    vec![
        Stmt::Assign {
            dest: reg64(Reg::X86Scratch),
            src: Source::Reg(reg64(Reg::Rdx)),
        },
        Stmt::BinAssign {
            dest: reg64(Reg::X86Scratch),
            op: BinOp::Shl,
            src: Source::Imm(32),
        },
        Stmt::Assign {
            dest: reg32(Reg::Rax),
            src: Source::Reg(reg32(Reg::Rax)),
        },
        Stmt::BinAssign {
            dest: reg64(Reg::Rax),
            op: BinOp::Or,
            src: Source::Reg(reg64(Reg::X86Scratch)),
        },
    ]
}

fn destination(at: &Decoded) -> Result<u8> {
    if at.decoded.op0_kind() != OpKind::Register {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "only a 32-bit register destination is modelled for multi-word arithmetic",
        ));
    }
    gpr32_of(at.decoded.op0_register()).ok_or_else(|| {
        refusal(
            at.insn.address,
            &text(&at.insn),
            "only a 32-bit register destination is modelled for multi-word arithmetic",
        )
    })
}

fn carry_producer(at: &Decoded, mem: Option<&MemRef>) -> Result<Vec<Stmt>> {
    let decoded: &Instruction = &at.decoded;
    let dest: RegRef = reg32(gpr_reg(destination(at)?));
    let carry: RegRef = RegRef {
        reg: Reg::X86Temp,
        width: Width::W8,
    };
    let widen = Stmt::Extend {
        dest: reg32(Reg::X86Temp),
        src: ExtSource::Reg(carry),
        signed: false,
    };
    match decoded.mnemonic() {
        Mnemonic::Add => {
            let src: Source = source_operand(decoded, 1, mem)
                .ok_or_else(|| refusal(at.insn.address, &text(&at.insn), "add source operand"))?;
            Ok(vec![
                Stmt::Assign {
                    dest: reg32(Reg::X86Scratch),
                    src: Source::Reg(dest),
                },
                Stmt::BinAssign {
                    dest,
                    op: BinOp::Add,
                    src,
                },
                Stmt::SetCc {
                    dest: carry,
                    kind: CondKind::B,
                    flags: Flags::Cmp {
                        lhs: dest,
                        rhs: Source::Reg(reg32(Reg::X86Scratch)),
                    },
                },
                widen,
            ])
        }
        Mnemonic::Sub | Mnemonic::Cmp => {
            let src: Source = source_operand(decoded, 1, mem)
                .ok_or_else(|| refusal(at.insn.address, &text(&at.insn), "sub source operand"))?;
            let mut stmts: Vec<Stmt> = vec![
                Stmt::SetCc {
                    dest: carry,
                    kind: CondKind::B,
                    flags: Flags::Cmp {
                        lhs: dest,
                        rhs: src.clone(),
                    },
                },
                widen,
            ];
            if decoded.mnemonic() == Mnemonic::Sub {
                stmts.push(Stmt::BinAssign {
                    dest,
                    op: BinOp::Sub,
                    src,
                });
            }
            Ok(stmts)
        }
        Mnemonic::Neg => Ok(vec![
            Stmt::SetCc {
                dest: carry,
                kind: CondKind::Ne,
                flags: Flags::Cmp {
                    lhs: dest,
                    rhs: Source::Imm(0),
                },
            },
            widen,
            Stmt::UnAssign {
                dest,
                op: super::UnOp::Neg,
            },
        ]),
        _ => Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "carry producer is not modelled",
        )),
    }
}

fn carry_consumer(at: &Decoded, mem: Option<&MemRef>) -> Result<Vec<Stmt>> {
    let decoded: &Instruction = &at.decoded;
    let dest: RegRef = reg32(gpr_reg(destination(at)?));
    let src: Source = source_operand(decoded, 1, mem)
        .ok_or_else(|| refusal(at.insn.address, &text(&at.insn), "carry source operand"))?;
    let op: BinOp = if decoded.mnemonic() == Mnemonic::Adc {
        BinOp::Add
    } else {
        BinOp::Sub
    };
    Ok(vec![
        Stmt::BinAssign { dest, op, src },
        Stmt::BinAssign {
            dest,
            op,
            src: Source::Reg(reg32(Reg::X86Temp)),
        },
    ])
}

fn wide_multiply(at: &Decoded, mem: Option<&MemRef>) -> Result<Vec<Stmt>> {
    let decoded: &Instruction = &at.decoded;
    let signed: bool = decoded.mnemonic() == Mnemonic::Imul;
    let operand: ExtSource = match decoded.op0_kind() {
        OpKind::Register => {
            let register: Register = decoded.op0_register();
            if register.size() != 4 {
                return Err(refusal(
                    at.insn.address,
                    &text(&at.insn),
                    "only a 32-bit one-operand multiply is modelled",
                ));
            }
            ExtSource::Reg(reg32(gpr_reg(gpr32_of(register).ok_or_else(|| {
                refusal(at.insn.address, &text(&at.insn), "multiply operand")
            })?)))
        }
        OpKind::Memory => {
            let mem: MemRef = *mem
                .filter(|mem: &&MemRef| mem.width == Width::W32)
                .ok_or_else(|| {
                    refusal(
                        at.insn.address,
                        &text(&at.insn),
                        "only a 32-bit one-operand multiply is modelled",
                    )
                })?;
            ExtSource::Mem(mem)
        }
        _ => {
            return Err(refusal(
                at.insn.address,
                &text(&at.insn),
                "multiply operand",
            ));
        }
    };
    let product: RegRef = reg64(Reg::X86Scratch);
    let factor: RegRef = reg64(Reg::X86Temp);
    let mut stmts: Vec<Stmt> = Vec::with_capacity(6);
    if signed {
        stmts.push(Stmt::Extend {
            dest: product,
            src: ExtSource::Reg(reg32(Reg::Rax)),
            signed: true,
        });
        stmts.push(Stmt::Extend {
            dest: factor,
            src: operand,
            signed: true,
        });
    } else {
        stmts.push(Stmt::Assign {
            dest: reg32(Reg::X86Scratch),
            src: Source::Reg(reg32(Reg::Rax)),
        });
        stmts.push(match operand {
            ExtSource::Reg(register) => Stmt::Assign {
                dest: reg32(Reg::X86Temp),
                src: Source::Reg(register),
            },
            ExtSource::Mem(mem) => Stmt::Assign {
                dest: reg32(Reg::X86Temp),
                src: Source::Mem(mem),
            },
        });
    }
    stmts.push(Stmt::BinAssign {
        dest: product,
        op: BinOp::Imul,
        src: Source::Reg(factor),
    });
    stmts.push(Stmt::Assign {
        dest: reg32(Reg::Rax),
        src: Source::Reg(reg32(Reg::X86Scratch)),
    });
    stmts.push(Stmt::Assign {
        dest: reg64(Reg::Rdx),
        src: Source::Reg(product),
    });
    stmts.push(Stmt::BinAssign {
        dest: reg64(Reg::Rdx),
        op: BinOp::Shr,
        src: Source::Imm(32),
    });
    stmts.push(Stmt::Assign {
        dest: reg32(Reg::Rdx),
        src: Source::Reg(reg32(Reg::Rdx)),
    });
    Ok(stmts)
}

fn double_shift(at: &Decoded) -> Result<Vec<Stmt>> {
    let decoded: &Instruction = &at.decoded;
    let amount: i64 = immediate_operand(decoded, 2).ok_or_else(|| {
        refusal(
            at.insn.address,
            &text(&at.insn),
            "a double shift by cl depends on a run-time count whose zero case leaves the flags and destination untouched, which is not modelled",
        )
    })? & 31;
    if decoded.op0_kind() != OpKind::Register || decoded.op1_kind() != OpKind::Register {
        return Err(refusal(
            at.insn.address,
            &text(&at.insn),
            "only a register double shift is modelled",
        ));
    }
    let dest: RegRef = reg32(gpr_reg(gpr32_of(decoded.op0_register()).ok_or_else(
        || refusal(at.insn.address, &text(&at.insn), "double shift destination"),
    )?));
    let src: RegRef = reg32(gpr_reg(gpr32_of(decoded.op1_register()).ok_or_else(
        || refusal(at.insn.address, &text(&at.insn), "double shift source"),
    )?));
    if amount == 0 {
        return Ok(Vec::new());
    }
    let left: bool = decoded.mnemonic() == Mnemonic::Shld;
    let (into_dest, into_scratch): (BinOp, BinOp) = if left {
        (BinOp::Shl, BinOp::Shr)
    } else {
        (BinOp::Shr, BinOp::Shl)
    };
    let scratch: RegRef = reg32(Reg::X86Scratch);
    Ok(vec![
        Stmt::Assign {
            dest: scratch,
            src: Source::Reg(src),
        },
        Stmt::BinAssign {
            dest: scratch,
            op: into_scratch,
            src: Source::Imm(32 - amount),
        },
        Stmt::BinAssign {
            dest,
            op: into_dest,
            src: Source::Imm(amount),
        },
        Stmt::BinAssign {
            dest,
            op: BinOp::Or,
            src: Source::Reg(scratch),
        },
    ])
}

fn convention_of(
    analysis: &Analysis,
    highest_stack_read: Option<usize>,
) -> Result<(I386Signature, Vec<Reg>)> {
    let pop_bytes: u16 = analysis.pop_bytes.unwrap_or(0);
    for (gpr, address) in &analysis.live_in {
        if !REGISTER_ARGUMENTS.contains(gpr) {
            return Err(Error::LlvmIr(format!(
                "x86-32 function reads `{}` at {address:#x} before writing it; only ecx and edx carry register arguments (fastcall, thiscall), so a register convention such as regparm or Borland register is not modelled",
                gpr_name(*gpr)
            )));
        }
    }
    let reads_ecx: bool = analysis.live_in.contains_key(&ECX);
    let reads_edx: bool = analysis.live_in.contains_key(&EDX);
    if pop_bytes % 4 != 0 {
        return Err(Error::LlvmIr(format!(
            "x86-32 function pops {pop_bytes} argument bytes, which is not a whole number of four-byte stack slots"
        )));
    }
    let popped_slots: usize = usize::from(pop_bytes / 4);
    if popped_slots > MAX_STACK_ARGUMENTS {
        return Err(Error::LlvmIr(format!(
            "x86-32 function pops {popped_slots} stack arguments, over the bounded eight-slot lift"
        )));
    }
    let read_slots: usize = highest_stack_read.map_or(0, |highest: usize| highest + 1);
    if pop_bytes > 0 && read_slots > popped_slots {
        return Err(Error::LlvmIr(format!(
            "x86-32 function pops {popped_slots} stack arguments but reads incoming stack slot {}, which belongs to its caller",
            read_slots - 1
        )));
    }
    let (convention, registers): (I386Convention, Vec<Reg>) = match (reads_ecx, reads_edx) {
        (_, true) => (I386Convention::Fastcall, vec![Reg::Rcx, Reg::Rdx]),
        (true, false) if popped_slots > 0 => (I386Convention::Thiscall, vec![Reg::Rcx]),
        (true, false) => (I386Convention::Fastcall, vec![Reg::Rcx]),
        (false, false) if pop_bytes > 0 => (I386Convention::Stdcall, Vec::new()),
        (false, false) => (I386Convention::Cdecl, Vec::new()),
    };
    if !registers.is_empty() && pop_bytes == 0 && read_slots > 0 {
        return Err(Error::LlvmIr(
            "x86-32 function takes register arguments in ecx or edx and reads stack arguments but pops none; fastcall and thiscall callees pop their stack arguments, so this convention is not modelled"
                .to_owned(),
        ));
    }
    let stack_arguments: usize = if pop_bytes > 0 {
        popped_slots
    } else {
        read_slots
    };
    let register_arguments: u8 = u8::try_from(registers.len())
        .map_err(|_| Error::LlvmIr("x86-32 register argument count overflows".to_owned()))?;
    Ok((
        I386Signature {
            convention,
            register_arguments,
            stack_arguments: u8::try_from(stack_arguments)
                .map_err(|_| Error::LlvmIr("x86-32 stack argument count overflows".to_owned()))?,
            callee_pop_bytes: pop_bytes,
            returns_edx_eax: analysis.returns_edx_eax,
        },
        registers,
    ))
}

fn highest_incoming_read(function: &Function<'_>, analysis: &Analysis) -> Option<usize> {
    let mut highest: Option<usize> = None;
    for (position, state) in analysis.before.iter().enumerate() {
        let Some(state) = state else {
            continue;
        };
        let Some((start, end)) = memory_range(&function.code[position].decoded, state) else {
            continue;
        };
        if end <= WORD {
            continue;
        }
        let last: i64 = (end.saturating_sub(1).saturating_sub(WORD)) / WORD;
        let first: i64 = (start.max(WORD).saturating_sub(WORD)) / WORD;
        if let Ok(last) = usize::try_from(last.max(first)) {
            highest = Some(highest.map_or(last, |known: usize| known.max(last)));
        }
    }
    highest
}

pub(super) fn lower(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    resolved: &[ResolvedCall],
) -> Result<Lowering> {
    let image: Option<Image<'_>> = Image::parse(object)?;
    let code: Vec<Decoded> = decode_function(base, machine_code)?;
    let end: u64 = base
        .checked_add(u64::try_from(machine_code.len()).map_err(|_| {
            Error::LlvmIr("machine code length exceeds the address space".to_owned())
        })?)
        .ok_or_else(|| Error::LlvmIr("machine code range overflows".to_owned()))?;
    if end > u64::from(u32::MAX) {
        return Err(Error::LlvmIr(
            "x86-32 function lies above the 32-bit address space".to_owned(),
        ));
    }
    let index: BTreeMap<u64, usize> = code
        .iter()
        .enumerate()
        .map(|(position, at): (usize, &Decoded)| (at.insn.address, position))
        .collect();
    let function: Function<'_> = Function {
        code,
        index,
        start: base,
        end,
        image: image.as_ref(),
        resolved,
    };
    let mut scan: Option<CalleeScan<'_, '_>> = image.as_ref().map(|image: &Image<'_>| CalleeScan {
        image,
        memo: BTreeMap::new(),
        active: BTreeSet::new(),
        factory: InstructionInfoFactory::new(),
    });
    let analysis: Analysis = analyse(&function, &mut scan)?;
    let mut lowerer: Lowerer<'_> = Lowerer {
        function: &function,
        analysis: &analysis,
        insns: Vec::with_capacity(function.code.len()),
        lowered: BTreeMap::new(),
        pending_carry: BTreeSet::new(),
        caller_pop_arguments: caller_pop_arguments(&analysis),
    };
    lowerer.lower()?;
    let mut insns: Vec<DisasmInsn> = Vec::with_capacity(function.code.len());
    let kept: BTreeMap<u64, DisasmInsn> = lowerer
        .insns
        .drain(..)
        .map(|insn: DisasmInsn| (insn.address, insn))
        .collect();
    for at in &function.code {
        match kept.get(&at.insn.address) {
            Some(insn) => insns.push(insn.clone()),
            None => insns.push(at.insn.clone()),
        }
    }
    let (signature, register_parameters): (I386Signature, Vec<Reg>) =
        convention_of(&analysis, highest_incoming_read(&function, &analysis))?;
    let shape: FrameShape = FrameShape {
        base: Some(Reg::Rsp),
        rbp_is_frame: false,
        red_zone: false,
        stack_extent: Some(StackFrameExtent {
            owned_start: Some(analysis.min_depth),
            private_end: 0,
            boundary: StackFrameBoundary::ReturnAddress {
                linkage_bytes: WORD,
                home_bytes: 0,
            },
            slot_bytes: WORD,
        }),
        stack_pointer_break: None,
    };
    let mut callee_clobbers: BTreeMap<u64, call_clobber::CalleeClobbers> = BTreeMap::new();
    let mut callees: BTreeMap<u64, I386Signature> = BTreeMap::new();
    for (position, site) in &analysis.calls {
        let address: u64 = function.code[*position].insn.address;
        let mut gprs: BTreeSet<Reg> = BTreeSet::new();
        for gpr in [EAX, ECX, EDX] {
            if site.facts.clobbers & bit(gpr) != 0 && !(gpr == EDX && site.returns_edx_eax) {
                gprs.insert(gpr_reg(gpr));
            }
        }
        let fp: BTreeSet<u8> = (0..8_u8)
            .filter(|index: &u8| site.facts.xmm_clobbers & (1 << index) != 0)
            .collect();
        callee_clobbers.insert(
            address,
            call_clobber::CalleeClobbers::from_registers(gprs, fp),
        );
        let callee_signature: I386Signature = site.resolved_signature.unwrap_or_else(|| {
            let register_arguments: u8 = register_count(site.facts.register_arguments);
            let stack_slots: usize = if site.facts.pop_bytes > 0 {
                usize::from(site.facts.pop_bytes) / 4
            } else {
                lowerer
                    .caller_pop_arguments
                    .get(&site.target)
                    .copied()
                    .unwrap_or(0)
            };
            let stack_arguments: u8 = u8::try_from(stack_slots).unwrap_or(u8::MAX);
            I386Signature {
                convention: match (register_arguments, site.facts.pop_bytes) {
                    (0, 0) => I386Convention::Cdecl,
                    (0, _) => I386Convention::Stdcall,
                    (1, popped) if popped > 0 => I386Convention::Thiscall,
                    _ => I386Convention::Fastcall,
                },
                register_arguments,
                stack_arguments,
                callee_pop_bytes: site.facts.pop_bytes,
                returns_edx_eax: site.returns_edx_eax,
            }
        });
        callees.insert(site.target, callee_signature);
    }
    Ok(Lowering {
        insns,
        lowered: lowerer.lowered,
        shape,
        signature,
        register_parameters,
        callee_clobbers,
        callees,
    })
}

pub(super) fn refuse_exception_tables(object: &[u8]) -> Result<()> {
    use object::{Object as _, ObjectSection as _};

    let Ok(file) = object::File::parse(object) else {
        return Ok(());
    };
    if file.sections().any(|section| {
        section
            .name()
            .is_ok_and(|name: &str| name == ".gcc_except_table")
    }) {
        return Err(Error::LlvmIr(
            "x86-32 C++ exception tables (.gcc_except_table) are not modelled, so a landing pad could be dropped"
                .to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct I386Emit {
    pub(super) convention: I386Convention,
    pub(super) externs: BTreeMap<String, String>,
}

fn collect_externs(
    body: &[Node],
    callees: &BTreeMap<u64, I386Signature>,
    externs: &mut BTreeMap<String, String>,
) -> Result<()> {
    for node in body {
        match node {
            Node::Stmt(Stmt::Call {
                target: CallTarget::Address(address),
                args,
                name,
            }) => {
                let display: String = call_display_name(*address, name.as_deref());
                let signature: I386Signature = callees.get(address).copied().ok_or_else(|| {
                    Error::LlvmIr(format!(
                        "x86-32 call to {address:#x} has no callee prototype"
                    ))
                })?;
                let arity: usize = usize::from(signature.register_arguments)
                    .saturating_add(usize::from(signature.stack_arguments));
                if arity != args.len() {
                    return Err(Error::LlvmIr(format!(
                        "x86-32 call to {address:#x} passes {} arguments but its prototype takes {arity}",
                        args.len()
                    )));
                }
                let prototype: String = signature.prototype(&display, Width::W32);
                if let Some(existing) = externs.get(&display)
                    && *existing != prototype
                {
                    return Err(Error::LlvmIr(format!(
                        "x86-32 calls to `{display}` disagree on its prototype"
                    )));
                }
                externs.insert(display, prototype);
            }
            Node::Stmt(_)
            | Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::BreakLoop(_)
            | Node::ContinueLoop(_)
            | Node::ResumeAt(_)
            | Node::OuterResume(_)
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_externs(then_body, callees, externs)?;
                if let Some(other) = else_body {
                    collect_externs(other, callees, externs)?;
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                collect_externs(body, callees, externs)?;
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_externs(&case.body, callees, externs)?;
                }
                collect_externs(default, callees, externs)?;
            }
        }
    }
    Ok(())
}

pub(super) fn recover(
    object: &[u8],
    machine_code: &[u8],
    base: u64,
    calls: &[ResolvedCall],
    coverage: Option<&mut LifterCoverageTrace>,
) -> Result<LeafRecovery> {
    let lowering: Lowering = lower(object, machine_code, base, calls)?;
    let empty: EmptyObjectCallFacts = EmptyObjectCallFacts::default();
    let LeafItems {
        mut items,
        frame_shape,
        ..
    } = build_leaf_items(
        machine_code,
        base,
        Abi::I386,
        &[],
        &[],
        empty.facts().with_i386(&lowering),
        RipRelativeLeaPolicy::Refuse,
        coverage,
    )?;
    call_clobber::refuse_reads_after_calls(
        &items,
        Abi::I386,
        calls,
        &lowering.callee_clobbers,
        &|address: u64| address,
    )?;
    let rewrote: bool = rewrite_incoming_stack_items(&mut items, base, frame_shape)?;
    let mut structured: Structured = structure_items(&items, base)?;
    if !calls.is_empty() {
        let call_map: BTreeMap<u64, &ResolvedCall> = calls
            .iter()
            .map(|call: &ResolvedCall| (call.target, call))
            .collect();
        annotate_calls_block(&mut structured.body, &call_map, Abi::I386)?;
    }
    if !rewrote {
        rewrite_incoming_stack_arguments(&mut structured.body, frame_shape)?;
    }
    normalize_noreturn_guards(&mut structured.body);
    let mut call_targets: Vec<u64> = Vec::new();
    collect_call_targets(&structured.body, &mut call_targets);
    let return_width: Width = if lowering.signature.returns_edx_eax {
        Width::W64
    } else {
        Width::W32
    };
    let mut int: Vec<(Reg, Width)> = lowering
        .register_parameters
        .iter()
        .map(|reg: &Reg| (*reg, Width::W32))
        .collect();
    for slot in 0..usize::from(lowering.signature.stack_arguments) {
        let reg: Reg = x86_stack_argument_reg(slot).ok_or_else(|| {
            Error::LlvmIr("x86-32 stack parameter exceeds the bounded eight-slot lift".to_owned())
        })?;
        int.push((reg, Width::W32));
    }
    let mut externs: BTreeMap<String, String> = BTreeMap::new();
    collect_externs(&structured.body, &lowering.callees, &mut externs)?;
    let signature: FnSignature = FnSignature {
        fp: Vec::new(),
        stack_fp: Vec::new(),
        int: int.clone(),
        vec: Vec::new(),
        ret: FnReturn::Int(return_width),
        exact_integer_types: true,
        abi: Abi::I386,
        i386: Some(I386Emit {
            convention: lowering.signature.convention,
            externs,
        }),
    };
    let params: Vec<Reg> = int.iter().map(|(reg, _): &(Reg, Width)| *reg).collect();
    let frame_plan: Option<FramePlan> = plan_frame(&structured.body, frame_shape)?;
    let aggregate_plan: AggregatePlan =
        infer_aggregate_plan(&structured.body, &params, frame_plan.as_ref());
    let emitted: Block = spilled_body(&structured.body, frame_plan.as_ref(), None, &aggregate_plan);
    let source: String = emit_c(
        &emitted,
        &signature,
        frame_plan.as_ref(),
        None,
        &aggregate_plan,
    )?;
    let bindings: Vec<ParameterBinding> = int
        .iter()
        .map(
            |(register, width): &(Reg, Width)| ParameterBinding::Integer {
                register: *register,
                width_bits: width.bits(),
            },
        )
        .collect();
    Ok(LeafRecovery {
        source,
        rust_source: None,
        return_width_bits: return_width.bits(),
        signature: RecoveredSignature::from_bindings(Abi::I386, bindings)?
            .with_i386(lowering.signature),
        returns_fp: None,
        lifted_split_return: structured.lifted_split_return,
        lifted_loop: structured.lifted_loop,
        lifted_switch: false,
        call_targets,
        sret: None,
        call_site_signature: None,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests;
