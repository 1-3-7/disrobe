use std::collections::BTreeMap;

use iced_x86::{
    FlowControl, Instruction, InstructionInfo, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register, UsedRegister,
};

use crate::abi::{Convention, int_arg_registers};
use crate::cells::CellStore;
use crate::cfg::{self, BasicBlock, Cfg};
use crate::decode::decode_all;
use crate::import_map::{ImportMap, ImportRef};
use crate::lattice::{Sign, TypeVar, Width};
use crate::memssa::{self, MemSsa, VersionInfo};
use crate::recover::CIntType;
use crate::sigdb::{Abi, Prototype, SigDb, Ty};

const MAX_COPY_DEPTH: u8 = 8;
const MAX_THUNK_INSNS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiType {
    Unknown,
    Integer { width: Width, sign: Sign },
    Float { width: Width },
    Pointer,
    Handle,
    Code,
    Conflict,
}

impl ApiType {
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, value) | (value, Self::Unknown) => value,
            (
                Self::Integer {
                    width: wl,
                    sign: sl,
                },
                Self::Integer {
                    width: wr,
                    sign: sr,
                },
            ) => Self::Integer {
                width: meet_width(wl, wr),
                sign: sl.join(sr),
            },
            (Self::Float { width: wl }, Self::Float { width: wr }) => Self::Float {
                width: meet_width(wl, wr),
            },
            (Self::Pointer, Self::Pointer) => Self::Pointer,
            (Self::Handle, Self::Handle) => Self::Handle,
            (Self::Code, Self::Code) => Self::Code,
            _ => Self::Conflict,
        }
    }

    #[must_use]
    pub const fn resolved(self) -> Self {
        match self {
            Self::Conflict => Self::Unknown,
            other => other,
        }
    }

    #[must_use]
    pub const fn is_determined(self) -> bool {
        !matches!(self, Self::Unknown | Self::Conflict)
    }
}

const fn meet_width(a: Width, b: Width) -> Width {
    match (a, b) {
        (Width::Byte, Width::Byte) => Width::Byte,
        (Width::Word, Width::Word) => Width::Word,
        (Width::Dword, Width::Dword) => Width::Dword,
        (Width::Qword, Width::Qword) => Width::Qword,
        (Width::Oword, Width::Oword) => Width::Oword,
        _ => Width::Unknown,
    }
}

const fn api_type_of(ty: &Ty) -> ApiType {
    match ty {
        Ty::Void | Ty::Struct(_) => ApiType::Unknown,
        Ty::Int(c) => ApiType::Integer {
            width: c.width(),
            sign: int_sign(*c),
        },
        Ty::Float(width) => ApiType::Float { width: *width },
        Ty::Pointer(_) => ApiType::Pointer,
        Ty::Handle(_) => ApiType::Handle,
        Ty::Code => ApiType::Code,
    }
}

const fn int_sign(c: CIntType) -> Sign {
    if c.is_signed() {
        Sign::Signed
    } else {
        Sign::Unsigned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSite {
    Return,
    Arg(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    ApiDb {
        library: String,
        name: String,
        site: ApiSite,
    },
    LivenessInferred,
    Heuristic,
}

impl Provenance {
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::ApiDb { .. } => 2,
            Self::LivenessInferred => 1,
            Self::Heuristic => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypedFact {
    ty: ApiType,
    provenance: Provenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotMeta {
    rbp_disp: i64,
    live_lo: u64,
    live_hi: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSlot {
    pub rbp_disp: i64,
    pub live_lo: u64,
    pub live_hi: u64,
    pub ty: ApiType,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Default)]
pub struct CallsiteTyping {
    facts: BTreeMap<TypeVar, TypedFact>,
    meta: BTreeMap<TypeVar, SlotMeta>,
}

impl CallsiteTyping {
    fn record(&mut self, cell: TypeVar, meta: SlotMeta, ty: ApiType, provenance: Provenance) {
        if !ty.is_determined() {
            return;
        }
        self.meta.insert(cell, meta);
        match self.facts.get_mut(&cell) {
            Some(existing) => combine(existing, ty, provenance),
            None => {
                self.facts.insert(cell, TypedFact { ty, provenance });
            }
        }
    }

    #[must_use]
    pub fn typed_slots(&self) -> Vec<TypedSlot> {
        self.facts
            .iter()
            .filter_map(|(cell, fact): (&TypeVar, &TypedFact)| {
                let meta: &SlotMeta = self.meta.get(cell)?;
                let resolved: ApiType = fact.ty.resolved();
                resolved.is_determined().then(|| TypedSlot {
                    rbp_disp: meta.rbp_disp,
                    live_lo: meta.live_lo,
                    live_hi: meta.live_hi,
                    ty: resolved,
                    provenance: fact.provenance.clone(),
                })
            })
            .collect()
    }

    #[must_use]
    pub fn slot_covering(&self, rbp_disp: i64, lo: u64, hi: u64) -> Option<TypedSlot> {
        self.typed_slots().into_iter().find(|slot: &TypedSlot| {
            slot.rbp_disp == rbp_disp
                && slot.live_lo <= slot.live_hi
                && slot.live_lo < hi
                && lo <= slot.live_hi
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.typed_slots().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.typed_slots().is_empty()
    }
}

fn combine(existing: &mut TypedFact, ty: ApiType, provenance: Provenance) {
    match provenance.rank().cmp(&existing.provenance.rank()) {
        core::cmp::Ordering::Greater => {
            existing.ty = ty;
            existing.provenance = provenance;
        }
        core::cmp::Ordering::Less => {}
        core::cmp::Ordering::Equal => {
            existing.ty = existing.ty.meet(ty);
        }
    }
}

#[derive(Debug)]
struct ResolvedCall<'a> {
    library: String,
    name: String,
    proto: &'a Prototype,
}

#[derive(Debug, Clone, Copy)]
enum ParamLoc {
    IntReg(Register),
    SseReg,
    Stack(i64),
}

#[must_use]
pub fn type_function(
    image_text: &[u8],
    text_base: u64,
    low_pc: u64,
    high_pc: u64,
    imports: &ImportMap,
    sigdb: &SigDb,
    abi: Abi,
) -> CallsiteTyping {
    let mut typing: CallsiteTyping = CallsiteTyping::default();
    let Some(bytes): Option<&[u8]> = function_bytes(image_text, text_base, low_pc, high_pc) else {
        return typing;
    };
    let instrs: Vec<Instruction> = decode_all(bytes, low_pc);
    if instrs.is_empty() {
        return typing;
    }
    let cfg: Cfg = cfg::build(&instrs);
    let mut store: CellStore = CellStore::new();
    let ssa: MemSsa = memssa::build(&instrs, &cfg, &mut store);
    let by_cell: BTreeMap<TypeVar, SlotMeta> = cell_meta(&ssa);
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();

    for (index, insn) in instrs.iter().enumerate() {
        if !matches!(
            insn.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            continue;
        }
        let Some(resolved): Option<ResolvedCall<'_>> =
            resolve_call(insn, image_text, text_base, imports, sigdb, abi)
        else {
            continue;
        };
        if !mappable(resolved.proto) {
            continue;
        }
        let locations: Vec<ParamLoc> = map_params(resolved.proto, abi);
        type_arguments(
            &instrs,
            &cfg,
            &ssa,
            &by_cell,
            &mut factory,
            index,
            &resolved,
            &locations,
            &mut typing,
        );
        type_return(
            &instrs,
            &cfg,
            &ssa,
            &by_cell,
            &mut factory,
            index,
            &resolved,
            &mut typing,
        );
    }
    typing
}

fn function_bytes(image_text: &[u8], text_base: u64, low_pc: u64, high_pc: u64) -> Option<&[u8]> {
    let start: usize = usize::try_from(low_pc.checked_sub(text_base)?).ok()?;
    let end: usize = usize::try_from(high_pc.checked_sub(text_base)?).ok()?;
    if end <= start {
        return None;
    }
    image_text.get(start..end)
}

fn cell_meta(ssa: &MemSsa) -> BTreeMap<TypeVar, SlotMeta> {
    let mut out: BTreeMap<TypeVar, SlotMeta> = BTreeMap::new();
    for version in ssa.versions() {
        let version: VersionInfo = *version;
        out.insert(
            version.cell,
            SlotMeta {
                rbp_disp: version.rbp_disp,
                live_lo: version.live_lo,
                live_hi: version.live_hi,
            },
        );
    }
    out
}

fn mappable(proto: &Prototype) -> bool {
    if matches!(proto.return_type, Ty::Struct(_)) {
        return false;
    }
    !proto
        .params
        .iter()
        .any(|param: &crate::sigdb::Param| matches!(param.ty, Ty::Struct(_)))
}

fn map_params(proto: &Prototype, abi: Abi) -> Vec<ParamLoc> {
    match abi.convention() {
        Convention::SysVAmd64 => map_sysv(proto),
        Convention::Win64 | Convention::Unknown => map_win64(proto),
    }
}

fn map_sysv(proto: &Prototype) -> Vec<ParamLoc> {
    let int_regs: &[Register] = int_arg_registers(Convention::SysVAmd64);
    let mut int_index: usize = 0;
    let mut sse_index: u8 = 0;
    let mut stack_off: i64 = 0;
    let mut out: Vec<ParamLoc> = Vec::with_capacity(proto.params.len());
    for param in &proto.params {
        if is_float(&param.ty) {
            if sse_index < 8 {
                out.push(ParamLoc::SseReg);
                sse_index += 1;
            } else {
                out.push(ParamLoc::Stack(stack_off));
                stack_off += 8;
            }
        } else if let Some(reg) = int_regs.get(int_index) {
            out.push(ParamLoc::IntReg(*reg));
            int_index += 1;
        } else {
            out.push(ParamLoc::Stack(stack_off));
            stack_off += 8;
        }
    }
    out
}

fn map_win64(proto: &Prototype) -> Vec<ParamLoc> {
    let int_regs: &[Register] = int_arg_registers(Convention::Win64);
    let mut out: Vec<ParamLoc> = Vec::with_capacity(proto.params.len());
    let mut stack_off: i64 = 0x20;
    for (position, param) in proto.params.iter().enumerate() {
        if let Some(reg) = int_regs.get(position) {
            if is_float(&param.ty) {
                out.push(ParamLoc::SseReg);
            } else {
                out.push(ParamLoc::IntReg(*reg));
            }
        } else {
            out.push(ParamLoc::Stack(stack_off));
            stack_off += 8;
        }
    }
    out
}

const fn is_float(ty: &Ty) -> bool {
    matches!(ty, Ty::Float(_))
}

#[allow(clippy::too_many_arguments)]
fn type_arguments(
    instrs: &[Instruction],
    cfg: &Cfg,
    ssa: &MemSsa,
    by_cell: &BTreeMap<TypeVar, SlotMeta>,
    factory: &mut InstructionInfoFactory,
    call_index: usize,
    resolved: &ResolvedCall<'_>,
    locations: &[ParamLoc],
    typing: &mut CallsiteTyping,
) {
    for (position, location) in locations.iter().enumerate() {
        let Some(param): Option<&crate::sigdb::Param> = resolved.proto.params.get(position) else {
            continue;
        };
        let ty: ApiType = api_type_of(&param.ty);
        if !ty.is_determined() {
            continue;
        }
        let provenance: Provenance = Provenance::ApiDb {
            library: resolved.library.clone(),
            name: resolved.name.clone(),
            site: ApiSite::Arg(position),
        };
        match location {
            ParamLoc::IntReg(reg) => {
                if let Some((load_ip, rbp_disp)) =
                    reg_slot_source(instrs, cfg, factory, call_index, *reg, 0)
                {
                    attach(ssa, by_cell, typing, load_ip, rbp_disp, ty, provenance);
                }
            }
            ParamLoc::Stack(offset) => {
                if let Some((load_ip, rbp_disp)) =
                    stack_slot_source(instrs, cfg, factory, call_index, *offset)
                {
                    attach(ssa, by_cell, typing, load_ip, rbp_disp, ty, provenance);
                }
            }
            ParamLoc::SseReg => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn type_return(
    instrs: &[Instruction],
    cfg: &Cfg,
    ssa: &MemSsa,
    by_cell: &BTreeMap<TypeVar, SlotMeta>,
    factory: &mut InstructionInfoFactory,
    call_index: usize,
    resolved: &ResolvedCall<'_>,
    typing: &mut CallsiteTyping,
) {
    let ty: ApiType = api_type_of(&resolved.proto.return_type);
    if !ty.is_determined() {
        return;
    }
    let float_return: bool = matches!(ty, ApiType::Float { .. });
    let Some((store_ip, rbp_disp)): Option<(u64, i64)> =
        return_store_slot(instrs, cfg, factory, call_index, float_return)
    else {
        return;
    };
    let provenance: Provenance = Provenance::ApiDb {
        library: resolved.library.clone(),
        name: resolved.name.clone(),
        site: ApiSite::Return,
    };
    attach(ssa, by_cell, typing, store_ip, rbp_disp, ty, provenance);
}

fn attach(
    ssa: &MemSsa,
    by_cell: &BTreeMap<TypeVar, SlotMeta>,
    typing: &mut CallsiteTyping,
    access_ip: u64,
    rbp_disp: i64,
    ty: ApiType,
    provenance: Provenance,
) {
    let Some(cell): Option<TypeVar> = ssa.version_cell(access_ip, rbp_disp) else {
        return;
    };
    let Some(meta): Option<&SlotMeta> = by_cell.get(&cell) else {
        return;
    };
    typing.record(cell, *meta, ty, provenance);
}

fn block_bounds(cfg: &Cfg, index: usize) -> (usize, usize) {
    cfg.block_containing(index)
        .map_or((0, index), |block_index: usize| {
            cfg.blocks
                .get(block_index)
                .map_or((0, index), |block: &BasicBlock| (block.start, block.end))
        })
}

fn reg_slot_source(
    instrs: &[Instruction],
    cfg: &Cfg,
    factory: &mut InstructionInfoFactory,
    from_index: usize,
    reg: Register,
    depth: u8,
) -> Option<(u64, i64)> {
    if depth > MAX_COPY_DEPTH {
        return None;
    }
    let (block_start, _): (usize, usize) =
        block_bounds(cfg, from_index.min(instrs.len().saturating_sub(1)));
    let mut cursor: usize = from_index;
    while cursor > block_start {
        cursor -= 1;
        let insn: &Instruction = instrs.get(cursor)?;
        if !writes_register(insn, factory, reg) {
            continue;
        }
        if let Some((load_ip, rbp_disp)) = slot_load(insn, reg) {
            return Some((load_ip, rbp_disp));
        }
        if let Some(source) = register_copy(insn, reg) {
            return reg_slot_source(instrs, cfg, factory, cursor, source, depth + 1);
        }
        return None;
    }
    None
}

fn stack_slot_source(
    instrs: &[Instruction],
    cfg: &Cfg,
    factory: &mut InstructionInfoFactory,
    call_index: usize,
    rsp_offset: i64,
) -> Option<(u64, i64)> {
    let (block_start, _): (usize, usize) = block_bounds(cfg, call_index);
    let mut cursor: usize = call_index;
    while cursor > block_start {
        cursor -= 1;
        let insn: &Instruction = instrs.get(cursor)?;
        let Some(source): Option<Register> = rsp_store_source(insn, rsp_offset) else {
            continue;
        };
        return reg_slot_source(instrs, cfg, factory, cursor, source, 0);
    }
    None
}

fn slot_load(insn: &Instruction, reg: Register) -> Option<(u64, i64)> {
    if insn.mnemonic() != Mnemonic::Mov
        || insn.op0_kind() != OpKind::Register
        || insn.op1_kind() != OpKind::Memory
    {
        return None;
    }
    if insn.op_register(0).full_register() != reg {
        return None;
    }
    if insn.memory_base() != Register::RBP || insn.memory_index() != Register::None {
        return None;
    }
    let rbp_disp: i64 = i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes());
    Some((insn.ip(), rbp_disp))
}

fn register_copy(insn: &Instruction, reg: Register) -> Option<Register> {
    if insn.mnemonic() != Mnemonic::Mov
        || insn.op0_kind() != OpKind::Register
        || insn.op1_kind() != OpKind::Register
    {
        return None;
    }
    if insn.op_register(0).full_register() != reg {
        return None;
    }
    Some(insn.op_register(1).full_register())
}

fn rsp_store_source(insn: &Instruction, rsp_offset: i64) -> Option<Register> {
    if insn.mnemonic() != Mnemonic::Mov
        || insn.op0_kind() != OpKind::Memory
        || insn.op1_kind() != OpKind::Register
    {
        return None;
    }
    if insn.memory_base() != Register::RSP || insn.memory_index() != Register::None {
        return None;
    }
    let disp: i64 = i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes());
    (disp == rsp_offset).then(|| insn.op_register(1).full_register())
}

fn return_store_slot(
    instrs: &[Instruction],
    cfg: &Cfg,
    factory: &mut InstructionInfoFactory,
    call_index: usize,
    float_return: bool,
) -> Option<(u64, i64)> {
    let ret_reg: Register = if float_return {
        Register::XMM0
    } else {
        Register::RAX
    };
    let (_, block_end): (usize, usize) = block_bounds(cfg, call_index);
    let mut cursor: usize = call_index + 1;
    while cursor < block_end {
        let insn: &Instruction = instrs.get(cursor)?;
        if let Some((store_ip, rbp_disp)) = ret_store(insn, ret_reg) {
            return Some((store_ip, rbp_disp));
        }
        if touches_register(insn, factory, ret_reg) {
            return None;
        }
        if insn.flow_control() != FlowControl::Next {
            return None;
        }
        cursor += 1;
    }
    None
}

fn ret_store(insn: &Instruction, ret_reg: Register) -> Option<(u64, i64)> {
    if insn.mnemonic() != Mnemonic::Mov
        || insn.op0_kind() != OpKind::Memory
        || insn.op1_kind() != OpKind::Register
    {
        return None;
    }
    if insn.op_register(1).full_register() != ret_reg {
        return None;
    }
    if insn.memory_base() != Register::RBP || insn.memory_index() != Register::None {
        return None;
    }
    let rbp_disp: i64 = i64::from_ne_bytes(insn.memory_displacement64().to_ne_bytes());
    Some((insn.ip(), rbp_disp))
}

fn writes_register(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    reg: Register,
) -> bool {
    let info: &InstructionInfo = factory.info(insn);
    info.used_registers().iter().any(|used: &UsedRegister| {
        matches!(used.access(), OpAccess::Write | OpAccess::ReadWrite)
            && used.register().full_register() == reg
    })
}

fn touches_register(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    reg: Register,
) -> bool {
    let info: &InstructionInfo = factory.info(insn);
    info.used_registers()
        .iter()
        .any(|used: &UsedRegister| used.register().full_register() == reg)
}

fn resolve_call<'a>(
    insn: &Instruction,
    image_text: &[u8],
    text_base: u64,
    imports: &ImportMap,
    sigdb: &'a SigDb,
    abi: Abi,
) -> Option<ResolvedCall<'a>> {
    let slot_va: u64 = call_slot_va(insn, image_text, text_base, imports)?;
    let import: &ImportRef = imports.resolve(slot_va)?;
    let name: &str = import.lookup_key()?;
    let library: String = resolve_library(import, abi);
    let proto: &Prototype = sigdb.lookup(&library, name, abi)?;
    Some(ResolvedCall {
        library,
        name: name.to_owned(),
        proto,
    })
}

fn call_slot_va(
    insn: &Instruction,
    image_text: &[u8],
    text_base: u64,
    imports: &ImportMap,
) -> Option<u64> {
    if let Some(slot) = indirect_slot_va(insn) {
        return Some(slot);
    }
    let target: u64 = direct_call_target(insn)?;
    follow_thunk(image_text, text_base, target, imports)
}

fn indirect_slot_va(insn: &Instruction) -> Option<u64> {
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.is_ip_rel_memory_operand() {
        return Some(insn.ip_rel_memory_address());
    }
    if insn.memory_base() == Register::None && insn.memory_index() == Register::None {
        return Some(insn.memory_displacement64());
    }
    None
}

fn direct_call_target(insn: &Instruction) -> Option<u64> {
    matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| insn.near_branch_target())
}

fn follow_thunk(
    image_text: &[u8],
    text_base: u64,
    target: u64,
    imports: &ImportMap,
) -> Option<u64> {
    let start: usize = usize::try_from(target.checked_sub(text_base)?).ok()?;
    let window: &[u8] = image_text.get(start..)?;
    let capped: &[u8] = &window[..window.len().min(MAX_THUNK_INSNS * 15)];
    let stub: Vec<Instruction> = decode_all(capped, target);
    for insn in stub.iter().take(MAX_THUNK_INSNS) {
        match insn.flow_control() {
            FlowControl::IndirectBranch | FlowControl::UnconditionalBranch => {
                if let Some(slot) = indirect_slot_va(insn)
                    && imports.resolve(slot).is_some()
                {
                    return Some(slot);
                }
                return None;
            }
            FlowControl::Next => {}
            _ => return None,
        }
    }
    None
}

fn resolve_library(import: &ImportRef, abi: Abi) -> String {
    if !import.library.is_empty() {
        return import.library.clone();
    }
    match abi {
        Abi::SysV => "libc".to_owned(),
        Abi::Win64 => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::import_map::{ImportFormat, ImportSource, ImportSymbol};

    fn elf_import(name: &str) -> ImportRef {
        ImportRef {
            library: String::new(),
            symbol: ImportSymbol::Name(name.to_owned()),
            source: ImportSource::ElfGlobData,
        }
    }

    fn map_with(entries: &[(u64, ImportRef)]) -> ImportMap {
        let mut map: ImportMap = ImportMap {
            format: ImportFormat::Elf,
            ..ImportMap::default()
        };
        for (slot, import) in entries {
            map.by_slot_va.insert(*slot, import.clone());
        }
        map
    }

    #[test]
    fn api_type_meet_abstains_on_pointer_versus_integer() {
        let pointer: ApiType = ApiType::Pointer;
        let integer: ApiType = ApiType::Integer {
            width: Width::Qword,
            sign: Sign::Unsigned,
        };
        assert_eq!(pointer.meet(integer), ApiType::Conflict);
        assert_eq!(pointer.meet(integer).resolved(), ApiType::Unknown);
        assert_eq!(pointer.meet(ApiType::Unknown), ApiType::Pointer);
        assert_eq!(pointer.meet(ApiType::Pointer), ApiType::Pointer);
    }

    #[test]
    fn api_type_meet_drops_disagreeing_sign_to_unknown_not_conflict() {
        let signed: ApiType = ApiType::Integer {
            width: Width::Dword,
            sign: Sign::Signed,
        };
        let unsigned: ApiType = ApiType::Integer {
            width: Width::Dword,
            sign: Sign::Unsigned,
        };
        assert_eq!(
            signed.meet(unsigned),
            ApiType::Integer {
                width: Width::Dword,
                sign: Sign::Unknown
            }
        );
    }

    #[test]
    fn api_type_meet_keeps_a_disagreeing_width_unknown_regardless_of_order() {
        let dword: ApiType = ApiType::Integer {
            width: Width::Dword,
            sign: Sign::Signed,
        };
        let qword: ApiType = ApiType::Integer {
            width: Width::Qword,
            sign: Sign::Signed,
        };
        let unwidthed: ApiType = ApiType::Integer {
            width: Width::Unknown,
            sign: Sign::Signed,
        };
        assert_eq!(dword.meet(qword).meet(dword), unwidthed);
        assert_eq!(dword.meet(dword).meet(qword), unwidthed);
        assert_eq!(dword.meet(qword).meet(dword), dword.meet(dword).meet(qword));
    }

    #[test]
    fn provenance_ordering_never_lets_a_lower_source_overwrite_higher() {
        let mut fact: TypedFact = TypedFact {
            ty: ApiType::Pointer,
            provenance: Provenance::ApiDb {
                library: "libc".to_owned(),
                name: "memcpy".to_owned(),
                site: ApiSite::Arg(0),
            },
        };
        combine(
            &mut fact,
            ApiType::Integer {
                width: Width::Qword,
                sign: Sign::Unsigned,
            },
            Provenance::Heuristic,
        );
        assert_eq!(fact.ty, ApiType::Pointer, "a lower source cannot overwrite");
    }

    fn seeded_db() -> SigDb {
        SigDb::builtin()
    }

    #[test]
    fn direct_import_slot_call_types_register_argument() {
        let low_pc: u64 = 0x1000;
        let slot_va: u64 = 0x2ffc;
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x7d, 0xf8, 0xff, 0x15,
            0xea, 0x1f, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf0, 0x5d, 0xc3,
        ];
        let map: ImportMap = map_with(&[(slot_va, elf_import("strlen"))]);
        let typing: CallsiteTyping = type_function(
            bytes,
            low_pc,
            low_pc,
            low_pc + bytes.len() as u64,
            &map,
            &seeded_db(),
            Abi::SysV,
        );
        let arg: TypedSlot = typing
            .slot_covering(-8, low_pc, low_pc + bytes.len() as u64)
            .expect("strlen s argument slot recovered");
        assert_eq!(arg.ty, ApiType::Pointer, "strlen s is const char*");
        let ret: TypedSlot = typing
            .slot_covering(-16, low_pc, low_pc + bytes.len() as u64)
            .expect("strlen return slot recovered");
        assert_eq!(
            ret.ty,
            ApiType::Integer {
                width: Width::Qword,
                sign: Sign::Unsigned
            },
            "strlen returns size_t"
        );
    }

    #[test]
    fn unresolved_target_abstains() {
        let low_pc: u64 = 0x1000;
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x7d, 0xf8, 0xff, 0x15,
            0xea, 0x1f, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf0, 0x5d, 0xc3,
        ];
        let map: ImportMap = map_with(&[(0x9999, elf_import("strlen"))]);
        let typing: CallsiteTyping = type_function(
            bytes,
            low_pc,
            low_pc,
            low_pc + bytes.len() as u64,
            &map,
            &seeded_db(),
            Abi::SysV,
        );
        assert!(
            typing.is_empty(),
            "a call whose slot resolves to nothing must emit no type"
        );
    }

    #[test]
    fn missing_prototype_abstains() {
        let low_pc: u64 = 0x1000;
        let slot_va: u64 = 0x2ffc;
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x7d, 0xf8, 0xff, 0x15,
            0xea, 0x1f, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf0, 0x5d, 0xc3,
        ];
        let map: ImportMap = map_with(&[(slot_va, elf_import("not_a_seeded_symbol"))]);
        let typing: CallsiteTyping = type_function(
            bytes,
            low_pc,
            low_pc,
            low_pc + bytes.len() as u64,
            &map,
            &seeded_db(),
            Abi::SysV,
        );
        assert!(
            typing.is_empty(),
            "a target with no SigDb prototype must abstain"
        );
    }

    #[test]
    fn conflicting_callsites_join_to_unknown() {
        let low_pc: u64 = 0x1000;
        let strlen_slot: u64 = 0x2ff8;
        let free_slot: u64 = 0x2ff7;
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x7d, 0xf8, 0xff, 0x15,
            0xe6, 0x1f, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf0, 0x48, 0x8b, 0x7d, 0xf0, 0xff, 0x15,
            0xd7, 0x1f, 0x00, 0x00, 0x5d, 0xc3,
        ];
        let map: ImportMap = map_with(&[
            (strlen_slot, elf_import("strlen")),
            (free_slot, elf_import("free")),
        ]);
        let typing: CallsiteTyping = type_function(
            bytes,
            low_pc,
            low_pc,
            low_pc + bytes.len() as u64,
            &map,
            &seeded_db(),
            Abi::SysV,
        );
        let end: u64 = low_pc + bytes.len() as u64;
        assert_eq!(
            typing
                .slot_covering(-8, low_pc, end)
                .map(|slot: TypedSlot| slot.ty),
            Some(ApiType::Pointer),
            "the strlen argument slot is a pointer"
        );
        assert!(
            typing.slot_covering(-16, low_pc, end).is_none(),
            "size_t-return then pointer-argument is contradictory and must abstain"
        );
    }

    #[test]
    fn win64_stack_argument_backpropagates_through_the_outgoing_store() {
        let low_pc: u64 = 0x2000;
        let slot_va: u64 = 0x4ff0;
        let bytes: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x40, 0x89, 0x4d, 0xfc, 0x8b, 0x45, 0xfc,
            0x89, 0x44, 0x24, 0x20, 0xff, 0x15, 0xd8, 0x2f, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x40,
            0x5d, 0xc3,
        ];
        let map: ImportMap = map_with(&[(
            slot_va,
            ImportRef {
                library: "kernel32.dll".to_owned(),
                symbol: ImportSymbol::Name("CreateFileW".to_owned()),
                source: ImportSource::PeImport,
            },
        )]);
        let mut pe_map: ImportMap = map;
        pe_map.format = ImportFormat::Pe;
        let typing: CallsiteTyping = type_function(
            bytes,
            low_pc,
            low_pc,
            low_pc + bytes.len() as u64,
            &pe_map,
            &seeded_db(),
            Abi::Win64,
        );
        let arg: TypedSlot = typing
            .slot_covering(-4, low_pc, low_pc + bytes.len() as u64)
            .expect("the fifth CreateFileW argument backpropagates to its local");
        assert_eq!(
            arg.ty,
            ApiType::Integer {
                width: Width::Dword,
                sign: Sign::Unsigned
            },
            "dwCreationDisposition is a DWORD"
        );
    }
}
