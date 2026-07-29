use std::collections::{BTreeMap, BTreeSet};

use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, InsnFlow, RegAccess};
use disrobe_similarity::{
    BasicBlock as StructureBlock, ControlFlowGraph, DataReference, FunctionFeatures, FunctionId,
    InstructionCategory,
};
use iced_x86::{
    ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo,
    InstructionInfoFactory, Mnemonic, OpKind, Register, UsedMemory,
};

use crate::arch::Arch;
use crate::basic_blocks::{BasicBlock, Transfer, build_cfg};
use crate::desync::ReadOnlyWindow;
use crate::disasm_ir::{
    DisasmBuild, FunctionSpan, FunctionUniverse, build_disasm_payload_with_discovery,
    function_spans, image_arch, map_access, mapped_address_extent, read_only_windows,
    span_instructions,
};
use crate::error::{Error, Result};
use crate::fingerprint::{ASCII_XREF_MIN_LEN, StringXref, extract_ascii_xrefs};
use crate::plt_resolve::{ImportStub, resolve_elf_plt_imports, resolve_pe_iat_imports};
use crate::pseudo_c::aarch64::{
    AARCH64_INSTRUCTION_BYTES, Aarch64DirectTransfer, aarch64_adr_target, aarch64_adrp_target,
    aarch64_direct_transfer, aarch64_is_indirect_branch, aarch64_is_return, aarch64_is_trap,
    aarch64_stops_traversal, aarch64_word, immediate_field, register_field,
};

const ADRP_PAIR_SCAN_LIMIT: usize = 16;

const WIDE_MOVE_CHAIN_LIMIT: usize = 3;

const ADDRESS_IMMEDIATE_MIN_BITS: u32 = 32;

const ADD_IMMEDIATE_64: u32 = 0x9100_0000;

const ADD_IMMEDIATE_MASK: u32 = 0xffc0_0000;

const WIDE_MOVE_MASK: u32 = 0x7f80_0000;

const MOVN: u32 = 0x1280_0000;

const MOVZ: u32 = 0x5280_0000;

const MOVK: u32 = 0x7280_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureArch {
    X86 { bits: u32 },
    Aarch64,
}

impl FeatureArch {
    const fn from_arch(arch: Arch) -> Option<Self> {
        match arch {
            Arch::X86 => Some(Self::X86 { bits: 32 }),
            Arch::X86_64 => Some(Self::X86 { bits: 64 }),
            Arch::Aarch64 => Some(Self::Aarch64),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct ImageIndex {
    strings: BTreeMap<u64, String>,
    import_slots: BTreeMap<u64, String>,
    import_stubs: BTreeMap<u64, String>,
    mapped: Option<(u64, u64)>,
}

struct Aarch64FeatureParts {
    references: Vec<DataReference>,
    structure: Option<ControlFlowGraph>,
    calls: BTreeSet<FunctionId>,
}

struct FunctionBody<'a> {
    address: u64,
    instructions: &'a [DisasmInstruction],
}

impl ImageIndex {
    fn build(bytes: &[u8], payload: &DisasmPayload, arch: FeatureArch) -> Self {
        let (import_slots, mut import_stubs): (BTreeMap<u64, String>, BTreeMap<u64, String>) =
            index_imports(bytes, arch);
        if let FeatureArch::X86 { bits } = arch {
            import_stubs.extend(index_import_thunks(payload, bits, &import_slots));
        }
        Self {
            strings: index_strings(bytes),
            import_slots,
            import_stubs,
            mapped: mapped_address_extent(bytes),
        }
    }

    fn string_at(&self, address: u64) -> Option<&String> {
        self.strings.get(&address)
    }

    fn is_mapped_address(&self, value: u64) -> bool {
        self.mapped
            .is_some_and(|(low, high): (u64, u64)| value >= low && value < high)
    }

    fn constant(&self, value: u64) -> Option<DataReference> {
        if self.is_mapped_address(value) || is_packed_ascii(value) {
            return None;
        }
        DataReference::constant(value)
    }
}

pub fn extract_function_features(bytes: &[u8]) -> Result<Vec<FunctionFeatures>> {
    let build: DisasmBuild = build_disasm_payload_with_discovery(bytes)?;
    let function_universe: FunctionUniverse = build.function_universe;
    let payload: DisasmPayload = build.payload;
    let arch: Arch = image_arch(bytes).ok_or_else(|| {
        Error::UnsupportedArch("image carries no architecture the disassembler maps".to_owned())
    })?;
    let Some(feature_arch): Option<FeatureArch> = FeatureArch::from_arch(arch) else {
        return Err(Error::UnsupportedArch(format!(
            "{} has no data-reference extractor",
            arch.label()
        )));
    };

    let index: ImageIndex = ImageIndex::build(bytes, &payload, feature_arch);
    let spans: Vec<FunctionSpan> = function_spans(&payload, arch);
    let mut bodies: Vec<FunctionBody<'_>> = Vec::with_capacity(spans.len());
    for span in &spans {
        let instructions: &[DisasmInstruction] = span_instructions(&payload.instructions, span);
        if !instructions.is_empty() {
            bodies.push(FunctionBody {
                address: span.address,
                instructions,
            });
        }
    }
    let entries: BTreeSet<u64> = bodies
        .iter()
        .map(|body: &FunctionBody<'_>| body.address)
        .collect();

    let mut features: Vec<FunctionFeatures> = Vec::with_capacity(bodies.len());
    for body in bodies {
        let (references, structure, calls): (
            Vec<DataReference>,
            Option<ControlFlowGraph>,
            BTreeSet<FunctionId>,
        ) = match feature_arch {
            FeatureArch::X86 { bits } => {
                let decoded: Vec<Option<Instruction>> = body
                    .instructions
                    .iter()
                    .map(|insn: &DisasmInstruction| decode_x86(bits, insn))
                    .collect();
                (
                    x86_references(body.instructions, &decoded, &index),
                    x86_structure(body.instructions, &decoded),
                    x86_call_targets(body.instructions, &index, &entries),
                )
            }
            FeatureArch::Aarch64 => {
                let reference_anchors_trusted: bool =
                    function_universe.reference_anchors_trusted(body.address);
                let parts: Aarch64FeatureParts = aarch64_feature_parts(
                    body.instructions,
                    &index,
                    &entries,
                    reference_anchors_trusted,
                );
                (parts.references, parts.structure, parts.calls)
            }
        };
        let id: FunctionId = FunctionId::from(body.address);
        let carried: FunctionFeatures = match structure {
            Some(graph) => FunctionFeatures::with_structure(id, references, graph),
            None => FunctionFeatures::new(id, references),
        };
        features.push(carried.calling(calls));
    }
    Ok(features)
}

fn aarch64_feature_parts(
    body: &[DisasmInstruction],
    index: &ImageIndex,
    entries: &BTreeSet<u64>,
    reference_anchors: bool,
) -> Aarch64FeatureParts {
    let Some(parts): Option<Aarch64FeatureParts> =
        aarch64_reachable_feature_parts(body, index, entries, reference_anchors)
    else {
        let prefix: &[DisasmInstruction] = aarch64_terminated_prefix(body);
        return Aarch64FeatureParts {
            references: if reference_anchors {
                aarch64_references(prefix, index)
            } else {
                Vec::new()
            },
            structure: None,
            calls: aarch64_call_targets(prefix, entries),
        };
    };
    parts
}

fn aarch64_terminated_prefix(body: &[DisasmInstruction]) -> &[DisasmInstruction] {
    let mut previous_address: Option<u64> = None;
    for (index, instruction) in body.iter().enumerate() {
        if instruction.bytes.len() != AARCH64_INSTRUCTION_BYTES
            || previous_address.is_some_and(|address: u64| {
                address.checked_add(AARCH64_INSTRUCTION_BYTES as u64) != Some(instruction.offset)
            })
        {
            return &[];
        }
        previous_address = Some(instruction.offset);
        let Some(word): Option<u32> = instruction_word(instruction) else {
            return &[];
        };
        let stops: bool = match aarch64_direct_transfer(instruction.offset, word) {
            Some(Aarch64DirectTransfer::BranchLink { .. }) => false,
            Some(
                Aarch64DirectTransfer::UnconditionalBranch { .. }
                | Aarch64DirectTransfer::ConditionalBranch { .. }
                | Aarch64DirectTransfer::CompareBranch { .. }
                | Aarch64DirectTransfer::TestBranch { .. },
            ) => true,
            None => aarch64_stops_traversal(&instruction.mnemonic),
        };
        if stops {
            let Some(end): Option<usize> = index.checked_add(1) else {
                return &[];
            };
            let Some(prefix): Option<&[DisasmInstruction]> = body.get(..end) else {
                return &[];
            };
            return prefix;
        }
    }
    &[]
}

fn aarch64_reachable_feature_parts(
    body: &[DisasmInstruction],
    index: &ImageIndex,
    entries: &BTreeSet<u64>,
    reference_anchors: bool,
) -> Option<Aarch64FeatureParts> {
    let blocks: Vec<BasicBlock> = aarch64_blocks(body)?;
    let spans: Vec<&[DisasmInstruction]> = aarch64_reachable_spans(body, &blocks)?;
    let reference_capacity: usize = if reference_anchors { blocks.len() } else { 0 };
    let mut references: Vec<DataReference> = Vec::with_capacity(reference_capacity);
    let mut calls: BTreeSet<FunctionId> = BTreeSet::new();
    for span in spans {
        if reference_anchors {
            references.extend(aarch64_references(span, index));
        }
        calls.extend(aarch64_call_targets(span, entries));
    }
    let structure: Option<ControlFlowGraph> = aarch64_structure_from_blocks(body, &blocks);
    Some(Aarch64FeatureParts {
        references,
        structure,
        calls,
    })
}

fn aarch64_reachable_spans<'a>(
    body: &'a [DisasmInstruction],
    blocks: &[BasicBlock],
) -> Option<Vec<&'a [DisasmInstruction]>> {
    let mut reachable: Vec<u8> = vec![0; body.len()];
    for block in blocks {
        let marked: &mut [u8] = reachable.get_mut(block.insns.clone())?;
        marked.fill(1);
    }

    let mut spans: Vec<&[DisasmInstruction]> = Vec::with_capacity(blocks.len());
    let mut cursor: usize = 0;
    while cursor < reachable.len() {
        while cursor < reachable.len() && reachable.get(cursor).copied()? == 0 {
            cursor = cursor.checked_add(1)?;
        }
        let start: usize = cursor;
        while cursor < reachable.len() && reachable.get(cursor).copied()? != 0 {
            cursor = cursor.checked_add(1)?;
        }
        if start < cursor {
            spans.push(body.get(start..cursor)?);
        }
    }
    Some(spans)
}

fn x86_call_targets(
    body: &[DisasmInstruction],
    index: &ImageIndex,
    entries: &BTreeSet<u64>,
) -> BTreeSet<FunctionId> {
    let mut out: BTreeSet<FunctionId> = BTreeSet::new();
    for insn in body {
        if !matches!(insn.flow, InsnFlow::Call) {
            continue;
        }
        let Some(target): Option<u64> = insn.branch_target else {
            continue;
        };
        if index.import_stubs.contains_key(&target) || !entries.contains(&target) {
            continue;
        }
        out.insert(FunctionId::from(target));
    }
    out
}

fn aarch64_call_targets(
    body: &[DisasmInstruction],
    entries: &BTreeSet<u64>,
) -> BTreeSet<FunctionId> {
    let mut out: BTreeSet<FunctionId> = BTreeSet::new();
    for insn in body {
        if insn.mnemonic != "bl" {
            continue;
        }
        let Some(target): Option<u64> = instruction_word(insn)
            .and_then(|word: u32| aarch64_branch_link_target(insn.offset, word))
        else {
            continue;
        };
        if !entries.contains(&target) {
            continue;
        }
        out.insert(FunctionId::from(target));
    }
    out
}

fn aarch64_branch_link_target(address: u64, word: u32) -> Option<u64> {
    match aarch64_direct_transfer(address, word) {
        Some(Aarch64DirectTransfer::BranchLink { target }) => Some(target),
        Some(
            Aarch64DirectTransfer::UnconditionalBranch { .. }
            | Aarch64DirectTransfer::ConditionalBranch { .. }
            | Aarch64DirectTransfer::CompareBranch { .. }
            | Aarch64DirectTransfer::TestBranch { .. },
        )
        | None => None,
    }
}

fn instruction_positions(body: &[DisasmInstruction]) -> Option<BTreeMap<u64, usize>> {
    let positions: BTreeMap<u64, usize> = body
        .iter()
        .enumerate()
        .map(|(position, insn): (usize, &DisasmInstruction)| (insn.offset, position))
        .collect();
    (positions.len() == body.len()).then_some(positions)
}

fn control_flow_graph(
    blocks: &[BasicBlock],
    categories: &[InstructionCategory],
) -> Option<ControlFlowGraph> {
    let mut out: Vec<StructureBlock> = Vec::with_capacity(blocks.len());
    for block in blocks {
        let span: &[InstructionCategory] = categories.get(block.insns.clone())?;
        out.push(StructureBlock::new(
            block.successors.iter().copied(),
            span.iter().copied(),
        ));
    }
    ControlFlowGraph::new(0, out)
}

fn index_strings(bytes: &[u8]) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    for window in read_only_windows(bytes) {
        let window: ReadOnlyWindow<'_> = window;
        for xref in extract_ascii_xrefs(window.bytes, ASCII_XREF_MIN_LEN) {
            let xref: StringXref = xref;
            let Some(address): Option<u64> = window.address.checked_add(xref.offset) else {
                continue;
            };
            out.insert(address, xref.value);
        }
    }
    out
}

fn index_imports(
    bytes: &[u8],
    arch: FeatureArch,
) -> (BTreeMap<u64, String>, BTreeMap<u64, String>) {
    let mut slots: BTreeMap<u64, String> = BTreeMap::new();
    let mut stubs: BTreeMap<u64, String> = BTreeMap::new();
    if !matches!(arch, FeatureArch::X86 { .. }) {
        return (slots, stubs);
    }
    for stub in resolve_elf_plt_imports(bytes) {
        let stub: ImportStub = stub;
        slots.insert(stub.slot_address, stub.name.clone());
        stubs.insert(stub.stub_address, stub.name);
    }
    for stub in resolve_pe_iat_imports(bytes) {
        let stub: ImportStub = stub;
        slots.insert(stub.slot_address, stub.name);
    }
    (slots, stubs)
}

fn index_import_thunks(
    payload: &DisasmPayload,
    bits: u32,
    slots: &BTreeMap<u64, String>,
) -> BTreeMap<u64, String> {
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    if slots.is_empty() {
        return out;
    }
    for insn in &payload.instructions {
        if !matches!(insn.flow, InsnFlow::IndirectBranch) {
            continue;
        }
        let Some(decoded): Option<Instruction> = decode_x86(bits, insn) else {
            continue;
        };
        if decoded.mnemonic() != Mnemonic::Jmp {
            continue;
        }
        let Some(slot): Option<u64> = absolute_memory_target(&decoded) else {
            continue;
        };
        let Some(name): Option<&String> = slots.get(&slot) else {
            continue;
        };
        out.insert(insn.offset, name.clone());
    }
    out
}

fn decode_x86(bits: u32, insn: &DisasmInstruction) -> Option<Instruction> {
    if insn.bytes.is_empty() {
        return None;
    }
    let mut decoder: Decoder<'_> =
        Decoder::with_ip(bits, &insn.bytes, insn.offset, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let mut decoded: Instruction = Instruction::default();
    decoder.decode_out(&mut decoded);
    if decoded.is_invalid() || decoded.len() != insn.bytes.len() {
        return None;
    }
    Some(decoded)
}

fn absolute_memory_target(decoded: &Instruction) -> Option<u64> {
    if !(0..decoded.op_count()).any(|operand: u32| decoded.op_kind(operand) == OpKind::Memory) {
        return None;
    }
    if decoded.is_ip_rel_memory_operand() {
        return Some(decoded.ip_rel_memory_address());
    }
    if decoded.memory_base() == Register::None && decoded.memory_index() == Register::None {
        return Some(decoded.memory_displacement64());
    }
    None
}

fn x86_references(
    body: &[DisasmInstruction],
    decoded: &[Option<Instruction>],
    index: &ImageIndex,
) -> Vec<DataReference> {
    let mut out: Vec<DataReference> = Vec::new();
    for (insn, slot) in body.iter().zip(decoded) {
        let Some(decoded): Option<&Instruction> = slot.as_ref() else {
            continue;
        };
        if let Some(reference) = x86_reference(insn, decoded, index) {
            out.push(reference);
        }
    }
    out
}

fn x86_structure(
    body: &[DisasmInstruction],
    decoded: &[Option<Instruction>],
) -> Option<ControlFlowGraph> {
    let mut resolved: Vec<&Instruction> = Vec::with_capacity(body.len());
    for slot in decoded {
        resolved.push(slot.as_ref()?);
    }
    if resolved.len() != body.len() {
        return None;
    }
    let positions: BTreeMap<u64, usize> = instruction_positions(body)?;
    let transfers: Vec<Transfer> = resolved.iter().copied().map(x86_transfer).collect();
    let blocks: Vec<BasicBlock> = build_cfg(&transfers, &positions, 0)?;
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let categories: Vec<InstructionCategory> = resolved
        .iter()
        .copied()
        .map(|insn: &Instruction| x86_category(insn, &mut factory))
        .collect();
    control_flow_graph(&blocks, &categories)
}

fn x86_transfer(decoded: &Instruction) -> Transfer {
    let direct: bool = matches!(
        decoded.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    match decoded.flow_control() {
        FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => Transfer::FallsThrough,
        FlowControl::Return => Transfer::Terminal { returns: true },
        FlowControl::Interrupt => Transfer::Terminal { returns: false },
        FlowControl::ConditionalBranch if direct => Transfer::ConditionalBranch {
            taken: decoded.near_branch_target(),
        },
        FlowControl::UnconditionalBranch if direct => Transfer::UnconditionalBranch {
            taken: decoded.near_branch_target(),
        },
        _ => Transfer::Unresolved,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Simple(InstructionCategory),
    DataMove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryTouch {
    None,
    Read,
    Write,
}

impl MemoryTouch {
    const fn resolve(self, absent: InstructionCategory) -> InstructionCategory {
        match self {
            Self::None => absent,
            Self::Read => InstructionCategory::Load,
            Self::Write => InstructionCategory::Store,
        }
    }
}

fn x86_category(
    decoded: &Instruction,
    factory: &mut InstructionInfoFactory,
) -> InstructionCategory {
    if let Some(category) = flow_category(decoded.flow_control()) {
        return category;
    }
    if decoded.is_stack_instruction() {
        return InstructionCategory::Stack;
    }
    let operation: Option<Operation> = x86_operation(decoded);
    if let Some(Operation::Simple(category)) = operation {
        return category;
    }
    let info: &InstructionInfo = factory.info(decoded);
    let touch: MemoryTouch = memory_touch(info);
    if matches!(operation, Some(Operation::DataMove)) {
        return touch.resolve(InstructionCategory::Move);
    }
    register_class_category(info).unwrap_or_else(|| touch.resolve(InstructionCategory::Other))
}

const fn flow_category(flow: FlowControl) -> Option<InstructionCategory> {
    match flow {
        FlowControl::Call | FlowControl::IndirectCall => Some(InstructionCategory::Call),
        FlowControl::Return => Some(InstructionCategory::Return),
        FlowControl::ConditionalBranch
        | FlowControl::UnconditionalBranch
        | FlowControl::IndirectBranch => Some(InstructionCategory::Branch),
        FlowControl::Interrupt => Some(InstructionCategory::System),
        _ => None,
    }
}

fn memory_touch(info: &InstructionInfo) -> MemoryTouch {
    let mut touch: MemoryTouch = MemoryTouch::None;
    for used in info.used_memory() {
        let used: &UsedMemory = used;
        let access: RegAccess = map_access(used.access());
        if access.writes() {
            return MemoryTouch::Write;
        }
        if access.reads() {
            touch = MemoryTouch::Read;
        }
    }
    touch
}

fn register_class_category(info: &InstructionInfo) -> Option<InstructionCategory> {
    let mut vector: bool = false;
    for used in info.used_registers() {
        let register: Register = used.register();
        if register.is_st() {
            return Some(InstructionCategory::FloatingPoint);
        }
        vector |= register.is_xmm() || register.is_ymm() || register.is_zmm() || register.is_mm();
    }
    vector.then_some(InstructionCategory::Vector)
}

fn x86_operation(decoded: &Instruction) -> Option<Operation> {
    if decoded.condition_code() != ConditionCode::None {
        return Some(Operation::DataMove);
    }
    Some(match decoded.mnemonic() {
        Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Adcx
        | Mnemonic::Adox
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::Inc
        | Mnemonic::Dec
        | Mnemonic::Neg
        | Mnemonic::Mul
        | Mnemonic::Imul
        | Mnemonic::Div
        | Mnemonic::Idiv
        | Mnemonic::Mulx
        | Mnemonic::Xadd
        | Mnemonic::Cbw
        | Mnemonic::Cwde
        | Mnemonic::Cdqe
        | Mnemonic::Cwd
        | Mnemonic::Cdq
        | Mnemonic::Cqo => Operation::Simple(InstructionCategory::Arithmetic),
        Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Xor
        | Mnemonic::Not
        | Mnemonic::Andn
        | Mnemonic::Bextr
        | Mnemonic::Blsi
        | Mnemonic::Blsmsk
        | Mnemonic::Blsr
        | Mnemonic::Bzhi
        | Mnemonic::Pext
        | Mnemonic::Pdep
        | Mnemonic::Popcnt
        | Mnemonic::Lzcnt
        | Mnemonic::Tzcnt
        | Mnemonic::Bsf
        | Mnemonic::Bsr
        | Mnemonic::Bt
        | Mnemonic::Btc
        | Mnemonic::Btr
        | Mnemonic::Bts => Operation::Simple(InstructionCategory::Logic),
        Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr
        | Mnemonic::Shld
        | Mnemonic::Shrd
        | Mnemonic::Shlx
        | Mnemonic::Shrx
        | Mnemonic::Sarx
        | Mnemonic::Rorx => Operation::Simple(InstructionCategory::Shift),
        Mnemonic::Cmp
        | Mnemonic::Test
        | Mnemonic::Cmpxchg
        | Mnemonic::Comiss
        | Mnemonic::Comisd
        | Mnemonic::Ucomiss
        | Mnemonic::Ucomisd
        | Mnemonic::Vcomiss
        | Mnemonic::Vcomisd
        | Mnemonic::Vucomiss
        | Mnemonic::Vucomisd
        | Mnemonic::Ptest
        | Mnemonic::Vptest => Operation::Simple(InstructionCategory::Compare),
        Mnemonic::Syscall
        | Mnemonic::Sysenter
        | Mnemonic::Sysexit
        | Mnemonic::Sysret
        | Mnemonic::Cpuid
        | Mnemonic::Rdtsc
        | Mnemonic::Rdtscp
        | Mnemonic::Rdpmc
        | Mnemonic::Hlt
        | Mnemonic::Ud0
        | Mnemonic::Ud1
        | Mnemonic::Ud2
        | Mnemonic::Cli
        | Mnemonic::Sti
        | Mnemonic::In
        | Mnemonic::Out
        | Mnemonic::Wrmsr
        | Mnemonic::Rdmsr
        | Mnemonic::Xgetbv
        | Mnemonic::Xsetbv
        | Mnemonic::Swapgs
        | Mnemonic::Wbinvd
        | Mnemonic::Invd
        | Mnemonic::Invlpg
        | Mnemonic::Mfence
        | Mnemonic::Lfence
        | Mnemonic::Sfence
        | Mnemonic::Pause
        | Mnemonic::Endbr32
        | Mnemonic::Endbr64
        | Mnemonic::Xabort
        | Mnemonic::Xbegin
        | Mnemonic::Xend
        | Mnemonic::Xtest => Operation::Simple(InstructionCategory::System),
        Mnemonic::Mov
        | Mnemonic::Movzx
        | Mnemonic::Movsx
        | Mnemonic::Movsxd
        | Mnemonic::Movbe
        | Mnemonic::Lea
        | Mnemonic::Xchg => Operation::DataMove,
        _ => return None,
    })
}

fn x86_reference(
    insn: &DisasmInstruction,
    decoded: &Instruction,
    index: &ImageIndex,
) -> Option<DataReference> {
    if let Some(name) = x86_import_name(insn, decoded, index) {
        return Some(DataReference::imported_call(name));
    }
    if let Some(target) = absolute_memory_target(decoded)
        && let Some(text) = index.string_at(target)
    {
        return Some(DataReference::string_literal(text.clone()));
    }
    x86_immediate_reference(decoded, index)
}

fn x86_import_name(
    insn: &DisasmInstruction,
    decoded: &Instruction,
    index: &ImageIndex,
) -> Option<String> {
    match insn.flow {
        InsnFlow::Call => index.import_stubs.get(&insn.branch_target?).cloned(),
        InsnFlow::IndirectCall => index
            .import_slots
            .get(&absolute_memory_target(decoded)?)
            .cloned(),
        _ => None,
    }
}

fn x86_immediate_reference(decoded: &Instruction, index: &ImageIndex) -> Option<DataReference> {
    if touches_frame_register(decoded) {
        return None;
    }
    for operand in 0..decoded.op_count() {
        let Some(width): Option<u32> = harvestable_immediate_width(decoded.op_kind(operand)) else {
            continue;
        };
        let value: u64 = decoded.immediate(operand);
        if width >= ADDRESS_IMMEDIATE_MIN_BITS
            && let Some(text) = index.string_at(value)
        {
            return Some(DataReference::string_literal(text.clone()));
        }
        if let Some(reference) = index.constant(value) {
            return Some(reference);
        }
    }
    None
}

const fn harvestable_immediate_width(kind: OpKind) -> Option<u32> {
    match kind {
        OpKind::Immediate16 => Some(16),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(32),
        OpKind::Immediate64 => Some(64),
        _ => None,
    }
}

fn touches_frame_register(decoded: &Instruction) -> bool {
    if is_frame_register(decoded.memory_base()) || is_frame_register(decoded.memory_index()) {
        return true;
    }
    (0..decoded.op_count()).any(|operand: u32| is_frame_register(decoded.op_register(operand)))
}

const fn is_frame_register(register: Register) -> bool {
    matches!(
        register,
        Register::RSP
            | Register::ESP
            | Register::SP
            | Register::SPL
            | Register::RBP
            | Register::EBP
            | Register::BP
            | Register::BPL
    )
}

fn is_packed_ascii(value: u64) -> bool {
    let mut remaining: u64 = value;
    let mut printable: u32 = 0;
    while remaining != 0 {
        let byte: u8 = (remaining & 0xff) as u8;
        if !(0x20..=0x7e).contains(&byte) {
            return false;
        }
        printable += 1;
        remaining >>= 8;
    }
    printable >= 2
}

fn aarch64_references(body: &[DisasmInstruction], index: &ImageIndex) -> Vec<DataReference> {
    let words: Vec<Option<u32>> = body.iter().map(instruction_word).collect();
    let mut out: Vec<DataReference> = Vec::new();
    let mut position: usize = 0;
    while position < body.len() {
        let (Some(insn), Some(word)): (Option<&DisasmInstruction>, Option<u32>) =
            (body.get(position), words.get(position).copied().flatten())
        else {
            position += 1;
            continue;
        };
        match insn.mnemonic.as_str() {
            "adr" | "adrp" => {
                for target in aarch64_address_targets(insn, word, body, &words, position) {
                    if let Some(text) = index.string_at(target) {
                        out.push(DataReference::string_literal(text.clone()));
                    }
                }
                position += 1;
            }
            "mov" | "movn" | "movz" => {
                let (value, consumed): (Option<u64>, usize) =
                    fold_wide_move(body, &words, position);
                if let Some(value) = value
                    && let Some(reference) = index.constant(value)
                {
                    out.push(reference);
                }
                position += consumed;
            }
            _ => position += 1,
        }
    }
    out
}

const AARCH64_CALLS: [&str; 6] = ["bl", "blr", "blraa", "blrab", "blraaz", "blrabz"];

const AARCH64_SYSTEM: [&str; 20] = [
    "svc", "hvc", "smc", "brk", "hlt", "udf", "msr", "mrs", "dsb", "dmb", "isb", "sys", "sysl",
    "wfe", "wfi", "sev", "sevl", "yield", "clrex", "tlbi",
];

const AARCH64_COMPARE: [&str; 9] = [
    "cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp", "fccmpe",
];

const AARCH64_ARITHMETIC: [&str; 27] = [
    "add", "adds", "sub", "subs", "adc", "adcs", "sbc", "sbcs", "neg", "negs", "ngc", "ngcs",
    "mul", "madd", "msub", "mneg", "smull", "smnegl", "smaddl", "smsubl", "smulh", "umull",
    "umnegl", "umaddl", "umsubl", "umulh", "sdiv",
];

const AARCH64_LOGIC: [&str; 16] = [
    "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "mvn", "clz", "cls", "rbit", "rev",
    "rev16", "rev32", "rev64",
];

const AARCH64_SHIFT: [&str; 18] = [
    "lsl", "lsr", "asr", "ror", "lslv", "lsrv", "asrv", "rorv", "extr", "bfi", "bfxil", "bfm",
    "ubfm", "sbfm", "ubfx", "sbfx", "ubfiz", "sbfiz",
];

const AARCH64_MOVE: [&str; 21] = [
    "mov", "movz", "movn", "movk", "adr", "adrp", "csel", "csinc", "csinv", "csneg", "cset",
    "csetm", "cinc", "cinv", "cneg", "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw",
];

#[cfg(test)]
fn aarch64_structure(body: &[DisasmInstruction]) -> Option<ControlFlowGraph> {
    let blocks: Vec<BasicBlock> = aarch64_blocks(body)?;
    aarch64_structure_from_blocks(body, &blocks)
}

fn aarch64_blocks(body: &[DisasmInstruction]) -> Option<Vec<BasicBlock>> {
    if body
        .iter()
        .any(|insn: &DisasmInstruction| insn.bytes.len() != AARCH64_INSTRUCTION_BYTES)
        || body.windows(2).any(|pair: &[DisasmInstruction]| {
            pair[0].offset.checked_add(AARCH64_INSTRUCTION_BYTES as u64) != Some(pair[1].offset)
        })
    {
        return None;
    }
    let positions: BTreeMap<u64, usize> = instruction_positions(body)?;
    let transfers: Vec<Transfer> = body.iter().map(aarch64_transfer).collect();
    build_cfg(&transfers, &positions, 0)
}

fn aarch64_structure_from_blocks(
    body: &[DisasmInstruction],
    blocks: &[BasicBlock],
) -> Option<ControlFlowGraph> {
    let categories: Vec<InstructionCategory> = body.iter().map(aarch64_category).collect();
    control_flow_graph(blocks, &categories)
}

fn aarch64_transfer(insn: &DisasmInstruction) -> Transfer {
    let mnemonic: &str = insn.mnemonic.as_str();
    if aarch64_is_return(mnemonic) {
        return Transfer::Terminal { returns: true };
    }
    if aarch64_is_trap(mnemonic) {
        return Transfer::Terminal { returns: false };
    }
    if aarch64_is_indirect_branch(mnemonic) {
        return Transfer::Unresolved;
    }
    if AARCH64_CALLS.contains(&mnemonic) {
        return Transfer::FallsThrough;
    }
    if mnemonic == "b" {
        return match instruction_word(insn)
            .and_then(|word: u32| aarch64_direct_transfer(insn.offset, word))
        {
            Some(Aarch64DirectTransfer::UnconditionalBranch { target }) => {
                Transfer::UnconditionalBranch { taken: target }
            }
            Some(
                Aarch64DirectTransfer::BranchLink { .. }
                | Aarch64DirectTransfer::ConditionalBranch { .. }
                | Aarch64DirectTransfer::CompareBranch { .. }
                | Aarch64DirectTransfer::TestBranch { .. },
            )
            | None => Transfer::Unresolved,
        };
    }
    if is_direct_conditional_branch(mnemonic) {
        return match instruction_word(insn)
            .and_then(|word: u32| aarch64_direct_transfer(insn.offset, word))
        {
            Some(
                Aarch64DirectTransfer::ConditionalBranch { target, .. }
                | Aarch64DirectTransfer::CompareBranch { target }
                | Aarch64DirectTransfer::TestBranch { target },
            ) => Transfer::ConditionalBranch { taken: target },
            Some(
                Aarch64DirectTransfer::BranchLink { .. }
                | Aarch64DirectTransfer::UnconditionalBranch { .. },
            )
            | None => Transfer::Unresolved,
        };
    }
    Transfer::FallsThrough
}

fn is_direct_conditional_branch(mnemonic: &str) -> bool {
    matches!(mnemonic, "cbz" | "cbnz" | "tbz" | "tbnz")
        || mnemonic.starts_with("b.")
        || is_conditional_branch(mnemonic)
}

fn aarch64_category(insn: &DisasmInstruction) -> InstructionCategory {
    let mnemonic: &str = insn.mnemonic.as_str();
    if aarch64_is_return(mnemonic) {
        return InstructionCategory::Return;
    }
    if AARCH64_CALLS.contains(&mnemonic) {
        return InstructionCategory::Call;
    }
    if mnemonic == "b"
        || aarch64_is_indirect_branch(mnemonic)
        || is_direct_conditional_branch(mnemonic)
    {
        return InstructionCategory::Branch;
    }
    if AARCH64_SYSTEM.contains(&mnemonic) {
        return InstructionCategory::System;
    }
    if mnemonic.starts_with("ld") {
        return InstructionCategory::Load;
    }
    if mnemonic.starts_with("st") {
        return InstructionCategory::Store;
    }
    if names_vector_register(insn) {
        return InstructionCategory::Vector;
    }
    if AARCH64_COMPARE.contains(&mnemonic) {
        return InstructionCategory::Compare;
    }
    if mnemonic.starts_with('f') || matches!(mnemonic, "scvtf" | "ucvtf" | "fjcvtzs") {
        return InstructionCategory::FloatingPoint;
    }
    if AARCH64_ARITHMETIC.contains(&mnemonic) || mnemonic == "udiv" {
        return InstructionCategory::Arithmetic;
    }
    if AARCH64_LOGIC.contains(&mnemonic) {
        return InstructionCategory::Logic;
    }
    if AARCH64_SHIFT.contains(&mnemonic) {
        return InstructionCategory::Shift;
    }
    if AARCH64_MOVE.contains(&mnemonic) {
        return InstructionCategory::Move;
    }
    InstructionCategory::Other
}

fn names_vector_register(insn: &DisasmInstruction) -> bool {
    insn.operands.iter().any(|operand: &String| {
        operand
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '.')
            .any(is_vector_register_token)
    })
}

fn is_vector_register_token(token: &str) -> bool {
    token
        .strip_prefix('v')
        .and_then(|rest: &str| rest.chars().next())
        .is_some_and(|character: char| character.is_ascii_digit())
}

fn instruction_word(insn: &DisasmInstruction) -> Option<u32> {
    aarch64_word(&insn.bytes)
}

fn aarch64_address_targets(
    insn: &DisasmInstruction,
    word: u32,
    body: &[DisasmInstruction],
    words: &[Option<u32>],
    position: usize,
) -> Vec<u64> {
    if insn.mnemonic == "adr" {
        return aarch64_adr_target(insn.offset, word)
            .map(|target: u64| vec![target])
            .unwrap_or_default();
    }
    let Some(page): Option<u64> = aarch64_adrp_target(insn.offset, word) else {
        return Vec::new();
    };
    let destination: u8 = register_field(word, 0);
    paired_low_bits(destination, body, words, position)
        .into_iter()
        .filter_map(|low: u64| page.checked_add(low))
        .collect()
}

fn paired_low_bits(
    destination: u8,
    body: &[DisasmInstruction],
    words: &[Option<u32>],
    position: usize,
) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for step in 1..=ADRP_PAIR_SCAN_LIMIT {
        let index: usize = position.saturating_add(step);
        let (Some(insn), Some(word)): (Option<&DisasmInstruction>, Option<u32>) =
            (body.get(index), words.get(index).copied().flatten())
        else {
            return out;
        };
        if word & ADD_IMMEDIATE_MASK == ADD_IMMEDIATE_64 && register_field(word, 5) == destination {
            out.push(u64::from(immediate_field(word, 10, 12)));
            if register_field(word, 0) == destination {
                return out;
            }
            continue;
        }
        if is_branch(&insn.mnemonic) || register_field(word, 0) == destination {
            return out;
        }
    }
    out
}

fn is_branch(mnemonic: &str) -> bool {
    aarch64_stops_traversal(mnemonic)
        || AARCH64_CALLS.contains(&mnemonic)
        || matches!(mnemonic, "b" | "hvc" | "smc" | "svc")
        || is_direct_conditional_branch(mnemonic)
}

fn is_conditional_branch(mnemonic: &str) -> bool {
    let Some(condition): Option<&str> = mnemonic.strip_prefix('b') else {
        return false;
    };
    matches!(
        condition,
        "eq" | "ne"
            | "cs"
            | "hs"
            | "cc"
            | "lo"
            | "mi"
            | "pl"
            | "vs"
            | "vc"
            | "hi"
            | "ls"
            | "ge"
            | "lt"
            | "gt"
            | "le"
            | "al"
            | "nv"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WideMove {
    register: u8,
    shift: u32,
    immediate: u64,
    mask: u64,
}

fn wide_move(word: u32, expected: u32) -> Option<WideMove> {
    if word & WIDE_MOVE_MASK != expected {
        return None;
    }
    let wide: bool = word & 0x8000_0000 != 0;
    let half: u32 = immediate_field(word, 21, 2);
    if !wide && half > 1 {
        return None;
    }
    let shift: u32 = half.checked_mul(16)?;
    Some(WideMove {
        register: register_field(word, 0),
        shift,
        immediate: u64::from(immediate_field(word, 5, 16)).checked_shl(shift)?,
        mask: if wide { u64::MAX } else { u64::from(u32::MAX) },
    })
}

fn fold_wide_move(
    body: &[DisasmInstruction],
    words: &[Option<u32>],
    position: usize,
) -> (Option<u64>, usize) {
    let Some(word): Option<u32> = words.get(position).copied().flatten() else {
        return (None, 1);
    };
    let negated = |negated: WideMove| WideMove {
        immediate: !negated.immediate & negated.mask,
        ..negated
    };
    let Some(start): Option<WideMove> =
        wide_move(word, MOVZ).or_else(|| wide_move(word, MOVN).map(negated))
    else {
        return (None, 1);
    };

    let mut value: u64 = start.immediate & start.mask;
    let mut consumed: usize = 1;
    while consumed <= WIDE_MOVE_CHAIN_LIMIT {
        let index: usize = position.saturating_add(consumed);
        let (Some(insn), Some(word)): (Option<&DisasmInstruction>, Option<u32>) =
            (body.get(index), words.get(index).copied().flatten())
        else {
            break;
        };
        if insn.mnemonic != "movk" {
            break;
        }
        let Some(patch): Option<WideMove> = wide_move(word, MOVK) else {
            break;
        };
        if patch.register != start.register || patch.mask != start.mask {
            break;
        }
        let Some(halfword): Option<u64> = 0xffff_u64.checked_shl(patch.shift) else {
            break;
        };
        value = (value & !halfword) | patch.immediate;
        value &= start.mask;
        consumed += 1;
    }

    let complete: bool = body
        .get(position.saturating_add(consumed))
        .is_some_and(|insn: &DisasmInstruction| !is_branch(&insn.mnemonic));
    (complete.then_some(value), consumed)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
