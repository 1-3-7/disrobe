use std::collections::BTreeSet;

use disrobe_binfmt::native::{
    Arch as BinArch, Endian, NativeFile, NativeFormat, SectionInfo, parse_native,
};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnEncoding, InsnFlow,
    InsnSegments, IsaTag, MemUse, RegAccess, RegUse, RflagsEffect, StackEffect,
};
use iced_x86::{
    ConstantOffsets, Decoder, DecoderOptions, EncodingKind, FlowControl, Instruction,
    InstructionInfoFactory, OpAccess, OpKind, RflagsBits,
};
use object::{
    Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind,
    SymbolScope as ObjSymbolScope,
};

use crate::arch::{Arch as DisasmArch, DisasmInsn, disassemble};
use crate::cxx_recovery::parse_windows_seh_scope_table;
use crate::desync::{
    Bitness, CodeWindow, DiscoveredFunctions, DiscoveryInput, ReadOnlyWindow,
    discover_aarch64_functions, discover_functions, is_noreturn_import_name,
};
use crate::error::{Error, Result};
use crate::pseudo_c::aarch64::AARCH64_INSTRUCTION_BYTES;

pub const MAX_DECODE_TEXT_BYTES: usize = 32 * 1024 * 1024;

pub const MAX_PAYLOAD_INSTRUCTIONS: usize = 4_000_000;

pub(crate) enum FunctionUniverse {
    Complete,
    Aarch64Fallback { discovered_starts: BTreeSet<u64> },
}

impl FunctionUniverse {
    pub(crate) fn reference_anchors_trusted(&self, address: u64) -> bool {
        match self {
            Self::Complete => true,
            Self::Aarch64Fallback { discovered_starts } => !discovered_starts.contains(&address),
        }
    }
}

pub(crate) struct DisasmBuild {
    pub(crate) payload: DisasmPayload,
    pub(crate) function_universe: FunctionUniverse,
}

pub fn build_disasm_payload(bytes: &[u8]) -> Result<DisasmPayload> {
    let build: DisasmBuild = build_disasm_payload_with_discovery(bytes)?;
    Ok(build.payload)
}

pub(crate) fn build_disasm_payload_with_discovery(bytes: &[u8]) -> Result<DisasmBuild> {
    let native: NativeFile = parse_native(bytes).map_err(|e| Error::ObjectParse(e.to_string()))?;
    let arch: DisasmArch = map_arch(native.arch, native.endian).ok_or_else(|| {
        Error::UnsupportedArch(format!(
            "{} is not wired into the disasm-IR query path",
            native.arch.label()
        ))
    })?;

    let sections: Vec<ExecutableSection> = executable_sections(bytes, &native.sections);
    if sections.is_empty() {
        return Err(Error::ObjectParse(format!(
            "{} carries no readable executable section to disassemble",
            native.format.label()
        )));
    }

    let mut instructions: Vec<DisasmInstruction> = Vec::new();
    let mut text_budget: usize = MAX_DECODE_TEXT_BYTES;
    'sections: for section in &sections {
        if text_budget == 0 || instructions.len() >= MAX_PAYLOAD_INSTRUCTIONS {
            break;
        }
        let remaining_instructions: usize =
            MAX_PAYLOAD_INSTRUCTIONS.saturating_sub(instructions.len());
        let instruction_byte_limit: usize = decode_byte_limit(arch, remaining_instructions);
        let window: usize = section
            .bytes
            .len()
            .min(text_budget)
            .min(instruction_byte_limit);
        text_budget -= window;
        let decoded: Vec<DisasmInsn> =
            disassemble(arch, section.address, &section.bytes[..window])?;
        let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
        for insn in decoded {
            if instructions.len() >= MAX_PAYLOAD_INSTRUCTIONS {
                break 'sections;
            }
            let facts: InstructionFacts =
                instruction_facts(arch, &insn.bytes, insn.address, &mut factory);
            instructions.push(DisasmInstruction {
                offset: insn.address,
                bytes: insn.bytes,
                mnemonic: insn.mnemonic,
                operands: split_operands(&insn.operands),
                flow: facts.flow,
                branch_target: facts.branch_target,
                reg_uses: facts.reg_uses,
                mem_uses: facts.mem_uses,
                rflags: facts.rflags,
                isa: facts.isa,
                stack_effect: facts.stack_effect,
                segments: facts.segments,
            });
        }
    }
    instructions.sort_by_key(|i: &DisasmInstruction| i.offset);

    let mut symbol_table: Vec<DisasmSymbol> = build_symbol_table(bytes, &native);
    let has_function_or_export: bool = symbol_table.iter().any(|s: &DisasmSymbol| {
        matches!(
            s.kind,
            DisasmSymbolKind::Function | DisasmSymbolKind::Export
        )
    });
    let needs_discovery: bool = needs_function_discovery(arch, has_function_or_export);
    let discovered_starts: BTreeSet<u64> = if needs_discovery {
        inject_discovered_functions(
            arch,
            &native,
            &sections,
            &instructions,
            bytes,
            &mut symbol_table,
        )
    } else {
        BTreeSet::new()
    };
    let aarch64_fallback: bool = matches!(arch, DisasmArch::Aarch64)
        && matches!(native.format, NativeFormat::Elf64)
        && matches!(native.endian, Endian::Little);
    let function_universe: FunctionUniverse = if aarch64_fallback {
        FunctionUniverse::Aarch64Fallback { discovered_starts }
    } else {
        FunctionUniverse::Complete
    };

    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    Ok(DisasmBuild {
        payload: DisasmPayload {
            source_hash,
            instructions,
            symbol_table,
        },
        function_universe,
    })
}

const fn decode_byte_limit(arch: DisasmArch, remaining_instructions: usize) -> usize {
    if matches!(arch, DisasmArch::Aarch64) {
        remaining_instructions.saturating_mul(AARCH64_INSTRUCTION_BYTES)
    } else {
        usize::MAX
    }
}

const fn needs_function_discovery(arch: DisasmArch, has_function_or_export: bool) -> bool {
    matches!(arch, DisasmArch::Aarch64) || !has_function_or_export
}

fn inject_discovered_functions(
    arch: DisasmArch,
    native: &NativeFile,
    sections: &[ExecutableSection],
    instructions: &[DisasmInstruction],
    bytes: &[u8],
    symbol_table: &mut Vec<DisasmSymbol>,
) -> BTreeSet<u64> {
    let code: Vec<CodeWindow<'_>> = sections
        .iter()
        .map(|s: &ExecutableSection| CodeWindow {
            address: s.address,
            bytes: &s.bytes,
        })
        .collect();
    let discovered: DiscoveredFunctions = if matches!(arch, DisasmArch::Aarch64) {
        if !matches!(native.format, NativeFormat::Elf64) || !matches!(native.endian, Endian::Little)
        {
            return BTreeSet::new();
        }
        let seeds: Vec<u64> = aarch64_function_seeds(native, bytes);
        let Some(discovered): Option<DiscoveredFunctions> =
            discover_aarch64_functions(&code, instructions, &seeds)
        else {
            return BTreeSet::new();
        };
        discovered
    } else {
        let Some(bitness): Option<Bitness> = discovery_bitness(arch) else {
            return BTreeSet::new();
        };
        let rodata: Vec<ReadOnlyWindow<'_>> = read_only_windows(bytes);
        let seeds: Vec<u64> = discovery_seeds(native, bytes);
        let noreturn: BTreeSet<u64> = noreturn_import_targets(bytes);
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness,
            code,
            rodata,
            seeds,
            noreturn,
        };
        discover_functions(&input)
    };

    let mut seen: BTreeSet<u64> = symbol_table
        .iter()
        .map(|s: &DisasmSymbol| s.address)
        .collect();
    let retain_provenance: bool = matches!(arch, DisasmArch::Aarch64);
    let mut injected_starts: BTreeSet<u64> = BTreeSet::new();
    for start in discovered.starts {
        if !seen.insert(start) {
            continue;
        }
        if retain_provenance {
            injected_starts.insert(start);
        }
        symbol_table.push(DisasmSymbol {
            address: start,
            name: format!("sub_{start:x}"),
            kind: DisasmSymbolKind::Function,
        });
    }
    symbol_table.sort_by(|a: &DisasmSymbol, b: &DisasmSymbol| {
        a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name))
    });
    injected_starts
}

fn noreturn_import_targets(bytes: &[u8]) -> BTreeSet<u64> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return BTreeSet::new();
    };
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name): core::result::Result<&str, object::Error> = sym.name() else {
            continue;
        };
        if sym.address() == 0 {
            continue;
        }
        let bare: &str = name.split('@').next().unwrap_or(name);
        if is_noreturn_import_name(bare) {
            targets.insert(sym.address());
        }
    }
    targets
}

const fn discovery_bitness(arch: DisasmArch) -> Option<Bitness> {
    match arch {
        DisasmArch::X86 => Some(Bitness::Bits32),
        DisasmArch::X86_64 => Some(Bitness::Bits64),
        _ => None,
    }
}

fn discovery_seeds(native: &NativeFile, bytes: &[u8]) -> Vec<u64> {
    let mut seeds: Vec<u64> = entry_export_seeds(native, bytes);
    seeds.extend(pdata_function_starts(bytes));
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

fn entry_export_seeds(native: &NativeFile, bytes: &[u8]) -> Vec<u64> {
    let mut seeds: Vec<u64> = Vec::new();
    if let Ok(file) = object::File::parse(bytes) {
        let entry: u64 = file.entry();
        if entry != 0 {
            seeds.push(entry);
        }
    }
    for export in &native.exports {
        if export.address != 0 {
            seeds.push(export.address);
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

fn aarch64_function_seeds(native: &NativeFile, bytes: &[u8]) -> Vec<u64> {
    let mut seeds: Vec<u64> = entry_export_seeds(native, bytes);
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return seeds;
    };
    seeds.extend(
        file.symbols()
            .filter(|symbol: &object::Symbol<'_, '_>| {
                matches!(symbol.kind(), ObjSymbolKind::Text)
                    && !symbol.is_undefined()
                    && symbol.address() != 0
            })
            .map(|symbol: object::Symbol<'_, '_>| symbol.address()),
    );
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

fn pdata_function_starts(bytes: &[u8]) -> Vec<u64> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return Vec::new();
    };
    if !matches!(file.format(), object::BinaryFormat::Pe) {
        return Vec::new();
    }
    let image_base: u64 = file.relative_address_base();
    let Some(section): Option<object::Section<'_, '_>> = file
        .sections()
        .find(|s: &object::Section<'_, '_>| s.name().is_ok_and(|n: &str| n == ".pdata"))
    else {
        return Vec::new();
    };
    let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
        return Vec::new();
    };
    let mut starts: Vec<u64> = Vec::new();
    let mut idx: usize = 0;
    while idx + 12 <= data.len() {
        let begin_rva: u32 =
            u32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
        if begin_rva != 0 {
            starts.push(image_base.saturating_add(u64::from(begin_rva)));
        }
        idx += 12;
    }
    starts
}

#[must_use]
pub fn seh_scope_function_starts(bytes: &[u8]) -> Vec<u64> {
    parse_windows_seh_scope_table(bytes)
        .map(|entries: Vec<crate::cxx_recovery::SehScopeEntry>| {
            entries
                .iter()
                .filter(|e: &&crate::cxx_recovery::SehScopeEntry| e.begin_address != 0)
                .map(|e: &crate::cxx_recovery::SehScopeEntry| u64::from(e.begin_address))
                .collect::<Vec<u64>>()
        })
        .unwrap_or_default()
}

struct ExecutableSection {
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSpan {
    pub address: u64,
    pub end: u64,
    pub name: String,
    pub is_export: bool,
}

#[must_use]
pub fn function_spans(payload: &DisasmPayload) -> Vec<FunctionSpan> {
    let mut starts: Vec<(u64, String, bool)> = payload
        .symbol_table
        .iter()
        .filter(|symbol: &&DisasmSymbol| {
            matches!(
                symbol.kind,
                DisasmSymbolKind::Function | DisasmSymbolKind::Export
            )
        })
        .map(|symbol: &DisasmSymbol| {
            (
                symbol.address,
                symbol.name.clone(),
                matches!(symbol.kind, DisasmSymbolKind::Export),
            )
        })
        .collect();
    starts.sort_by_key(|start: &(u64, String, bool)| start.0);
    starts.dedup_by_key(|start: &mut (u64, String, bool)| start.0);

    let last_end: u64 = payload
        .instructions
        .iter()
        .max_by_key(|insn: &&DisasmInstruction| insn.offset)
        .map_or(0, |insn: &DisasmInstruction| {
            insn.offset.saturating_add(insn.bytes.len() as u64)
        });

    let mut spans: Vec<FunctionSpan> = Vec::with_capacity(starts.len());
    for (index, (address, name, is_export)) in starts.iter().enumerate() {
        let end: u64 = starts
            .get(index + 1)
            .map_or(last_end, |next: &(u64, String, bool)| next.0);
        spans.push(FunctionSpan {
            address: *address,
            end,
            name: name.clone(),
            is_export: *is_export,
        });
    }
    spans
}

pub(crate) fn span_instructions<'a>(
    sorted: &'a [DisasmInstruction],
    span: &FunctionSpan,
) -> &'a [DisasmInstruction] {
    let low: usize = sorted.partition_point(|insn: &DisasmInstruction| insn.offset < span.address);
    let high: usize = sorted.partition_point(|insn: &DisasmInstruction| insn.offset < span.end);
    sorted.get(low..high).unwrap_or_default()
}

pub(crate) fn image_arch(bytes: &[u8]) -> Option<DisasmArch> {
    let native: NativeFile = parse_native(bytes).ok()?;
    map_arch(native.arch, native.endian)
}

pub(crate) fn mapped_address_extent(bytes: &[u8]) -> Option<(u64, u64)> {
    let file: object::File<'_> = object::File::parse(bytes).ok()?;
    let mut low: u64 = u64::MAX;
    let mut high: u64 = 0;
    for section in file.sections() {
        let address: u64 = section.address();
        if address == 0 || section.size() == 0 {
            continue;
        }
        low = low.min(address);
        high = high.max(address.saturating_add(section.size()));
    }
    (low < high).then_some((low, high))
}

pub(crate) fn read_only_windows(bytes: &[u8]) -> Vec<ReadOnlyWindow<'_>> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return Vec::new();
    };
    let mut out: Vec<ReadOnlyWindow<'_>> = Vec::new();
    for section in file.sections() {
        if matches!(section.kind(), object::SectionKind::Text) {
            continue;
        }
        let readable: bool = matches!(
            section.kind(),
            object::SectionKind::ReadOnlyData
                | object::SectionKind::Data
                | object::SectionKind::ReadOnlyString
                | object::SectionKind::ReadOnlyDataWithRel
        );
        if !readable {
            continue;
        }
        let address: u64 = section.address();
        if address == 0 {
            continue;
        }
        if let Ok(data) = section.data()
            && !data.is_empty()
        {
            out.push(ReadOnlyWindow {
                address,
                bytes: data,
            });
        }
    }
    out
}

#[must_use]
pub fn text_section_window(bytes: &[u8]) -> Option<(u64, u32, &[u8])> {
    let native: NativeFile = parse_native(bytes).ok()?;
    let bits: u32 = match map_arch(native.arch, native.endian)? {
        DisasmArch::X86 => 32,
        DisasmArch::X86_64 => 64,
        _ => return None,
    };
    let file: object::File<'_> = object::File::parse(bytes).ok()?;
    let mut best: Option<(u64, &[u8])> = None;
    for section in file.sections() {
        let is_text: bool = matches!(section.kind(), object::SectionKind::Text)
            || section
                .name()
                .is_ok_and(|n: &str| n == ".text" || n == "__text" || n.starts_with(".text"));
        if !is_text {
            continue;
        }
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        if best.is_none_or(|(_, b): (u64, &[u8])| data.len() > b.len()) {
            best = Some((section.address(), data));
        }
    }
    best.map(|(address, data): (u64, &[u8])| (address, bits, data))
}

fn executable_sections(bytes: &[u8], parsed: &[SectionInfo]) -> Vec<ExecutableSection> {
    let Ok(file): core::result::Result<object::File<'_>, object::Error> =
        object::File::parse(bytes)
    else {
        return Vec::new();
    };
    let mut out: Vec<ExecutableSection> = Vec::new();
    for section in file.sections() {
        let is_text: bool = matches!(section.kind(), object::SectionKind::Text)
            || section
                .name()
                .is_ok_and(|n: &str| n == ".text" || n == "__text" || n.starts_with(".text"));
        if !is_text {
            continue;
        }
        let Ok(data): core::result::Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        out.push(ExecutableSection {
            address: section.address(),
            bytes: data.to_vec(),
        });
    }
    if out.is_empty() {
        for section in parsed {
            let is_text: bool = section.name == ".text"
                || section.name == "__text"
                || section.name.starts_with(".text");
            if !is_text || section.size == 0 {
                continue;
            }
            let start: usize = usize::try_from(section.address).unwrap_or(usize::MAX);
            let len: usize = usize::try_from(section.size).unwrap_or(0);
            if let Some(slice) = bytes.get(start..start.saturating_add(len)) {
                out.push(ExecutableSection {
                    address: section.address,
                    bytes: slice.to_vec(),
                });
            }
        }
    }
    out.sort_by_key(|s: &ExecutableSection| s.address);
    out
}

struct InstructionFacts {
    flow: InsnFlow,
    branch_target: Option<u64>,
    reg_uses: Vec<RegUse>,
    mem_uses: Vec<MemUse>,
    rflags: RflagsEffect,
    isa: IsaTag,
    stack_effect: StackEffect,
    segments: InsnSegments,
}

impl Default for InstructionFacts {
    fn default() -> Self {
        Self {
            flow: InsnFlow::Sequential,
            branch_target: None,
            reg_uses: Vec::new(),
            mem_uses: Vec::new(),
            rflags: RflagsEffect::default(),
            isa: IsaTag::default(),
            stack_effect: StackEffect::default(),
            segments: InsnSegments::default(),
        }
    }
}

fn instruction_facts(
    arch: DisasmArch,
    raw: &[u8],
    address: u64,
    factory: &mut InstructionInfoFactory,
) -> InstructionFacts {
    let bits: u32 = match arch {
        DisasmArch::X86 => 32,
        DisasmArch::X86_64 => 64,
        _ => return InstructionFacts::default(),
    };
    if raw.is_empty() {
        return InstructionFacts::default();
    }
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, raw, address, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return InstructionFacts::default();
    }
    let mut insn: Instruction = Instruction::default();
    decoder.decode_out(&mut insn);
    if insn.is_invalid() {
        return InstructionFacts::default();
    }
    let offsets: ConstantOffsets = decoder.get_constant_offsets(&insn);

    let (flow, branch_target): (InsnFlow, Option<u64>) = flow_from_insn(&insn);
    let (reg_uses, mem_uses, rflags): (Vec<RegUse>, Vec<MemUse>, RflagsEffect) =
        info_from_insn(factory, &insn);
    let (isa, stack_effect, segments): (IsaTag, StackEffect, InsnSegments) =
        machine_facts_from_insn(&insn, raw, offsets);

    InstructionFacts {
        flow,
        branch_target,
        reg_uses,
        mem_uses,
        rflags,
        isa,
        stack_effect,
        segments,
    }
}

fn flow_from_insn(insn: &Instruction) -> (InsnFlow, Option<u64>) {
    let direct: bool = matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    match insn.flow_control() {
        FlowControl::Call if direct => (InsnFlow::Call, Some(insn.near_branch_target())),
        FlowControl::Call => (InsnFlow::IndirectCall, None),
        FlowControl::IndirectCall => (InsnFlow::IndirectCall, None),
        FlowControl::ConditionalBranch => {
            (InsnFlow::ConditionalBranch, Some(insn.near_branch_target()))
        }
        FlowControl::UnconditionalBranch if direct => (
            InsnFlow::UnconditionalBranch,
            Some(insn.near_branch_target()),
        ),
        FlowControl::UnconditionalBranch => (InsnFlow::UnconditionalBranch, None),
        FlowControl::IndirectBranch => (InsnFlow::IndirectBranch, None),
        FlowControl::Return => (InsnFlow::Return, None),
        FlowControl::Interrupt => (InsnFlow::Interrupt, None),
        FlowControl::Next | FlowControl::XbeginXabortXend | FlowControl::Exception => {
            (InsnFlow::Sequential, None)
        }
    }
}

fn info_from_insn(
    factory: &mut InstructionInfoFactory,
    insn: &Instruction,
) -> (Vec<RegUse>, Vec<MemUse>, RflagsEffect) {
    let info: &iced_x86::InstructionInfo = factory.info(insn);
    let reg_uses: Vec<RegUse> = info
        .used_registers()
        .iter()
        .map(|r: &iced_x86::UsedRegister| RegUse {
            register: format!("{:?}", r.register()),
            access: map_access(r.access()),
        })
        .collect();
    let mem_uses: Vec<MemUse> = info
        .used_memory()
        .iter()
        .map(|m: &iced_x86::UsedMemory| MemUse {
            segment: format!("{:?}", m.segment()),
            base: format!("{:?}", m.base()),
            index: format!("{:?}", m.index()),
            scale: u8::try_from(m.scale()).unwrap_or(1),
            displacement: m.displacement(),
            memory_size: format!("{:?}", m.memory_size()),
            access: map_access(m.access()),
        })
        .collect();
    let rflags: RflagsEffect = RflagsEffect {
        read: narrow_rflags(insn.rflags_read()),
        written: narrow_rflags(insn.rflags_written()),
        cleared: narrow_rflags(insn.rflags_cleared()),
        set: narrow_rflags(insn.rflags_set()),
        undefined: narrow_rflags(insn.rflags_undefined()),
    };
    (reg_uses, mem_uses, rflags)
}

fn machine_facts_from_insn(
    insn: &Instruction,
    raw: &[u8],
    offsets: ConstantOffsets,
) -> (IsaTag, StackEffect, InsnSegments) {
    let encoding: InsnEncoding = match insn.encoding() {
        EncodingKind::Legacy => InsnEncoding::Legacy,
        EncodingKind::VEX => InsnEncoding::Vex,
        EncodingKind::EVEX => InsnEncoding::Evex,
        EncodingKind::XOP => InsnEncoding::Xop,
        EncodingKind::D3NOW => InsnEncoding::D3now,
        _ => InsnEncoding::Unknown,
    };
    let cpuid_features: Vec<String> = insn
        .cpuid_features()
        .iter()
        .map(|f: &iced_x86::CpuidFeature| format!("{f:?}"))
        .collect();
    let isa: IsaTag = IsaTag {
        cpuid_features,
        encoding,
    };

    let fpu: iced_x86::FpuStackIncrementInfo = insn.fpu_stack_increment_info();
    let stack_effect: StackEffect = StackEffect {
        sp_delta: if insn.is_stack_instruction() {
            insn.stack_pointer_increment()
        } else {
            0
        },
        is_stack: insn.is_stack_instruction(),
        fpu_increment: i8::try_from(fpu.increment()).unwrap_or(0),
        fpu_writes_top: fpu.writes_top(),
        fpu_conditional: fpu.conditional(),
    };

    let segments: InsnSegments = decompose_segments(insn.encoding(), raw, insn.len(), offsets);
    (isa, stack_effect, segments)
}

#[cfg(test)]
fn decode_single(
    arch: DisasmArch,
    raw: &[u8],
    address: u64,
) -> Option<(Instruction, ConstantOffsets)> {
    let bits: u32 = match arch {
        DisasmArch::X86 => 32,
        DisasmArch::X86_64 => 64,
        _ => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, raw, address, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let mut insn: Instruction = Instruction::default();
    decoder.decode_out(&mut insn);
    if insn.is_invalid() {
        return None;
    }
    let offsets: ConstantOffsets = decoder.get_constant_offsets(&insn);
    Some((insn, offsets))
}

#[cfg(test)]
fn flow_of(arch: DisasmArch, raw: &[u8], address: u64) -> (InsnFlow, Option<u64>) {
    match decode_single(arch, raw, address) {
        Some((insn, _)) => flow_from_insn(&insn),
        None => (InsnFlow::Sequential, None),
    }
}

#[cfg(test)]
fn instruction_info(
    arch: DisasmArch,
    raw: &[u8],
    address: u64,
) -> (Vec<RegUse>, Vec<MemUse>, RflagsEffect) {
    match decode_single(arch, raw, address) {
        Some((insn, _)) => {
            let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
            info_from_insn(&mut factory, &insn)
        }
        None => (Vec::new(), Vec::new(), RflagsEffect::default()),
    }
}

#[cfg(test)]
fn instruction_machine_facts(
    arch: DisasmArch,
    raw: &[u8],
    address: u64,
) -> (IsaTag, StackEffect, InsnSegments) {
    match decode_single(arch, raw, address) {
        Some((insn, offsets)) => machine_facts_from_insn(&insn, raw, offsets),
        None => (
            IsaTag::default(),
            StackEffect::default(),
            InsnSegments::default(),
        ),
    }
}

const LEGACY_PREFIXES: [u8; 11] = [
    0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67,
];

fn decompose_segments(
    encoding: EncodingKind,
    raw: &[u8],
    len: usize,
    offsets: ConstantOffsets,
) -> InsnSegments {
    if len == 0 || len > raw.len() {
        return InsnSegments::default();
    }
    let displacement_len: usize = if offsets.has_displacement() {
        offsets.displacement_size()
    } else {
        0
    };
    let immediate_len: usize = (if offsets.has_immediate() {
        offsets.immediate_size()
    } else {
        0
    }) + (if offsets.has_immediate2() {
        offsets.immediate_size2()
    } else {
        0
    });

    let tail: usize = displacement_len + immediate_len;
    if tail > len {
        return InsnSegments {
            opcode: u8::try_from(len).unwrap_or(u8::MAX),
            ..InsnSegments::default()
        };
    }
    let head_end: usize = len - tail;

    let legacy_prefix_len: usize = match encoding {
        EncodingKind::Legacy | EncodingKind::D3NOW => count_legacy_prefixes(&raw[..head_end]),
        _ => 0,
    };

    let (opcode_len, modrm_len, sib_len): (usize, usize, usize) =
        split_opcode_modrm_sib(encoding, raw, legacy_prefix_len, head_end);

    let segments: InsnSegments = InsnSegments {
        legacy_prefix: u8::try_from(legacy_prefix_len).unwrap_or(u8::MAX),
        opcode: u8::try_from(opcode_len).unwrap_or(u8::MAX),
        modrm: u8::try_from(modrm_len).unwrap_or(u8::MAX),
        sib: u8::try_from(sib_len).unwrap_or(u8::MAX),
        displacement: u8::try_from(displacement_len).unwrap_or(u8::MAX),
        immediate: u8::try_from(immediate_len).unwrap_or(u8::MAX),
    };
    if segments.total() == len {
        segments
    } else {
        InsnSegments {
            opcode: u8::try_from(head_end).unwrap_or(u8::MAX),
            displacement: segments.displacement,
            immediate: segments.immediate,
            ..InsnSegments::default()
        }
    }
}

fn count_legacy_prefixes(head: &[u8]) -> usize {
    let mut idx: usize = 0;
    while idx < head.len() {
        let b: u8 = head[idx];
        if LEGACY_PREFIXES.contains(&b) {
            idx += 1;
            continue;
        }
        if (0x40..=0x4F).contains(&b) {
            idx += 1;
            break;
        }
        break;
    }
    idx
}

fn split_opcode_modrm_sib(
    encoding: EncodingKind,
    raw: &[u8],
    legacy_prefix_len: usize,
    head_end: usize,
) -> (usize, usize, usize) {
    let region_len: usize = head_end.saturating_sub(legacy_prefix_len);
    if region_len == 0 {
        return (0, 0, 0);
    }
    let escape_len: usize = match encoding {
        EncodingKind::VEX => vex_escape_len(raw.get(legacy_prefix_len).copied()),
        EncodingKind::XOP => 3,
        EncodingKind::EVEX => 4,
        _ => 0,
    };
    let opcode_byte_offset: usize = legacy_prefix_len + escape_len;
    let opcode_len_guess: usize = escape_len + legacy_opcode_len(raw, opcode_byte_offset, encoding);
    let after_opcode: usize = legacy_prefix_len + opcode_len_guess;
    if after_opcode >= head_end {
        return (region_len, 0, 0);
    }
    let modrm_offset: usize = after_opcode;
    let modrm: u8 = raw[modrm_offset];
    let has_sib: bool = modrm_has_sib(modrm);
    let modrm_len: usize = 1;
    let sib_len: usize = usize::from(has_sib && modrm_offset + 1 < head_end);
    let opcode_len: usize = region_len.saturating_sub(modrm_len + sib_len);
    (opcode_len, modrm_len, sib_len)
}

const fn vex_escape_len(first: Option<u8>) -> usize {
    match first {
        Some(0xC5) => 2,
        Some(0xC4) => 3,
        _ => 2,
    }
}

fn legacy_opcode_len(raw: &[u8], opcode_offset: usize, encoding: EncodingKind) -> usize {
    if !matches!(encoding, EncodingKind::Legacy) {
        return 1;
    }
    match raw.get(opcode_offset).copied() {
        Some(0x0F) => match raw.get(opcode_offset + 1).copied() {
            Some(0x38 | 0x3A) => 3,
            _ => 2,
        },
        _ => 1,
    }
}

const fn modrm_has_sib(modrm: u8) -> bool {
    let mod_bits: u8 = modrm >> 6;
    let rm_bits: u8 = modrm & 0x07;
    mod_bits != 0b11 && rm_bits == 0b100
}

pub(crate) const fn map_access(access: OpAccess) -> RegAccess {
    match access {
        OpAccess::None => RegAccess::None,
        OpAccess::Read => RegAccess::Read,
        OpAccess::CondRead => RegAccess::CondRead,
        OpAccess::Write => RegAccess::Write,
        OpAccess::CondWrite => RegAccess::CondWrite,
        OpAccess::ReadWrite => RegAccess::ReadWrite,
        OpAccess::ReadCondWrite => RegAccess::ReadCondWrite,
        OpAccess::NoMemAccess => RegAccess::NoMemAccess,
    }
}

const fn narrow_rflags(bits: u32) -> u16 {
    let mut out: u16 = 0;
    if bits & RflagsBits::OF != 0 {
        out |= RflagsEffect::OF;
    }
    if bits & RflagsBits::SF != 0 {
        out |= RflagsEffect::SF;
    }
    if bits & RflagsBits::ZF != 0 {
        out |= RflagsEffect::ZF;
    }
    if bits & RflagsBits::AF != 0 {
        out |= RflagsEffect::AF;
    }
    if bits & RflagsBits::CF != 0 {
        out |= RflagsEffect::CF;
    }
    if bits & RflagsBits::PF != 0 {
        out |= RflagsEffect::PF;
    }
    if bits & RflagsBits::DF != 0 {
        out |= RflagsEffect::DF;
    }
    if bits & RflagsBits::IF != 0 {
        out |= RflagsEffect::IF;
    }
    if bits & RflagsBits::AC != 0 {
        out |= RflagsEffect::AC;
    }
    out
}

fn build_symbol_table(bytes: &[u8], native: &NativeFile) -> Vec<DisasmSymbol> {
    let dyn_export_names: BTreeSet<String> = native
        .exports
        .iter()
        .map(|e: &disrobe_binfmt::native::ExportInfo| e.name.clone())
        .collect();
    let dyn_import_names: BTreeSet<String> = native
        .imports
        .iter()
        .map(|i: &disrobe_binfmt::native::ImportInfo| i.name.clone())
        .collect();

    let mut out: Vec<DisasmSymbol> = Vec::new();
    let mut seen: BTreeSet<(u64, String)> = BTreeSet::new();
    if let Ok(file) = object::File::parse(bytes) {
        for sym in file.symbols() {
            let Ok(name): core::result::Result<&str, object::Error> = sym.name() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let is_text: bool = matches!(sym.kind(), ObjSymbolKind::Text | ObjSymbolKind::Label);
            let undefined: bool = sym.is_undefined();
            if !is_text && !undefined {
                continue;
            }
            let owned: String = name.to_owned();
            if !seen.insert((sym.address(), owned.clone())) {
                continue;
            }
            let exported: bool = is_text && matches!(sym.scope(), ObjSymbolScope::Dynamic);
            let kind: DisasmSymbolKind = if undefined || dyn_import_names.contains(&owned) {
                DisasmSymbolKind::Import
            } else if dyn_export_names.contains(&owned) || exported {
                DisasmSymbolKind::Export
            } else {
                DisasmSymbolKind::Function
            };
            out.push(DisasmSymbol {
                address: sym.address(),
                name: owned,
                kind,
            });
        }
    }

    for export in &native.exports {
        if export.name.is_empty() {
            continue;
        }
        if !seen.insert((export.address, export.name.clone())) {
            continue;
        }
        out.push(DisasmSymbol {
            address: export.address,
            name: export.name.clone(),
            kind: DisasmSymbolKind::Export,
        });
    }

    out.sort_by(|a: &DisasmSymbol, b: &DisasmSymbol| {
        a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name))
    });
    out
}

fn split_operands(operands: &str) -> Vec<String> {
    let trimmed: &str = operands.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split(',')
        .map(|s: &str| s.trim().to_owned())
        .collect()
}

const fn map_arch(arch: BinArch, endian: Endian) -> Option<DisasmArch> {
    match arch {
        BinArch::X86 => Some(DisasmArch::X86),
        BinArch::X86_64 => Some(DisasmArch::X86_64),
        BinArch::Aarch64 => Some(DisasmArch::Aarch64),
        BinArch::Arm => Some(DisasmArch::Arm32),
        BinArch::RiscV32 => Some(DisasmArch::RiscV32),
        BinArch::RiscV64 => Some(DisasmArch::RiscV64),
        BinArch::Mips => match endian {
            Endian::Big => Some(DisasmArch::MipsBe32),
            Endian::Little => Some(DisasmArch::MipsLe32),
        },
        BinArch::Mips64 => Some(DisasmArch::Mips64),
        BinArch::PowerPc => Some(DisasmArch::PowerPc32),
        BinArch::PowerPc64 => Some(DisasmArch::PowerPc64),
        BinArch::Sparc => Some(DisasmArch::Sparc),
        BinArch::Sparc64 => Some(DisasmArch::Sparc64),
        BinArch::Ebpf => Some(DisasmArch::Ebpf),
        _ => None,
    }
}

#[must_use]
pub fn is_disassemblable_format(format: NativeFormat) -> bool {
    matches!(
        format,
        NativeFormat::Pe32
            | NativeFormat::Pe64
            | NativeFormat::Elf32
            | NativeFormat::Elf64
            | NativeFormat::MachO32
            | NativeFormat::MachO64
            | NativeFormat::Coff
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use object::write::{
        Object as WriteObject, StandardSection, Symbol as WriteSymbol,
        SymbolFlags as WriteSymbolFlags, SymbolKind as WriteSymbolKind, SymbolScope, SymbolSection,
    };
    use object::{Architecture, BinaryFormat, Endianness};

    use super::*;

    fn call_rel32(buf: &mut [u8], at: usize, target: i64) {
        let next: i64 = at as i64 + 5;
        let rel: i32 = i32::try_from(target - next).expect("rel32 fits");
        buf[at] = 0xE8;
        buf[at + 1..at + 5].copy_from_slice(&rel.to_le_bytes());
    }

    fn two_function_elf() -> Vec<u8> {
        let mut code: Vec<u8> = vec![0xCCu8; 0x40];
        code[0x00] = 0x90;
        code[0x01] = 0xC3;
        call_rel32(&mut code, 0x10, 0x00 - 0x10);
        code[0x15] = 0xC3;

        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let text: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _ = obj.append_section_data(text, &code, 16);
        for (name, off, size, export) in [
            ("callee", 0x00u64, 0x02u64, false),
            ("caller", 0x10, 0x06, true),
        ] {
            let sym: WriteSymbol = WriteSymbol {
                name: name.as_bytes().to_vec(),
                value: off,
                size,
                kind: WriteSymbolKind::Text,
                scope: if export {
                    SymbolScope::Dynamic
                } else {
                    SymbolScope::Linkage
                },
                weak: false,
                section: SymbolSection::Section(text),
                flags: WriteSymbolFlags::None,
            };
            let _ = obj.add_symbol(sym);
        }
        obj.write().expect("elf write")
    }

    fn aarch64_object_with_entry_and_internal_bl() -> Vec<u8> {
        let words: [u32; 5] = [
            0xd503_201f,
            0x9400_0003,
            0xd503_201f,
            0xd503_201f,
            0xd65f_03c0,
        ];
        let code: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
        let text: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _: u64 = obj.append_section_data(text, &code, 4);
        let mut elf: Vec<u8> = obj.write().expect("aarch64 elf write");
        let entry: [u8; 8] = 4_u64.to_le_bytes();
        elf.get_mut(24..32)
            .expect("elf64 entry field")
            .copy_from_slice(&entry);
        elf
    }

    fn aarch64_object_with_retained_local_caller() -> Vec<u8> {
        let words: [u32; 7] = [
            0xd503_201f,
            0xd65f_03c0,
            0xd503_201f,
            0xd503_201f,
            0x9400_0002,
            0xd65f_03c0,
            0xd65f_03c0,
        ];
        let code: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect();
        let mut obj: WriteObject<'_> =
            WriteObject::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
        let text: object::write::SectionId = obj.section_id(StandardSection::Text);
        let _: u64 = obj.append_section_data(text, &code, 4);
        let symbol: WriteSymbol = WriteSymbol {
            name: b"retained_local".to_vec(),
            value: 0x10,
            size: 8,
            kind: WriteSymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: WriteSymbolFlags::None,
        };
        let _: object::write::SymbolId = obj.add_symbol(symbol);
        let mut elf: Vec<u8> = obj.write().expect("aarch64 elf write");
        let entry: [u8; 8] = 4_u64.to_le_bytes();
        elf.get_mut(24..32)
            .expect("elf64 entry field")
            .copy_from_slice(&entry);
        elf
    }

    #[test]
    fn builds_instructions_and_symbols_from_real_elf() {
        let elf: Vec<u8> = two_function_elf();
        let payload: DisasmPayload = build_disasm_payload(&elf).expect("build payload");
        assert!(!payload.instructions.is_empty());
        let names: Vec<&str> = payload
            .symbol_table
            .iter()
            .map(|s: &DisasmSymbol| s.name.as_str())
            .collect();
        assert!(names.contains(&"callee"));
        assert!(names.contains(&"caller"));
        let caller: &DisasmSymbol = payload
            .symbol_table
            .iter()
            .find(|s: &&DisasmSymbol| s.name == "caller")
            .expect("caller symbol");
        assert_eq!(caller.kind, DisasmSymbolKind::Export);
        let call: &DisasmInstruction = payload
            .instructions
            .iter()
            .find(|i: &&DisasmInstruction| i.mnemonic == "call")
            .expect("a call instruction");
        assert!(!call.operands.is_empty());
    }

    #[test]
    fn aarch64_entry_seed_injects_the_decoded_bl_target() {
        let elf: Vec<u8> = aarch64_object_with_entry_and_internal_bl();
        let build: DisasmBuild = build_disasm_payload_with_discovery(&elf).expect("build payload");
        let starts: Vec<u64> = build
            .payload
            .symbol_table
            .iter()
            .filter(|symbol: &&DisasmSymbol| {
                matches!(
                    symbol.kind,
                    DisasmSymbolKind::Function | DisasmSymbolKind::Export
                )
            })
            .map(|symbol: &DisasmSymbol| symbol.address)
            .collect();
        assert_eq!(starts, vec![0x4, 0x10]);
        assert!(!build.function_universe.reference_anchors_trusted(0x4));
        assert!(!build.function_universe.reference_anchors_trusted(0x10));
        assert!(build.function_universe.reference_anchors_trusted(0x14));
    }

    #[test]
    fn aarch64_retained_local_function_seeds_its_internal_call_target() {
        let elf: Vec<u8> = aarch64_object_with_retained_local_caller();
        let build: DisasmBuild = build_disasm_payload_with_discovery(&elf).expect("build payload");
        let starts: Vec<(u64, String)> = build
            .payload
            .symbol_table
            .iter()
            .filter(|symbol: &&DisasmSymbol| {
                matches!(
                    symbol.kind,
                    DisasmSymbolKind::Function | DisasmSymbolKind::Export
                )
            })
            .map(|symbol: &DisasmSymbol| (symbol.address, symbol.name.clone()))
            .collect();
        assert_eq!(
            starts,
            vec![
                (0x4, "sub_4".to_owned()),
                (0x10, "retained_local".to_owned()),
                (0x18, "sub_18".to_owned()),
            ]
        );
        assert!(!build.function_universe.reference_anchors_trusted(0x4));
        assert!(build.function_universe.reference_anchors_trusted(0x10));
        assert!(!build.function_universe.reference_anchors_trusted(0x18));
    }

    #[test]
    fn rejects_input_without_known_arch() {
        let err: Error = build_disasm_payload(b"not a binary at all").expect_err("must reject");
        assert!(matches!(
            err,
            Error::ObjectParse(_) | Error::UnsupportedArch(_)
        ));
    }

    #[test]
    fn split_operands_splits_on_commas() {
        assert_eq!(split_operands(""), Vec::<String>::new());
        assert_eq!(split_operands("eax, eax"), vec!["eax", "eax"]);
        assert_eq!(split_operands("0x1234"), vec!["0x1234"]);
    }

    fn reg(reg_uses: &[RegUse], name: &str) -> RegAccess {
        reg_uses
            .iter()
            .find(|r: &&RegUse| r.register == name)
            .unwrap_or_else(|| panic!("register {name} not in {reg_uses:?}"))
            .access
    }

    #[test]
    fn info_add_reads_eax_ebx_writes_eax_and_arithmetic_flags() {
        let (regs, mem, rflags): (Vec<RegUse>, Vec<MemUse>, RflagsEffect) =
            instruction_info(DisasmArch::X86, &[0x01, 0xD8], 0x1000);
        assert!(reg(&regs, "EAX").reads(), "add reads its destination eax");
        assert!(reg(&regs, "EAX").writes(), "add writes eax");
        assert!(reg(&regs, "EBX").reads(), "add reads source ebx");
        assert!(!reg(&regs, "EBX").writes(), "add does not write ebx");
        assert!(mem.is_empty(), "reg-reg add touches no memory");
        let arith: u16 = RflagsEffect::OF
            | RflagsEffect::SF
            | RflagsEffect::ZF
            | RflagsEffect::AF
            | RflagsEffect::CF
            | RflagsEffect::PF;
        assert_eq!(
            rflags.written, arith,
            "add writes OF/SF/ZF/AF/CF/PF per the x86 arithmetic-flags semantics"
        );
        assert_eq!(rflags.read, 0, "add reads no flags");
    }

    #[test]
    fn info_xor_self_writes_eax_clears_of_cf_sets_zf() {
        let (regs, mem, rflags): (Vec<RegUse>, Vec<MemUse>, RflagsEffect) =
            instruction_info(DisasmArch::X86, &[0x31, 0xC0], 0x1000);
        assert!(reg(&regs, "EAX").writes(), "xor eax,eax writes eax");
        assert!(mem.is_empty());
        assert_ne!(
            rflags.cleared & RflagsEffect::OF,
            0,
            "xor clears OF (cleared mask {:#06x})",
            rflags.cleared
        );
        assert_ne!(rflags.cleared & RflagsEffect::CF, 0, "xor clears CF");
        assert_ne!(rflags.set & RflagsEffect::ZF, 0, "xor self sets ZF");
    }

    #[test]
    fn info_ret_reads_rsp_and_stack_memory() {
        let (regs, mem, rflags): (Vec<RegUse>, Vec<MemUse>, RflagsEffect) =
            instruction_info(DisasmArch::X86_64, &[0xC3], 0x1000);
        assert!(reg(&regs, "RSP").reads(), "ret pops, so it reads rsp");
        assert_eq!(mem.len(), 1, "ret reads one stack slot");
        assert!(mem[0].access.reads(), "the stack read is a memory read");
        assert_eq!(mem[0].base, "RSP", "the stack slot is based on rsp");
        assert!(rflags.is_empty(), "ret touches no flags");
    }

    #[test]
    fn info_push_rax_reads_rax_rsp_writes_rsp_and_memory() {
        let (regs, mem, _rflags): (Vec<RegUse>, Vec<MemUse>, RflagsEffect) =
            instruction_info(DisasmArch::X86_64, &[0x50], 0x1000);
        assert!(reg(&regs, "RAX").reads(), "push rax reads rax");
        assert!(reg(&regs, "RSP").reads(), "push decrements then uses rsp");
        assert!(reg(&regs, "RSP").writes(), "push updates rsp");
        assert_eq!(mem.len(), 1, "push writes one stack slot");
        assert!(mem[0].access.writes(), "the stack slot is written");
        assert_eq!(mem[0].base, "RSP", "the slot is rsp-relative");
    }

    #[test]
    fn machine_facts_push_rax_has_sp_delta_minus_eight() {
        let (isa, stack, segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(DisasmArch::X86_64, &[0x50], 0x1000);
        assert!(stack.is_stack, "push is a stack instruction");
        assert_eq!(stack.sp_delta, -8, "push rax decrements rsp by 8 in 64-bit");
        assert_eq!(isa.encoding, InsnEncoding::Legacy);
        assert_eq!(
            segments.total(),
            1,
            "single-byte push: prefix+opcode sums to len"
        );
        assert_eq!(segments.opcode, 1);
    }

    #[test]
    fn machine_facts_pop_rax_has_sp_delta_plus_eight() {
        let (_isa, stack, _segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(DisasmArch::X86_64, &[0x58], 0x1000);
        assert!(stack.is_stack);
        assert_eq!(stack.sp_delta, 8, "pop rax increments rsp by 8");
    }

    #[test]
    fn machine_facts_vex_avx_instruction_tagged_avx_and_vex() {
        let (isa, _stack, segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(DisasmArch::X86_64, &[0xC5, 0xF8, 0x10, 0xC1], 0x1000);
        assert_eq!(
            isa.encoding,
            InsnEncoding::Vex,
            "C5 F8 10 is a 2-byte-VEX vmovups"
        );
        assert!(
            isa.cpuid_features.iter().any(|f: &String| f == "AVX"),
            "a VEX-encoded AVX instruction carries the AVX CPUID feature: {:?}",
            isa.cpuid_features
        );
        assert_eq!(
            segments.total(),
            4,
            "vex prefix folds into opcode region, modrm closes the instruction"
        );
        assert_eq!(segments.legacy_prefix, 0, "vex carries no legacy prefix");
    }

    #[test]
    fn machine_facts_evex_avx512_instruction_tagged_evex() {
        let (isa, _stack, segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(
                DisasmArch::X86_64,
                &[0x62, 0xF1, 0x7C, 0x48, 0x10, 0xC1],
                0x1000,
            );
        assert_eq!(
            isa.encoding,
            InsnEncoding::Evex,
            "62 .. is EVEX vmovups zmm"
        );
        assert!(
            isa.cpuid_features
                .iter()
                .any(|f: &String| f.contains("AVX512")),
            "EVEX zmm op requires an AVX-512 feature: {:?}",
            isa.cpuid_features
        );
        assert_eq!(segments.total(), 6);
    }

    #[test]
    fn machine_facts_mov_with_disp_and_imm_splits_components() {
        let raw: [u8; 7] = [0xC7, 0x40, 0x10, 0x04, 0x03, 0x02, 0x01];
        let (_isa, _stack, segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(DisasmArch::X86_64, &raw, 0x1000);
        assert_eq!(
            segments.total(),
            7,
            "mov [rax+0x10], imm32 sums to seven bytes"
        );
        assert_eq!(segments.opcode, 1, "single-byte C7 opcode");
        assert_eq!(segments.modrm, 1, "one modrm byte");
        assert_eq!(segments.sib, 0, "rm=rax needs no sib");
        assert_eq!(segments.displacement, 1, "disp8 = 0x10");
        assert_eq!(segments.immediate, 4, "imm32 = 0x01020304");
    }

    #[test]
    fn machine_facts_sib_addressing_emits_sib_byte() {
        let raw: [u8; 4] = [0x8B, 0x04, 0x88, 0x90];
        let (_isa, _stack, segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(DisasmArch::X86_64, &raw[..3], 0x1000);
        assert_eq!(
            segments.total(),
            3,
            "mov eax,[rax+rcx*4] sums to three bytes"
        );
        assert_eq!(segments.modrm, 1);
        assert_eq!(segments.sib, 1, "rm=0b100 with mod!=11 means a sib byte");
    }

    #[test]
    fn machine_facts_segments_sum_to_length_across_a_real_function() {
        let stripped: Vec<u8> = match corpus_bytes("native/discovery/disc.stripped.elf") {
            Some(b) => b,
            None => return,
        };
        let payload: DisasmPayload =
            build_disasm_payload(&stripped).expect("build stripped payload");
        let mut checked: usize = 0;
        for insn in &payload.instructions {
            if insn.segments.is_empty() {
                continue;
            }
            assert_eq!(
                insn.segments.total(),
                insn.bytes.len(),
                "instruction component segments must sum to the decoded length at {:#x} ({} {:?}): {:?}",
                insn.offset,
                insn.mnemonic,
                insn.bytes,
                insn.segments
            );
            checked += 1;
        }
        assert!(
            checked > 50,
            "expected to component-check many real instructions, only saw {checked}"
        );
    }

    #[test]
    fn machine_facts_real_function_isa_and_stack_are_populated() {
        let stripped: Vec<u8> = match corpus_bytes("native/discovery/disc.stripped.elf") {
            Some(b) => b,
            None => return,
        };
        let payload: DisasmPayload =
            build_disasm_payload(&stripped).expect("build stripped payload");
        assert!(
            payload
                .instructions
                .iter()
                .any(|i: &DisasmInstruction| matches!(i.isa.encoding, InsnEncoding::Legacy)),
            "an x86-64 ELF function carries legacy-encoded instructions"
        );
        assert!(
            payload
                .instructions
                .iter()
                .any(|i: &DisasmInstruction| i.stack_effect.is_stack),
            "a real function prologue pushes/pops the stack"
        );
    }

    #[test]
    fn machine_facts_empty_for_non_x86_arch() {
        let (isa, stack, segments): (IsaTag, StackEffect, InsnSegments) =
            instruction_machine_facts(DisasmArch::Aarch64, &[0xC0, 0x03, 0x5F, 0xD6], 0x0);
        assert!(isa.is_empty());
        assert!(stack.is_neutral());
        assert!(segments.is_empty());
    }

    #[test]
    fn aarch64_decode_byte_limit_matches_fixed_instruction_width() {
        assert_eq!(decode_byte_limit(DisasmArch::Aarch64, 4), 16);
        assert_eq!(decode_byte_limit(DisasmArch::Aarch64, 0), 0);
        assert_eq!(
            decode_byte_limit(DisasmArch::Aarch64, 1),
            AARCH64_INSTRUCTION_BYTES
        );
        assert_eq!(
            decode_byte_limit(DisasmArch::Aarch64, MAX_PAYLOAD_INSTRUCTIONS),
            MAX_PAYLOAD_INSTRUCTIONS.saturating_mul(AARCH64_INSTRUCTION_BYTES)
        );
        assert_eq!(decode_byte_limit(DisasmArch::X86_64, 4), usize::MAX);
    }

    #[test]
    fn aarch64_dynamic_exports_do_not_suppress_function_discovery() {
        assert!(needs_function_discovery(DisasmArch::Aarch64, true));
        assert!(!needs_function_discovery(DisasmArch::X86_64, true));
        assert!(needs_function_discovery(DisasmArch::X86_64, false));
    }

    #[test]
    fn info_is_empty_for_non_x86_arch() {
        let (regs, mem, rflags): (Vec<RegUse>, Vec<MemUse>, RflagsEffect) =
            instruction_info(DisasmArch::Aarch64, &[0xC0, 0x03, 0x5F, 0xD6], 0x0);
        assert!(regs.is_empty());
        assert!(mem.is_empty());
        assert!(rflags.is_empty());
    }

    #[test]
    fn flow_of_classifies_direct_call_conditional_branch_and_ret() {
        let (call_flow, call_target): (InsnFlow, Option<u64>) =
            flow_of(DisasmArch::X86_64, &[0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(call_flow, InsnFlow::Call);
        assert_eq!(call_target, Some(0x1005), "rel32 call resolves its target");
        let (jcc_flow, jcc_target): (InsnFlow, Option<u64>) =
            flow_of(DisasmArch::X86_64, &[0x74, 0x10], 0x2000);
        assert_eq!(jcc_flow, InsnFlow::ConditionalBranch);
        assert_eq!(jcc_target, Some(0x2012), "je rel8 resolves its target");
        let (ret_flow, ret_target): (InsnFlow, Option<u64>) =
            flow_of(DisasmArch::X86_64, &[0xC3], 0x3000);
        assert_eq!(ret_flow, InsnFlow::Return);
        assert_eq!(ret_target, None);
        let (indirect_flow, _): (InsnFlow, Option<u64>) =
            flow_of(DisasmArch::X86_64, &[0xFF, 0xD0], 0x4000);
        assert_eq!(
            indirect_flow,
            InsnFlow::IndirectCall,
            "call rax is indirect"
        );
        let (none_flow, none_target): (InsnFlow, Option<u64>) =
            flow_of(DisasmArch::Aarch64, &[0xC3], 0x0);
        assert_eq!(none_flow, InsnFlow::Sequential, "non-x86 arch is neutral");
        assert_eq!(none_target, None);
    }

    #[test]
    fn build_payload_populates_instruction_info_for_x86() {
        let elf: Vec<u8> = two_function_elf();
        let payload: DisasmPayload = build_disasm_payload(&elf).expect("build payload");
        let call: &DisasmInstruction = payload
            .instructions
            .iter()
            .find(|i: &&DisasmInstruction| i.mnemonic == "call")
            .expect("a call instruction");
        assert!(
            call.reg_uses.iter().any(|r: &RegUse| r.register == "RSP"),
            "a near call pushes the return address, so it touches rsp: {:?}",
            call.reg_uses
        );
        assert!(
            !call.mem_uses.is_empty(),
            "the call's return-address push is a memory write: {:?}",
            call.mem_uses
        );
    }

    #[test]
    fn call_instruction_carries_structured_flow() {
        let elf: Vec<u8> = two_function_elf();
        let payload: DisasmPayload = build_disasm_payload(&elf).expect("build payload");
        let call: &DisasmInstruction = payload
            .instructions
            .iter()
            .find(|i: &&DisasmInstruction| i.mnemonic == "call")
            .expect("a call instruction");
        assert_eq!(call.flow, InsnFlow::Call);
        assert!(
            call.branch_target.is_some(),
            "a direct call resolves a near-branch target"
        );
        let ret: &DisasmInstruction = payload
            .instructions
            .iter()
            .find(|i: &&DisasmInstruction| i.mnemonic == "ret")
            .expect("a ret");
        assert_eq!(ret.flow, InsnFlow::Return);
        assert_eq!(ret.branch_target, None);
    }

    fn corpus_bytes(rel: &str) -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel);
        std::fs::read(path).ok()
    }

    fn ground_truth_text_starts(unstripped: &[u8]) -> BTreeSet<u64> {
        let file: object::File<'_> = object::File::parse(unstripped).expect("parse unstripped");
        let text_indices: BTreeSet<usize> = file
            .sections()
            .filter(|s: &object::Section<'_, '_>| matches!(s.kind(), object::SectionKind::Text))
            .map(|s: object::Section<'_, '_>| s.index().0)
            .collect();
        let mut starts: BTreeSet<u64> = BTreeSet::new();
        for sym in file.symbols() {
            if !matches!(sym.kind(), ObjSymbolKind::Text) {
                continue;
            }
            if let object::SymbolSection::Section(idx) = sym.section()
                && text_indices.contains(&idx.0)
            {
                starts.insert(sym.address());
            }
        }
        starts
    }

    #[test]
    fn stripped_elf_recovers_functions_with_high_coverage() {
        let Some(stripped): Option<Vec<u8>> = corpus_bytes("native/discovery/disc.stripped.elf")
        else {
            return;
        };
        let unstripped: Vec<u8> =
            corpus_bytes("native/discovery/disc.unstripped.elf").expect("unstripped twin present");

        let truth: BTreeSet<u64> = ground_truth_text_starts(&unstripped);
        assert!(truth.len() >= 6, "ground truth has the helpers: {truth:?}");

        let payload: DisasmPayload =
            build_disasm_payload(&stripped).expect("build stripped payload");
        let recovered: BTreeSet<u64> = payload
            .symbol_table
            .iter()
            .filter(|s: &&DisasmSymbol| {
                matches!(
                    s.kind,
                    DisasmSymbolKind::Function | DisasmSymbolKind::Export
                )
            })
            .map(|s: &DisasmSymbol| s.address)
            .collect();

        assert!(
            !recovered.is_empty(),
            "G3 closed: a stripped binary now yields functions, got {}",
            recovered.len()
        );
        let hits: usize = truth
            .iter()
            .filter(|a: &&u64| recovered.contains(a))
            .count();
        let coverage: f64 = hits as f64 / truth.len() as f64;
        assert!(
            coverage >= 0.85,
            "function-discovery coverage {coverage:.3} ({hits}/{}) below 0.85; recovered = {recovered:?}",
            truth.len()
        );
        let false_positives: usize = recovered
            .iter()
            .filter(|a: &&u64| !truth.contains(a))
            .count();
        assert!(
            false_positives <= 2,
            "too many false-positive starts: {false_positives} (recovered {recovered:?}, truth {truth:?})"
        );
    }

    #[test]
    fn stripped_elf_resolves_the_dispatch_jump_table() {
        let Some(unstripped): Option<Vec<u8>> =
            corpus_bytes("native/discovery/disc.unstripped.elf")
        else {
            return;
        };
        let stripped: Vec<u8> =
            corpus_bytes("native/discovery/disc.stripped.elf").expect("stripped twin present");

        let native: NativeFile = parse_native(&stripped).expect("parse native");
        let sections: Vec<ExecutableSection> = executable_sections(&stripped, &native.sections);
        let code: Vec<CodeWindow<'_>> = sections
            .iter()
            .map(|s: &ExecutableSection| CodeWindow {
                address: s.address,
                bytes: &s.bytes,
            })
            .collect();
        let rodata: Vec<ReadOnlyWindow<'_>> = read_only_windows(&stripped);
        assert!(
            rodata
                .iter()
                .any(|w: &ReadOnlyWindow<'_>| w.address <= 0x0020_0120
                    && 0x0020_0120 < w.address + w.bytes.len() as u64),
            "the .rodata window covering the jump table must be collected: {:?}",
            rodata
                .iter()
                .map(|w: &ReadOnlyWindow<'_>| (w.address, w.bytes.len()))
                .collect::<Vec<(u64, usize)>>()
        );
        let seeds: Vec<u64> = discovery_seeds(&native, &stripped);
        let input: DiscoveryInput<'_> = DiscoveryInput {
            bitness: Bitness::Bits64,
            code,
            rodata,
            seeds,
            noreturn: std::collections::BTreeSet::new(),
        };
        let discovered: DiscoveredFunctions = discover_functions(&input);
        assert!(
            !discovered.jump_tables.is_empty(),
            "the dispatch switch's jump table must resolve from .rodata; starts={:?}",
            discovered.starts
        );
        let hit: &crate::desync::JumpTableHit = &discovered.jump_tables[0];
        assert!(
            hit.targets.len() >= 4,
            "expected several case targets, got {:?}",
            hit.targets
        );
        let _ = unstripped;
    }

    #[test]
    fn pe_pdata_seeds_function_starts() {
        let Some(pe): Option<Vec<u8>> = corpus_bytes("native/discovery/disc.pe.exe") else {
            return;
        };
        let starts: Vec<u64> = pdata_function_starts(&pe);
        assert!(
            starts.len() >= 3,
            "the .pdata RUNTIME_FUNCTION table seeds function starts, got {starts:?}"
        );
        let payload: DisasmPayload = build_disasm_payload(&pe).expect("build pe payload");
        let funcs: usize = payload
            .symbol_table
            .iter()
            .filter(|s: &&DisasmSymbol| {
                matches!(
                    s.kind,
                    DisasmSymbolKind::Function | DisasmSymbolKind::Export
                )
            })
            .count();
        assert!(funcs > 0, "stripped PE yields functions via .pdata seeding");
    }
}
