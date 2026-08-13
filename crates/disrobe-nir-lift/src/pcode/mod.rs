use std::collections::BTreeSet;

use disrobe_lift_x86::decode_block_x86;
use disrobe_nir::{
    NirArtifact, NirClass, NirFunction, NirInstr, NirModule, NirOp, SourceBytes, SourceBytesRef,
    SourceLang, SourceOffset, SourceRef, SourceUnit, SourceUnitRef,
};
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use disrobe_sleigh::syntax::Endian;

use crate::error::{LiftError, ProvenanceLiftError, ProvenanceResult, Result};

mod arch;
mod flags;
mod ops;
mod spec;
mod varnode;

pub use arch::{
    ArchLift, LiftGap, LiftGaps, PcodeArch, block_gaps, lower_arch, lower_for_arch_with_provenance,
};
use spec::{SpecRegisterMap, SpecRegisters};
pub use varnode::RegisterCell;
use varnode::VarnodeLowerer;

const ARM32_REQUIRED_CELLS: &[&str] = &[
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr",
    "pc", "cpsr", "NG", "ZR", "CY", "OV",
];

const ARM32_DISCARDED_CELLS: &[&str] = &[
    "NG",
    "ZR",
    "CY",
    "OV",
    "tmpNG",
    "tmpZR",
    "tmpCY",
    "tmpOV",
    "shift_carry",
];

const MIPS32_REQUIRED_CELLS: &[&str] = &[
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "gp", "sp", "s8", "ra", "pc", "hi", "lo",
];

const MIPS32_DISCARDED_CELLS: &[&str] = &["zero"];

const MIPS32_CONSTANT_ZERO_CELLS: &[&str] = &["zero"];

const MAX_PCODE_INSTRUCTIONS: usize = 65_536;
const MAX_PCODE_OPERATIONS: usize = 1_048_576;
const MAX_IDENTIFIER_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcodeLiftConfig {
    lang: SourceLang,
    registers: Vec<RegisterCell>,
    max_instructions: usize,
    max_operations: usize,
    no_return_targets: BTreeSet<u64>,
    tail_call_sites: BTreeSet<u64>,
    return_value: Option<String>,
    x86_callother_contracts: bool,
    discarded_registers: BTreeSet<String>,
    constant_zero_registers: BTreeSet<String>,
    fold_condition_codes: bool,
    big_endian_register_space: bool,
    branch_delay_slots: bool,
}

impl PcodeLiftConfig {
    #[must_use]
    pub const fn new(lang: SourceLang, registers: Vec<RegisterCell>) -> Self {
        Self {
            lang,
            registers,
            max_instructions: MAX_PCODE_INSTRUCTIONS,
            max_operations: MAX_PCODE_OPERATIONS,
            no_return_targets: BTreeSet::new(),
            tail_call_sites: BTreeSet::new(),
            return_value: None,
            x86_callother_contracts: false,
            discarded_registers: BTreeSet::new(),
            constant_zero_registers: BTreeSet::new(),
            fold_condition_codes: false,
            big_endian_register_space: false,
            branch_delay_slots: false,
        }
    }

    #[must_use]
    pub fn x86_64() -> Self {
        let mut registers: Vec<RegisterCell> = Vec::with_capacity(73);
        for (offset, name) in [
            (0x00, "rax"),
            (0x08, "rcx"),
            (0x10, "rdx"),
            (0x18, "rbx"),
            (0x20, "rsp"),
            (0x28, "rbp"),
            (0x30, "rsi"),
            (0x38, "rdi"),
            (0x80, "r8"),
            (0x88, "r9"),
            (0x90, "r10"),
            (0x98, "r11"),
            (0xa0, "r12"),
            (0xa8, "r13"),
            (0xb0, "r14"),
            (0xb8, "r15"),
        ] {
            registers.push(RegisterCell::new(offset, 8, name, Some(4)));
        }
        registers.extend([
            RegisterCell::new(0x200, 1, "cf", None),
            RegisterCell::new(0x202, 1, "pf", None),
            RegisterCell::new(0x204, 1, "af", None),
            RegisterCell::new(0x206, 1, "zf", None),
            RegisterCell::new(0x207, 1, "sf", None),
            RegisterCell::new(0x20a, 1, "df", None),
            RegisterCell::new(0x20b, 1, "of", None),
            RegisterCell::new(0x288, 8, "rip", None),
            RegisterCell::new(0x1094, 4, "mxcsr", None),
        ]);
        for index in 0_u64..32_u64 {
            let offset: u64 = 0x1200_u64 + index * 0x40_u64;
            let name: String = format!("zmm{index}");
            registers.push(RegisterCell::new(offset, 64, name, None));
        }
        for index in 0_u64..8_u64 {
            let offset: u64 = 0x834_u64 + index * 8_u64;
            let name: String = format!("k{index}");
            registers.push(RegisterCell::new(offset, 8, name, None));
        }
        registers.extend([
            RegisterCell::new(0x100, 2, "es", None),
            RegisterCell::new(0x102, 2, "cs", None),
            RegisterCell::new(0x104, 2, "ss", None),
            RegisterCell::new(0x106, 2, "ds", None),
            RegisterCell::new(0x108, 2, "fs", None),
            RegisterCell::new(0x10a, 2, "gs", None),
            RegisterCell::new(0x110, 8, "fsbase", None),
            RegisterCell::new(0x118, 8, "gsbase", None),
        ]);
        let mut config: Self = Self::new(SourceLang::NativeX86, registers)
            .with_return_value("rax")
            .with_x86_callother_contracts();
        for name in ["cf", "pf", "af", "zf", "sf", "of"] {
            config.discarded_registers.insert(name.to_owned());
        }
        config
    }

    #[must_use]
    pub fn aarch64() -> Self {
        let mut registers: Vec<RegisterCell> = Vec::with_capacity(37);
        registers.push(RegisterCell::new(0x0, 8, "pc", None));
        registers.push(RegisterCell::new(0x8, 8, "sp", Some(4)));
        for index in 0_u64..31_u64 {
            let offset: u64 = 0x4000_u64 + index * 8_u64;
            let name: String = format!("x{index}");
            registers.push(RegisterCell::new(offset, 8, name, Some(4)));
        }
        registers.extend([
            RegisterCell::new(0x100, 1, "ng", None),
            RegisterCell::new(0x101, 1, "zr", None),
            RegisterCell::new(0x102, 1, "cy", None),
            RegisterCell::new(0x103, 1, "ov", None),
        ]);
        let mut config: Self = Self::new(SourceLang::NativeArm, registers)
            .with_return_value("x0")
            .with_condition_code_folding();
        for name in ["ng", "zr", "cy", "ov"] {
            config.discarded_registers.insert(name.to_owned());
        }
        config
    }

    pub fn arm32() -> Result<Self> {
        let map: SpecRegisters = spec::registers(SpecRegisterMap::Arm32)?;
        spec::require_cells(&map.cells, ARM32_REQUIRED_CELLS, "arm32")?;
        let mut config: Self = Self::new(SourceLang::NativeArm, map.cells)
            .with_return_value("r0")
            .with_condition_code_folding()
            .with_big_endian_register_space(map.big_endian);
        for name in ARM32_DISCARDED_CELLS {
            config.discarded_registers.insert((*name).to_owned());
        }
        Ok(config)
    }

    pub fn mips32(endian: Endian) -> Result<Self> {
        let map: SpecRegisters = spec::registers(SpecRegisterMap::mips32(endian))?;
        spec::require_cells(&map.cells, MIPS32_REQUIRED_CELLS, "mips32")?;
        let mut config: Self = Self::new(SourceLang::Unknown, map.cells)
            .with_return_value("v0")
            .with_big_endian_register_space(map.big_endian)
            .with_branch_delay_slots();
        for name in MIPS32_DISCARDED_CELLS {
            config.discarded_registers.insert((*name).to_owned());
        }
        for name in MIPS32_CONSTANT_ZERO_CELLS {
            config.constant_zero_registers.insert((*name).to_owned());
        }
        Ok(config)
    }

    #[must_use]
    pub fn registers(&self) -> &[RegisterCell] {
        &self.registers
    }

    #[must_use]
    pub fn is_discarded_register(&self, name: &str) -> bool {
        self.discarded_registers.contains(name)
    }

    #[must_use]
    pub const fn with_big_endian_register_space(mut self, big_endian: bool) -> Self {
        self.big_endian_register_space = big_endian;
        self
    }

    #[must_use]
    pub const fn with_branch_delay_slots(mut self) -> Self {
        self.branch_delay_slots = true;
        self
    }

    #[must_use]
    pub const fn with_limits(mut self, max_instructions: usize, max_operations: usize) -> Self {
        self.max_instructions = if max_instructions < MAX_PCODE_INSTRUCTIONS {
            max_instructions
        } else {
            MAX_PCODE_INSTRUCTIONS
        };
        self.max_operations = if max_operations < MAX_PCODE_OPERATIONS {
            max_operations
        } else {
            MAX_PCODE_OPERATIONS
        };
        self
    }

    #[must_use]
    pub fn with_no_return_target(mut self, target: u64) -> Self {
        self.no_return_targets.insert(target);
        self
    }

    #[must_use]
    pub fn with_tail_call_site(mut self, address: u64) -> Self {
        self.tail_call_sites.insert(address);
        self
    }

    #[must_use]
    pub fn with_return_value(mut self, value: impl Into<String>) -> Self {
        self.return_value = Some(value.into());
        self
    }

    #[must_use]
    pub const fn with_x86_callother_contracts(mut self) -> Self {
        self.x86_callother_contracts = true;
        self
    }

    #[must_use]
    pub const fn with_condition_code_folding(mut self) -> Self {
        self.fold_condition_codes = true;
        self
    }

    fn is_no_return_target(&self, target: Option<u64>) -> bool {
        target.is_some_and(|value: u64| self.no_return_targets.contains(&value))
    }

    fn is_tail_call_site(&self, address: u64) -> bool {
        self.tail_call_sites.contains(&address)
    }
}

pub fn lower_x86_64(bytes: &[u8], address: u64, name: &str) -> Result<NirFunction> {
    let block: DecodedBlock = decode_block_x86(bytes, address, 64);
    let artifact: NirArtifact =
        lower_owned_pcode_block_with_provenance(block, name, &PcodeLiftConfig::x86_64())
            .map_err(provenance_error_as_lift)?;
    artifact
        .into_module()
        .functions
        .pop()
        .ok_or(LiftError::Empty)
}

pub fn lower_x86_64_with_provenance(
    bytes: &[u8],
    address: u64,
    name: &str,
) -> ProvenanceResult<NirArtifact> {
    let block: DecodedBlock = decode_block_x86(bytes, address, 64);
    lower_owned_pcode_block_with_provenance(block, name, &PcodeLiftConfig::x86_64())
}

pub fn lower_aarch64(bytes: &[u8], address: u64, name: &str) -> Result<NirFunction> {
    let block: DecodedBlock = decode_block_for_language(Language::AArch64, bytes, address);
    lower_pcode_block(&block, name, &PcodeLiftConfig::aarch64())
}

pub fn lower_arm32(bytes: &[u8], address: u64, name: &str, mode: ArmMode) -> Result<ArchLift> {
    lower_language(Language::Arm32(mode), bytes, address, name)
}

pub fn lower_mips32(bytes: &[u8], address: u64, name: &str, endian: Endian) -> Result<ArchLift> {
    lower_language(Language::Mips32(endian), bytes, address, name)
}

fn lower_language(language: Language, bytes: &[u8], address: u64, name: &str) -> Result<ArchLift> {
    let arch: PcodeArch =
        PcodeArch::for_language(language).ok_or_else(|| LiftError::InvalidPcode {
            address,
            operation: "ARCH_TABLE".to_owned(),
            reason: "the lowering table has no row for this sleigh language".to_owned(),
        })?;
    lower_arch(arch, bytes, address, name)
}

pub fn lower_pcode_block(
    block: &DecodedBlock,
    name: &str,
    config: &PcodeLiftConfig,
) -> Result<NirFunction> {
    if block.instructions.is_empty() {
        return Err(LiftError::Empty);
    }
    if name.len() > MAX_IDENTIFIER_BYTES || !valid_identifier(name) {
        let address: u64 = block
            .instructions
            .first()
            .map_or(0, |instruction: &PcodeInstr| instruction.address);
        return Err(LiftError::InvalidPcode {
            address,
            operation: "BLOCK".to_owned(),
            reason: "function name is not a valid identifier".to_owned(),
        });
    }
    if config.return_value.as_ref().is_some_and(|value: &String| {
        value.len() > MAX_IDENTIFIER_BYTES || !valid_identifier(value)
    }) {
        let address: u64 = block
            .instructions
            .first()
            .map_or(0, |instruction: &PcodeInstr| instruction.address);
        return Err(LiftError::InvalidPcode {
            address,
            operation: "BLOCK".to_owned(),
            reason: "return value is not a valid identifier".to_owned(),
        });
    }
    if block.instructions.len() > config.max_instructions {
        return Err(LiftError::PcodeInstructionLimit {
            limit: config.max_instructions,
        });
    }
    let end: u64 = validate_instruction_order(block)?;
    let mut operation_count: usize = 0;
    for instruction in &block.instructions {
        operation_count = operation_count.checked_add(instruction.ops.len()).ok_or(
            LiftError::PcodeOperationLimit {
                limit: config.max_operations,
            },
        )?;
        if operation_count > config.max_operations {
            return Err(LiftError::PcodeOperationLimit {
                limit: config.max_operations,
            });
        }
    }
    let mut lowerer: VarnodeLowerer = VarnodeLowerer::new(
        config.lang,
        &config.registers,
        config.big_endian_register_space,
        &config.constant_zero_registers,
    )?;
    let mut instructions: Vec<NirInstr> = Vec::new();
    let branch_targets: BTreeSet<u64> = explicit_branch_targets(block);
    let has_indirect_branch: bool = block.instructions.iter().any(|instruction: &PcodeInstr| {
        instruction
            .ops
            .iter()
            .any(|operation: &PcodeOp| matches!(operation, PcodeOp::BranchIndirect { .. }))
    });
    let scheduled: Option<ScheduledBlock> = config
        .branch_delay_slots
        .then(|| schedule_delay_slots(&block.instructions));
    let scheduled_instructions: &[PcodeInstr] = scheduled
        .as_ref()
        .map_or(block.instructions.as_slice(), |value: &ScheduledBlock| {
            value.instructions.as_slice()
        });
    let mut previous_stops_fallthrough: bool = false;
    for (index, instruction) in scheduled_instructions.iter().enumerate() {
        let clear_registers: bool = has_indirect_branch
            || previous_stops_fallthrough
            || branch_targets.contains(&instruction.address);
        lowerer.begin_instruction(clear_registers);
        lower_instruction(
            instruction,
            scheduled
                .as_ref()
                .is_some_and(|value: &ScheduledBlock| value.consumed_slots.contains(&index)),
            config,
            &mut lowerer,
            &mut instructions,
        )?;
        previous_stops_fallthrough = instruction_stops_fallthrough(instruction, config);
    }
    let instructions: Vec<NirInstr> = if config.fold_condition_codes {
        flags::fold_condition_codes(instructions, &config.registers)
    } else {
        instructions
    };
    let instructions: Vec<NirInstr> =
        flags::eliminate_dead_values(instructions, &config.registers, &config.discarded_registers);
    let first: &PcodeInstr = block.instructions.first().ok_or(LiftError::Empty)?;
    Ok(NirFunction {
        name: name.to_owned(),
        address: first.address,
        end,
        is_export: false,
        instructions,
        source: SourceRef::new(config.lang, first.address),
    })
}

pub fn lower_pcode_block_with_provenance(
    block: &DecodedBlock,
    name: &str,
    config: &PcodeLiftConfig,
) -> ProvenanceResult<NirArtifact> {
    let lowered: LoweredProvenance = lower_provenance(block, name, config)?;
    let mut source_units: Vec<SourceUnitRef<'_>> = provenance_vec(block.instructions.len())?;
    for (source, mapping) in block.instructions.iter().zip(&lowered.mappings) {
        source_units.push(SourceUnitRef::new(
            0,
            mapping.instructions.clone(),
            SourceBytesRef::Original(&source.bytes),
            SourceOffset::MemoryImage(source.address),
        )?);
    }
    NirArtifact::from_borrowed(lowered.module(config.lang), &source_units)
        .map_err(ProvenanceLiftError::from)
}

#[derive(Debug)]
struct SourceMapping {
    instructions: std::ops::Range<u32>,
}

#[derive(Debug)]
struct LoweredProvenance {
    function: NirFunction,
    mappings: Vec<SourceMapping>,
    source_hash: [u8; 32],
}

impl LoweredProvenance {
    fn module(self, lang: SourceLang) -> NirModule {
        NirModule {
            source_hash: self.source_hash,
            lang,
            functions: vec![self.function],
            symbols: Vec::new(),
        }
    }
}

fn lower_owned_pcode_block_with_provenance(
    block: DecodedBlock,
    name: &str,
    config: &PcodeLiftConfig,
) -> ProvenanceResult<NirArtifact> {
    let lowered: LoweredProvenance = lower_provenance(&block, name, config)?;
    let mut source_units: Vec<SourceUnit> = provenance_vec(block.instructions.len())?;
    for (source, mapping) in block.instructions.into_iter().zip(&lowered.mappings) {
        source_units.push(SourceUnit::new(
            0,
            mapping.instructions.clone(),
            SourceBytes::Original(source.bytes),
            SourceOffset::MemoryImage(source.address),
        )?);
    }
    NirArtifact::new(lowered.module(config.lang), source_units).map_err(ProvenanceLiftError::from)
}

fn lower_provenance(
    block: &DecodedBlock,
    name: &str,
    config: &PcodeLiftConfig,
) -> ProvenanceResult<LoweredProvenance> {
    if config.branch_delay_slots {
        return Err(ProvenanceLiftError::DelaySlots);
    }
    if block.instructions.len() > config.max_instructions {
        return Err(LiftError::PcodeInstructionLimit {
            limit: config.max_instructions,
        }
        .into());
    }
    validate_source_layout(block)?;
    let function: NirFunction = lower_pcode_block(block, name, config)?;
    let source_hash: [u8; 32] = source_hash(block);
    let mappings: Vec<SourceMapping> = map_source_instructions(block, &function)?;
    Ok(LoweredProvenance {
        function,
        mappings,
        source_hash,
    })
}

fn validate_source_layout(block: &DecodedBlock) -> ProvenanceResult<()> {
    let mut expected_address: Option<u64> = None;
    let mut previous_address: Option<u64> = None;
    let mut source_bytes: usize = 0;
    for source in &block.instructions {
        let actual_length: usize = source.bytes.len();
        if actual_length != source.length || actual_length == 0 {
            return Err(ProvenanceLiftError::SourceByteLength {
                address: source.address,
                declared: source.length,
                actual: actual_length,
            });
        }
        if previous_address == Some(source.address) {
            return Err(ProvenanceLiftError::DuplicateSourceAddress {
                address: source.address,
            });
        }
        if let Some(expected) = expected_address
            && source.address != expected
        {
            return Err(ProvenanceLiftError::SourceAddressGap {
                expected,
                actual: source.address,
            });
        }
        let address_length: u64 = u64::try_from(actual_length).map_err(|_error| {
            ProvenanceLiftError::SourceByteLength {
                address: source.address,
                declared: source.length,
                actual: actual_length,
            }
        })?;
        expected_address = Some(source.address.checked_add(address_length).ok_or_else(|| {
            LiftError::InvalidPcode {
                address: source.address,
                operation: "BLOCK".to_owned(),
                reason: "source instruction range overflows its address space".to_owned(),
            }
        })?);
        source_bytes = source_bytes
            .checked_add(actual_length)
            .ok_or(ProvenanceLiftError::SourceByteTotalOverflow)?;
        previous_address = Some(source.address);
    }
    if source_bytes != block.consumed {
        return Err(ProvenanceLiftError::ConsumedBytes {
            declared: block.consumed,
            actual: source_bytes,
        });
    }
    Ok(())
}

fn source_hash(block: &DecodedBlock) -> [u8; 32] {
    let mut source_hasher: blake3::Hasher = blake3::Hasher::new();
    for instruction in &block.instructions {
        source_hasher.update(&instruction.bytes);
    }
    *source_hasher.finalize().as_bytes()
}

fn map_source_instructions(
    block: &DecodedBlock,
    function: &NirFunction,
) -> ProvenanceResult<Vec<SourceMapping>> {
    let mut mappings: Vec<SourceMapping> = provenance_vec(block.instructions.len())?;
    let mut instruction_cursor: usize = 0;
    for source in &block.instructions {
        let instruction_start: usize = instruction_cursor;
        while function
            .instructions
            .get(instruction_cursor)
            .is_some_and(|instruction: &NirInstr| instruction.address == source.address)
        {
            instruction_cursor = instruction_cursor.saturating_add(1);
        }
        let instructions: std::ops::Range<u32> = u32::try_from(instruction_start)
            .map_err(|_error| disrobe_nir::NirProvenanceError::IndexOverflow)?
            ..u32::try_from(instruction_cursor)
                .map_err(|_error| disrobe_nir::NirProvenanceError::IndexOverflow)?;
        mappings.push(SourceMapping { instructions });
    }
    if instruction_cursor != function.instructions.len() {
        return Err(disrobe_nir::NirProvenanceError::InstructionCoverage {
            function_index: 0,
            instruction_index: u32::try_from(instruction_cursor)
                .map_err(|_error| disrobe_nir::NirProvenanceError::IndexOverflow)?,
        }
        .into());
    }
    Ok(mappings)
}

fn provenance_vec<T>(capacity: usize) -> ProvenanceResult<Vec<T>> {
    let mut values: Vec<T> = Vec::new();
    values.try_reserve_exact(capacity).map_err(|_error| {
        disrobe_nir::NirProvenanceError::Allocation {
            requested: capacity,
        }
    })?;
    Ok(values)
}

fn provenance_error_as_lift(error: ProvenanceLiftError) -> LiftError {
    match error {
        ProvenanceLiftError::Lift(error) => error,
        other => LiftError::InvalidPcode {
            address: 0,
            operation: "PROVENANCE".to_owned(),
            reason: other.to_string(),
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScheduledBlock {
    instructions: Vec<PcodeInstr>,
    consumed_slots: BTreeSet<usize>,
}

fn schedule_delay_slots(instructions: &[PcodeInstr]) -> ScheduledBlock {
    let mut scheduled: Vec<PcodeInstr> = instructions.to_vec();
    let mut consumed_slots: BTreeSet<usize> = BTreeSet::new();
    let pairs: Vec<(usize, usize)> = scheduled
        .iter()
        .enumerate()
        .filter_map(|(index, transfer): (usize, &PcodeInstr)| {
            let slot: &PcodeInstr = scheduled.get(index.saturating_add(1))?;
            Some((index, delay_slot_transfer(transfer, slot)?))
        })
        .collect();
    for (index, transfer_op) in pairs {
        let slot_index: usize = index.saturating_add(1);
        if consumed_slots.contains(&index) {
            continue;
        }
        let Some(slot_ops): Option<Vec<PcodeOp>> = scheduled
            .get_mut(slot_index)
            .map(|slot: &mut PcodeInstr| std::mem::take(&mut slot.ops))
        else {
            continue;
        };
        let Some(transfer): Option<&mut PcodeInstr> = scheduled.get_mut(index) else {
            continue;
        };
        let splice_at: usize = transfer_op.min(transfer.ops.len());
        let tail: Vec<PcodeOp> = transfer.ops.split_off(splice_at);
        transfer.ops.extend(slot_ops);
        transfer.ops.extend(tail);
        consumed_slots.insert(slot_index);
    }
    ScheduledBlock {
        instructions: scheduled,
        consumed_slots,
    }
}

fn delay_slot_transfer(transfer: &PcodeInstr, slot: &PcodeInstr) -> Option<usize> {
    if transfer.status != DecodeStatus::Supported || transfer.length == 0 {
        return None;
    }
    let length: u64 = u64::try_from(transfer.length).ok()?;
    if transfer.address.checked_add(length)? != slot.address {
        return None;
    }
    if slot.ops.is_empty() || slot.ops.iter().any(is_machine_transfer) {
        return None;
    }
    transfer.ops.iter().rposition(is_machine_transfer)
}

const fn is_machine_transfer(operation: &PcodeOp) -> bool {
    matches!(
        operation,
        PcodeOp::Branch { .. }
            | PcodeOp::BranchIndirect { .. }
            | PcodeOp::CBranch { .. }
            | PcodeOp::Call { .. }
            | PcodeOp::CallIndirect { .. }
            | PcodeOp::Return { .. }
    )
}

fn explicit_branch_targets(block: &DecodedBlock) -> BTreeSet<u64> {
    block
        .instructions
        .iter()
        .flat_map(|instruction: &PcodeInstr| instruction.ops.iter())
        .filter_map(|operation: &PcodeOp| match operation {
            PcodeOp::Branch { target }
            | PcodeOp::BranchIndirect { target }
            | PcodeOp::CBranch { target, .. } => explicit_target(*target),
            _ => None,
        })
        .collect()
}

fn validate_instruction_order(block: &DecodedBlock) -> Result<u64> {
    let mut previous_address: Option<u64> = None;
    let mut previous_end: Option<u64> = None;
    let mut function_end: u64 = 0;
    let final_index: usize = block.instructions.len().saturating_sub(1);
    for (index, instruction) in block.instructions.iter().enumerate() {
        if previous_address.is_some_and(|address: u64| instruction.address <= address) {
            return Err(LiftError::InvalidPcode {
                address: instruction.address,
                operation: "BLOCK".to_owned(),
                reason: "machine instruction addresses are not strictly increasing".to_owned(),
            });
        }
        if instruction.length == 0
            && (instruction.status == DecodeStatus::Supported || index != final_index)
        {
            return Err(LiftError::InvalidPcode {
                address: instruction.address,
                operation: "BLOCK".to_owned(),
                reason: "zero-length machine instruction is invalid here".to_owned(),
            });
        }
        let length: u64 =
            u64::try_from(instruction.length).map_err(|_error| LiftError::InvalidPcode {
                address: instruction.address,
                operation: "BLOCK".to_owned(),
                reason: "machine instruction length exceeds address range".to_owned(),
            })?;
        let instruction_end: u64 =
            instruction
                .address
                .checked_add(length)
                .ok_or_else(|| LiftError::InvalidPcode {
                    address: instruction.address,
                    operation: "BLOCK".to_owned(),
                    reason: "machine instruction range overflows its address space".to_owned(),
                })?;
        if previous_end.is_some_and(|end: u64| end > instruction.address) {
            return Err(LiftError::InvalidPcode {
                address: instruction.address,
                operation: "BLOCK".to_owned(),
                reason: "machine instruction ranges overlap".to_owned(),
            });
        }
        previous_address = Some(instruction.address);
        previous_end = Some(instruction_end);
        function_end = function_end.max(instruction_end);
    }
    Ok(function_end)
}

fn instruction_stops_fallthrough(instruction: &PcodeInstr, config: &PcodeLiftConfig) -> bool {
    instruction
        .ops
        .iter()
        .any(|operation: &PcodeOp| match operation {
            PcodeOp::Branch { .. } | PcodeOp::BranchIndirect { .. } | PcodeOp::Return { .. } => {
                true
            }
            PcodeOp::Call { target } | PcodeOp::CallIndirect { target } => {
                config.is_no_return_target(explicit_target(*target))
            }
            _ => false,
        })
}

const fn explicit_target(target: Varnode) -> Option<u64> {
    match target.space {
        Space::Constant | Space::Ram => Some(varnode::mask_value(target.offset, target.size_bytes)),
        Space::Register | Space::Unique => None,
    }
}

fn lower_instruction(
    instruction: &PcodeInstr,
    slot_was_consumed: bool,
    config: &PcodeLiftConfig,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    if instruction.ops.is_empty() {
        if !slot_was_consumed && instruction.status != DecodeStatus::Supported {
            return Err(LiftError::InvalidPcode {
                address: instruction.address,
                operation: "BLOCK".to_owned(),
                reason: "non-supported machine instruction has no P-code semantics".to_owned(),
            });
        }
        instructions.push(lowerer.instruction(
            instruction.address,
            NirOp::Nop,
            &instruction.mnemonic,
            Vec::new(),
        ));
        return Ok(());
    }
    let mut terminated: bool = false;
    for operation in &instruction.ops {
        if terminated {
            return Err(LiftError::InvalidPcode {
                address: instruction.address,
                operation: operation.name().to_owned(),
                reason: "operation follows a machine control-flow terminator".to_owned(),
            });
        }
        let emitted_start: usize = instructions.len();
        ops::lower(operation, instruction, config, lowerer, instructions)?;
        terminated = instructions
            .get(emitted_start..)
            .is_some_and(|emitted: &[NirInstr]| emitted.iter().any(nir_stops_machine_instruction));
    }
    Ok(())
}

const fn nir_stops_machine_instruction(instruction: &NirInstr) -> bool {
    matches!(
        instruction.class(),
        NirClass::ConditionalJump | NirClass::UnconditionalJump | NirClass::Return
    ) || instruction.op.is_terminal_call()
}

fn valid_identifier(value: &str) -> bool {
    let mut characters: std::str::Chars<'_> = value.chars();
    let Some(first): Option<char> = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character: char| character == '_' || character.is_ascii_alphanumeric())
}
