use std::collections::BTreeSet;
use std::sync::OnceLock;

use disrobe_lift_x86::decode_block_x86;
use disrobe_nir::{NirClass, NirFunction, NirInstr, NirOp, SourceLang, SourceRef};
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use disrobe_sleigh::syntax::Endian;
use disrobe_sleigh::vendor::{
    preprocessed_arm32_source, preprocessed_mips32be_source, preprocessed_mips32le_source,
};

use crate::error::{LiftError, Result};

mod arch;
mod flags;
mod ops;
mod registers;
mod varnode;

pub use arch::{PcodeArch, lower_for_arch};
use registers::{SpecRegisters, canonical_registers};
pub use varnode::RegisterCell;
use varnode::VarnodeLowerer;

type CachedRegisters = core::result::Result<SpecRegisters, String>;

static ARM32_REGISTERS: OnceLock<CachedRegisters> = OnceLock::new();
static MIPS32BE_REGISTERS: OnceLock<CachedRegisters> = OnceLock::new();
static MIPS32LE_REGISTERS: OnceLock<CachedRegisters> = OnceLock::new();

const ARM32_DISCARDED: [&str; 9] = [
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

const MIPS32_DISCARDED: [&str; 1] = ["zero"];

fn cached_registers(
    cache: &'static OnceLock<CachedRegisters>,
    source: fn() -> core::result::Result<String, disrobe_sleigh::SleighError>,
) -> Result<SpecRegisters> {
    let cached: &CachedRegisters = cache.get_or_init(|| {
        let text: String = source().map_err(|error: disrobe_sleigh::SleighError| {
            format!("compiled spec did not preprocess: {error}")
        })?;
        canonical_registers(&text).map_err(|error: LiftError| error.to_string())
    });
    match cached {
        Ok(value) => Ok(value.clone()),
        Err(reason) => Err(LiftError::InvalidPcode {
            address: 0,
            operation: "REGISTER_MAP".to_owned(),
            reason: reason.clone(),
        }),
    }
}

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
        let spec: SpecRegisters = cached_registers(&ARM32_REGISTERS, preprocessed_arm32_source)?;
        let mut config: Self = Self::new(SourceLang::NativeArm, spec.cells)
            .with_return_value("r0")
            .with_condition_code_folding()
            .with_big_endian_register_space(spec.big_endian);
        config.require_registers(&["r0", "sp", "lr", "pc", "NG", "ZR", "CY", "OV"])?;
        for name in ARM32_DISCARDED {
            config.discarded_registers.insert(name.to_owned());
        }
        Ok(config)
    }

    pub fn mips32(endian: Endian) -> Result<Self> {
        let spec: SpecRegisters = match endian {
            Endian::Big => cached_registers(&MIPS32BE_REGISTERS, preprocessed_mips32be_source)?,
            Endian::Little => cached_registers(&MIPS32LE_REGISTERS, preprocessed_mips32le_source)?,
        };
        let mut config: Self = Self::new(SourceLang::Unknown, spec.cells)
            .with_return_value("v0")
            .with_big_endian_register_space(spec.big_endian)
            .with_branch_delay_slots();
        config.require_registers(&["zero", "v0", "a0", "sp", "ra", "pc", "hi", "lo"])?;
        for name in MIPS32_DISCARDED {
            config.discarded_registers.insert(name.to_owned());
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

    fn require_registers(&self, names: &[&str]) -> Result<()> {
        for name in names {
            if !self
                .registers
                .iter()
                .any(|cell: &RegisterCell| cell.name.eq_ignore_ascii_case(name))
            {
                return Err(LiftError::InvalidPcode {
                    address: 0,
                    operation: "REGISTER_MAP".to_owned(),
                    reason: format!("compiled spec defines no whole register cell named {name}"),
                });
            }
        }
        Ok(())
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
    lower_pcode_block(&block, name, &PcodeLiftConfig::x86_64())
}

pub fn lower_aarch64(bytes: &[u8], address: u64, name: &str) -> Result<NirFunction> {
    let block: DecodedBlock = decode_block_for_language(Language::AArch64, bytes, address);
    lower_pcode_block(&block, name, &PcodeLiftConfig::aarch64())
}

pub fn lower_arm32(bytes: &[u8], address: u64, name: &str, mode: ArmMode) -> Result<NirFunction> {
    let arch: PcodeArch = match mode {
        ArmMode::A32 => PcodeArch::Arm32A32,
        ArmMode::Thumb => PcodeArch::Arm32Thumb,
    };
    lower_for_arch(arch, bytes, address, name)
}

pub fn lower_mips32(bytes: &[u8], address: u64, name: &str, endian: Endian) -> Result<NirFunction> {
    let arch: PcodeArch = match endian {
        Endian::Big => PcodeArch::Mips32Be,
        Endian::Little => PcodeArch::Mips32Le,
    };
    lower_for_arch(arch, bytes, address, name)
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
    let scheduled: Vec<PcodeInstr> = if config.branch_delay_slots {
        schedule_delay_slots(&block.instructions)
    } else {
        block.instructions.clone()
    };
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
    )?;
    let mut instructions: Vec<NirInstr> = Vec::new();
    let branch_targets: BTreeSet<u64> = explicit_branch_targets(block);
    let has_indirect_branch: bool = scheduled.iter().any(|instruction: &PcodeInstr| {
        instruction
            .ops
            .iter()
            .any(|operation: &PcodeOp| matches!(operation, PcodeOp::BranchIndirect { .. }))
    });
    let mut previous_stops_fallthrough: bool = false;
    for instruction in &scheduled {
        let clear_registers: bool = has_indirect_branch
            || previous_stops_fallthrough
            || branch_targets.contains(&instruction.address);
        lowerer.begin_instruction(clear_registers);
        lower_instruction(instruction, config, &mut lowerer, &mut instructions)?;
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

fn schedule_delay_slots(instructions: &[PcodeInstr]) -> Vec<PcodeInstr> {
    let mut scheduled: Vec<PcodeInstr> = instructions.to_vec();
    let pairs: Vec<usize> = scheduled
        .iter()
        .enumerate()
        .filter(|(index, transfer): &(usize, &PcodeInstr)| {
            transfer.ops.last().is_some_and(is_delayed_transfer)
                && u64::try_from(transfer.length).is_ok_and(|length: u64| {
                    scheduled
                        .get(index.saturating_add(1))
                        .is_some_and(|slot: &PcodeInstr| {
                            slot.address == transfer.address.wrapping_add(length)
                                && !slot.ops.is_empty()
                                && !slot.ops.iter().any(is_delayed_transfer)
                        })
                })
        })
        .map(|(index, _transfer): (usize, &PcodeInstr)| index)
        .collect();
    for index in pairs {
        let Some(slot_ops): Option<Vec<PcodeOp>> = scheduled
            .get_mut(index.saturating_add(1))
            .map(|slot: &mut PcodeInstr| std::mem::take(&mut slot.ops))
        else {
            continue;
        };
        let Some(transfer): Option<&mut PcodeInstr> = scheduled.get_mut(index) else {
            continue;
        };
        let mut merged: Vec<PcodeOp> = slot_ops;
        merged.append(&mut transfer.ops);
        transfer.ops = merged;
    }
    scheduled
}

const fn is_delayed_transfer(operation: &PcodeOp) -> bool {
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
    config: &PcodeLiftConfig,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    if instruction.ops.is_empty() {
        if instruction.status != DecodeStatus::Supported {
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
    for (index, operation) in instruction.ops.iter().enumerate() {
        let operation: &PcodeOp = operation;
        let emitted_start: usize = instructions.len();
        ops::lower(operation, instruction, config, lowerer, instructions)?;
        let has_following_operation: bool = index.saturating_add(1) < instruction.ops.len();
        let emitted_terminal: bool = instructions
            .get(emitted_start..)
            .is_some_and(|emitted: &[NirInstr]| emitted.iter().any(nir_stops_machine_instruction));
        if has_following_operation && emitted_terminal {
            let next_operation: String = instruction.ops.get(index.saturating_add(1)).map_or_else(
                || "PCODE".to_owned(),
                |next: &PcodeOp| next.name().to_owned(),
            );
            return Err(LiftError::InvalidPcode {
                address: instruction.address,
                operation: next_operation,
                reason: "operation follows a machine control-flow terminator".to_owned(),
            });
        }
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
