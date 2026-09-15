mod ebpf;
mod mips;
mod ppc;
mod riscv;
mod sparc;

use capstone::arch::ArchDetail;
use capstone::arch::DetailsArchInsn as _;
use capstone::arch::arm::{ArmCC, ArmOperandType};
use capstone::{Capstone, InsnDetail, InsnGroupId, InsnGroupType, Instructions};
use disrobe_ir::payload::InsnFlow;
use iced_x86::{Code, FlowControl, Instruction, OpKind};

use crate::arch::{Arch as DisasmArch, capstone_for, decode_one_x86};
use crate::desync::is_noreturn_import_name;
use crate::error::{Error, Result};
use crate::pseudo_c::aarch64::{
    Aarch64DirectTransfer, aarch64_direct_transfer, aarch64_is_exception_entry,
    aarch64_is_indirect_branch, aarch64_is_indirect_call, aarch64_is_return, aarch64_is_trap,
    aarch64_word,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowEvidence {
    Decoded,
    Undecodable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectTrap {
    InvalidOpcode,
    Breakpoint,
    FastFail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoreturnParameter {
    SignedInt,
    UnsignedInt,
    UnsignedPointerSized,
    ConstCharPointer,
    VoidPointer,
}

impl NoreturnParameter {
    pub(crate) const fn c_type(self) -> &'static str {
        match self {
            Self::SignedInt => "int",
            Self::UnsignedInt => "unsigned int",
            Self::UnsignedPointerSized => "uintptr_t",
            Self::ConstCharPointer => "const char *",
            Self::VoidPointer => "void *",
        }
    }

    pub(crate) const fn rust_type(self) -> &'static str {
        match self {
            Self::SignedInt => "i32",
            Self::UnsignedInt => "u32",
            Self::UnsignedPointerSized => "usize",
            Self::ConstCharPointer => "*const u8",
            Self::VoidPointer => "*mut u8",
        }
    }

    pub(crate) const fn is_pointer(self) -> bool {
        matches!(self, Self::ConstCharPointer | Self::VoidPointer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoreturnLibraryFunction {
    pub(crate) name: &'static str,
    pub(crate) parameters: &'static [NoreturnParameter],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoreturnImportEvidence {
    Relocation(&'static NoreturnLibraryFunction),
}

impl NoreturnImportEvidence {
    pub(crate) const fn function(self) -> &'static NoreturnLibraryFunction {
        match self {
            Self::Relocation(function) => function,
        }
    }
}

const NORETURN_LIBRARY_PROTOTYPES: &[NoreturnLibraryFunction] = &[
    NoreturnLibraryFunction {
        name: "abort",
        parameters: &[],
    },
    NoreturnLibraryFunction {
        name: "exit",
        parameters: &[NoreturnParameter::SignedInt],
    },
    NoreturnLibraryFunction {
        name: "_exit",
        parameters: &[NoreturnParameter::SignedInt],
    },
    NoreturnLibraryFunction {
        name: "_Exit",
        parameters: &[NoreturnParameter::SignedInt],
    },
    NoreturnLibraryFunction {
        name: "quick_exit",
        parameters: &[NoreturnParameter::SignedInt],
    },
    NoreturnLibraryFunction {
        name: "pthread_exit",
        parameters: &[NoreturnParameter::VoidPointer],
    },
    NoreturnLibraryFunction {
        name: "__stack_chk_fail",
        parameters: &[],
    },
    NoreturnLibraryFunction {
        name: "___report_gsfailure",
        parameters: &[],
    },
    NoreturnLibraryFunction {
        name: "__report_gsfailure",
        parameters: &[NoreturnParameter::UnsignedPointerSized],
    },
    NoreturnLibraryFunction {
        name: "__assert_fail",
        parameters: &[
            NoreturnParameter::ConstCharPointer,
            NoreturnParameter::ConstCharPointer,
            NoreturnParameter::UnsignedInt,
            NoreturnParameter::ConstCharPointer,
        ],
    },
    NoreturnLibraryFunction {
        name: "_Unwind_Resume",
        parameters: &[NoreturnParameter::VoidPointer],
    },
    NoreturnLibraryFunction {
        name: "__cxa_throw",
        parameters: &[
            NoreturnParameter::VoidPointer,
            NoreturnParameter::VoidPointer,
            NoreturnParameter::VoidPointer,
        ],
    },
    NoreturnLibraryFunction {
        name: "__cxa_rethrow",
        parameters: &[],
    },
    NoreturnLibraryFunction {
        name: "ExitProcess",
        parameters: &[NoreturnParameter::UnsignedInt],
    },
    NoreturnLibraryFunction {
        name: "ExitThread",
        parameters: &[NoreturnParameter::UnsignedInt],
    },
    NoreturnLibraryFunction {
        name: "RtlExitUserProcess",
        parameters: &[NoreturnParameter::UnsignedInt],
    },
    NoreturnLibraryFunction {
        name: "RtlExitUserThread",
        parameters: &[NoreturnParameter::UnsignedInt],
    },
    NoreturnLibraryFunction {
        name: "_invalid_parameter_noinfo_noreturn",
        parameters: &[],
    },
];

pub(crate) fn noreturn_import_evidence(symbol: &str) -> Option<NoreturnImportEvidence> {
    if !is_noreturn_import_name(symbol) {
        return None;
    }
    let exact: Option<&'static NoreturnLibraryFunction> = NORETURN_LIBRARY_PROTOTYPES
        .iter()
        .find(|entry: &&NoreturnLibraryFunction| entry.name == symbol);
    if exact.is_some() {
        return exact.map(NoreturnImportEvidence::Relocation);
    }
    let undecorated: &str = symbol
        .strip_prefix("__imp_")
        .or_else(|| symbol.strip_prefix('_'))?;
    NORETURN_LIBRARY_PROTOTYPES
        .iter()
        .find(|entry: &&NoreturnLibraryFunction| entry.name == undecorated)
        .map(NoreturnImportEvidence::Relocation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlFlow {
    pub(crate) flow: InsnFlow,
    pub(crate) branch_target: Option<u64>,
    pub(crate) evidence: FlowEvidence,
}

impl ControlFlow {
    pub(crate) const fn decoded(flow: InsnFlow, branch_target: Option<u64>) -> Self {
        Self {
            flow,
            branch_target,
            evidence: FlowEvidence::Decoded,
        }
    }

    pub(crate) const fn undecodable() -> Self {
        Self {
            flow: InsnFlow::Sequential,
            branch_target: None,
            evidence: FlowEvidence::Undecodable,
        }
    }

    pub(crate) const fn is_decoded(self) -> bool {
        matches!(self.evidence, FlowEvidence::Decoded)
    }
}

#[derive(Debug)]
pub(crate) enum FlowModel {
    X86 { bits: u32 },
    Aarch64,
    Arm { engine: Capstone },
    Mips { big_endian: bool },
    PowerPc,
    RiscV { rv64: bool },
    Sparc,
    Ebpf,
}

impl FlowModel {
    pub(crate) fn for_arch(arch: DisasmArch) -> Result<Self> {
        match arch {
            DisasmArch::X86 => Ok(Self::X86 { bits: 32 }),
            DisasmArch::X86_64 => Ok(Self::X86 { bits: 64 }),
            DisasmArch::Aarch64 => Ok(Self::Aarch64),
            DisasmArch::Arm32 | DisasmArch::Thumb => capstone_for(arch, true)?
                .ok_or_else(|| missing_model(arch))
                .map(|engine: Capstone| Self::Arm { engine }),
            DisasmArch::MipsBe32 | DisasmArch::Mips64 => Ok(Self::Mips { big_endian: true }),
            DisasmArch::MipsLe32 => Ok(Self::Mips { big_endian: false }),
            DisasmArch::PowerPc32 | DisasmArch::PowerPc64 => Ok(Self::PowerPc),
            DisasmArch::RiscV32 => Ok(Self::RiscV { rv64: false }),
            DisasmArch::RiscV64 => Ok(Self::RiscV { rv64: true }),
            DisasmArch::Sparc | DisasmArch::Sparc64 => Ok(Self::Sparc),
            DisasmArch::Ebpf => Ok(Self::Ebpf),
            DisasmArch::Avr => Err(missing_model(arch)),
        }
    }

    pub(crate) const fn x86_bits(&self) -> Option<u32> {
        match self {
            Self::X86 { bits } => Some(*bits),
            _ => None,
        }
    }

    pub(crate) fn control_flow(&self, raw: &[u8], address: u64, mnemonic: &str) -> ControlFlow {
        match self {
            Self::X86 { bits } => decode_one_x86(*bits, address, raw).map_or_else(
                ControlFlow::undecodable,
                |insn: Instruction| {
                    let (flow, branch_target): (InsnFlow, Option<u64>) = x86_flow(&insn);
                    ControlFlow::decoded(flow, branch_target)
                },
            ),
            Self::Aarch64 => aarch64_control_flow(raw, address, mnemonic),
            Self::Arm { engine } => arm_control_flow(engine, raw, address),
            Self::Mips { big_endian } => fixed_word(raw, *big_endian)
                .map_or_else(ControlFlow::undecodable, |word: u32| {
                    mips::control_flow(address, word)
                }),
            Self::PowerPc => fixed_word(raw, true)
                .map_or_else(ControlFlow::undecodable, |word: u32| {
                    ppc::control_flow(address, word)
                }),
            Self::RiscV { rv64 } => riscv::control_flow(address, raw, *rv64),
            Self::Sparc => fixed_word(raw, true)
                .map_or_else(ControlFlow::undecodable, |word: u32| {
                    sparc::control_flow(address, word)
                }),
            Self::Ebpf => ebpf::control_flow(address, raw),
        }
    }

    pub(crate) fn decodes_whole_slice(&self, raw: &[u8], address: u64) -> bool {
        if raw.is_empty() {
            return false;
        }
        match self {
            Self::X86 { bits } => decode_one_x86(*bits, address, raw)
                .is_some_and(|insn: Instruction| insn.len() == raw.len()),
            Self::Aarch64 => aarch64_word(raw).is_some(),
            Self::Arm { engine } => {
                engine
                    .disasm_count(raw, address, 1)
                    .is_ok_and(|decoded: Instructions<'_>| {
                        decoded
                            .iter()
                            .next()
                            .is_some_and(|insn: &capstone::Insn<'_>| {
                                insn.bytes().len() == raw.len()
                            })
                    })
            }
            Self::Mips { .. } | Self::PowerPc | Self::Sparc => raw.len() == 4,
            Self::RiscV { .. } => matches!(raw.len(), 2 | 4),
            Self::Ebpf => matches!(raw.len(), 8 | 16),
        }
    }
}

pub(crate) fn x86_direct_trap(raw: &[u8], address: u64) -> Option<DirectTrap> {
    let instruction: Instruction = decode_one_x86(64, address, raw)?;
    if instruction.len() != raw.len() {
        return None;
    }
    match instruction.code() {
        Code::Ud0
        | Code::Ud0_r16_rm16
        | Code::Ud0_r32_rm32
        | Code::Ud0_r64_rm64
        | Code::Ud1_r16_rm16
        | Code::Ud1_r32_rm32
        | Code::Ud1_r64_rm64
        | Code::Ud2 => Some(DirectTrap::InvalidOpcode),
        Code::Int3 => Some(DirectTrap::Breakpoint),
        Code::Int_imm8 if instruction.immediate8() == 0x29 => Some(DirectTrap::FastFail),
        _ => None,
    }
}

fn missing_model(arch: DisasmArch) -> Error {
    Error::UnsupportedArch(format!(
        "{} has no control-flow model, so call and branch facts cannot be derived",
        arch.label()
    ))
}

fn fixed_word(raw: &[u8], big_endian: bool) -> Option<u32> {
    let bytes: &[u8; 4] = raw.first_chunk::<4>()?;
    Some(if big_endian {
        u32::from_be_bytes(*bytes)
    } else {
        u32::from_le_bytes(*bytes)
    })
}

pub(crate) fn x86_flow(insn: &Instruction) -> (InsnFlow, Option<u64>) {
    let direct: bool = matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    match insn.flow_control() {
        FlowControl::Call if direct => (InsnFlow::Call, Some(insn.near_branch_target())),
        FlowControl::Call | FlowControl::IndirectCall => (InsnFlow::IndirectCall, None),
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

fn aarch64_control_flow(raw: &[u8], address: u64, mnemonic: &str) -> ControlFlow {
    let Some(word): Option<u32> = aarch64_word(raw) else {
        return ControlFlow::undecodable();
    };
    if let Some(transfer) = aarch64_direct_transfer(address, word) {
        return match transfer {
            Aarch64DirectTransfer::BranchLink { target } => {
                ControlFlow::decoded(InsnFlow::Call, Some(target))
            }
            Aarch64DirectTransfer::UnconditionalBranch { target } => {
                ControlFlow::decoded(InsnFlow::UnconditionalBranch, Some(target))
            }
            Aarch64DirectTransfer::ConditionalBranch { target, .. }
            | Aarch64DirectTransfer::CompareBranch { target }
            | Aarch64DirectTransfer::TestBranch { target } => {
                ControlFlow::decoded(InsnFlow::ConditionalBranch, Some(target))
            }
        };
    }
    let flow: InsnFlow = if aarch64_is_indirect_call(mnemonic) {
        InsnFlow::IndirectCall
    } else if aarch64_is_return(mnemonic) {
        InsnFlow::Return
    } else if aarch64_is_indirect_branch(mnemonic) {
        InsnFlow::IndirectBranch
    } else if aarch64_is_trap(mnemonic) || aarch64_is_exception_entry(mnemonic) {
        InsnFlow::Interrupt
    } else {
        InsnFlow::Sequential
    };
    ControlFlow::decoded(flow, None)
}

fn has_group(groups: &[InsnGroupId], group: InsnGroupType::Type) -> bool {
    u8::try_from(group).is_ok_and(|id: u8| groups.contains(&InsnGroupId(id)))
}

fn arm_control_flow(engine: &Capstone, raw: &[u8], address: u64) -> ControlFlow {
    let Ok(decoded): core::result::Result<Instructions<'_>, capstone::Error> =
        engine.disasm_count(raw, address, 1)
    else {
        return ControlFlow::undecodable();
    };
    let Some(insn): Option<&capstone::Insn<'_>> = decoded.iter().next() else {
        return ControlFlow::undecodable();
    };
    let Ok(detail): core::result::Result<InsnDetail<'_>, capstone::Error> =
        engine.insn_detail(insn)
    else {
        return ControlFlow::undecodable();
    };
    let groups: &[InsnGroupId] = detail.groups();
    if has_group(groups, InsnGroupType::CS_GRP_INT) {
        return ControlFlow::decoded(InsnFlow::Interrupt, None);
    }
    let arch_detail: ArchDetail<'_> = detail.arch_detail();
    let Some(arm): Option<&capstone::arch::arm::ArmInsnDetail<'_>> = arch_detail.arm() else {
        return ControlFlow::undecodable();
    };
    let target: Option<u64> = arm.operands().find_map(|operand| match operand.op_type {
        ArmOperandType::Imm(value) => Some(u64::from(value.cast_unsigned())),
        _ => None,
    });
    let conditional: bool = !matches!(arm.cc(), ArmCC::ARM_CC_AL | ArmCC::ARM_CC_INVALID);
    if has_group(groups, InsnGroupType::CS_GRP_CALL) {
        return target.map_or_else(
            || ControlFlow::decoded(InsnFlow::IndirectCall, None),
            |destination: u64| ControlFlow::decoded(InsnFlow::Call, Some(destination)),
        );
    }
    if has_group(groups, InsnGroupType::CS_GRP_RET) {
        return ControlFlow::decoded(InsnFlow::Return, None);
    }
    if !has_group(groups, InsnGroupType::CS_GRP_JUMP) {
        return ControlFlow::decoded(InsnFlow::Sequential, None);
    }
    let Some(destination): Option<u64> = target else {
        return ControlFlow::decoded(InsnFlow::IndirectBranch, None);
    };
    if conditional {
        ControlFlow::decoded(InsnFlow::ConditionalBranch, Some(destination))
    } else {
        ControlFlow::decoded(InsnFlow::UnconditionalBranch, Some(destination))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::arch::{DisasmInsn, disassemble};

    struct Case {
        arch: DisasmArch,
        address: u64,
        raw: &'static [u8],
        flow: InsnFlow,
        target: Option<u64>,
        engine_renders_target: bool,
    }

    const fn case(
        arch: DisasmArch,
        address: u64,
        raw: &'static [u8],
        flow: InsnFlow,
        target: Option<u64>,
        engine_renders_target: bool,
    ) -> Case {
        Case {
            arch,
            address,
            raw,
            flow,
            target,
            engine_renders_target,
        }
    }

    fn encodings() -> Vec<Case> {
        vec![
            case(
                DisasmArch::Arm32,
                0x1000,
                &[0x06, 0x00, 0x00, 0xEB],
                InsnFlow::Call,
                Some(0x1020),
                true,
            ),
            case(
                DisasmArch::Arm32,
                0x1000,
                &[0x1E, 0xFF, 0x2F, 0xE1],
                InsnFlow::IndirectBranch,
                None,
                false,
            ),
            case(
                DisasmArch::Arm32,
                0x1000,
                &[0x06, 0x00, 0x00, 0xEA],
                InsnFlow::UnconditionalBranch,
                Some(0x1020),
                true,
            ),
            case(
                DisasmArch::Arm32,
                0x1000,
                &[0x06, 0x00, 0x00, 0x0A],
                InsnFlow::ConditionalBranch,
                Some(0x1020),
                true,
            ),
            case(
                DisasmArch::Arm32,
                0x1000,
                &[0x33, 0xFF, 0x2F, 0xE1],
                InsnFlow::IndirectCall,
                None,
                false,
            ),
            case(
                DisasmArch::Thumb,
                0x1000,
                &[0x00, 0xF0, 0x0E, 0xF8],
                InsnFlow::Call,
                Some(0x1020),
                false,
            ),
            case(
                DisasmArch::Thumb,
                0x1000,
                &[0x70, 0x47],
                InsnFlow::IndirectBranch,
                None,
                false,
            ),
            case(
                DisasmArch::Thumb,
                0x1000,
                &[0x00, 0xD0],
                InsnFlow::ConditionalBranch,
                Some(0x1004),
                false,
            ),
            case(
                DisasmArch::MipsBe32,
                0x0040_0000,
                &[0x0C, 0x10, 0x00, 0x08],
                InsnFlow::Call,
                Some(0x0040_0020),
                true,
            ),
            case(
                DisasmArch::MipsBe32,
                0x0040_0000,
                &[0x03, 0xE0, 0x00, 0x08],
                InsnFlow::Return,
                None,
                false,
            ),
            case(
                DisasmArch::MipsBe32,
                0x0040_0000,
                &[0x10, 0x85, 0x00, 0x02],
                InsnFlow::ConditionalBranch,
                Some(0x0040_000C),
                true,
            ),
            case(
                DisasmArch::MipsBe32,
                0x0040_0000,
                &[0x08, 0x10, 0x00, 0x10],
                InsnFlow::UnconditionalBranch,
                Some(0x0040_0040),
                true,
            ),
            case(
                DisasmArch::MipsBe32,
                0x0040_0000,
                &[0x00, 0x60, 0xF8, 0x09],
                InsnFlow::IndirectCall,
                None,
                false,
            ),
            case(
                DisasmArch::MipsLe32,
                0x0040_0000,
                &[0x08, 0x00, 0x10, 0x0C],
                InsnFlow::Call,
                Some(0x0040_0020),
                true,
            ),
            case(
                DisasmArch::PowerPc32,
                0x10000,
                &[0x48, 0x00, 0x00, 0x21],
                InsnFlow::Call,
                Some(0x10020),
                true,
            ),
            case(
                DisasmArch::PowerPc32,
                0x10000,
                &[0x4E, 0x80, 0x00, 0x20],
                InsnFlow::Return,
                None,
                false,
            ),
            case(
                DisasmArch::PowerPc32,
                0x10000,
                &[0x48, 0x00, 0x00, 0x20],
                InsnFlow::UnconditionalBranch,
                Some(0x10020),
                true,
            ),
            case(
                DisasmArch::PowerPc32,
                0x10000,
                &[0x41, 0x82, 0x00, 0x10],
                InsnFlow::ConditionalBranch,
                Some(0x10010),
                true,
            ),
            case(
                DisasmArch::PowerPc32,
                0x10000,
                &[0x4E, 0x80, 0x04, 0x20],
                InsnFlow::IndirectBranch,
                None,
                false,
            ),
            case(
                DisasmArch::RiscV64,
                0x1000,
                &[0xEF, 0x00, 0x00, 0x02],
                InsnFlow::Call,
                Some(0x1020),
                false,
            ),
            case(
                DisasmArch::RiscV64,
                0x1000,
                &[0xE7, 0x00, 0x05, 0x00],
                InsnFlow::IndirectCall,
                None,
                false,
            ),
            case(
                DisasmArch::RiscV64,
                0x1000,
                &[0x63, 0x04, 0xB5, 0x00],
                InsnFlow::ConditionalBranch,
                Some(0x1008),
                false,
            ),
            case(
                DisasmArch::RiscV64,
                0x1000,
                &[0x67, 0x80, 0x00, 0x00],
                InsnFlow::Return,
                None,
                false,
            ),
            case(
                DisasmArch::RiscV64,
                0x1000,
                &[0x73, 0x00, 0x00, 0x00],
                InsnFlow::Interrupt,
                None,
                false,
            ),
            case(
                DisasmArch::Sparc,
                0x1000,
                &[0x40, 0x00, 0x00, 0x08],
                InsnFlow::Call,
                Some(0x1020),
                true,
            ),
            case(
                DisasmArch::Sparc,
                0x1000,
                &[0x81, 0xC7, 0xE0, 0x08],
                InsnFlow::Return,
                None,
                false,
            ),
            case(
                DisasmArch::Sparc,
                0x1000,
                &[0x10, 0x80, 0x00, 0x08],
                InsnFlow::UnconditionalBranch,
                Some(0x1020),
                true,
            ),
            case(
                DisasmArch::Sparc,
                0x1000,
                &[0x02, 0x80, 0x00, 0x08],
                InsnFlow::ConditionalBranch,
                Some(0x1020),
                true,
            ),
            case(
                DisasmArch::Ebpf,
                0x0,
                &[0x85, 0, 0, 0, 0x05, 0, 0, 0],
                InsnFlow::IndirectCall,
                None,
                false,
            ),
            case(
                DisasmArch::Ebpf,
                0x0,
                &[0x95, 0, 0, 0, 0, 0, 0, 0],
                InsnFlow::Return,
                None,
                false,
            ),
            case(
                DisasmArch::Ebpf,
                0x0,
                &[0x05, 0, 0x02, 0, 0, 0, 0, 0],
                InsnFlow::UnconditionalBranch,
                Some(0x18),
                false,
            ),
            case(
                DisasmArch::Ebpf,
                0x0,
                &[0x15, 0x01, 0x02, 0, 0, 0, 0, 0],
                InsnFlow::ConditionalBranch,
                Some(0x18),
                false,
            ),
        ]
    }

    #[test]
    fn every_isa_classifies_its_transfer_encodings() {
        for entry in encodings() {
            let model: FlowModel = FlowModel::for_arch(entry.arch).expect("arch has a flow model");
            let actual: ControlFlow = model.control_flow(entry.raw, entry.address, "");
            assert!(
                actual.is_decoded(),
                "{} {:02x?} must decode",
                entry.arch.label(),
                entry.raw
            );
            assert_eq!(
                (actual.flow, actual.branch_target),
                (entry.flow, entry.target),
                "{} {:02x?} at {:#x}",
                entry.arch.label(),
                entry.raw,
                entry.address
            );
        }
    }

    #[test]
    fn computed_targets_agree_with_the_disassembler_rendering() {
        let mut checked: usize = 0;
        for entry in encodings() {
            if !entry.engine_renders_target {
                continue;
            }
            let target: u64 = entry.target.expect("a rendered case carries a target");
            let decoded: Vec<DisasmInsn> =
                disassemble(entry.arch, entry.address, entry.raw).expect("engine decodes");
            let rendered: &DisasmInsn = decoded.first().expect("one instruction");
            let displacement: i64 = target.cast_signed() - entry.address.cast_signed();
            let relative: String = if displacement < 0 {
                format!("$-{:#x}", displacement.unsigned_abs())
            } else {
                format!("$+{displacement:#x}")
            };
            assert!(
                rendered.operands.contains(&format!("{target:#x}"))
                    || rendered.operands.contains(&relative),
                "{} rendered {} {} but the recovered target is {target:#x}",
                entry.arch.label(),
                rendered.mnemonic,
                rendered.operands
            );
            checked += 1;
        }
        assert!(checked >= 12, "expected a broad cross-check, saw {checked}");
    }

    #[test]
    fn an_architecture_without_a_flow_model_is_refused_by_name() {
        let error: Error = FlowModel::for_arch(DisasmArch::Avr).expect_err("avr has no model");
        let text: String = error.to_string();
        assert!(
            matches!(error, Error::UnsupportedArch(_)),
            "expected an unsupported-architecture error, got {text}"
        );
        assert!(
            text.contains("avr"),
            "the error must name the architecture: {text}"
        );
        assert!(
            text.contains("control-flow model"),
            "the error must say what is missing: {text}"
        );
    }

    #[test]
    fn a_truncated_instruction_reports_blindness_rather_than_sequential_flow() {
        let cases: [(DisasmArch, &[u8]); 4] = [
            (DisasmArch::Aarch64, &[0xC0, 0x03]),
            (DisasmArch::MipsBe32, &[0x0C, 0x10]),
            (DisasmArch::PowerPc32, &[0x48, 0x00]),
            (DisasmArch::Ebpf, &[0x85, 0x00]),
        ];
        for (arch, raw) in cases {
            let model: FlowModel = FlowModel::for_arch(arch).expect("model");
            let actual: ControlFlow = model.control_flow(raw, 0x1000, "");
            assert!(
                !actual.is_decoded(),
                "{} must report undecodable for {raw:02x?}",
                arch.label()
            );
            assert!(!model.decodes_whole_slice(raw, 0x1000));
        }
    }

    #[test]
    fn a_genuinely_sequential_instruction_is_decoded_not_blind() {
        let cases: [(DisasmArch, &[u8]); 4] = [
            (DisasmArch::Aarch64, &[0x1F, 0x20, 0x03, 0xD5]),
            (DisasmArch::MipsBe32, &[0x00, 0x00, 0x00, 0x00]),
            (DisasmArch::PowerPc32, &[0x60, 0x00, 0x00, 0x00]),
            (DisasmArch::RiscV64, &[0x13, 0x00, 0x00, 0x00]),
        ];
        for (arch, raw) in cases {
            let model: FlowModel = FlowModel::for_arch(arch).expect("model");
            let actual: ControlFlow = model.control_flow(raw, 0x1000, "nop");
            assert!(actual.is_decoded(), "{} nop must decode", arch.label());
            assert_eq!(actual.flow, InsnFlow::Sequential);
            assert_eq!(actual.branch_target, None);
        }
    }

    #[test]
    fn x86_direct_traps_require_exact_decoded_encodings() {
        let traps: [(&[u8], DirectTrap); 5] = [
            (&[0x0f, 0x0b], DirectTrap::InvalidOpcode),
            (&[0x0f, 0xff, 0xc0], DirectTrap::InvalidOpcode),
            (&[0x0f, 0xb9, 0xc0], DirectTrap::InvalidOpcode),
            (&[0xcc], DirectTrap::Breakpoint),
            (&[0xcd, 0x29], DirectTrap::FastFail),
        ];
        for (raw, expected) in traps {
            assert_eq!(x86_direct_trap(raw, 0x1000), Some(expected), "{raw:02x?}");
        }
        for raw in [&[0xcd, 0x80][..], &[0x0f][..], &[0xcc, 0x90][..]] {
            assert_eq!(x86_direct_trap(raw, 0x1000), None, "{raw:02x?}");
        }
    }

    #[test]
    fn noreturn_library_lookup_distinguishes_the_posix_underscore_names() {
        let exit_entry: &NoreturnLibraryFunction = noreturn_import_evidence("exit")
            .expect("exit is a declared non-returning import")
            .function();
        let underscore_exit: &NoreturnLibraryFunction = noreturn_import_evidence("_exit")
            .expect("_exit is a declared non-returning import")
            .function();
        assert_eq!(exit_entry.name, "exit");
        assert_eq!(underscore_exit.name, "_exit");
        let capital_exit: &NoreturnLibraryFunction = noreturn_import_evidence("_Exit")
            .expect("_Exit is a declared non-returning import")
            .function();
        assert_eq!(capital_exit.name, "_Exit");
        assert_eq!(
            noreturn_import_evidence("abort")
                .map(NoreturnImportEvidence::function)
                .map(|entry: &NoreturnLibraryFunction| entry.name),
            Some("abort")
        );
        assert_eq!(
            noreturn_import_evidence("_abort")
                .map(NoreturnImportEvidence::function)
                .map(|entry: &NoreturnLibraryFunction| entry.name),
            Some("abort")
        );
        assert_eq!(
            noreturn_import_evidence("__imp_exit")
                .map(NoreturnImportEvidence::function)
                .map(|entry: &NoreturnLibraryFunction| entry.name),
            Some("exit")
        );
        assert_eq!(
            noreturn_import_evidence("__imp__exit")
                .map(NoreturnImportEvidence::function)
                .map(|entry: &NoreturnLibraryFunction| entry.name),
            Some("_exit")
        );
        assert_eq!(
            noreturn_import_evidence("__imp___stack_chk_fail")
                .map(NoreturnImportEvidence::function)
                .map(|entry: &NoreturnLibraryFunction| entry.name),
            Some("__stack_chk_fail")
        );
        let x64_gsfailure: &NoreturnLibraryFunction =
            noreturn_import_evidence("__report_gsfailure")
                .expect("x64 gsfailure is a declared non-returning import")
                .function();
        assert_eq!(
            x64_gsfailure.parameters,
            &[NoreturnParameter::UnsignedPointerSized]
        );
        let x86_gsfailure: &NoreturnLibraryFunction =
            noreturn_import_evidence("__imp____report_gsfailure")
                .expect("decorated x86 gsfailure is a declared non-returning import")
                .function();
        assert_eq!(x86_gsfailure.name, "___report_gsfailure");
        assert!(x86_gsfailure.parameters.is_empty());
    }

    #[test]
    fn noreturn_library_lookup_refuses_names_that_can_return() {
        for name in [
            "TerminateProcess",
            "exit_group_helper",
            "myexit",
            "printf",
            "longjmp",
            "",
            "_",
        ] {
            assert!(
                noreturn_import_evidence(name).is_none(),
                "{name} must not be treated as a non-returning library exit"
            );
        }
    }

    #[test]
    fn noreturn_library_prototypes_bind_every_declared_parameter() {
        for entry in NORETURN_LIBRARY_PROTOTYPES {
            assert!(
                !entry.name.is_empty(),
                "a declared non-returning function has no name"
            );
            assert!(
                entry.parameters.len() <= 4,
                "{} declares more parameters than the narrowest integer argument register file",
                entry.name
            );
            for parameter in entry.parameters {
                assert!(
                    !parameter.c_type().is_empty() && !parameter.rust_type().is_empty(),
                    "{} has a parameter with no spelled type",
                    entry.name
                );
                assert_eq!(
                    parameter.is_pointer(),
                    parameter.c_type().ends_with('*'),
                    "{} spells a pointer parameter inconsistently",
                    entry.name
                );
            }
        }
    }
}
