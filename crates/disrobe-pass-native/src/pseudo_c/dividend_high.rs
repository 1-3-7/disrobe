use std::collections::BTreeSet;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, OpAccess, Register};

use crate::arch::{DisasmInsn, decode_one_x86};
use crate::error::{Error, Result};

use super::{
    Reg, RegRef, Source, Stmt, Width, instruction_access_writes, lift_dividend_extend, lift_one,
    parse_divide_operand,
};

#[derive(Debug, Clone, Copy)]
struct Step {
    flow: FlowControl,
    reads_rdx: bool,
    writes_rdx: bool,
    writes_rax: bool,
}

pub(super) fn refuse_unset_dividend_high_halves(insns: &[DisasmInsn]) -> Result<()> {
    if !insns
        .iter()
        .any(|insn: &DisasmInsn| matches!(insn.mnemonic.as_str(), "div" | "idiv" | "cqo" | "cdq"))
    {
        return Ok(());
    }
    let mut factory: InstructionInfoFactory = InstructionInfoFactory::new();
    let mut steps: Vec<Step> = Vec::with_capacity(insns.len());
    let mut labels: BTreeSet<u64> = BTreeSet::new();
    for insn in insns {
        let decoded: Instruction =
            decode_one_x86(64, insn.address, &insn.bytes).ok_or_else(|| {
                Error::LlvmIr(format!(
                    "`{}` at {:#x} does not decode for the dividend high-half check",
                    text(insn),
                    insn.address
                ))
            })?;
        let flow: FlowControl = decoded.flow_control();
        if matches!(
            flow,
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) {
            labels.insert(decoded.near_branch_target());
        }
        let mut step: Step = Step {
            flow,
            reads_rdx: false,
            writes_rdx: false,
            writes_rax: false,
        };
        for used in factory.info(&decoded).used_registers() {
            let full: Register = used.register().full_register();
            let access: OpAccess = used.access();
            if full == Register::RDX {
                step.reads_rdx |= matches!(
                    access,
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                );
                step.writes_rdx |= instruction_access_writes(access);
            } else if full == Register::RAX {
                step.writes_rax |= instruction_access_writes(access);
            }
        }
        steps.push(step);
    }
    for (index, insn) in insns.iter().enumerate() {
        if let Some(divisor) = parse_divide_operand(&insn.mnemonic, &insn.operands) {
            check_divide(insns, &steps, &labels, index, divisor)?;
        } else if lift_dividend_extend(&insn.mnemonic, &insn.operands).is_some() {
            check_sign_extension(insns, &steps, &labels, index)?;
        }
    }
    Ok(())
}

fn text(insn: &DisasmInsn) -> String {
    format!("{} {}", insn.mnemonic, insn.operands)
        .trim_end()
        .to_owned()
}

fn zeroes_rdx(insn: &DisasmInsn) -> bool {
    matches!(
        lift_one(&insn.mnemonic, &insn.operands),
        Some(Stmt::Assign {
            dest: RegRef {
                reg: Reg::Rdx,
                width: Width::W32 | Width::W64,
            },
            src: Source::Imm(0),
        })
    )
}

fn divide_refusal(at: u64, reason: &str) -> Error {
    Error::LlvmIr(format!("division at {at:#x}: {reason}"))
}

fn check_divide(
    insns: &[DisasmInsn],
    steps: &[Step],
    labels: &BTreeSet<u64>,
    index: usize,
    divisor: RegRef,
) -> Result<()> {
    let at: u64 = insns[index].address;
    if divisor.reg == Reg::Rdx {
        return Err(divide_refusal(
            at,
            "it divides by rdx, the high half of its own dividend",
        ));
    }
    for position in (0..index).rev() {
        let next: u64 = insns[position + 1].address;
        if labels.contains(&next) {
            return Err(divide_refusal(
                at,
                &format!(
                    "a branch joins at {next:#x} after the high half of the dividend was set, so rdx may hold another value"
                ),
            ));
        }
        let insn: &DisasmInsn = &insns[position];
        if lift_dividend_extend(&insn.mnemonic, &insn.operands).is_some() || zeroes_rdx(insn) {
            return Ok(());
        }
        let step: Step = steps[position];
        match step.flow {
            FlowControl::Next | FlowControl::ConditionalBranch => {}
            FlowControl::Call | FlowControl::IndirectCall => {
                return Err(divide_refusal(
                    at,
                    &format!(
                        "the call at {:#x} may read or change rdx, the high half of the dividend",
                        insn.address
                    ),
                ));
            }
            FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Return
            | FlowControl::Interrupt
            | FlowControl::Exception
            | FlowControl::XbeginXabortXend => break,
        }
        if step.writes_rdx {
            return Err(divide_refusal(
                at,
                &format!(
                    "`{}` at {:#x} leaves rdx neither zero nor the sign of rax",
                    text(insn),
                    insn.address
                ),
            ));
        }
    }
    Err(divide_refusal(
        at,
        "no cqo, cdq or full-width zeroing of rdx sets the high half of the dividend in its block, so rdx holds a value the lift does not model",
    ))
}

fn check_sign_extension(
    insns: &[DisasmInsn],
    steps: &[Step],
    labels: &BTreeSet<u64>,
    index: usize,
) -> Result<()> {
    let extension: &DisasmInsn = &insns[index];
    let refusal = |reason: String| -> Error {
        Error::LlvmIr(format!(
            "`{}` at {:#x} sets rdx to the sign of rax for a division, but {reason}",
            extension.mnemonic, extension.address
        ))
    };
    for (insn, step) in insns.iter().zip(steps).skip(index + 1) {
        if labels.contains(&insn.address) {
            return Err(refusal(format!(
                "a branch joins at {:#x} before the division",
                insn.address
            )));
        }
        if parse_divide_operand(&insn.mnemonic, &insn.operands).is_some() {
            return Ok(());
        }
        match step.flow {
            FlowControl::Next => {}
            FlowControl::Call | FlowControl::IndirectCall => {
                return Err(refusal(format!(
                    "the call at {:#x} may read or change rdx",
                    insn.address
                )));
            }
            FlowControl::ConditionalBranch
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Return
            | FlowControl::Interrupt
            | FlowControl::Exception
            | FlowControl::XbeginXabortXend => {
                return Err(refusal(format!(
                    "rdx leaves the block at {:#x} before the division",
                    insn.address
                )));
            }
        }
        let effect: Option<&str> = if step.reads_rdx {
            Some("reads rdx")
        } else if step.writes_rdx {
            Some("overwrites rdx")
        } else if step.writes_rax {
            Some("changes rax")
        } else {
            None
        };
        if let Some(effect) = effect {
            return Err(refusal(format!(
                "`{}` at {:#x} {effect} before the division",
                text(insn),
                insn.address
            )));
        }
    }
    Err(refusal("no division follows it".to_owned()))
}
