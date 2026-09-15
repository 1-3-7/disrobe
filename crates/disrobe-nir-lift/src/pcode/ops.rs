use disrobe_nir::{CallOtherEffect, NirInstr, NirOp, ValueOp};
use disrobe_sleigh::pcode::{PcodeInstr, PcodeOp, Space, Varnode};

use crate::error::{LiftError, Result};

use super::flags::callother_effect;
use super::varnode::{PendingOutput, VarnodeLowerer};
use super::{PcodeLiftConfig, valid_identifier};

const MAX_CALLOTHER_INPUTS: usize = 4096;
const MAX_CALLOTHER_NAME_BYTES: usize = 4096;

pub(super) fn lower(
    operation: &PcodeOp,
    instruction: &PcodeInstr,
    config: &PcodeLiftConfig,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    match operation {
        PcodeOp::Copy { output, input } => lower_copy(
            *output,
            *input,
            operation,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::BoolAnd {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::BoolAnd,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::BoolNegate { output, input } => lower_unary(
            ValueOp::BoolNegate,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::BoolOr {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::BoolOr,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::BoolXor {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::BoolXor,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatAdd {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatAdd,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatDiv {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatDiv,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatEqual {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatEqual,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatLess {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatLess,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatLessEqual {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatLessEqual,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatMult {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatMult,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatSqrt { output, input } => lower_unary(
            ValueOp::FloatSqrt,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatSub {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::FloatSub,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatToFloat { output, input } => lower_unary(
            ValueOp::FloatToFloat,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::FloatTrunc { output, input } => lower_unary(
            ValueOp::FloatTrunc,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntToFloat { output, input } => lower_unary(
            ValueOp::IntToFloat,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntAdd {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntAdd,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntAnd {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntAnd,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntCarry {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntCarry,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntDiv {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntDiv,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntEqual {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntEqual,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntLeft {
            output,
            input,
            amount,
        } => lower_binary(
            ValueOp::IntLeft,
            *output,
            *input,
            *amount,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntLess {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntLess,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntLessEqual {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntLessEqual,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntMult {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntMult,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntNegate { output, input } => lower_unary(
            ValueOp::IntNegate,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntNotEqual {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntNotEqual,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntOr {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntOr,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntRem {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntRem,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntRight {
            output,
            input,
            amount,
        } => lower_binary(
            ValueOp::IntRight,
            *output,
            *input,
            *amount,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedBorrow {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSignedBorrow,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedCarry {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSignedCarry,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedDiv {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSignedDiv,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedLess {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSignedLess,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedLessEqual {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSignedLessEqual,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedRem {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSignedRem,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSignedRight {
            output,
            input,
            amount,
        } => lower_binary(
            ValueOp::IntSignedRight,
            *output,
            *input,
            *amount,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSub {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntSub,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntXor {
            output,
            left,
            right,
        } => lower_binary(
            ValueOp::IntXor,
            *output,
            *left,
            *right,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntSext { output, input } => lower_unary(
            ValueOp::IntSext,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::IntZext { output, input } => lower_unary(
            ValueOp::IntZext,
            *output,
            *input,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::Load {
            output,
            space,
            pointer,
        } => lower_load(
            *output,
            *space,
            *pointer,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::Store {
            space,
            pointer,
            value,
        } => lower_store(*space, *pointer, *value, instruction, lowerer, instructions),
        PcodeOp::Piece { output, high, low } => {
            lower_piece(*output, *high, *low, instruction, lowerer, instructions)
        }
        PcodeOp::Subpiece {
            output,
            input,
            byte_offset,
        } => lower_subpiece(
            *output,
            *input,
            *byte_offset,
            instruction,
            lowerer,
            instructions,
        ),
        PcodeOp::CallOther {
            name,
            output,
            inputs,
        } => lower_callother(
            name,
            *output,
            inputs,
            instruction,
            config,
            lowerer,
            instructions,
        ),
        PcodeOp::Branch { target } | PcodeOp::BranchIndirect { target } => {
            lower_branch(*target, instruction, config, lowerer, instructions)
        }
        PcodeOp::CBranch { target, condition } => {
            lower_conditional_branch(*target, *condition, instruction, lowerer, instructions)
        }
        PcodeOp::Call { target } | PcodeOp::CallIndirect { target } => {
            lower_call(*target, instruction, config, lowerer, instructions)
        }
        PcodeOp::Return { .. } => {
            let operands: Vec<String> = config.return_value.iter().cloned().collect();
            instructions.push(lowerer.instruction(
                instruction.address,
                NirOp::Return,
                "RETURN",
                operands,
            ));
            Ok(())
        }
    }
}

fn lower_copy(
    output: Varnode,
    input: Varnode,
    operation: &PcodeOp,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    if output.size_bytes != input.size_bytes {
        return Err(invalid(
            instruction.address,
            operation.name(),
            "copy input and output widths do not match",
        ));
    }
    let known: Option<u64> = lowerer.resolved_constant(input);
    let source: String =
        lowerer.read(input, instruction.address, operation.name(), instructions)?;
    let destination: PendingOutput =
        lowerer.output(output, instruction.address, operation.name())?;
    instructions.push(lowerer.instruction(
        instruction.address,
        NirOp::Copy {
            src: source.clone(),
            size: output.size_bytes,
        },
        operation.name(),
        vec![destination.value.clone(), source],
    ));
    lowerer.finish(destination, instruction.address, instructions);
    lowerer.record_constant(output, known);
    Ok(())
}

fn lower_branch(
    target: Varnode,
    instruction: &PcodeInstr,
    config: &PcodeLiftConfig,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    let (value, resolved): (String, Option<u64>) =
        lowerer.control_target(target, instruction.address, "BRANCHIND", instructions)?;
    let op: NirOp = if config.is_tail_call_site(instruction.address) {
        NirOp::TailCall { target: resolved }
    } else {
        NirOp::Branch { target: resolved }
    };
    instructions.push(lowerer.instruction(instruction.address, op, "BRANCH", vec![value]));
    Ok(())
}

fn lower_conditional_branch(
    target: Varnode,
    condition: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    let (_target_value, resolved): (String, Option<u64>) =
        lowerer.control_target(target, instruction.address, "CBRANCH", instructions)?;
    let condition_value: String =
        lowerer.read(condition, instruction.address, "CBRANCH", instructions)?;
    instructions.push(lowerer.instruction(
        instruction.address,
        NirOp::CondBranch { target: resolved },
        "CBRANCH",
        vec![condition_value],
    ));
    Ok(())
}

fn lower_call(
    target: Varnode,
    instruction: &PcodeInstr,
    config: &PcodeLiftConfig,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    let (value, resolved): (String, Option<u64>) =
        lowerer.control_target(target, instruction.address, "CALL", instructions)?;
    let op: NirOp = if config.is_no_return_target(resolved) {
        NirOp::NoReturnCall { target: resolved }
    } else if resolved.is_some() {
        NirOp::Call { target: resolved }
    } else {
        NirOp::IndirectCall
    };
    instructions.push(lowerer.instruction(instruction.address, op, "CALL", vec![value]));
    lowerer.invalidate_register_constants();
    Ok(())
}

fn lower_binary(
    op: ValueOp,
    output: Varnode,
    left: Varnode,
    right: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    lower_value(
        op,
        output,
        &[left, right],
        instruction,
        lowerer,
        instructions,
    )
}

fn lower_unary(
    op: ValueOp,
    output: Varnode,
    input: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    lower_value(op, output, &[input], instruction, lowerer, instructions)
}

fn lower_value(
    op: ValueOp,
    output: Varnode,
    inputs: &[Varnode],
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    validate_value_widths(op, output, inputs, instruction.address)?;
    let mut values: Vec<String> = Vec::with_capacity(inputs.len());
    let mut sizes: Vec<u32> = Vec::with_capacity(inputs.len());
    for input in inputs {
        let value: String =
            lowerer.read(*input, instruction.address, op.mnemonic(), instructions)?;
        values.push(value);
        sizes.push(input.size_bytes);
    }
    let destination: PendingOutput = lowerer.output(output, instruction.address, op.mnemonic())?;
    let mut operands: Vec<String> = Vec::with_capacity(values.len().saturating_add(1));
    operands.push(destination.value.clone());
    operands.extend(values.iter().cloned());
    instructions.push(lowerer.instruction(
        instruction.address,
        NirOp::Value {
            op,
            inputs: values,
            input_sizes: sizes,
            size: output.size_bytes,
        },
        op.mnemonic(),
        operands,
    ));
    lowerer.finish(destination, instruction.address, instructions);
    Ok(())
}

fn lower_load(
    output: Varnode,
    space: Space,
    pointer: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    require_ram(space, instruction.address, "LOAD")?;
    let addr: String = lowerer.read(pointer, instruction.address, "LOAD", instructions)?;
    let destination: PendingOutput = lowerer.output(output, instruction.address, "LOAD")?;
    let mut lowered: NirInstr = lowerer.instruction(
        instruction.address,
        NirOp::RawLoad {
            addr: addr.clone(),
            size: output.size_bytes,
        },
        "LOAD",
        vec![destination.value.clone(), addr],
    );
    lowered.reads_memory = true;
    lowered.byte_width = output.size_bytes == 1;
    instructions.push(lowered);
    lowerer.finish(destination, instruction.address, instructions);
    Ok(())
}

fn lower_store(
    space: Space,
    pointer: Varnode,
    value: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    require_ram(space, instruction.address, "STORE")?;
    let addr: String = lowerer.read(pointer, instruction.address, "STORE", instructions)?;
    let stored: String = lowerer.read(value, instruction.address, "STORE", instructions)?;
    let mut lowered: NirInstr = lowerer.instruction(
        instruction.address,
        NirOp::RawStore {
            addr: addr.clone(),
            value: stored.clone(),
            size: value.size_bytes,
        },
        "STORE",
        vec![addr, stored],
    );
    lowered.writes_memory = true;
    lowered.byte_width = value.size_bytes == 1;
    instructions.push(lowered);
    Ok(())
}

fn lower_piece(
    output: Varnode,
    high: Varnode,
    low: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    let combined_size: u32 = high
        .size_bytes
        .checked_add(low.size_bytes)
        .ok_or_else(|| invalid(instruction.address, "PIECE", "input size overflow"))?;
    if combined_size != output.size_bytes {
        return Err(invalid(
            instruction.address,
            "PIECE",
            "output size does not equal input sizes",
        ));
    }
    let high_value: String = lowerer.read(high, instruction.address, "PIECE", instructions)?;
    let low_value: String = lowerer.read(low, instruction.address, "PIECE", instructions)?;
    let destination: PendingOutput = lowerer.output(output, instruction.address, "PIECE")?;
    instructions.push(lowerer.instruction(
        instruction.address,
        NirOp::Piece {
            high: high_value.clone(),
            low: low_value.clone(),
            high_size: high.size_bytes,
            low_size: low.size_bytes,
            size: output.size_bytes,
        },
        "PIECE",
        vec![destination.value.clone(), high_value, low_value],
    ));
    lowerer.finish(destination, instruction.address, instructions);
    Ok(())
}

fn lower_subpiece(
    output: Varnode,
    input: Varnode,
    byte_offset: Varnode,
    instruction: &PcodeInstr,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    if byte_offset.space != Space::Constant {
        return Err(invalid(
            instruction.address,
            "SUBPIECE",
            "byte offset is not constant",
        ));
    }
    let _validated_offset: String =
        lowerer.read(byte_offset, instruction.address, "SUBPIECE", instructions)?;
    let offset_value: u64 = lowerer.resolved_constant(byte_offset).ok_or_else(|| {
        invalid(
            instruction.address,
            "SUBPIECE",
            "byte offset did not resolve as a constant",
        )
    })?;
    let offset: u32 = u32::try_from(offset_value)
        .map_err(|_| invalid(instruction.address, "SUBPIECE", "byte offset exceeds u32"))?;
    let end: u32 = offset
        .checked_add(output.size_bytes)
        .ok_or_else(|| invalid(instruction.address, "SUBPIECE", "output range overflow"))?;
    if end > input.size_bytes {
        return Err(invalid(
            instruction.address,
            "SUBPIECE",
            "output range exceeds input",
        ));
    }
    let source: String = lowerer.read(input, instruction.address, "SUBPIECE", instructions)?;
    let destination: PendingOutput = lowerer.output(output, instruction.address, "SUBPIECE")?;
    instructions.push(lowerer.instruction(
        instruction.address,
        NirOp::Subpiece {
            src: source.clone(),
            offset,
            size: output.size_bytes,
        },
        "SUBPIECE",
        vec![destination.value.clone(), source, offset.to_string()],
    ));
    lowerer.finish(destination, instruction.address, instructions);
    Ok(())
}

fn lower_callother(
    name: &str,
    output: Option<Varnode>,
    inputs: &[Varnode],
    instruction: &PcodeInstr,
    config: &PcodeLiftConfig,
    lowerer: &mut VarnodeLowerer<'_>,
    instructions: &mut Vec<NirInstr>,
) -> Result<()> {
    if name.len() > MAX_CALLOTHER_NAME_BYTES {
        return Err(invalid(
            instruction.address,
            "CALLOTHER",
            "effect name is longer than the limit",
        ));
    }
    if !valid_identifier(name) {
        return Err(invalid(
            instruction.address,
            "CALLOTHER",
            "effect name is not an identifier",
        ));
    }
    if inputs.len() > MAX_CALLOTHER_INPUTS {
        return Err(invalid(
            instruction.address,
            "CALLOTHER",
            "effect input count exceeds limit",
        ));
    }
    let mut reads: Vec<String> = Vec::with_capacity(inputs.len());
    for input in inputs {
        reads.push(lowerer.read(*input, instruction.address, "CALLOTHER", instructions)?);
    }
    let pending: Option<PendingOutput> = output
        .map(|value: Varnode| lowerer.output(value, instruction.address, "CALLOTHER"))
        .transpose()?;
    let writes: Vec<String> = pending
        .as_ref()
        .map(|value: &PendingOutput| vec![value.value.clone()])
        .unwrap_or_default();
    let effect: CallOtherEffect =
        callother_effect(name, reads.clone(), writes, config.x86_callother_contracts);
    let operands: Vec<String> = pending
        .as_ref()
        .map(|value: &PendingOutput| vec![value.value.clone()])
        .unwrap_or_default();
    let mut lowered: NirInstr = lowerer.instruction(
        instruction.address,
        NirOp::CallOther {
            effect: effect.clone(),
        },
        "CALLOTHER",
        operands,
    );
    lowered.reads_memory = effect.reads_memory;
    lowered.writes_memory = effect.writes_memory;
    instructions.push(lowered);
    if let Some(destination) = pending {
        lowerer.finish(destination, instruction.address, instructions);
    }
    if effect.unknown_registers {
        lowerer.invalidate_register_constants();
    }
    Ok(())
}

fn validate_value_widths(
    op: ValueOp,
    output: Varnode,
    inputs: &[Varnode],
    address: u64,
) -> Result<()> {
    if output.size_bytes == 0 || inputs.iter().any(|input: &Varnode| input.size_bytes == 0) {
        return Err(invalid(address, op.mnemonic(), "zero-sized value"));
    }
    let boolean_output: bool = matches!(
        op,
        ValueOp::BoolAnd
            | ValueOp::BoolNegate
            | ValueOp::BoolOr
            | ValueOp::BoolXor
            | ValueOp::FloatEqual
            | ValueOp::FloatLess
            | ValueOp::FloatLessEqual
            | ValueOp::IntCarry
            | ValueOp::IntEqual
            | ValueOp::IntLess
            | ValueOp::IntLessEqual
            | ValueOp::IntNotEqual
            | ValueOp::IntSignedBorrow
            | ValueOp::IntSignedCarry
            | ValueOp::IntSignedLess
            | ValueOp::IntSignedLessEqual
    );
    if boolean_output && output.size_bytes != 1 {
        return Err(invalid(
            address,
            op.mnemonic(),
            "boolean output is not one byte",
        ));
    }
    let first_size: u32 = inputs.first().map_or(0, |input: &Varnode| input.size_bytes);
    let equal_value_inputs: bool = matches!(
        op,
        ValueOp::BoolAnd
            | ValueOp::BoolOr
            | ValueOp::BoolXor
            | ValueOp::FloatAdd
            | ValueOp::FloatDiv
            | ValueOp::FloatEqual
            | ValueOp::FloatLess
            | ValueOp::FloatLessEqual
            | ValueOp::FloatMult
            | ValueOp::FloatSub
            | ValueOp::IntAdd
            | ValueOp::IntAnd
            | ValueOp::IntCarry
            | ValueOp::IntDiv
            | ValueOp::IntEqual
            | ValueOp::IntLess
            | ValueOp::IntLessEqual
            | ValueOp::IntMult
            | ValueOp::IntNotEqual
            | ValueOp::IntOr
            | ValueOp::IntRem
            | ValueOp::IntSignedBorrow
            | ValueOp::IntSignedCarry
            | ValueOp::IntSignedDiv
            | ValueOp::IntSignedLess
            | ValueOp::IntSignedLessEqual
            | ValueOp::IntSignedRem
            | ValueOp::IntSub
            | ValueOp::IntXor
    );
    if equal_value_inputs
        && inputs
            .iter()
            .any(|input: &Varnode| input.size_bytes != first_size)
    {
        return Err(invalid(address, op.mnemonic(), "input widths do not match"));
    }
    let result_matches_input: bool = matches!(
        op,
        ValueOp::BoolAnd
            | ValueOp::BoolNegate
            | ValueOp::BoolOr
            | ValueOp::BoolXor
            | ValueOp::FloatAdd
            | ValueOp::FloatDiv
            | ValueOp::FloatMult
            | ValueOp::FloatSqrt
            | ValueOp::FloatSub
            | ValueOp::IntAdd
            | ValueOp::IntAnd
            | ValueOp::IntDiv
            | ValueOp::IntLeft
            | ValueOp::IntMult
            | ValueOp::IntNegate
            | ValueOp::IntOr
            | ValueOp::IntRem
            | ValueOp::IntRight
            | ValueOp::IntSignedDiv
            | ValueOp::IntSignedRem
            | ValueOp::IntSignedRight
            | ValueOp::IntSub
            | ValueOp::IntXor
    );
    if result_matches_input && output.size_bytes != first_size {
        return Err(invalid(
            address,
            op.mnemonic(),
            "output width does not match input",
        ));
    }
    let extension: bool = matches!(op, ValueOp::IntSext | ValueOp::IntZext);
    if extension
        && inputs
            .first()
            .is_none_or(|input: &Varnode| output.size_bytes <= input.size_bytes)
    {
        return Err(invalid(
            address,
            op.mnemonic(),
            "integer extension does not widen",
        ));
    }
    Ok(())
}

fn require_ram(space: Space, address: u64, operation: &str) -> Result<()> {
    if space != Space::Ram {
        return Err(invalid(address, operation, "memory space is not ram"));
    }
    Ok(())
}

fn invalid(address: u64, operation: &str, reason: &str) -> LiftError {
    LiftError::InvalidPcode {
        address,
        operation: operation.to_owned(),
        reason: reason.to_owned(),
    }
}
