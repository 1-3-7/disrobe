use std::collections::{BTreeMap, BTreeSet};

use super::{BasicBlock, BinOp, BlockId, CilType, DvIr, IrInstruction, Terminator, ValueId};

struct RenderPlan<'a> {
    ir: &'a DvIr,
    blocks: Vec<&'a BasicBlock>,
    return_type: CilType,
}

impl<'a> RenderPlan<'a> {
    fn new(ir: &'a DvIr) -> Result<Self, String> {
        validate_ir(ir).map_err(|reason: String| format!("invalid DvIr: {reason}"))?;
        let blocks: Vec<&BasicBlock> = ordered_blocks(ir)?;
        let return_type: CilType = infer_return_type(ir, &blocks)?;
        Ok(Self {
            ir,
            blocks,
            return_type,
        })
    }
}

pub fn emit_pseudo_csharp(ir: &DvIr) -> String {
    let plan: Result<RenderPlan<'_>, String> = RenderPlan::new(ir);
    plan.map_or_else(unrecovered, |value: RenderPlan<'_>| {
        render_pseudo_csharp(&value)
    })
}

pub fn emit_normalized_cil(ir: &DvIr) -> String {
    let plan: Result<RenderPlan<'_>, String> = RenderPlan::new(ir);
    plan.map_or_else(unrecovered, |value: RenderPlan<'_>| {
        render_normalized_cil(&value)
    })
}

fn validate_ir(ir: &DvIr) -> Result<(), String> {
    if ir.blocks.is_empty() {
        return Err("IR has no blocks".to_owned());
    }
    let mut block_ids: BTreeSet<BlockId> = BTreeSet::new();
    for block in &ir.blocks {
        if !block_ids.insert(block.id) {
            return Err("IR has duplicate block identifiers".to_owned());
        }
    }
    if !block_ids.contains(&ir.entry) {
        return Err("IR entry block is absent".to_owned());
    }
    let mut definitions: BTreeMap<ValueId, CilType> = BTreeMap::new();
    for block in &ir.blocks {
        for instruction in &block.instructions {
            validate_instruction(instruction, ir.argument_count, ir.local_count, &definitions)?;
            if let Some((destination, value_type)) = instruction_metadata(instruction)
                && definitions.insert(destination, value_type).is_some()
            {
                return Err("IR value has multiple definitions".to_owned());
            }
        }
        validate_terminator(&block.terminator, &definitions, &block_ids)?;
    }
    if definitions != ir.value_types {
        return Err("IR value type table does not match definitions".to_owned());
    }
    Ok(())
}

fn validate_instruction(
    instruction: &IrInstruction,
    argument_count: u16,
    local_count: u16,
    definitions: &BTreeMap<ValueId, CilType>,
) -> Result<(), String> {
    match instruction {
        IrInstruction::LoadArgument { index, .. } | IrInstruction::StoreArgument { index, .. }
            if *index >= argument_count =>
        {
            return Err("IR argument index is out of range".to_owned());
        }
        IrInstruction::LoadLocal { index, .. } | IrInstruction::StoreLocal { index, .. }
            if *index >= local_count =>
        {
            return Err("IR local index is out of range".to_owned());
        }
        _ => {}
    }
    match instruction {
        IrInstruction::Const { .. }
        | IrInstruction::LoadArgument { .. }
        | IrInstruction::LoadLocal { .. } => {}
        IrInstruction::StoreArgument { value, .. } | IrInstruction::StoreLocal { value, .. } => {
            ensure_defined(*value, definitions)?;
        }
        IrInstruction::Binary {
            op, left, right, ..
        } => {
            ensure_defined(*left, definitions)?;
            ensure_defined(*right, definitions)?;
            let left_type: CilType = definitions
                .get(left)
                .copied()
                .ok_or_else(|| "IR binary left operand is undefined".to_owned())?;
            let right_type: CilType = definitions
                .get(right)
                .copied()
                .ok_or_else(|| "IR binary right operand is undefined".to_owned())?;
            if left_type != right_type || !left_type.is_numeric() {
                return Err("IR binary operand types are incompatible".to_owned());
            }
            let expected_type: CilType = if op.is_comparison() {
                CilType::I4
            } else {
                left_type
            };
            let actual_type: CilType = instruction_metadata(instruction).map_or_else(
                || CilType::Void,
                |(_, value_type): (ValueId, CilType)| value_type,
            );
            if expected_type != actual_type {
                return Err("IR binary result type is incompatible".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_terminator(
    terminator: &Terminator,
    definitions: &BTreeMap<ValueId, CilType>,
    block_ids: &BTreeSet<BlockId>,
) -> Result<(), String> {
    match terminator {
        Terminator::CondBr { condition, .. } => {
            ensure_defined(*condition, definitions)?;
            let condition_type: CilType = definitions
                .get(condition)
                .copied()
                .ok_or_else(|| "IR branch condition is undefined".to_owned())?;
            if !condition_type.is_integer() {
                return Err("IR branch condition is not an integer".to_owned());
            }
        }
        Terminator::Ret(Some(value)) => {
            ensure_defined(*value, definitions)?;
        }
        Terminator::Br(_) | Terminator::Ret(None) => {}
    }
    match terminator {
        Terminator::Br(target) if !block_ids.contains(target) => {
            return Err("IR branch target is absent".to_owned());
        }
        Terminator::CondBr {
            when_true,
            when_false,
            ..
        } if !block_ids.contains(when_true) || !block_ids.contains(when_false) => {
            return Err("IR branch target is absent".to_owned());
        }
        Terminator::Br(_) | Terminator::CondBr { .. } | Terminator::Ret(_) => {}
    }
    Ok(())
}

fn ensure_defined(value: ValueId, definitions: &BTreeMap<ValueId, CilType>) -> Result<(), String> {
    if !definitions.contains_key(&value) {
        return Err("IR use precedes its definition".to_owned());
    }
    Ok(())
}

const fn instruction_metadata(instruction: &IrInstruction) -> Option<(ValueId, CilType)> {
    match instruction {
        IrInstruction::Const { destination, .. }
        | IrInstruction::LoadArgument { destination, .. }
        | IrInstruction::LoadLocal { destination, .. } => Some((*destination, CilType::I8)),
        IrInstruction::Binary {
            destination, op, ..
        } => Some((
            *destination,
            if op.is_comparison() {
                CilType::I4
            } else {
                CilType::I8
            },
        )),
        IrInstruction::StoreArgument { .. } | IrInstruction::StoreLocal { .. } => None,
    }
}

fn ordered_blocks(ir: &DvIr) -> Result<Vec<&BasicBlock>, String> {
    let mut blocks: Vec<&BasicBlock> = ir.blocks.iter().collect();
    blocks.sort_by_key(|block: &&BasicBlock| block.id);
    let entry_index: usize = blocks
        .iter()
        .position(|block: &&BasicBlock| block.id == ir.entry)
        .ok_or_else(|| "IR entry block is absent".to_owned())?;
    let entry: &BasicBlock = blocks.remove(entry_index);
    blocks.insert(0, entry);
    Ok(blocks)
}

fn infer_return_type(ir: &DvIr, blocks: &[&BasicBlock]) -> Result<CilType, String> {
    let mut recovered_type: Option<CilType> = None;
    for block in blocks {
        let candidate: Option<CilType> = match &block.terminator {
            Terminator::Ret(None) => Some(CilType::Void),
            Terminator::Ret(Some(value)) => Some(value_type(ir, *value)?),
            Terminator::Br(_) | Terminator::CondBr { .. } => None,
        };
        if let Some(candidate_type) = candidate {
            match recovered_type {
                Some(existing_type) if existing_type != candidate_type => {
                    return Err("IR return types are inconsistent".to_owned());
                }
                Some(_) => {}
                None => recovered_type = Some(candidate_type),
            }
        }
    }
    let return_type: CilType =
        recovered_type.ok_or_else(|| "IR has no return terminator".to_owned())?;
    if return_type == CilType::Unknown {
        return Err("IR return type is unknown".to_owned());
    }
    Ok(return_type)
}

fn render_pseudo_csharp(plan: &RenderPlan<'_>) -> String {
    let return_type: &str = match csharp_type_name(plan.return_type) {
        Ok(value) => value,
        Err(reason) => return unrecovered(reason),
    };
    let arguments: String = csharp_arguments(plan.ir.argument_count);
    let mut output: String = format!("{return_type} recovered({arguments})\n{{\n");
    append_csharp_locals(&mut output, plan.ir.local_count);
    for block in &plan.blocks {
        append_label(&mut output, block.id);
        for instruction in &block.instructions {
            if let Err(reason) = append_csharp_instruction(&mut output, plan.ir, instruction) {
                return unrecovered(reason);
            }
        }
        append_csharp_terminator(&mut output, &block.terminator);
    }
    output.push_str("}\n");
    output
}

fn render_normalized_cil(plan: &RenderPlan<'_>) -> String {
    let return_type: &str = match cil_type_name(plan.return_type) {
        Ok(value) => value,
        Err(reason) => return unrecovered(reason),
    };
    let arguments: String = cil_arguments(plan.ir.argument_count);
    let mut output: String = format!(".method {return_type} recovered({arguments})\n{{\n");
    append_cil_locals(&mut output, plan.ir.local_count);
    for block in &plan.blocks {
        append_label(&mut output, block.id);
        for instruction in &block.instructions {
            append_cil_instruction(&mut output, instruction);
        }
        append_cil_terminator(&mut output, &block.terminator);
    }
    output.push_str("}\n");
    output
}

fn csharp_arguments(argument_count: u16) -> String {
    let arguments: Vec<String> = (0..argument_count)
        .map(|index: u16| format!("long arg{index}"))
        .collect();
    arguments.join(", ")
}

fn cil_arguments(argument_count: u16) -> String {
    let arguments: Vec<String> = (0..argument_count)
        .map(|index: u16| format!("int64 arg{index}"))
        .collect();
    arguments.join(", ")
}

fn append_csharp_locals(output: &mut String, local_count: u16) {
    for index in 0..local_count {
        append_indented(output, 1, &format!("long local{index} = 0L;"));
    }
    if local_count != 0 {
        output.push('\n');
    }
}

fn append_cil_locals(output: &mut String, local_count: u16) {
    if local_count == 0 {
        return;
    }
    let locals: Vec<String> = (0..local_count)
        .map(|index: u16| format!("[{index}] int64 local{index}"))
        .collect();
    append_indented(output, 1, &format!(".locals init ({})", locals.join(", ")));
}

fn append_csharp_instruction(
    output: &mut String,
    ir: &DvIr,
    instruction: &IrInstruction,
) -> Result<(), String> {
    let line: String = match instruction {
        IrInstruction::Const { destination, value } => {
            let value_type: &str = csharp_type_name(value_type(ir, *destination)?)?;
            format!(
                "{value_type} v{} = {};",
                destination.get(),
                csharp_i64(*value)
            )
        }
        IrInstruction::LoadArgument { destination, index } => {
            let value_type: &str = csharp_type_name(value_type(ir, *destination)?)?;
            format!("{value_type} v{} = arg{index};", destination.get())
        }
        IrInstruction::StoreArgument { index, value } => {
            format!("arg{index} = v{};", value.get())
        }
        IrInstruction::LoadLocal { destination, index } => {
            let value_type: &str = csharp_type_name(value_type(ir, *destination)?)?;
            format!("{value_type} v{} = local{index};", destination.get())
        }
        IrInstruction::StoreLocal { index, value } => {
            format!("local{index} = v{};", value.get())
        }
        IrInstruction::Binary {
            destination,
            op,
            left,
            right,
        } => {
            let value_type: &str = csharp_type_name(value_type(ir, *destination)?)?;
            let expression: String = if op.is_comparison() {
                format!(
                    "(v{} {} v{}) ? 1 : 0",
                    left.get(),
                    csharp_binary_operator(*op),
                    right.get()
                )
            } else {
                format!(
                    "v{} {} v{}",
                    left.get(),
                    csharp_binary_operator(*op),
                    right.get()
                )
            };
            format!("{value_type} v{} = {expression};", destination.get())
        }
    };
    append_indented(output, 1, &line);
    Ok(())
}

fn append_cil_instruction(output: &mut String, instruction: &IrInstruction) {
    let line: String = match instruction {
        IrInstruction::Const { destination, value } => {
            format!("ldc.i8 {value} -> v{}", destination.get())
        }
        IrInstruction::LoadArgument { destination, index } => {
            format!("ldarg {index} -> v{}", destination.get())
        }
        IrInstruction::StoreArgument { index, value } => {
            format!("starg {index}, v{}", value.get())
        }
        IrInstruction::LoadLocal { destination, index } => {
            format!("ldloc {index} -> v{}", destination.get())
        }
        IrInstruction::StoreLocal { index, value } => {
            format!("stloc {index}, v{}", value.get())
        }
        IrInstruction::Binary {
            destination,
            op,
            left,
            right,
        } => format!(
            "{} v{}, v{} -> v{}",
            cil_binary_operator(*op),
            left.get(),
            right.get(),
            destination.get()
        ),
    };
    append_indented(output, 1, &line);
}

fn append_csharp_terminator(output: &mut String, terminator: &Terminator) {
    match terminator {
        Terminator::Br(target) => append_indented(output, 1, &format!("goto L{};", target.get())),
        Terminator::CondBr {
            condition,
            when_true,
            when_false,
        } => {
            append_indented(
                output,
                1,
                &format!("if (v{} != 0) goto L{};", condition.get(), when_true.get()),
            );
            append_indented(output, 1, &format!("goto L{};", when_false.get()));
        }
        Terminator::Ret(Some(value)) => {
            append_indented(output, 1, &format!("return v{};", value.get()));
        }
        Terminator::Ret(None) => append_indented(output, 1, "return;"),
    }
}

fn append_cil_terminator(output: &mut String, terminator: &Terminator) {
    let line: String = match terminator {
        Terminator::Br(target) => format!("br L{}", target.get()),
        Terminator::CondBr {
            condition,
            when_true,
            when_false,
        } => format!(
            "brtrue v{}, L{}, L{}",
            condition.get(),
            when_true.get(),
            when_false.get()
        ),
        Terminator::Ret(Some(value)) => format!("ret v{}", value.get()),
        Terminator::Ret(None) => "ret".to_owned(),
    };
    append_indented(output, 1, &line);
}

fn append_indented(output: &mut String, depth: usize, line: &str) {
    for _ in 0..depth {
        output.push_str("    ");
    }
    output.push_str(line);
    output.push('\n');
}

fn append_label(output: &mut String, block_id: BlockId) {
    output.push('L');
    output.push_str(&block_id.get().to_string());
    output.push_str(":\n");
}

fn value_type(ir: &DvIr, value: ValueId) -> Result<CilType, String> {
    ir.value_types
        .get(&value)
        .copied()
        .ok_or_else(|| "IR value type is missing".to_owned())
}

fn csharp_type_name(value_type: CilType) -> Result<&'static str, String> {
    match value_type {
        CilType::I4 => Ok("int"),
        CilType::I8 => Ok("long"),
        CilType::R4 => Ok("float"),
        CilType::R8 => Ok("double"),
        CilType::NativeInt => Ok("nint"),
        CilType::Ref => Ok("object"),
        CilType::Void => Ok("void"),
        CilType::Unknown => Err("IR value type is unknown".to_owned()),
    }
}

fn cil_type_name(value_type: CilType) -> Result<&'static str, String> {
    match value_type {
        CilType::I4 => Ok("int32"),
        CilType::I8 => Ok("int64"),
        CilType::R4 => Ok("float32"),
        CilType::R8 => Ok("float64"),
        CilType::NativeInt => Ok("native int"),
        CilType::Ref => Ok("object"),
        CilType::Void => Ok("void"),
        CilType::Unknown => Err("IR value type is unknown".to_owned()),
    }
}

const fn csharp_binary_operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Xor => "^",
        BinOp::Ceq => "==",
        BinOp::Clt => "<",
        BinOp::Cgt => ">",
    }
}

const fn cil_binary_operator(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Ceq => "ceq",
        BinOp::Clt => "clt",
        BinOp::Cgt => "cgt",
    }
}

fn csharp_i64(value: i64) -> String {
    if value == i64::MIN {
        return "long.MinValue".to_owned();
    }
    format!("{value}L")
}

fn unrecovered(reason: String) -> String {
    format!("/* unrecovered: {reason} */\n")
}
