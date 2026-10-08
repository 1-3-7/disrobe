use crate::cil::{
    FlowControl, Instruction, MethodBody, ONE_BYTE_OPCODES, OpcodeDef, OperandKind, OperandValue,
    TWO_BYTE_OPCODES,
};

pub(crate) const MAX_REBUILT_INSTRUCTIONS: usize = 65_536;

#[must_use]
pub(crate) fn opcode(name: &str) -> Option<&'static OpcodeDef> {
    ONE_BYTE_OPCODES
        .iter()
        .chain(TWO_BYTE_OPCODES.iter())
        .find(|def: &&OpcodeDef| def.name == name)
}

#[must_use]
pub(crate) fn instruction(name: &str, operand: OperandValue) -> Option<Instruction> {
    let def: &OpcodeDef = opcode(name)?;
    Some(Instruction {
        offset: 0,
        opcode: def.code,
        name: def.name.to_owned(),
        operand,
        flow: def.flow,
    })
}

pub(crate) fn nop_in_place(ins: &mut Instruction) {
    ins.opcode = 0;
    "nop".clone_into(&mut ins.name);
    ins.operand = OperandValue::None;
    ins.flow = FlowControl::Next;
}

pub(crate) fn replace_in_place(ins: &mut Instruction, name: &str, operand: OperandValue) -> bool {
    let Some(def): Option<&OpcodeDef> = opcode(name) else {
        return false;
    };
    ins.opcode = def.code;
    def.name.clone_into(&mut ins.name);
    ins.operand = operand;
    ins.flow = def.flow;
    true
}

#[must_use]
pub(crate) fn int_literal(ins: &Instruction) -> Option<i64> {
    crate::peel::deflatten::blocks::int_literal(ins)
}

#[must_use]
pub(crate) fn absolute_target(body: &MethodBody, index: usize) -> Option<u32> {
    let ins: &Instruction = body.instructions.get(index)?;
    let OperandValue::BrTarget(rel) = ins.operand else {
        return None;
    };
    let next: u32 = body
        .instructions
        .get(index.checked_add(1)?)
        .map_or(body.code_size, |n: &Instruction| n.offset);
    u32::try_from(i64::from(next).checked_add(i64::from(rel))?).ok()
}

#[must_use]
pub(crate) fn unreachable_indices(body: &MethodBody) -> Vec<usize> {
    let count: usize = body.instructions.len();
    if count == 0 {
        return Vec::new();
    }
    let index_of = |offset: u32| -> Option<usize> {
        body.instructions
            .binary_search_by_key(&offset, |i: &Instruction| i.offset)
            .ok()
    };
    let mut reachable: Vec<bool> = vec![false; count];
    let mut work: Vec<usize> = vec![0];
    for clause in &body.exception_clauses {
        if let Some(handler) = index_of(clause.handler_offset) {
            work.push(handler);
        }
        if clause.kind == crate::cil::ExceptionClauseKind::Filter
            && let Some(filter) = index_of(clause.class_token_or_filter)
        {
            work.push(filter);
        }
    }
    let mut steps: usize = 0;
    while let Some(index) = work.pop() {
        steps += 1;
        if steps > MAX_REBUILT_INSTRUCTIONS.saturating_mul(4) {
            break;
        }
        if index >= count || reachable[index] {
            continue;
        }
        reachable[index] = true;
        let ins: &Instruction = &body.instructions[index];
        match ins.flow {
            FlowControl::Return | FlowControl::Throw => {}
            FlowControl::Branch => {
                if let Some(target) = absolute_target(body, index).and_then(index_of) {
                    work.push(target);
                }
            }
            FlowControl::CondBranch => {
                if let OperandValue::Switch(targets) = &ins.operand {
                    let next: u32 = body
                        .instructions
                        .get(index + 1)
                        .map_or(body.code_size, |n: &Instruction| n.offset);
                    for rel in targets {
                        if let Some(t) = u32::try_from(i64::from(next) + i64::from(*rel))
                            .ok()
                            .and_then(index_of)
                        {
                            work.push(t);
                        }
                    }
                } else if let Some(target) = absolute_target(body, index).and_then(index_of) {
                    work.push(target);
                }
                work.push(index + 1);
            }
            FlowControl::Next | FlowControl::Call | FlowControl::Break | FlowControl::Meta => {
                work.push(index + 1);
            }
        }
    }
    reachable
        .iter()
        .enumerate()
        .filter(|(_, r): &(usize, &bool)| !**r)
        .map(|(i, _): (usize, &bool)| i)
        .collect()
}

#[must_use]
pub(crate) fn long_branch_name(name: &str) -> &str {
    name.strip_suffix(".s").unwrap_or(name)
}

fn encoded_size(ins: &Instruction) -> Option<u32> {
    let def: &OpcodeDef = crate::cil::lookup(ins.opcode)?;
    let operand: u32 = match def.operand {
        OperandKind::InlineNone => 0,
        OperandKind::InlineShortI
        | OperandKind::InlineShortVar
        | OperandKind::InlineShortBrTarget => 1,
        OperandKind::InlineVar => 2,
        OperandKind::InlineI
        | OperandKind::InlineMethod
        | OperandKind::InlineField
        | OperandKind::InlineType
        | OperandKind::InlineString
        | OperandKind::InlineSig
        | OperandKind::InlineTok
        | OperandKind::InlineShortR
        | OperandKind::InlineBrTarget => 4,
        OperandKind::InlineI8 | OperandKind::InlineR => 8,
        OperandKind::InlineSwitch => match &ins.operand {
            OperandValue::Switch(targets) => {
                4u32.checked_add(u32::try_from(targets.len()).ok()?.checked_mul(4)?)?
            }
            _ => return None,
        },
    };
    u32::from(def.size).checked_add(operand)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Terminator {
    Goto(usize),
    Cond {
        opcode: String,
        taken: usize,
        fallthrough: usize,
    },
    None,
}

#[derive(Debug, Clone)]
pub(crate) struct EmitBlock {
    pub(crate) instructions: Vec<Instruction>,
    pub(crate) terminator: Terminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssembleError {
    TooManyInstructions,
    UnknownOpcode,
    DanglingLabel,
    OffsetOverflow,
}

#[derive(Debug, Clone, Copy)]
enum Pending {
    Branch { target_block: usize },
}

pub(crate) fn assemble(
    template: &MethodBody,
    blocks: &[EmitBlock],
) -> Result<MethodBody, AssembleError> {
    let mut out: Vec<Instruction> = Vec::new();
    let mut pending: Vec<(usize, Pending)> = Vec::new();
    let mut block_offsets: Vec<u32> = Vec::with_capacity(blocks.len());
    let mut cursor: u32 = 0;
    for (block_index, block) in blocks.iter().enumerate() {
        let next_block: usize = block_index + 1;
        block_offsets.push(cursor);
        for ins in &block.instructions {
            if out.len() >= MAX_REBUILT_INSTRUCTIONS {
                return Err(AssembleError::TooManyInstructions);
            }
            let mut copy: Instruction = ins.clone();
            copy.offset = cursor;
            let size: u32 = encoded_size(&copy).ok_or(AssembleError::UnknownOpcode)?;
            cursor = cursor
                .checked_add(size)
                .ok_or(AssembleError::OffsetOverflow)?;
            out.push(copy);
        }
        match &block.terminator {
            Terminator::None => {}
            Terminator::Goto(target) if *target == next_block => {}
            Terminator::Goto(target) => {
                let mut br: Instruction = instruction("br", OperandValue::BrTarget(0))
                    .ok_or(AssembleError::UnknownOpcode)?;
                br.offset = cursor;
                cursor = cursor.checked_add(5).ok_or(AssembleError::OffsetOverflow)?;
                pending.push((
                    out.len(),
                    Pending::Branch {
                        target_block: *target,
                    },
                ));
                out.push(br);
            }
            Terminator::Cond {
                opcode,
                taken,
                fallthrough,
            } => {
                let long: &str = long_branch_name(opcode);
                let mut cond: Instruction = instruction(long, OperandValue::BrTarget(0))
                    .ok_or(AssembleError::UnknownOpcode)?;
                cond.offset = cursor;
                cursor = cursor.checked_add(5).ok_or(AssembleError::OffsetOverflow)?;
                pending.push((
                    out.len(),
                    Pending::Branch {
                        target_block: *taken,
                    },
                ));
                out.push(cond);
                if *fallthrough != next_block {
                    let mut br: Instruction = instruction("br", OperandValue::BrTarget(0))
                        .ok_or(AssembleError::UnknownOpcode)?;
                    br.offset = cursor;
                    cursor = cursor.checked_add(5).ok_or(AssembleError::OffsetOverflow)?;
                    pending.push((
                        out.len(),
                        Pending::Branch {
                            target_block: *fallthrough,
                        },
                    ));
                    out.push(br);
                }
            }
        }
        if out.len() > MAX_REBUILT_INSTRUCTIONS {
            return Err(AssembleError::TooManyInstructions);
        }
    }
    for (index, Pending::Branch { target_block }) in pending {
        let target: u32 = *block_offsets
            .get(target_block)
            .ok_or(AssembleError::DanglingLabel)?;
        let own: u32 = out[index].offset;
        let next: i64 = i64::from(own) + 5;
        let rel: i32 =
            i32::try_from(i64::from(target) - next).map_err(|_| AssembleError::OffsetOverflow)?;
        out[index].operand = OperandValue::BrTarget(rel);
    }
    Ok(MethodBody {
        max_stack: template.max_stack,
        code_size: cursor,
        local_var_sig_tok: template.local_var_sig_tok,
        init_locals: template.init_locals,
        instructions: out,
        exception_clauses: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn template() -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: 0,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: Vec::new(),
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn assembled_branches_point_at_block_starts() {
        let blocks: Vec<EmitBlock> = vec![
            EmitBlock {
                instructions: vec![instruction("ldarg.0", OperandValue::None).unwrap()],
                terminator: Terminator::Cond {
                    opcode: "brtrue.s".to_owned(),
                    taken: 2,
                    fallthrough: 1,
                },
            },
            EmitBlock {
                instructions: vec![instruction("ldc.i4.0", OperandValue::None).unwrap()],
                terminator: Terminator::Goto(3),
            },
            EmitBlock {
                instructions: vec![instruction("ldc.i4.1", OperandValue::None).unwrap()],
                terminator: Terminator::Goto(3),
            },
            EmitBlock {
                instructions: vec![instruction("ret", OperandValue::None).unwrap()],
                terminator: Terminator::None,
            },
        ];
        let body: MethodBody = assemble(&template(), &blocks).expect("assemble");
        let names: Vec<&str> = body
            .instructions
            .iter()
            .map(|i: &Instruction| i.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["ldarg.0", "brtrue", "ldc.i4.0", "br", "ldc.i4.1", "ret"]
        );
        assert_eq!(absolute_target(&body, 1), Some(body.instructions[4].offset));
        assert_eq!(absolute_target(&body, 3), Some(body.instructions[5].offset));
        assert_eq!(body.code_size, body.instructions[5].offset + 1);
    }

    #[test]
    fn a_label_outside_the_block_list_is_refused() {
        let blocks: Vec<EmitBlock> = vec![EmitBlock {
            instructions: Vec::new(),
            terminator: Terminator::Goto(7),
        }];
        assert_eq!(
            assemble(&template(), &blocks).err(),
            Some(AssembleError::DanglingLabel)
        );
    }
}
