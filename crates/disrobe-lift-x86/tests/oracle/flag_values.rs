use std::collections::{BTreeMap, BTreeSet};

use disrobe_sleigh::pcode::{PcodeOp, Space, Varnode};

use crate::evaluator::{Evaluation, ReferenceOp, evaluate, evaluate_reference};
use crate::machine::{
    ADJUST_BIT, CARRY_BIT, GPR_COUNT, IMAGE_BASE, MachineState, OVERFLOW_BIT, PARITY_BIT, SIGN_BIT,
    ZERO_BIT, flag_label,
};

const EDGE_VALUES: [u64; 19] = [
    0,
    1,
    2,
    9,
    0x0f,
    0x21,
    0x7f,
    0x80,
    0xff,
    0x7fff,
    0x8000,
    0xffff,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    u64::MAX,
    0x0123_4567_89ab_cdef,
];
const MEMORY_BYTES: usize = 0x2000;
const POINTER_BASE: u64 = IMAGE_BASE + 0x1000;
const ARITHMETIC_FLAGS: [(u64, u32); 6] = [
    (0x200, CARRY_BIT),
    (0x202, PARITY_BIT),
    (0x204, ADJUST_BIT),
    (0x206, ZERO_BIT),
    (0x207, SIGN_BIT),
    (0x20b, OVERFLOW_BIT),
];
const ALL_ARITHMETIC_FLAGS: u16 = (1 << CARRY_BIT)
    | (1 << PARITY_BIT)
    | (1 << ADJUST_BIT)
    | (1 << ZERO_BIT)
    | (1 << SIGN_BIT)
    | (1 << OVERFLOW_BIT);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FlagGrade {
    pub(crate) compared_states: usize,
    pub(crate) comparisons: usize,
    pub(crate) written: BTreeSet<u32>,
    pub(crate) graded: BTreeSet<u32>,
    pub(crate) disagreements: Vec<String>,
    pub(crate) unevaluated: BTreeMap<String, usize>,
}

pub(crate) fn parse_reference(text: &str) -> Result<Vec<ReferenceOp>, String> {
    if text == "none" {
        return Ok(Vec::new());
    }
    text.split(';').map(parse_operation).collect()
}

fn parse_operation(text: &str) -> Result<ReferenceOp, String> {
    let fields: Vec<&str> = text.split(' ').collect();
    let (Some(name), Some(output_text)): (Option<&&str>, Option<&&str>) =
        (fields.first(), fields.get(1))
    else {
        return Err(format!("malformed reference operation `{text}`"));
    };
    let output: Option<Varnode> = if *output_text == "-" {
        None
    } else {
        Some(parse_varnode(output_text)?)
    };
    let operands: &[&str] = fields.get(2..).unwrap_or_default();
    if name.starts_with("FLOAT_") || *name == "CALLOTHER" {
        return Ok(ReferenceOp::Opaque((*name).to_owned()));
    }
    if matches!(*name, "LOAD" | "STORE") {
        return parse_memory(name, output, operands, text);
    }
    let inputs: Vec<Varnode> = operands
        .iter()
        .map(|operand: &&str| parse_varnode(operand))
        .collect::<Result<Vec<Varnode>, String>>()?;
    let shape_error = || format!("unexpected operand shape in `{text}`");
    let result: Option<ReferenceOp> = match (*name, output, inputs.as_slice()) {
        ("POPCOUNT", Some(output), [input]) => Some(ReferenceOp::Popcount {
            output,
            input: *input,
        }),
        ("LZCOUNT", Some(output), [input]) => Some(ReferenceOp::LeadingZeroCount {
            output,
            input: *input,
        }),
        ("BRANCH", None, [target]) => Some(ReferenceOp::Pcode(PcodeOp::Branch { target: *target })),
        ("BRANCHIND", None, [target]) => Some(ReferenceOp::Pcode(PcodeOp::BranchIndirect {
            target: *target,
        })),
        ("CALL", None, [target]) => Some(ReferenceOp::Pcode(PcodeOp::Call { target: *target })),
        ("CALLIND", None, [target]) => Some(ReferenceOp::Pcode(PcodeOp::CallIndirect {
            target: *target,
        })),
        ("RETURN", None, [target]) => Some(ReferenceOp::Pcode(PcodeOp::Return {
            target: Some(*target),
        })),
        ("CBRANCH", None, [target, condition]) => Some(ReferenceOp::Pcode(PcodeOp::CBranch {
            target: *target,
            condition: *condition,
        })),
        (unary, Some(output), [input]) => unary_operation(unary, output, *input),
        (binary, Some(output), [left, right]) => binary_operation(binary, output, *left, *right),
        _ => None,
    };
    result.ok_or_else(shape_error)
}

fn parse_memory(
    name: &str,
    output: Option<Varnode>,
    operands: &[&str],
    text: &str,
) -> Result<ReferenceOp, String> {
    let (Some(space_name), Some(pointer_text)): (Option<&&str>, Option<&&str>) =
        (operands.first(), operands.get(1))
    else {
        return Err(format!(
            "memory operation without space and pointer `{text}`"
        ));
    };
    let space: Space = parse_space(space_name)?;
    let pointer: Varnode = parse_varnode(pointer_text)?;
    match (name, output, operands.get(2)) {
        ("LOAD", Some(output), None) => Ok(ReferenceOp::Pcode(PcodeOp::Load {
            output,
            space,
            pointer,
        })),
        ("STORE", None, Some(value_text)) => Ok(ReferenceOp::Pcode(PcodeOp::Store {
            space,
            pointer,
            value: parse_varnode(value_text)?,
        })),
        _ => Err(format!("unexpected memory operation shape `{text}`")),
    }
}

fn unary_operation(name: &str, output: Varnode, input: Varnode) -> Option<ReferenceOp> {
    let operation: PcodeOp = match name {
        "COPY" => PcodeOp::Copy { output, input },
        "INT_ZEXT" => PcodeOp::IntZext { output, input },
        "INT_SEXT" => PcodeOp::IntSext { output, input },
        "INT_NEGATE" => PcodeOp::IntNegate { output, input },
        "BOOL_NEGATE" => PcodeOp::BoolNegate { output, input },
        _ => return None,
    };
    Some(ReferenceOp::Pcode(operation))
}

fn binary_operation(
    name: &str,
    output: Varnode,
    left: Varnode,
    right: Varnode,
) -> Option<ReferenceOp> {
    let operation: PcodeOp = match name {
        "INT_ADD" => PcodeOp::IntAdd {
            output,
            left,
            right,
        },
        "INT_SUB" => PcodeOp::IntSub {
            output,
            left,
            right,
        },
        "INT_MULT" => PcodeOp::IntMult {
            output,
            left,
            right,
        },
        "INT_DIV" => PcodeOp::IntDiv {
            output,
            left,
            right,
        },
        "INT_REM" => PcodeOp::IntRem {
            output,
            left,
            right,
        },
        "INT_SDIV" => PcodeOp::IntSignedDiv {
            output,
            left,
            right,
        },
        "INT_SREM" => PcodeOp::IntSignedRem {
            output,
            left,
            right,
        },
        "INT_AND" => PcodeOp::IntAnd {
            output,
            left,
            right,
        },
        "INT_OR" => PcodeOp::IntOr {
            output,
            left,
            right,
        },
        "INT_XOR" => PcodeOp::IntXor {
            output,
            left,
            right,
        },
        "INT_CARRY" => PcodeOp::IntCarry {
            output,
            left,
            right,
        },
        "INT_SCARRY" => PcodeOp::IntSignedCarry {
            output,
            left,
            right,
        },
        "INT_SBORROW" => PcodeOp::IntSignedBorrow {
            output,
            left,
            right,
        },
        "INT_EQUAL" => PcodeOp::IntEqual {
            output,
            left,
            right,
        },
        "INT_NOTEQUAL" => PcodeOp::IntNotEqual {
            output,
            left,
            right,
        },
        "INT_LESS" => PcodeOp::IntLess {
            output,
            left,
            right,
        },
        "INT_LESSEQUAL" => PcodeOp::IntLessEqual {
            output,
            left,
            right,
        },
        "INT_SLESS" => PcodeOp::IntSignedLess {
            output,
            left,
            right,
        },
        "INT_SLESSEQUAL" => PcodeOp::IntSignedLessEqual {
            output,
            left,
            right,
        },
        "INT_LEFT" => PcodeOp::IntLeft {
            output,
            input: left,
            amount: right,
        },
        "INT_RIGHT" => PcodeOp::IntRight {
            output,
            input: left,
            amount: right,
        },
        "INT_SRIGHT" => PcodeOp::IntSignedRight {
            output,
            input: left,
            amount: right,
        },
        "BOOL_AND" => PcodeOp::BoolAnd {
            output,
            left,
            right,
        },
        "BOOL_OR" => PcodeOp::BoolOr {
            output,
            left,
            right,
        },
        "BOOL_XOR" => PcodeOp::BoolXor {
            output,
            left,
            right,
        },
        "SUBPIECE" => PcodeOp::Subpiece {
            output,
            input: left,
            byte_offset: right,
        },
        "PIECE" => PcodeOp::Piece {
            output,
            high: left,
            low: right,
        },
        _ => return None,
    };
    Some(ReferenceOp::Pcode(operation))
}

fn parse_space(text: &str) -> Result<Space, String> {
    match text {
        "const" => Ok(Space::Constant),
        "ram" => Ok(Space::Ram),
        "register" => Ok(Space::Register),
        "unique" => Ok(Space::Unique),
        other => Err(format!("unknown address space `{other}`")),
    }
}

fn parse_varnode(text: &str) -> Result<Varnode, String> {
    let mut parts: std::str::Split<'_, char> = text.split(':');
    let (Some(space_text), Some(offset_text), Some(size_text), None): (
        Option<&str>,
        Option<&str>,
        Option<&str>,
        Option<&str>,
    ) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(format!("malformed varnode `{text}`"));
    };
    let space: Space = parse_space(space_text)?;
    let offset: u64 = offset_text
        .strip_prefix("0x")
        .and_then(|digits: &str| u64::from_str_radix(digits, 16).ok())
        .ok_or_else(|| format!("malformed varnode offset `{text}`"))?;
    let size_bytes: u32 = size_text
        .parse::<u32>()
        .map_err(|error: std::num::ParseIntError| format!("varnode size `{text}`: {error}"))?;
    Ok(Varnode {
        offset,
        size_bytes,
        space,
    })
}

pub(crate) fn grade_flag_values(
    address: u64,
    next_address: u64,
    lifted: &[PcodeOp],
    reference: &[ReferenceOp],
) -> FlagGrade {
    let mut grade: FlagGrade = FlagGrade {
        written: written_flags(reference),
        ..FlagGrade::default()
    };
    for start in battery(address) {
        let lifted_outcome: Evaluation = evaluate(lifted, &start, next_address);
        let reference_outcome: Evaluation = evaluate_reference(reference, &start, next_address);
        match (lifted_outcome, reference_outcome) {
            (
                Evaluation::Completed(lifted_state, undefined),
                Evaluation::Completed(reference_state, _),
            ) => {
                grade.compared_states = grade.compared_states.saturating_add(1);
                compare_flags(
                    &mut grade,
                    address,
                    &start,
                    &lifted_state,
                    &reference_state,
                    &undefined,
                );
            }
            (Evaluation::Faulted, Evaluation::Faulted) => {
                *grade
                    .unevaluated
                    .entry("both fault".to_owned())
                    .or_insert(0) += 1;
            }
            (Evaluation::Unmodeled(reason), _) => {
                *grade
                    .unevaluated
                    .entry(format!("lifted: {reason}"))
                    .or_insert(0) += 1;
            }
            (_, Evaluation::Unmodeled(reason)) => {
                *grade
                    .unevaluated
                    .entry(format!("reference: {reason}"))
                    .or_insert(0) += 1;
            }
            (lifted_outcome, reference_outcome) => grade.disagreements.push(format!(
                "{address:#x} {}: lifted {} but reference {}",
                describe(&start),
                outcome_label(&lifted_outcome),
                outcome_label(&reference_outcome)
            )),
        }
    }
    grade
}

fn compare_flags(
    grade: &mut FlagGrade,
    address: u64,
    start: &MachineState,
    lifted: &MachineState,
    reference: &MachineState,
    undefined: &BTreeSet<u32>,
) {
    for (_, bit) in ARITHMETIC_FLAGS {
        if undefined.contains(&bit) || (bit == ADJUST_BIT && !grade.written.contains(&bit)) {
            continue;
        }
        grade.comparisons = grade.comparisons.saturating_add(1);
        if grade.written.contains(&bit) {
            let _: bool = grade.graded.insert(bit);
        }
        let lifted_value: u16 = lifted.flags.checked_shr(bit).unwrap_or(0) & 1;
        let reference_value: u16 = reference.flags.checked_shr(bit).unwrap_or(0) & 1;
        if lifted_value != reference_value {
            grade.disagreements.push(format!(
                "{address:#x} {} {}: lifted {lifted_value}, reference {reference_value}",
                flag_label(bit),
                describe(start)
            ));
        }
    }
}

fn written_flags(reference: &[ReferenceOp]) -> BTreeSet<u32> {
    let mut written: BTreeSet<u32> = BTreeSet::new();
    for operation in reference {
        let output: Option<Varnode> = match operation {
            ReferenceOp::Popcount { output, .. } | ReferenceOp::LeadingZeroCount { output, .. } => {
                Some(*output)
            }
            ReferenceOp::Pcode(pcode) => pcode_output(pcode),
            ReferenceOp::Opaque(_) => None,
        };
        let Some(node): Option<Varnode> = output else {
            continue;
        };
        if node.space != Space::Register || node.size_bytes != 1 {
            continue;
        }
        if let Some((_, bit)) = ARITHMETIC_FLAGS
            .iter()
            .find(|(offset, _): &&(u64, u32)| *offset == node.offset)
        {
            let _: bool = written.insert(*bit);
        }
    }
    written
}

const fn pcode_output(operation: &PcodeOp) -> Option<Varnode> {
    match operation {
        PcodeOp::BoolAnd { output, .. }
        | PcodeOp::BoolNegate { output, .. }
        | PcodeOp::BoolOr { output, .. }
        | PcodeOp::BoolXor { output, .. }
        | PcodeOp::Copy { output, .. }
        | PcodeOp::FloatAdd { output, .. }
        | PcodeOp::FloatDiv { output, .. }
        | PcodeOp::FloatEqual { output, .. }
        | PcodeOp::FloatLess { output, .. }
        | PcodeOp::FloatLessEqual { output, .. }
        | PcodeOp::FloatMult { output, .. }
        | PcodeOp::FloatSqrt { output, .. }
        | PcodeOp::FloatSub { output, .. }
        | PcodeOp::FloatToFloat { output, .. }
        | PcodeOp::FloatTrunc { output, .. }
        | PcodeOp::IntToFloat { output, .. }
        | PcodeOp::IntAdd { output, .. }
        | PcodeOp::IntAnd { output, .. }
        | PcodeOp::IntCarry { output, .. }
        | PcodeOp::IntDiv { output, .. }
        | PcodeOp::IntEqual { output, .. }
        | PcodeOp::IntLeft { output, .. }
        | PcodeOp::IntLess { output, .. }
        | PcodeOp::IntLessEqual { output, .. }
        | PcodeOp::IntMult { output, .. }
        | PcodeOp::IntNegate { output, .. }
        | PcodeOp::IntNotEqual { output, .. }
        | PcodeOp::IntOr { output, .. }
        | PcodeOp::IntRem { output, .. }
        | PcodeOp::IntRight { output, .. }
        | PcodeOp::IntSignedBorrow { output, .. }
        | PcodeOp::IntSignedCarry { output, .. }
        | PcodeOp::IntSignedDiv { output, .. }
        | PcodeOp::IntSignedLess { output, .. }
        | PcodeOp::IntSignedLessEqual { output, .. }
        | PcodeOp::IntSignedRem { output, .. }
        | PcodeOp::IntSignedRight { output, .. }
        | PcodeOp::IntSub { output, .. }
        | PcodeOp::IntXor { output, .. }
        | PcodeOp::IntSext { output, .. }
        | PcodeOp::IntZext { output, .. }
        | PcodeOp::Load { output, .. }
        | PcodeOp::Piece { output, .. }
        | PcodeOp::Subpiece { output, .. } => Some(*output),
        PcodeOp::CallOther { output, .. } => *output,
        PcodeOp::Branch { .. }
        | PcodeOp::BranchIndirect { .. }
        | PcodeOp::CBranch { .. }
        | PcodeOp::Call { .. }
        | PcodeOp::CallIndirect { .. }
        | PcodeOp::Return { .. }
        | PcodeOp::Store { .. } => None,
    }
}

fn battery(address: u64) -> Vec<MachineState> {
    let memory: Vec<u8> = patterned_memory();
    let count: usize = EDGE_VALUES.len();
    let mut states: Vec<MachineState> = Vec::with_capacity(count * count * 4);
    for pointers in [false, true] {
        for flags in [0, ALL_ARITHMETIC_FLAGS] {
            for row in 0..count {
                for stride in 0..count {
                    let mut state: MachineState = MachineState::new(memory.clone());
                    state.rip = address;
                    state.flags = flags;
                    for (index, slot) in state.registers.iter_mut().enumerate() {
                        let position: usize = (row + index * stride) % count;
                        *slot = if pointers {
                            POINTER_BASE + (position as u64) * 8
                        } else {
                            EDGE_VALUES[position]
                        };
                    }
                    states.push(state);
                }
            }
        }
    }
    states
}

fn patterned_memory() -> Vec<u8> {
    let mut memory: Vec<u8> = vec![0; MEMORY_BYTES];
    for (word, chunk) in memory.chunks_mut(8).enumerate() {
        let value: u64 = EDGE_VALUES[word % EDGE_VALUES.len()];
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }
    memory
}

fn describe(state: &MachineState) -> String {
    let registers: Vec<String> = (0..GPR_COUNT)
        .map(|index: usize| format!("r{index}={:#x}", state.registers[index]))
        .collect();
    format!("flags={:#x} {}", state.flags, registers.join(" "))
}

const fn outcome_label(outcome: &Evaluation) -> &'static str {
    match outcome {
        Evaluation::Completed(..) => "completed",
        Evaluation::Faulted => "faulted",
        Evaluation::Unmodeled(_) => "was unmodeled",
    }
}
