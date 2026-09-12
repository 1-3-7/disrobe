#![allow(clippy::panic)]

use std::collections::BTreeMap;

use disrobe_pass_dotnet::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use disrobe_pass_dotnet::devirt::oracle::{
    Divergence, FirstDiff, OracleReport, Outcome, SkipCause, check_against_model,
    check_lowered_against_model, dvir_to_method_body,
};
use disrobe_pass_dotnet::devirt::{
    BinOp, Budget, OperandEncoding, PrimitiveEffect, SyntheticHandler, SyntheticVmModel, VInstr,
    VmFlavor, devirtualize,
};

const fn handler(
    effects: Vec<PrimitiveEffect>,
    operand_encoding: OperandEncoding,
) -> SyntheticHandler {
    SyntheticHandler::new(effects, operand_encoding)
}

fn add_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::PushArgument(0)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(
                vec![PrimitiveEffect::PushArgument(1)],
                OperandEncoding::None,
            ),
        ),
        (
            3,
            handler(
                vec![PrimitiveEffect::Binary(BinOp::Add)],
                OperandEncoding::None,
            ),
        ),
        (
            4,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![
        VInstr::new(1, Vec::new()),
        VInstr::new(2, Vec::new()),
        VInstr::new(3, Vec::new()),
        VInstr::new(4, Vec::new()),
    ];
    SyntheticVmModel::new(VmFlavor::Stack, 2, 0, handlers, instructions)
}

fn sub_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::PushArgument(0)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(
                vec![PrimitiveEffect::PushArgument(1)],
                OperandEncoding::None,
            ),
        ),
        (
            3,
            handler(
                vec![PrimitiveEffect::Binary(BinOp::Sub)],
                OperandEncoding::None,
            ),
        ),
        (
            4,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![
        VInstr::new(1, Vec::new()),
        VInstr::new(2, Vec::new()),
        VInstr::new(3, Vec::new()),
        VInstr::new(4, Vec::new()),
    ];
    SyntheticVmModel::new(VmFlavor::Stack, 2, 0, handlers, instructions)
}

fn branch_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::PushArgument(0)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(vec![PrimitiveEffect::PushConst(0)], OperandEncoding::None),
        ),
        (
            3,
            handler(
                vec![PrimitiveEffect::Binary(BinOp::Cgt)],
                OperandEncoding::None,
            ),
        ),
        (
            4,
            handler(vec![PrimitiveEffect::BranchIfTrue], OperandEncoding::Target),
        ),
        (
            5,
            handler(vec![PrimitiveEffect::PushConst(-1)], OperandEncoding::None),
        ),
        (
            6,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
        (
            7,
            handler(vec![PrimitiveEffect::PushConst(1)], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![
        VInstr::new(1, Vec::new()),
        VInstr::new(2, Vec::new()),
        VInstr::new(3, Vec::new()),
        VInstr::new(4, 6_u32.to_le_bytes().to_vec()),
        VInstr::new(5, Vec::new()),
        VInstr::new(6, Vec::new()),
        VInstr::new(7, Vec::new()),
        VInstr::new(6, Vec::new()),
    ];
    SyntheticVmModel::new(VmFlavor::Stack, 1, 0, handlers, instructions)
}

fn load_second_argument_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::PushArgument(1)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![VInstr::new(1, Vec::new()), VInstr::new(2, Vec::new())];
    SyntheticVmModel::new(VmFlavor::Stack, 2, 0, handlers, instructions)
}

fn load_third_of_five_arguments_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::PushArgument(2)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![VInstr::new(1, Vec::new()), VInstr::new(2, Vec::new())];
    SyntheticVmModel::new(VmFlavor::Stack, 5, 0, handlers, instructions)
}

fn wrapping_add_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::PushArgument(0)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(vec![PrimitiveEffect::PushConst(1)], OperandEncoding::None),
        ),
        (
            3,
            handler(
                vec![PrimitiveEffect::Binary(BinOp::Add)],
                OperandEncoding::None,
            ),
        ),
        (
            4,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![
        VInstr::new(1, Vec::new()),
        VInstr::new(2, Vec::new()),
        VInstr::new(3, Vec::new()),
        VInstr::new(4, Vec::new()),
    ];
    SyntheticVmModel::new(VmFlavor::Stack, 1, 0, handlers, instructions)
}

fn opaque_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        1,
        handler(vec![PrimitiveEffect::Opaque], OperandEncoding::None),
    )]);
    let instructions: Vec<VInstr> = vec![VInstr::new(1, Vec::new())];
    SyntheticVmModel::new(VmFlavor::Stack, 0, 0, handlers, instructions)
}

fn lowered(model: &SyntheticVmModel) -> MethodBody {
    let mut budget: Budget = Budget::new(10_000);
    match devirtualize(model, &mut budget) {
        Ok(ir) => dvir_to_method_body(&ir),
        Err(reject) => panic!("model must lower for mutation test: {reject}"),
    }
}

fn binary_instruction_index(body: &MethodBody, name: &str) -> usize {
    body.instructions
        .iter()
        .position(|instruction: &Instruction| instruction.name == name)
        .unwrap_or_else(|| panic!("lowered method must contain {name}"))
}

fn failure(report: OracleReport) -> Divergence {
    match report.outcome {
        Outcome::Failed(divergence) => divergence,
        outcome => panic!("expected return divergence, got {outcome:?}"),
    }
}

fn assert_return_divergence(report: OracleReport) {
    let divergence: Divergence = failure(report);
    assert_eq!(divergence.first_diff, FirstDiff::ReturnValue);
}

#[test]
fn model_reference_detects_addition_lowered_as_subtraction() {
    let model: SyntheticVmModel = add_model();
    let mut mutated: MethodBody = lowered(&model);
    let binary_index: usize = binary_instruction_index(&mutated, "add");
    mutated.instructions[binary_index].name = "sub".to_owned();
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_lowered_against_model(&model, &mutated, &mut budget);

    assert_return_divergence(report);
}

#[test]
fn model_reference_detects_subtraction_operand_order_swap() {
    let model: SyntheticVmModel = sub_model();
    let mut mutated: MethodBody = lowered(&model);
    let binary_index: usize = binary_instruction_index(&mutated, "sub");
    let left_operand: OperandValue = mutated.instructions[binary_index - 2].operand.clone();
    let right_operand: OperandValue = mutated.instructions[binary_index - 1].operand.clone();
    mutated.instructions[binary_index - 2].operand = right_operand;
    mutated.instructions[binary_index - 1].operand = left_operand;
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_lowered_against_model(&model, &mutated, &mut budget);

    assert_return_divergence(report);
}

#[test]
fn model_reference_detects_inverted_branch_condition() {
    let model: SyntheticVmModel = branch_model();
    let mut mutated: MethodBody = lowered(&model);
    let branch_index: usize = binary_instruction_index(&mutated, "brtrue");
    mutated.instructions[branch_index].name = "brfalse".to_owned();
    mutated.instructions[branch_index].flow = FlowControl::CondBranch;
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_lowered_against_model(&model, &mutated, &mut budget);

    assert_return_divergence(report);
}

#[test]
fn model_reference_detects_argument_load_off_by_one() {
    let model: SyntheticVmModel = load_second_argument_model();
    let mut mutated: MethodBody = lowered(&model);
    mutated.instructions[0].operand = OperandValue::U16(0);
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_lowered_against_model(&model, &mutated, &mut budget);

    assert_return_divergence(report);
}

#[test]
fn model_reference_distinguishes_every_argument_slot_within_the_sample_cap() {
    let model: SyntheticVmModel = load_third_of_five_arguments_model();
    let mut mutated: MethodBody = lowered(&model);
    mutated.instructions[0].operand = OperandValue::U16(4);
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_lowered_against_model(&model, &mutated, &mut budget);

    assert_return_divergence(report);
}

#[test]
fn model_reference_detects_widened_wrapping_result() {
    let model: SyntheticVmModel = wrapping_add_model();
    let mut mutated: MethodBody = lowered(&model);
    let binary_index: usize = binary_instruction_index(&mutated, "add");
    let conversion: Instruction = Instruction {
        offset: 0,
        opcode: 0,
        name: "conv.u8".to_owned(),
        operand: OperandValue::None,
        flow: FlowControl::Next,
    };
    mutated.instructions.insert(binary_index + 1, conversion);
    for (index, instruction) in mutated.instructions.iter_mut().enumerate() {
        instruction.offset = u32::try_from(index).unwrap_or(u32::MAX);
    }
    mutated.code_size = u32::try_from(mutated.instructions.len()).unwrap_or(u32::MAX);
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_lowered_against_model(&model, &mutated, &mut budget);
    let divergence: Divergence = failure(report);

    assert_eq!(divergence.first_diff, FirstDiff::ReturnValue);
    assert_eq!(divergence.input.int_args, vec![i64::from(i32::MIN)]);
}

#[test]
fn model_reference_skips_opaque_effects() {
    let model: SyntheticVmModel = opaque_model();
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_against_model(&model, &mut budget);

    assert!(matches!(
        report.outcome,
        Outcome::Skipped(SkipCause::OpaqueEffect)
    ));
    assert_eq!(report.skipped, 1);
}

#[test]
fn model_reference_matches_unmutated_model_without_skips() {
    let model: SyntheticVmModel = add_model();
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_against_model(&model, &mut budget);

    assert!(matches!(
        report.outcome,
        Outcome::Equivalent { samples } if samples > 0
    ));
    assert_eq!(report.skipped, 0);
    assert_eq!(report.failed, 0);
}
