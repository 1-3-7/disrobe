#![allow(clippy::panic)]

use std::collections::BTreeMap;

use disrobe_pass_dotnet::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use disrobe_pass_dotnet::cil_emulator::{StubInput, StubOutput, emulate_stub};
use disrobe_pass_dotnet::devirt::oracle::{
    Divergence, FirstDiff, OracleReport, Outcome, SkipCause, check_against_reference,
    check_lowered_against_reference, dvir_to_method_body,
};
use disrobe_pass_dotnet::devirt::{
    BasicBlock, BinOp, Budget, DvIr, IrInstruction, OperandEncoding, PrimitiveEffect,
    SyntheticHandler, SyntheticVmModel, Terminator, VInstr, ValueId, VmFlavor, devirtualize,
};

const fn handler(
    effects: Vec<PrimitiveEffect>,
    operand_encoding: OperandEncoding,
) -> SyntheticHandler {
    SyntheticHandler::new(effects, operand_encoding)
}

fn recovered_model() -> SyntheticVmModel {
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
            handler(vec![PrimitiveEffect::PushOperandI64], OperandEncoding::I64),
        ),
        (
            5,
            handler(
                vec![PrimitiveEffect::Binary(BinOp::Xor)],
                OperandEncoding::None,
            ),
        ),
        (
            6,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![
        VInstr::new(1, Vec::new()),
        VInstr::new(2, Vec::new()),
        VInstr::new(3, Vec::new()),
        VInstr::new(4, 0x5a_i64.to_le_bytes().to_vec()),
        VInstr::new(5, Vec::new()),
        VInstr::new(6, Vec::new()),
    ];
    SyntheticVmModel::new(VmFlavor::Stack, 2, 0, handlers, instructions)
}

fn rejected_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        7,
        handler(vec![PrimitiveEffect::Opaque], OperandEncoding::None),
    )]);
    SyntheticVmModel::new(
        VmFlavor::Stack,
        0,
        0,
        handlers,
        vec![VInstr::new(7, Vec::new())],
    )
}

fn instruction(offset: u32, name: &str, operand: OperandValue, flow: FlowControl) -> Instruction {
    Instruction {
        offset,
        opcode: 0,
        name: name.to_owned(),
        operand,
        flow,
    }
}

const fn body(instructions: Vec<Instruction>) -> MethodBody {
    MethodBody {
        max_stack: 8,
        code_size: instructions.len() as u32,
        local_var_sig_tok: 0,
        init_locals: true,
        instructions,
        exception_clauses: Vec::new(),
    }
}

fn known_original() -> MethodBody {
    body(vec![
        instruction(0, "ldarg.0", OperandValue::None, FlowControl::Next),
        instruction(1, "ldarg.1", OperandValue::None, FlowControl::Next),
        instruction(2, "add", OperandValue::None, FlowControl::Next),
        instruction(3, "ldc.i4.s", OperandValue::U8(0x5a), FlowControl::Next),
        instruction(4, "xor", OperandValue::None, FlowControl::Next),
        instruction(5, "ret", OperandValue::None, FlowControl::Return),
    ])
}

#[test]
fn matching_integer_xor_model_is_equivalent_to_known_original() {
    let model: SyntheticVmModel = recovered_model();
    let reference_body: MethodBody = known_original();
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_against_reference(&model, &reference_body, &mut budget);

    assert!(matches!(
        report.outcome,
        Outcome::Equivalent { samples } if samples > 0
    ));
    assert_eq!(report.equivalent, 1);
    assert_eq!(report.failed, 0);
}

#[test]
fn refused_model_is_reported_as_rejected() {
    let model: SyntheticVmModel = rejected_model();
    let reference_body: MethodBody = known_original();
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_against_reference(&model, &reference_body, &mut budget);

    assert!(matches!(report.outcome, Outcome::Rejected(_)));
    assert_eq!(report.equivalent, 0);
    assert_eq!(report.failed, 0);
}

#[test]
fn external_reference_is_skipped_instead_of_equivalent() {
    let model: SyntheticVmModel = recovered_model();
    let reference_body: MethodBody = body(vec![
        instruction(0, "ldc.i4.0", OperandValue::None, FlowControl::Next),
        instruction(
            1,
            "call",
            OperandValue::Token(0x0a00_0001),
            FlowControl::Call,
        ),
        instruction(2, "ret", OperandValue::None, FlowControl::Return),
    ]);
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_against_reference(&model, &reference_body, &mut budget);

    assert!(matches!(
        report.outcome,
        Outcome::Skipped(SkipCause::UnsupportedOp)
    ));
    assert_eq!(report.equivalent, 0);
    assert_eq!(report.failed, 0);
}

#[test]
fn mutated_recovered_addition_produces_a_return_witness() {
    let model: SyntheticVmModel = recovered_model();
    let mut lowering_budget: Budget = Budget::new(10_000);
    let recovered: MethodBody = match devirtualize(&model, &mut lowering_budget) {
        Ok(ir) => dvir_to_method_body(&ir),
        Err(reject) => {
            panic!("model must lower for mutation test: {reject}");
        }
    };
    let mut mutated: MethodBody = recovered.clone();
    assert_eq!(recovered, mutated);
    let Some(add): Option<&mut Instruction> = mutated
        .instructions
        .iter_mut()
        .find(|instruction: &&mut Instruction| instruction.name == "add")
    else {
        panic!("lowered method must contain add");
    };
    add.name = "sub".to_owned();
    let reference_body: MethodBody = known_original();
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport =
        check_lowered_against_reference(&model, &mutated, &reference_body, &mut budget);

    let divergence: Divergence = match report.outcome {
        Outcome::Failed(divergence) => divergence,
        other => {
            panic!("expected divergence, got {other:?}");
        }
    };
    assert_eq!(divergence.first_diff, FirstDiff::ReturnValue);
    assert_eq!(report.equivalent, 0);
    assert_eq!(report.failed, 1);
}

#[test]
fn i8_arithmetic_reference_is_skipped() {
    let model: SyntheticVmModel = recovered_model();
    let reference_body: MethodBody = body(vec![
        instruction(0, "ldarg.0", OperandValue::None, FlowControl::Next),
        instruction(1, "ldc.i8", OperandValue::I64(0), FlowControl::Next),
        instruction(2, "add", OperandValue::None, FlowControl::Next),
        instruction(3, "ret", OperandValue::None, FlowControl::Return),
    ]);
    let mut budget: Budget = Budget::new(10_000);

    let report: OracleReport = check_against_reference(&model, &reference_body, &mut budget);

    assert!(matches!(
        report.outcome,
        Outcome::Skipped(SkipCause::I8Arithmetic)
    ));
    assert_eq!(report.equivalent, 0);
    assert_eq!(report.failed, 0);
}

#[test]
fn lowered_conditional_branch_uses_real_cil_targets() {
    let ir: DvIr = DvIr::new(
        1,
        0,
        vec![
            BasicBlock::new(
                0,
                vec![
                    IrInstruction::LoadArgument {
                        destination: ValueId::new(0),
                        index: 0,
                    },
                    IrInstruction::Const {
                        destination: ValueId::new(1),
                        value: 0,
                    },
                    IrInstruction::Binary {
                        destination: ValueId::new(2),
                        op: BinOp::Cgt,
                        left: ValueId::new(0),
                        right: ValueId::new(1),
                    },
                ],
                Terminator::CondBr {
                    condition: ValueId::new(2),
                    when_true: disrobe_pass_dotnet::devirt::BlockId::new(1),
                    when_false: disrobe_pass_dotnet::devirt::BlockId::new(2),
                },
            ),
            BasicBlock::new(
                1,
                vec![IrInstruction::Const {
                    destination: ValueId::new(3),
                    value: 1,
                }],
                Terminator::Ret(Some(ValueId::new(3))),
            ),
            BasicBlock::new(
                2,
                vec![IrInstruction::Const {
                    destination: ValueId::new(4),
                    value: -1,
                }],
                Terminator::Ret(Some(ValueId::new(4))),
            ),
        ],
    );
    let lowered: MethodBody = dvir_to_method_body(&ir);
    let positive: StubInput = StubInput {
        int_args: vec![1],
        byte_array_args: Vec::new(),
        char_array_args: Vec::new(),
    };
    let negative: StubInput = StubInput {
        int_args: vec![-1],
        byte_array_args: Vec::new(),
        char_array_args: Vec::new(),
    };

    assert_eq!(emulate_stub(&lowered, &positive), Ok(StubOutput::Int(1)));
    assert_eq!(emulate_stub(&lowered, &negative), Ok(StubOutput::Int(-1)));
}
