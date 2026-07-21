use std::collections::BTreeMap;

use disrobe_pass_dotnet::devirt::{
    BasicBlock, BinOp, Budget, DvIr, IrInstruction, OperandEncoding, PrimitiveEffect, Reject,
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

#[test]
fn recovers_add_xor_method_into_expected_ir() {
    let model: SyntheticVmModel = recovered_model();
    let mut budget: Budget = Budget::new(1_000);

    let expected: DvIr = DvIr::new(
        2,
        0,
        vec![BasicBlock::new(
            0,
            vec![
                IrInstruction::LoadArgument {
                    destination: ValueId::new(0),
                    index: 0,
                },
                IrInstruction::LoadArgument {
                    destination: ValueId::new(1),
                    index: 1,
                },
                IrInstruction::Binary {
                    destination: ValueId::new(2),
                    op: BinOp::Add,
                    left: ValueId::new(0),
                    right: ValueId::new(1),
                },
                IrInstruction::Const {
                    destination: ValueId::new(3),
                    value: 0x5a,
                },
                IrInstruction::Binary {
                    destination: ValueId::new(4),
                    op: BinOp::Xor,
                    left: ValueId::new(2),
                    right: ValueId::new(3),
                },
            ],
            Terminator::Ret(Some(ValueId::new(4))),
        )],
    );

    let actual: Result<DvIr, Reject> = devirtualize(&model, &mut budget);

    assert_eq!(actual, Ok(expected));
}

#[test]
fn rejects_unknown_handler_without_emitting_ir() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        7,
        handler(vec![PrimitiveEffect::Opaque], OperandEncoding::None),
    )]);
    let instructions: Vec<VInstr> = vec![VInstr::new(7, Vec::new())];
    let model: SyntheticVmModel =
        SyntheticVmModel::new(VmFlavor::Stack, 0, 0, handlers, instructions);
    let mut budget: Budget = Budget::new(100);

    let result: Result<DvIr, Reject> = devirtualize(&model, &mut budget);
    let reason: Option<&str> = result
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());
    let evidence_len: Option<usize> = result
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.evidence.len());

    assert!(reason.is_some_and(|value: &str| value.contains("unknown")));
    assert!(evidence_len.is_some_and(|value: usize| value > 0));
}

#[test]
fn rejects_when_budget_exhausts_before_pathological_program_finishes() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        1,
        handler(
            vec![PrimitiveEffect::PushArgument(0)],
            OperandEncoding::None,
        ),
    )]);
    let instructions: Vec<VInstr> = (0_u16..256_u16)
        .map(|_: u16| VInstr::new(1, Vec::new()))
        .collect();
    let model: SyntheticVmModel =
        SyntheticVmModel::new(VmFlavor::Stack, 1, 0, handlers, instructions);
    let mut budget: Budget = Budget::new(4);

    let result: Result<DvIr, Reject> = devirtualize(&model, &mut budget);
    let reason: Option<&str> = result
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("budget")));
}

#[test]
fn rejects_empty_program() {
    let model: SyntheticVmModel =
        SyntheticVmModel::new(VmFlavor::Stack, 0, 0, BTreeMap::new(), Vec::new());
    let mut budget: Budget = Budget::new(100);

    let result: Result<DvIr, Reject> = devirtualize(&model, &mut budget);
    let reason: Option<&str> = result
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("empty")));
}

#[test]
fn rejects_stack_underflow() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            handler(
                vec![PrimitiveEffect::Binary(BinOp::Add)],
                OperandEncoding::None,
            ),
        ),
        (
            2,
            handler(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![VInstr::new(1, Vec::new()), VInstr::new(2, Vec::new())];
    let model: SyntheticVmModel =
        SyntheticVmModel::new(VmFlavor::Stack, 0, 0, handlers, instructions);
    let mut budget: Budget = Budget::new(100);

    let result: Result<DvIr, Reject> = devirtualize(&model, &mut budget);
    let reason: Option<&str> = result
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("underflow")));
}

#[test]
fn rejects_oversized_operand() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        1,
        handler(vec![PrimitiveEffect::PushOperandI64], OperandEncoding::I64),
    )]);
    let instructions: Vec<VInstr> = vec![VInstr::new(1, vec![0_u8; 9])];
    let model: SyntheticVmModel =
        SyntheticVmModel::new(VmFlavor::Stack, 0, 0, handlers, instructions);
    let mut budget: Budget = Budget::new(100);

    let result: Result<DvIr, Reject> = devirtualize(&model, &mut budget);
    let reason: Option<&str> = result
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("operand")));
}
