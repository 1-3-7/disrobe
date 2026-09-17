use std::collections::BTreeMap;

use disrobe_pass_dotnet::devirt::{
    BasicBlock, BinOp, Budget, DvIr, HandlerSummary, IrInstruction, MicroOp, OperandEncoding,
    PrimitiveEffect, Reject, StateLocation, SyntheticHandler, SyntheticVmModel, Terminator, VInstr,
    ValueId, VmFlavor,
    byte_stack::ByteStackProfile,
    cil_handler::{BYTE_STACK_CIL_HANDLER_PROFILE, summarize_cil_handler},
    devirtualize,
};

static BYTE_STACK_ADD_CODE: [u8; 10] = [0x06, 0x25, 0x4d, 0x06, 0x1e, 0x59, 0x4d, 0x58, 0xdf, 0x2a];
static BYTE_STACK_CONST_THREE_CODE: [u8; 4] = [0x06, 0x19, 0xdf, 0x2a];
static BYTE_STACK_CONST_SEVEN_CODE: [u8; 4] = [0x06, 0x1d, 0xdf, 0x2a];
static BYTE_STACK_RETURN_CODE: [u8; 3] = [0x06, 0x4d, 0x2a];
static UNSUPPORTED_STACK_HANDLER_CODE: [u8; 2] = [0x07, 0x2a];

fn tiny_method(code: &[u8]) -> Vec<u8> {
    let code_size: u8 = match u8::try_from(code.len()) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    assert!(code_size < 64);
    let header: u8 = (code_size << 2) | 0x02;
    let mut body: Vec<u8> = Vec::with_capacity(code.len().saturating_add(1));
    body.push(header);
    body.extend_from_slice(code);
    body
}

fn byte_stack_model() -> SyntheticVmModel {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            0x10,
            SyntheticHandler::from_cil_handler(
                tiny_method(&BYTE_STACK_CONST_THREE_CODE),
                OperandEncoding::None,
            ),
        ),
        (
            0x11,
            SyntheticHandler::from_cil_handler(
                tiny_method(&BYTE_STACK_CONST_SEVEN_CODE),
                OperandEncoding::None,
            ),
        ),
        (
            0x12,
            SyntheticHandler::from_cil_handler(
                tiny_method(&BYTE_STACK_ADD_CODE),
                OperandEncoding::None,
            ),
        ),
        (
            0x13,
            SyntheticHandler::from_cil_handler(
                tiny_method(&BYTE_STACK_RETURN_CODE),
                OperandEncoding::None,
            ),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![
        VInstr::new(0x10, Vec::new()),
        VInstr::new(0x11, Vec::new()),
        VInstr::new(0x12, Vec::new()),
        VInstr::new(0x13, Vec::new()),
    ];
    SyntheticVmModel::byte_dispatched(0, 0, handlers, instructions)
}

const fn unknown_summary() -> HandlerSummary {
    HandlerSummary {
        stack_delta: 0,
        reads: Vec::new(),
        writes: Vec::new(),
        control_effect: disrobe_pass_dotnet::devirt::ControlEffect::Unknown,
        canonical_op: None,
    }
}

#[test]
fn summarizes_byte_stack_add_handler_with_shared_microop_matcher() {
    let body: Vec<u8> = tiny_method(&BYTE_STACK_ADD_CODE);
    let mut budget: Budget = Budget::new(10_000);
    let actual: Result<HandlerSummary, Reject> =
        summarize_cil_handler(&body, &BYTE_STACK_CIL_HANDLER_PROFILE, &mut budget);

    assert_eq!(
        actual,
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Stack],
            control_effect: disrobe_pass_dotnet::devirt::ControlEffect::Fallthrough,
            canonical_op: Some(MicroOp::Add),
        })
    );
}

#[test]
fn devirtualizes_profiled_byte_stack_method_to_expected_ir() {
    let model: SyntheticVmModel = byte_stack_model();
    let profile: ByteStackProfile = ByteStackProfile;
    let mut budget: Budget = Budget::new(10_000);
    let expected: DvIr = DvIr::new(
        0,
        0,
        vec![BasicBlock::new(
            0,
            vec![
                IrInstruction::Const {
                    destination: ValueId::new(0),
                    value: 3,
                },
                IrInstruction::Const {
                    destination: ValueId::new(1),
                    value: 7,
                },
                IrInstruction::Binary {
                    destination: ValueId::new(2),
                    op: BinOp::Add,
                    left: ValueId::new(0),
                    right: ValueId::new(1),
                },
            ],
            Terminator::Ret(Some(ValueId::new(2))),
        )],
    );

    let actual: Result<DvIr, Reject> = profile.devirtualize(&model, &mut budget);

    assert_eq!(actual, Ok(expected));
}

#[test]
fn returns_unknown_and_rejects_method_for_handler_outside_byte_stack_abi() {
    let body: Vec<u8> = tiny_method(&UNSUPPORTED_STACK_HANDLER_CODE);
    let mut budget: Budget = Budget::new(10_000);
    let actual: Result<HandlerSummary, Reject> =
        summarize_cil_handler(&body, &BYTE_STACK_CIL_HANDLER_PROFILE, &mut budget);

    assert_eq!(actual, Ok(unknown_summary()));

    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        0x14,
        SyntheticHandler::from_cil_handler(body, OperandEncoding::None),
    )]);
    let instructions: Vec<VInstr> = vec![VInstr::new(0x14, Vec::new())];
    let model: SyntheticVmModel = SyntheticVmModel::byte_dispatched(0, 0, handlers, instructions);
    let profile: ByteStackProfile = ByteStackProfile;
    let mut method_budget: Budget = Budget::new(10_000);
    let method: Result<DvIr, Reject> = profile.devirtualize(&model, &mut method_budget);
    let reason: Option<&str> = method
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("unknown")));
}

#[test]
fn rejects_opcode_outside_byte_dispatch_range() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        256,
        SyntheticHandler::from_cil_handler(
            tiny_method(&BYTE_STACK_CONST_THREE_CODE),
            OperandEncoding::None,
        ),
    )]);
    let instructions: Vec<VInstr> = vec![VInstr::new(256, Vec::new())];
    let model: SyntheticVmModel = SyntheticVmModel::byte_dispatched(0, 0, handlers, instructions);
    let profile: ByteStackProfile = ByteStackProfile;
    let mut budget: Budget = Budget::new(10_000);

    let actual: Result<DvIr, Reject> = profile.devirtualize(&model, &mut budget);
    let reason: Option<&str> = actual
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("byte-dispatch")));
}

#[test]
fn retains_existing_effect_profile_devirtualization() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            1,
            SyntheticHandler::new(vec![PrimitiveEffect::PushConst(9)], OperandEncoding::None),
        ),
        (
            2,
            SyntheticHandler::new(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> = vec![VInstr::new(1, Vec::new()), VInstr::new(2, Vec::new())];
    let model: SyntheticVmModel =
        SyntheticVmModel::new(VmFlavor::Stack, 0, 0, handlers, instructions);
    let mut budget: Budget = Budget::new(10_000);
    let expected: DvIr = DvIr::new(
        0,
        0,
        vec![BasicBlock::new(
            0,
            vec![IrInstruction::Const {
                destination: ValueId::new(0),
                value: 9,
            }],
            Terminator::Ret(Some(ValueId::new(0))),
        )],
    );

    let actual: Result<DvIr, Reject> = devirtualize(&model, &mut budget);

    assert_eq!(actual, Ok(expected));
}

#[test]
fn existing_effect_profile_rejects_byte_dispatch_shape() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([
        (
            0x10,
            SyntheticHandler::new(vec![PrimitiveEffect::PushConst(9)], OperandEncoding::None),
        ),
        (
            0x11,
            SyntheticHandler::new(vec![PrimitiveEffect::Return], OperandEncoding::None),
        ),
    ]);
    let instructions: Vec<VInstr> =
        vec![VInstr::new(0x10, Vec::new()), VInstr::new(0x11, Vec::new())];
    let model: SyntheticVmModel = SyntheticVmModel::byte_dispatched(0, 0, handlers, instructions);
    let mut budget: Budget = Budget::new(10_000);

    let actual: Result<DvIr, Reject> = devirtualize(&model, &mut budget);
    let reason: Option<&str> = actual
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("VM shape")));
}

#[test]
fn bounds_pathological_byte_stack_dispatch() {
    let handlers: BTreeMap<u16, SyntheticHandler> = BTreeMap::from([(
        0x10,
        SyntheticHandler::from_cil_handler(
            tiny_method(&BYTE_STACK_CONST_THREE_CODE),
            OperandEncoding::None,
        ),
    )]);
    let instructions: Vec<VInstr> = (0_u16..256_u16)
        .map(|_: u16| VInstr::new(0x10, Vec::new()))
        .collect();
    let model: SyntheticVmModel = SyntheticVmModel::byte_dispatched(0, 0, handlers, instructions);
    let profile: ByteStackProfile = ByteStackProfile;
    let mut budget: Budget = Budget::new(4);

    let actual: Result<DvIr, Reject> = profile.devirtualize(&model, &mut budget);
    let reason: Option<&str> = actual
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("budget")));
}
