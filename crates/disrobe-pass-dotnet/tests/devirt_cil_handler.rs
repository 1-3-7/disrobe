use disrobe_pass_dotnet::devirt::{
    AbstractState, Budget, CanonicalEffect, ControlEffect, Expr, HandlerSummary, MicroOp,
    OperandRange, PrimitiveEffect, Reject, StateLocation,
    cil_handler::{
        CilHandlerProfile, CilOperandAccess, CilSlot, CilSlotBinding, CilSlotRole, CilStackAccess,
        KOIVM_SHAPED_CIL_HANDLER_PROFILE, summarize_cil_handler,
    },
};

static ADD_BINDINGS: [CilSlotBinding; 2] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
];
static ADD_POP_OFFSETS: [CilStackAccess; 2] =
    [CilStackAccess::new(0, 0), CilStackAccess::new(-8, 1)];
static ADD_PUSH_OFFSETS: [CilStackAccess; 1] = [CilStackAccess::new(0, 0)];
static ADD_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&ADD_BINDINGS, &ADD_POP_OFFSETS, &ADD_PUSH_OFFSETS, &[]);

static MISSING_BINDINGS: [CilSlotBinding; 2] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
];
static MISSING_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&MISSING_BINDINGS, &[], &[], &[]);

static AMBIGUOUS_BINDINGS: [CilSlotBinding; 3] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(1), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
];
static AMBIGUOUS_PROFILE: CilHandlerProfile = CilHandlerProfile::new(
    &AMBIGUOUS_BINDINGS,
    &ADD_POP_OFFSETS,
    &ADD_PUSH_OFFSETS,
    &[],
);

static STORE_LOCAL_BINDINGS: [CilSlotBinding; 3] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
    CilSlotBinding::new(CilSlot::Local(2), CilSlotRole::Local(4)),
];
static STORE_ARGUMENT_BINDINGS: [CilSlotBinding; 3] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
    CilSlotBinding::new(CilSlot::Local(2), CilSlotRole::Argument(7)),
];
static STORE_POP_OFFSETS: [CilStackAccess; 1] = [CilStackAccess::new(0, 0)];
static STORE_LOCAL_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&STORE_LOCAL_BINDINGS, &STORE_POP_OFFSETS, &[], &[]);
static STORE_ARGUMENT_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&STORE_ARGUMENT_BINDINGS, &STORE_POP_OFFSETS, &[], &[]);

static IP_OPERAND_BINDINGS: [CilSlotBinding; 2] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Local(0), CilSlotRole::InstructionPointer),
];
static IP_OPERAND_PUSH_OFFSETS: [CilStackAccess; 1] = [CilStackAccess::new(0, 0)];
static IP_OPERAND_ACCESSES: [CilOperandAccess; 1] =
    [CilOperandAccess::new(1, OperandRange::new(0, 8))];
static IP_OPERAND_PROFILE: CilHandlerProfile = CilHandlerProfile::new(
    &IP_OPERAND_BINDINGS,
    &[],
    &IP_OPERAND_PUSH_OFFSETS,
    &IP_OPERAND_ACCESSES,
);

static IP_ADD_BINDINGS: [CilSlotBinding; 2] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Local(0), CilSlotRole::InstructionPointer),
];
static IP_ADD_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&IP_ADD_BINDINGS, &ADD_POP_OFFSETS, &ADD_PUSH_OFFSETS, &[]);

static LOAD_BINDINGS: [CilSlotBinding; 4] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(1), CilSlotRole::Argument(1)),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
    CilSlotBinding::new(CilSlot::Local(2), CilSlotRole::Local(2)),
];
static LOAD_PUSH_OFFSETS: [CilStackAccess; 1] = [CilStackAccess::new(0, 0)];
static LOAD_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&LOAD_BINDINGS, &[], &LOAD_PUSH_OFFSETS, &[]);

static CONTROL_BINDINGS: [CilSlotBinding; 2] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Argument(3), CilSlotRole::InstructionPointer),
];
static CONTROL_POP_OFFSETS: [CilStackAccess; 1] = [CilStackAccess::new(0, 0)];
static CONTROL_PROFILE: CilHandlerProfile =
    CilHandlerProfile::new(&CONTROL_BINDINGS, &CONTROL_POP_OFFSETS, &[], &[])
        .with_terminal_control(true, true);

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

fn fat_method(code: &[u8]) -> Vec<u8> {
    let code_size: u32 = match u32::try_from(code.len()) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let flags_size: u16 = (3_u16 << 12) | 0x03;
    let mut body: Vec<u8> = Vec::with_capacity(code.len().saturating_add(12));
    body.extend_from_slice(&flags_size.to_le_bytes());
    body.extend_from_slice(&8_u16.to_le_bytes());
    body.extend_from_slice(&code_size.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(code);
    body
}

fn summarize(body: &[u8], profile: &CilHandlerProfile) -> Result<HandlerSummary, Reject> {
    let mut budget: Budget = Budget::new(10_000);
    summarize_cil_handler(body, profile, &mut budget)
}

const fn unknown_summary() -> HandlerSummary {
    HandlerSummary {
        stack_delta: 0,
        reads: Vec::new(),
        writes: Vec::new(),
        control_effect: ControlEffect::Unknown,
        canonical_op: None,
    }
}

fn add_body() -> Vec<u8> {
    tiny_method(&[0x02, 0x25, 0x4d, 0x02, 0x1e, 0x59, 0x4d, 0x58, 0xdf, 0x2a])
}

fn binary_body(opcode: &[u8]) -> Vec<u8> {
    let mut code: Vec<u8> = vec![0x02, 0x25, 0x4d, 0x02, 0x1e, 0x59, 0x4d];
    code.extend_from_slice(opcode);
    code.extend_from_slice(&[0xdf, 0x2a]);
    tiny_method(&code)
}

#[test]
fn lowers_profiled_add_handler_from_relative_virtual_stack_slots() {
    let body: Vec<u8> = add_body();
    let expected: HandlerSummary = HandlerSummary {
        stack_delta: -1,
        reads: vec![StateLocation::Stack],
        writes: vec![StateLocation::Stack],
        control_effect: ControlEffect::Fallthrough,
        canonical_op: Some(MicroOp::Add),
    };

    assert_eq!(summarize(&body, &ADD_PROFILE), Ok(expected.clone()));
    assert_eq!(
        summarize(&body, &KOIVM_SHAPED_CIL_HANDLER_PROFILE),
        Ok(expected)
    );
}

#[test]
fn retains_profiled_cil_binary_handler_lowering() {
    let cases: [(&[u8], MicroOp); 8] = [
        (&[0x59], MicroOp::Sub),
        (&[0x5a], MicroOp::Mul),
        (&[0x5f], MicroOp::And),
        (&[0x60], MicroOp::Or),
        (&[0x61], MicroOp::Xor),
        (&[0xfe, 0x01], MicroOp::Ceq),
        (&[0xfe, 0x04], MicroOp::Clt),
        (&[0xfe, 0x02], MicroOp::Cgt),
    ];
    let reads: Vec<StateLocation> = vec![StateLocation::Stack];

    for (opcode, op) in cases {
        let expected: HandlerSummary = HandlerSummary {
            stack_delta: -1,
            reads: reads.clone(),
            writes: vec![StateLocation::Stack],
            control_effect: ControlEffect::Fallthrough,
            canonical_op: Some(op),
        };

        assert_eq!(summarize(&binary_body(opcode), &ADD_PROFILE), Ok(expected));
    }
}

#[test]
fn retains_profiled_cil_load_and_control_handler_lowering() {
    let local_body: Vec<u8> = tiny_method(&[0x02, 0x08, 0xdf, 0x2a]);
    let argument_body: Vec<u8> = tiny_method(&[0x02, 0x03, 0xdf, 0x2a]);
    let constant_body: Vec<u8> = tiny_method(&[0x02, 0x1f, 0xfb, 0xdf, 0x2a]);
    let branch_body: Vec<u8> = tiny_method(&[0x2b, 0x00, 0x2a]);
    let branch_true_body: Vec<u8> = tiny_method(&[0x02, 0x4d, 0x2d, 0x00, 0x2a]);
    let return_body: Vec<u8> = tiny_method(&[0x02, 0x4d, 0x2a]);

    assert_eq!(
        summarize(&local_body, &LOAD_PROFILE),
        Ok(HandlerSummary {
            stack_delta: 1,
            reads: vec![StateLocation::Local(2)],
            writes: vec![StateLocation::Stack],
            control_effect: ControlEffect::Fallthrough,
            canonical_op: Some(MicroOp::Ldloc(2)),
        })
    );
    assert_eq!(
        summarize(&argument_body, &LOAD_PROFILE),
        Ok(HandlerSummary {
            stack_delta: 1,
            reads: vec![StateLocation::Argument(1)],
            writes: vec![StateLocation::Stack],
            control_effect: ControlEffect::Fallthrough,
            canonical_op: Some(MicroOp::Ldarg(1)),
        })
    );
    assert_eq!(
        summarize(&constant_body, &LOAD_PROFILE),
        Ok(HandlerSummary {
            stack_delta: 1,
            reads: Vec::new(),
            writes: vec![StateLocation::Stack],
            control_effect: ControlEffect::Fallthrough,
            canonical_op: Some(MicroOp::Ldc(-5)),
        })
    );
    assert_eq!(
        summarize(&branch_body, &CONTROL_PROFILE),
        Ok(HandlerSummary {
            stack_delta: 0,
            reads: Vec::new(),
            writes: vec![StateLocation::Ip],
            control_effect: ControlEffect::Br,
            canonical_op: Some(MicroOp::Br),
        })
    );
    assert_eq!(
        summarize(&branch_true_body, &CONTROL_PROFILE),
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Ip],
            control_effect: ControlEffect::BrTrue,
            canonical_op: Some(MicroOp::BrTrue),
        })
    );
    assert_eq!(
        summarize(&return_body, &CONTROL_PROFILE),
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Ip],
            control_effect: ControlEffect::Ret,
            canonical_op: Some(MicroOp::Ret),
        })
    );
}

#[test]
fn unmodeled_or_ambiguous_abi_access_returns_unknown() {
    let unmodeled_body: Vec<u8> = tiny_method(&[0x07, 0x2a]);
    let add: Vec<u8> = add_body();

    assert_eq!(
        summarize(&unmodeled_body, &MISSING_PROFILE),
        Ok(unknown_summary())
    );
    assert_eq!(summarize(&add, &AMBIGUOUS_PROFILE), Ok(unknown_summary()));
}

#[test]
fn unknown_and_unlowered_cil_opcodes_return_unknown() {
    let unknown_body: Vec<u8> = tiny_method(&[0x24]);
    let unlowered_body: Vec<u8> = tiny_method(&[0x65, 0x2a]);

    assert_eq!(
        summarize(&unknown_body, &MISSING_PROFILE),
        Ok(unknown_summary())
    );
    assert_eq!(
        summarize(&unlowered_body, &MISSING_PROFILE),
        Ok(unknown_summary())
    );
}

#[test]
fn profile_slot_bindings_change_the_same_cil_body_interpretation() {
    let body: Vec<u8> = tiny_method(&[0x02, 0x4d, 0x0c, 0x2a]);
    let local: HandlerSummary = HandlerSummary {
        stack_delta: -1,
        reads: vec![StateLocation::Stack],
        writes: vec![StateLocation::Local(4)],
        control_effect: ControlEffect::Fallthrough,
        canonical_op: Some(MicroOp::Stloc(4)),
    };
    let argument: HandlerSummary = HandlerSummary {
        stack_delta: -1,
        reads: vec![StateLocation::Stack],
        writes: vec![StateLocation::Argument(7)],
        control_effect: ControlEffect::Fallthrough,
        canonical_op: Some(MicroOp::Starg(7)),
    };

    assert_eq!(summarize(&body, &STORE_LOCAL_PROFILE), Ok(local));
    assert_eq!(summarize(&body, &STORE_ARGUMENT_PROFILE), Ok(argument));
}

#[test]
fn profiles_instruction_pointer_updates_and_ip_relative_operand_reads() {
    let operand_body: Vec<u8> = tiny_method(&[0x02, 0x06, 0x17, 0x58, 0x4c, 0x55, 0x2a]);
    let ip_add_body: Vec<u8> = tiny_method(&[
        0x06, 0x17, 0x58, 0x0a, 0x02, 0x25, 0x4d, 0x02, 0x1e, 0x59, 0x4d, 0x58, 0xdf, 0x2a,
    ]);
    let operand: HandlerSummary = HandlerSummary {
        stack_delta: 1,
        reads: vec![StateLocation::OperandBytes(OperandRange::new(0, 8))],
        writes: vec![StateLocation::Stack],
        control_effect: ControlEffect::Fallthrough,
        canonical_op: Some(MicroOp::LdcOperand),
    };
    let ip_add: HandlerSummary = HandlerSummary {
        stack_delta: -1,
        reads: vec![StateLocation::Stack],
        writes: vec![StateLocation::Stack, StateLocation::Ip],
        control_effect: ControlEffect::Fallthrough,
        canonical_op: Some(MicroOp::Add),
    };

    assert_eq!(summarize(&operand_body, &IP_OPERAND_PROFILE), Ok(operand));
    assert_eq!(summarize(&ip_add_body, &IP_ADD_PROFILE), Ok(ip_add));
}

#[test]
fn canonical_effect_preserves_instruction_pointer_delta() -> Result<(), Reject> {
    let mut budget: Budget = Budget::new(10_000);
    let mut first: AbstractState = AbstractState::new();
    let mut second: AbstractState = AbstractState::new();
    first.apply(&PrimitiveEffect::AdvanceIp(1), &mut budget)?;
    second.apply(&PrimitiveEffect::AdvanceIp(8), &mut budget)?;
    let first_effect: Option<CanonicalEffect> = first.canonical_effect(&mut budget)?;
    let second_effect: Option<CanonicalEffect> = second.canonical_effect(&mut budget)?;

    assert_eq!(
        first_effect.map(|effect: CanonicalEffect| effect.instruction_pointer_write),
        Some(Some(Expr::IpDelta(1)))
    );
    assert_eq!(
        second_effect.map(|effect: CanonicalEffect| effect.instruction_pointer_write),
        Some(Some(Expr::IpDelta(8)))
    );
    Ok(())
}

#[test]
fn budget_aborts_before_pathological_handler_parse() {
    let body: Vec<u8> = fat_method(&[0x00; 128]);
    let mut budget: Budget = Budget::new(8);
    let actual: Result<HandlerSummary, Reject> =
        summarize_cil_handler(&body, &MISSING_PROFILE, &mut budget);
    let reason: Option<&str> = actual
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("budget")));
}

#[test]
fn empty_and_underflowing_handlers_reject_without_panicking() {
    let tiny_empty: Vec<u8> = tiny_method(&[]);
    let underflow: Vec<u8> = tiny_method(&[0x26, 0x2a]);
    let mut direct_budget: Budget = Budget::new(10_000);
    let direct: Result<HandlerSummary, Reject> =
        summarize_cil_handler(&[], &MISSING_PROFILE, &mut direct_budget);
    let tiny: Result<HandlerSummary, Reject> = summarize(&tiny_empty, &MISSING_PROFILE);
    let stack: Result<HandlerSummary, Reject> = summarize(&underflow, &MISSING_PROFILE);

    assert!(direct.is_err());
    assert!(tiny.is_err());
    assert!(stack.is_err());
}
