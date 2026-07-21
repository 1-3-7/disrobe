use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_dotnet::devirt::{
    Budget, ControlEffect, HandlerSummary, MicroOp, Reject, StateLocation,
    cil_handler::{CilArgumentRole, CilHandlerProfile, CilLocalRole, summarize_cil_handler},
};

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

fn profile(
    reads: &[(u32, u16)],
    writes: &[u32],
    controls: &[u32],
    returns: &[u32],
) -> CilHandlerProfile {
    let virtual_stack_reads: BTreeMap<u32, u16> = reads.iter().copied().collect();
    let virtual_stack_writes: BTreeSet<u32> = writes.iter().copied().collect();
    let virtual_control_offsets: BTreeSet<u32> = controls.iter().copied().collect();
    let virtual_return_offsets: BTreeSet<u32> = returns.iter().copied().collect();
    CilHandlerProfile::new(
        BTreeMap::from([
            (0, CilArgumentRole::VirtualStackPointer),
            (1, CilArgumentRole::VirtualArgument(1)),
            (2, CilArgumentRole::VirtualArgument(2)),
        ]),
        BTreeMap::from([(2, CilLocalRole::VirtualLocal(2))]),
        virtual_stack_reads,
        virtual_stack_writes,
        virtual_control_offsets,
        virtual_return_offsets,
    )
}

fn summarize(body: &[u8], handler_profile: &CilHandlerProfile) -> Result<HandlerSummary, Reject> {
    let mut budget: Budget = Budget::new(10_000);
    summarize_cil_handler(body, handler_profile, &mut budget)
}

fn output_summary(op: MicroOp, stack_delta: i16, reads: Vec<StateLocation>) -> HandlerSummary {
    HandlerSummary {
        stack_delta,
        reads,
        writes: vec![StateLocation::Stack],
        control_effect: ControlEffect::Fallthrough,
        canonical_op: Some(op),
    }
}

fn binary_body(opcode: &[u8]) -> Vec<u8> {
    let mut code: Vec<u8> = vec![0x02, 0x25, 0x4c, 0x02, 0x4c];
    code.extend_from_slice(opcode);
    code.extend_from_slice(&[0x55, 0x2a]);
    tiny_method(&code)
}

#[test]
fn recovers_profiled_cil_binary_handlers_through_virtual_stack_indirection() {
    let cases: [(&[u8], MicroOp); 9] = [
        (&[0x58], MicroOp::Add),
        (&[0x59], MicroOp::Sub),
        (&[0x5a], MicroOp::Mul),
        (&[0x5f], MicroOp::And),
        (&[0x60], MicroOp::Or),
        (&[0x61], MicroOp::Xor),
        (&[0xfe, 0x01], MicroOp::Ceq),
        (&[0xfe, 0x04], MicroOp::Clt),
        (&[0xfe, 0x02], MicroOp::Cgt),
    ];
    let expected_reads: Vec<StateLocation> = vec![StateLocation::Stack];

    for (opcode, op) in cases {
        let write_offset: u32 = if opcode.len() == 1 { 6 } else { 7 };
        let handler_profile: CilHandlerProfile =
            profile(&[(2, 0), (4, 1)], &[write_offset], &[], &[]);
        let actual: Result<HandlerSummary, Reject> =
            summarize(&binary_body(opcode), &handler_profile);
        let expected: HandlerSummary = output_summary(op, -1, expected_reads.clone());
        assert_eq!(actual, Ok(expected));
    }
}

#[test]
fn recovers_profiled_cil_local_load_with_temporary_dup_and_pop() {
    let body: Vec<u8> = tiny_method(&[0x02, 0x08, 0x25, 0x26, 0x55, 0x2a]);
    let handler_profile: CilHandlerProfile = profile(&[], &[4], &[], &[]);
    let actual: Result<HandlerSummary, Reject> = summarize(&body, &handler_profile);
    let expected: HandlerSummary =
        output_summary(MicroOp::Ldloc(2), 1, vec![StateLocation::Local(2)]);

    assert_eq!(actual, Ok(expected));
}

#[test]
fn recovers_profiled_cil_argument_and_integer_constant_loads() {
    let argument_body: Vec<u8> = tiny_method(&[0x02, 0x03, 0x55, 0x2a]);
    let short_constant_body: Vec<u8> = tiny_method(&[0x02, 0x1f, 0xfb, 0x55, 0x2a]);
    let mut i8_code: Vec<u8> = vec![0x02, 0x21];
    i8_code.extend_from_slice(&(-9_i64).to_le_bytes());
    i8_code.extend_from_slice(&[0x55, 0x2a]);
    let i8_constant_body: Vec<u8> = tiny_method(&i8_code);
    let argument_profile: CilHandlerProfile = profile(&[], &[2], &[], &[]);
    let short_constant_profile: CilHandlerProfile = profile(&[], &[3], &[], &[]);
    let i8_constant_profile: CilHandlerProfile = profile(&[], &[10], &[], &[]);
    let argument: Result<HandlerSummary, Reject> = summarize(&argument_body, &argument_profile);
    let short_constant: Result<HandlerSummary, Reject> =
        summarize(&short_constant_body, &short_constant_profile);
    let i8_constant: Result<HandlerSummary, Reject> =
        summarize(&i8_constant_body, &i8_constant_profile);

    assert_eq!(
        argument,
        Ok(output_summary(
            MicroOp::Ldarg(1),
            1,
            vec![StateLocation::Argument(1)],
        ))
    );
    assert_eq!(
        short_constant,
        Ok(output_summary(MicroOp::Ldc(-5), 1, Vec::new()))
    );
    assert_eq!(
        i8_constant,
        Ok(output_summary(MicroOp::Ldc(-9), 1, Vec::new()))
    );
}

#[test]
fn recovers_profiled_cil_store_handlers() {
    let store_local_body: Vec<u8> = tiny_method(&[0x02, 0x4c, 0x0c, 0x2a]);
    let store_argument_body: Vec<u8> = tiny_method(&[0x02, 0x4c, 0x10, 0x02, 0x2a]);
    let handler_profile: CilHandlerProfile = profile(&[(1, 0)], &[], &[], &[]);
    let store_local: Result<HandlerSummary, Reject> =
        summarize(&store_local_body, &handler_profile);
    let store_argument: Result<HandlerSummary, Reject> =
        summarize(&store_argument_body, &handler_profile);

    assert_eq!(
        store_local,
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Local(2)],
            control_effect: ControlEffect::Fallthrough,
            canonical_op: Some(MicroOp::Stloc(2)),
        })
    );
    assert_eq!(
        store_argument,
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Argument(2)],
            control_effect: ControlEffect::Fallthrough,
            canonical_op: Some(MicroOp::Starg(2)),
        })
    );
}

#[test]
fn recovers_profiled_cil_control_handlers() {
    let branch_body: Vec<u8> = tiny_method(&[0x2b, 0x00, 0x2a]);
    let true_body: Vec<u8> = tiny_method(&[0x02, 0x4c, 0x2d, 0x00, 0x2a]);
    let false_body: Vec<u8> = tiny_method(&[0x02, 0x4c, 0x2c, 0x00, 0x2a]);
    let return_body: Vec<u8> = tiny_method(&[0x02, 0x4c, 0x2a]);
    let branch_profile: CilHandlerProfile = profile(&[], &[], &[0], &[]);
    let conditional_profile: CilHandlerProfile = profile(&[(1, 0)], &[], &[2], &[]);
    let return_profile: CilHandlerProfile = profile(&[(1, 0)], &[], &[], &[2]);
    let branch: Result<HandlerSummary, Reject> = summarize(&branch_body, &branch_profile);
    let branch_true: Result<HandlerSummary, Reject> = summarize(&true_body, &conditional_profile);
    let branch_false: Result<HandlerSummary, Reject> = summarize(&false_body, &conditional_profile);
    let returned: Result<HandlerSummary, Reject> = summarize(&return_body, &return_profile);

    assert_eq!(
        branch,
        Ok(HandlerSummary {
            stack_delta: 0,
            reads: Vec::new(),
            writes: vec![StateLocation::Ip],
            control_effect: ControlEffect::Br,
            canonical_op: Some(MicroOp::Br),
        })
    );
    assert_eq!(
        branch_true,
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Ip],
            control_effect: ControlEffect::BrTrue,
            canonical_op: Some(MicroOp::BrTrue),
        })
    );
    assert_eq!(
        branch_false,
        Ok(HandlerSummary {
            stack_delta: -1,
            reads: vec![StateLocation::Stack],
            writes: vec![StateLocation::Ip],
            control_effect: ControlEffect::BrFalse,
            canonical_op: Some(MicroOp::BrFalse),
        })
    );
    assert_eq!(
        returned,
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
fn missing_abi_binding_returns_unknown_without_fabricating_a_handler_effect() {
    let body: Vec<u8> = binary_body(&[0x58]);
    let missing_profile: CilHandlerProfile = profile(&[(2, 0)], &[6], &[], &[]);
    let reversed_profile: CilHandlerProfile = profile(&[(2, 1), (4, 0)], &[6], &[], &[]);
    let missing: Result<HandlerSummary, Reject> = summarize(&body, &missing_profile);
    let reversed: Result<HandlerSummary, Reject> = summarize(&body, &reversed_profile);
    let expected: HandlerSummary = HandlerSummary {
        stack_delta: 0,
        reads: Vec::new(),
        writes: Vec::new(),
        control_effect: ControlEffect::Unknown,
        canonical_op: None,
    };

    assert_eq!(missing, Ok(expected.clone()));
    assert_eq!(reversed, Ok(expected));
}

#[test]
fn unknown_and_unlowered_cil_opcodes_do_not_fabricate_handler_effects() {
    let unknown_body: Vec<u8> = tiny_method(&[0x24]);
    let unlowered_body: Vec<u8> = tiny_method(&[0x65, 0x2a]);
    let handler_profile: CilHandlerProfile = profile(&[], &[], &[], &[]);
    let unknown: Result<HandlerSummary, Reject> = summarize(&unknown_body, &handler_profile);
    let unlowered: Result<HandlerSummary, Reject> = summarize(&unlowered_body, &handler_profile);
    let expected: HandlerSummary = HandlerSummary {
        stack_delta: 0,
        reads: Vec::new(),
        writes: Vec::new(),
        control_effect: ControlEffect::Unknown,
        canonical_op: None,
    };

    assert_eq!(unknown, Ok(expected.clone()));
    assert_eq!(unlowered, Ok(expected));
}

#[test]
fn rejects_empty_cil_handler_bodies() {
    let tiny_body: Vec<u8> = tiny_method(&[]);
    let handler_profile: CilHandlerProfile = profile(&[], &[], &[], &[]);
    let mut direct_budget: Budget = Budget::new(10_000);
    let direct: Result<HandlerSummary, Reject> =
        summarize_cil_handler(&[], &handler_profile, &mut direct_budget);
    let tiny: Result<HandlerSummary, Reject> = summarize(&tiny_body, &handler_profile);
    let direct_reason: Option<&str> = direct
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());
    let tiny_reason: Option<&str> = tiny
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(direct_reason.is_some_and(|value: &str| value.contains("empty")));
    assert!(tiny_reason.is_some_and(|value: &str| value.contains("empty")));
}

#[test]
fn rejects_cil_evaluation_stack_underflow() {
    let body: Vec<u8> = tiny_method(&[0x26, 0x2a]);
    let handler_profile: CilHandlerProfile = profile(&[], &[], &[], &[]);
    let actual: Result<HandlerSummary, Reject> = summarize(&body, &handler_profile);
    let reason: Option<&str> = actual
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("underflow")));
}

#[test]
fn rejects_budget_exhaustion_before_large_handler_parse() {
    let body: Vec<u8> = fat_method(&[0x00; 128]);
    let handler_profile: CilHandlerProfile = profile(&[], &[], &[], &[]);
    let mut budget: Budget = Budget::new(8);
    let actual: Result<HandlerSummary, Reject> =
        summarize_cil_handler(&body, &handler_profile, &mut budget);
    let reason: Option<&str> = actual
        .as_ref()
        .err()
        .map(|reject: &Reject| reject.reason.as_str());

    assert!(reason.is_some_and(|value: &str| value.contains("budget")));
}
