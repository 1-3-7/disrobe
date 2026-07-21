use std::collections::{BTreeMap, BTreeSet};

use crate::cil::{self, Instruction, MethodBody, OperandValue};
use crate::error::Error;

use super::Reject;
use super::budget::Budget;
use super::handlers::{HandlerSummary, summarize};
use super::ir::BinOp;
use super::state::{ControlEffect, Expr, PrimitiveEffect};

pub const MAX_CIL_HANDLER_BODY_BYTES: usize = 4_096;

const MAX_CIL_HANDLER_INSTRUCTIONS: usize = 512;
const MAX_CIL_EVALUATION_STACK: usize = 64;
const MAX_CIL_EXPRESSION_DEPTH: u8 = 32;
const MAX_CIL_EXPRESSION_NODES: u8 = 64;
const MAX_LOWERED_EFFECTS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CilArgumentRole {
    VirtualStackPointer,
    VirtualArgument(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CilLocalRole {
    VirtualLocal(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CilHandlerProfile {
    argument_roles: BTreeMap<u16, CilArgumentRole>,
    local_roles: BTreeMap<u16, CilLocalRole>,
    virtual_stack_reads: BTreeMap<u32, u16>,
    virtual_stack_writes: BTreeSet<u32>,
    virtual_control_offsets: BTreeSet<u32>,
    virtual_return_offsets: BTreeSet<u32>,
}

impl CilHandlerProfile {
    #[must_use]
    pub const fn new(
        argument_roles: BTreeMap<u16, CilArgumentRole>,
        local_roles: BTreeMap<u16, CilLocalRole>,
        virtual_stack_reads: BTreeMap<u32, u16>,
        virtual_stack_writes: BTreeSet<u32>,
        virtual_control_offsets: BTreeSet<u32>,
        virtual_return_offsets: BTreeSet<u32>,
    ) -> Self {
        Self {
            argument_roles,
            local_roles,
            virtual_stack_reads,
            virtual_stack_writes,
            virtual_control_offsets,
            virtual_return_offsets,
        }
    }

    fn argument_value(&self, index: u16) -> Option<CilValue> {
        match self.argument_roles.get(&index) {
            Some(CilArgumentRole::VirtualStackPointer) => Some(CilValue::StackPointer),
            Some(CilArgumentRole::VirtualArgument(value)) => {
                Some(CilValue::expression(Expr::Argument(*value)))
            }
            None => None,
        }
    }

    fn virtual_argument(&self, index: u16) -> Option<u16> {
        match self.argument_roles.get(&index) {
            Some(CilArgumentRole::VirtualArgument(value)) => Some(*value),
            Some(CilArgumentRole::VirtualStackPointer) | None => None,
        }
    }

    fn virtual_local(&self, index: u16) -> Option<u16> {
        self.local_roles
            .get(&index)
            .map(|value: &CilLocalRole| match value {
                CilLocalRole::VirtualLocal(index) => *index,
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CilValue {
    StackPointer,
    Expression { value: Expr, depth: u8, nodes: u8 },
}

impl CilValue {
    const fn expression(value: Expr) -> Self {
        Self::Expression {
            value,
            depth: 0,
            nodes: 1,
        }
    }

    const fn depth(&self) -> u8 {
        match self {
            Self::StackPointer => 0,
            Self::Expression { depth, .. } => *depth,
        }
    }

    const fn nodes(&self) -> u8 {
        match self {
            Self::StackPointer => 1,
            Self::Expression { nodes, .. } => *nodes,
        }
    }

    const fn expression_value(&self) -> Option<&Expr> {
        match self {
            Self::StackPointer => None,
            Self::Expression { value, .. } => Some(value),
        }
    }

    const fn stack_input(&self) -> Option<u16> {
        match self.expression_value() {
            Some(Expr::VStackAt(value)) => Some(*value),
            Some(
                Expr::VStackTop
                | Expr::VReg(_)
                | Expr::Local(_)
                | Expr::Argument(_)
                | Expr::OperandBytes(_)
                | Expr::Const(_)
                | Expr::IpDelta(_)
                | Expr::Binary { .. },
            )
            | None => None,
        }
    }

    fn binary(op: BinOp, left: Self, right: Self) -> Result<Option<Self>, Reject> {
        let child_depth: u8 = left.depth().max(right.depth());
        let depth: u8 = match child_depth.checked_add(1) {
            Some(value) => value,
            None => return Ok(None),
        };
        if depth > MAX_CIL_EXPRESSION_DEPTH {
            return Ok(None);
        }
        let child_nodes: u8 = match left.nodes().checked_add(right.nodes()) {
            Some(value) => value,
            None => return Ok(None),
        };
        let nodes: u8 = match child_nodes.checked_add(1) {
            Some(value) => value,
            None => return Ok(None),
        };
        if nodes > MAX_CIL_EXPRESSION_NODES {
            return Ok(None);
        }
        let Some(left_value): Option<&Expr> = left.expression_value() else {
            return Ok(None);
        };
        let Some(right_value): Option<&Expr> = right.expression_value() else {
            return Ok(None);
        };
        let value: Expr = Expr::binary(op, left_value.clone(), right_value.clone())?;
        Ok(Some(Self::Expression {
            value,
            depth,
            nodes,
        }))
    }

    fn contains_stack_input(&self, depth: u8) -> bool {
        self.expression_value()
            .is_some_and(|value: &Expr| expression_contains_stack_input(value, depth))
    }
}

pub fn summarize_cil_handler(
    body: &[u8],
    profile: &CilHandlerProfile,
    budget: &mut Budget,
) -> Result<HandlerSummary, Reject> {
    if body.is_empty() {
        return Err(Reject::new("CIL handler body is empty", Vec::new()));
    }
    if body.len() > MAX_CIL_HANDLER_BODY_BYTES {
        return Err(Reject::new(
            "CIL handler body exceeds byte cap",
            vec![
                body.len().to_string(),
                MAX_CIL_HANDLER_BODY_BYTES.to_string(),
            ],
        ));
    }
    let body_cost: u64 = match u64::try_from(body.len()) {
        Ok(value) => value.max(1),
        Err(_) => {
            return Err(Reject::new(
                "CIL handler body length cannot be represented for budgeting",
                Vec::new(),
            ));
        }
    };
    budget.spend(body_cost).map_err(Reject::from_budget_error)?;
    let method: MethodBody = match cil::parse_method_body(body) {
        Ok(value) => value,
        Err(Error::UnknownOpcode(_, _)) => return Ok(unknown_summary()),
        Err(error) => {
            return Err(Reject::new(
                "CIL handler body could not be parsed",
                vec![error.to_string()],
            ));
        }
    };
    if method.instructions.is_empty() {
        return Err(Reject::new(
            "CIL handler instruction stream is empty",
            Vec::new(),
        ));
    }
    if method.instructions.len() > MAX_CIL_HANDLER_INSTRUCTIONS
        || !method.exception_clauses.is_empty()
    {
        return Ok(unknown_summary());
    }
    let effects: Option<Vec<PrimitiveEffect>> = lower_handler(&method, profile, budget)?;
    let Some(value): Option<Vec<PrimitiveEffect>> = effects else {
        return Ok(unknown_summary());
    };
    let summary: HandlerSummary = summarize(&value, budget)?;
    if summary.canonical_op.is_some() {
        Ok(summary)
    } else {
        Ok(unknown_summary())
    }
}

fn lower_handler(
    method: &MethodBody,
    profile: &CilHandlerProfile,
    budget: &mut Budget,
) -> Result<Option<Vec<PrimitiveEffect>>, Reject> {
    let mut state: LoweringState = LoweringState::default();
    for (index, instruction) in method.instructions.iter().enumerate() {
        budget.spend(1).map_err(Reject::from_budget_error)?;
        if state.returned {
            return Ok(None);
        }
        let lowered: Option<()> =
            lower_instruction(method, profile, index, instruction, &mut state)?;
        if lowered.is_none() {
            return Ok(None);
        }
    }
    if !state.returned || !state.cil_stack.is_empty() {
        return Ok(None);
    }
    Ok(Some(state.effects))
}

#[derive(Default)]
struct LoweringState {
    cil_stack: Vec<CilValue>,
    effects: Vec<PrimitiveEffect>,
    consumed_inputs: BTreeSet<u16>,
    next_stack_input: u16,
    returned: bool,
}

fn lower_instruction(
    method: &MethodBody,
    profile: &CilHandlerProfile,
    index: usize,
    instruction: &Instruction,
    state: &mut LoweringState,
) -> Result<Option<()>, Reject> {
    let cil_stack: &mut Vec<CilValue> = &mut state.cil_stack;
    let effects: &mut Vec<PrimitiveEffect> = &mut state.effects;
    let consumed_inputs: &mut BTreeSet<u16> = &mut state.consumed_inputs;
    let next_stack_input: &mut u16 = &mut state.next_stack_input;
    let returned: &mut bool = &mut state.returned;
    match instruction.name.as_str() {
        "nop" => Ok(Some(())),
        "ldarg.0" => load_argument(profile, cil_stack, 0),
        "ldarg.1" => load_argument(profile, cil_stack, 1),
        "ldarg.2" => load_argument(profile, cil_stack, 2),
        "ldarg.3" => load_argument(profile, cil_stack, 3),
        "ldarg.s" | "ldarg" => variable_operand(instruction).map_or(Ok(None), |value: u16| {
            load_argument(profile, cil_stack, value)
        }),
        "starg.s" | "starg" => variable_operand(instruction).map_or(Ok(None), |value: u16| {
            store_argument(profile, cil_stack, effects, consumed_inputs, value)
        }),
        "ldloc.0" => load_local(profile, cil_stack, 0),
        "ldloc.1" => load_local(profile, cil_stack, 1),
        "ldloc.2" => load_local(profile, cil_stack, 2),
        "ldloc.3" => load_local(profile, cil_stack, 3),
        "ldloc.s" | "ldloc" => variable_operand(instruction)
            .map_or(Ok(None), |value: u16| load_local(profile, cil_stack, value)),
        "stloc.0" => store_local(profile, cil_stack, effects, consumed_inputs, 0),
        "stloc.1" => store_local(profile, cil_stack, effects, consumed_inputs, 1),
        "stloc.2" => store_local(profile, cil_stack, effects, consumed_inputs, 2),
        "stloc.3" => store_local(profile, cil_stack, effects, consumed_inputs, 3),
        "stloc.s" | "stloc" => variable_operand(instruction).map_or(Ok(None), |value: u16| {
            store_local(profile, cil_stack, effects, consumed_inputs, value)
        }),
        "ldc.i4.m1" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(-1))).map(Some),
        "ldc.i4.0" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(0))).map(Some),
        "ldc.i4.1" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(1))).map(Some),
        "ldc.i4.2" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(2))).map(Some),
        "ldc.i4.3" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(3))).map(Some),
        "ldc.i4.4" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(4))).map(Some),
        "ldc.i4.5" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(5))).map(Some),
        "ldc.i4.6" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(6))).map(Some),
        "ldc.i4.7" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(7))).map(Some),
        "ldc.i4.8" => push_cil_value(cil_stack, CilValue::expression(Expr::Const(8))).map(Some),
        "ldc.i4.s" => short_constant_operand(instruction).map_or(Ok(None), |value: i64| {
            push_cil_value(cil_stack, CilValue::expression(Expr::Const(value))).map(Some)
        }),
        "ldc.i4" => match &instruction.operand {
            OperandValue::I32(value) => push_cil_value(
                cil_stack,
                CilValue::expression(Expr::Const(i64::from(*value))),
            )
            .map(Some),
            _ => Ok(None),
        },
        "ldc.i8" => match &instruction.operand {
            OperandValue::I64(value) => {
                push_cil_value(cil_stack, CilValue::expression(Expr::Const(*value))).map(Some)
            }
            _ => Ok(None),
        },
        "dup" => duplicate_cil_value(cil_stack).map(Some),
        "pop" => discard_cil_value(cil_stack).map(Some),
        "ldind.i4" | "ldind.i8" | "ldind.i" => {
            let address: CilValue = pop_cil_value(cil_stack)?;
            if address != CilValue::StackPointer {
                return Ok(None);
            }
            let Some(input): Option<&u16> = profile.virtual_stack_reads.get(&instruction.offset)
            else {
                return Ok(None);
            };
            if *input != *next_stack_input {
                return Ok(None);
            }
            *next_stack_input = match next_stack_input.checked_add(1) {
                Some(value) => value,
                None => return Ok(None),
            };
            push_cil_value(cil_stack, CilValue::expression(Expr::VStackAt(*input))).map(Some)
        }
        "stind.i4" | "stind.i8" | "stind.i" => {
            let value: CilValue = pop_cil_value(cil_stack)?;
            let address: CilValue = pop_cil_value(cil_stack)?;
            if address != CilValue::StackPointer
                || !profile.virtual_stack_writes.contains(&instruction.offset)
                || !append_output_value(&value, effects, consumed_inputs, 0)?
            {
                return Ok(None);
            }
            Ok(Some(()))
        }
        "add" => combine_binary(cil_stack, BinOp::Add).map(Some),
        "sub" => combine_binary(cil_stack, BinOp::Sub).map(Some),
        "mul" => combine_binary(cil_stack, BinOp::Mul).map(Some),
        "and" => combine_binary(cil_stack, BinOp::And).map(Some),
        "or" => combine_binary(cil_stack, BinOp::Or).map(Some),
        "xor" => combine_binary(cil_stack, BinOp::Xor).map(Some),
        "ceq" => combine_binary(cil_stack, BinOp::Ceq).map(Some),
        "clt" => combine_binary(cil_stack, BinOp::Clt).map(Some),
        "cgt" => combine_binary(cil_stack, BinOp::Cgt).map(Some),
        "br.s" | "br" => lower_branch(
            method,
            profile,
            index,
            instruction,
            cil_stack,
            effects,
            consumed_inputs,
            PrimitiveEffect::Branch,
        ),
        "brtrue.s" | "brtrue" => lower_branch(
            method,
            profile,
            index,
            instruction,
            cil_stack,
            effects,
            consumed_inputs,
            PrimitiveEffect::BranchIfTrue,
        ),
        "brfalse.s" | "brfalse" => lower_branch(
            method,
            profile,
            index,
            instruction,
            cil_stack,
            effects,
            consumed_inputs,
            PrimitiveEffect::BranchIfFalse,
        ),
        "ret" => lower_return(
            profile,
            instruction,
            cil_stack,
            effects,
            consumed_inputs,
            returned,
        ),
        _ => Ok(None),
    }
}

fn load_argument(
    profile: &CilHandlerProfile,
    stack: &mut Vec<CilValue>,
    index: u16,
) -> Result<Option<()>, Reject> {
    let Some(value): Option<CilValue> = profile.argument_value(index) else {
        return Ok(None);
    };
    push_cil_value(stack, value).map(Some)
}

fn store_argument(
    profile: &CilHandlerProfile,
    stack: &mut Vec<CilValue>,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    index: u16,
) -> Result<Option<()>, Reject> {
    let Some(virtual_index): Option<u16> = profile.virtual_argument(index) else {
        return Ok(None);
    };
    let stored: CilValue = pop_cil_value(stack)?;
    if !append_consumed_value(&stored, effects, consumed_inputs, 0)? {
        return Ok(None);
    }
    push_effect(effects, PrimitiveEffect::StoreArgument(virtual_index))?;
    Ok(Some(()))
}

fn load_local(
    profile: &CilHandlerProfile,
    stack: &mut Vec<CilValue>,
    index: u16,
) -> Result<Option<()>, Reject> {
    let Some(virtual_index): Option<u16> = profile.virtual_local(index) else {
        return Ok(None);
    };
    push_cil_value(stack, CilValue::expression(Expr::Local(virtual_index))).map(Some)
}

fn store_local(
    profile: &CilHandlerProfile,
    stack: &mut Vec<CilValue>,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    index: u16,
) -> Result<Option<()>, Reject> {
    let Some(virtual_index): Option<u16> = profile.virtual_local(index) else {
        return Ok(None);
    };
    let stored: CilValue = pop_cil_value(stack)?;
    if !append_consumed_value(&stored, effects, consumed_inputs, 0)? {
        return Ok(None);
    }
    push_effect(effects, PrimitiveEffect::StoreLocal(virtual_index))?;
    Ok(Some(()))
}

fn variable_operand(instruction: &Instruction) -> Option<u16> {
    match instruction.operand {
        OperandValue::U8(value) => Some(u16::from(value)),
        OperandValue::U16(value) => Some(value),
        _ => None,
    }
}

fn short_constant_operand(instruction: &Instruction) -> Option<i64> {
    match instruction.operand {
        OperandValue::U8(value) => Some(i64::from(i8::from_ne_bytes([value]))),
        _ => None,
    }
}

fn push_cil_value(stack: &mut Vec<CilValue>, value: CilValue) -> Result<(), Reject> {
    if stack.len() >= MAX_CIL_EVALUATION_STACK {
        return Err(Reject::new(
            "CIL evaluation stack exceeds cap",
            vec![MAX_CIL_EVALUATION_STACK.to_string()],
        ));
    }
    stack.push(value);
    Ok(())
}

fn pop_cil_value(stack: &mut Vec<CilValue>) -> Result<CilValue, Reject> {
    stack
        .pop()
        .ok_or_else(|| Reject::new("CIL evaluation stack underflow", Vec::new()))
}

fn duplicate_cil_value(stack: &mut Vec<CilValue>) -> Result<(), Reject> {
    let value: CilValue = match stack.last() {
        Some(value) => value.clone(),
        None => return Err(Reject::new("CIL evaluation stack underflow", Vec::new())),
    };
    if value.contains_stack_input(0) {
        return Err(Reject::new(
            "CIL duplicate aliases a virtual stack input",
            Vec::new(),
        ));
    }
    push_cil_value(stack, value)
}

fn discard_cil_value(stack: &mut Vec<CilValue>) -> Result<(), Reject> {
    let value: CilValue = pop_cil_value(stack)?;
    if value.contains_stack_input(0) {
        return Err(Reject::new(
            "CIL discard consumes a virtual stack input",
            Vec::new(),
        ));
    }
    Ok(())
}

fn combine_binary(stack: &mut Vec<CilValue>, op: BinOp) -> Result<(), Reject> {
    let right: CilValue = pop_cil_value(stack)?;
    let left: CilValue = pop_cil_value(stack)?;
    let Some(value): Option<CilValue> = CilValue::binary(op, left, right)? else {
        return Err(Reject::new(
            "CIL symbolic expression exceeds configured cap",
            vec![
                MAX_CIL_EXPRESSION_DEPTH.to_string(),
                MAX_CIL_EXPRESSION_NODES.to_string(),
            ],
        ));
    };
    push_cil_value(stack, value)
}

fn append_output_value(
    value: &CilValue,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    depth: u8,
) -> Result<bool, Reject> {
    let Some(expression): Option<&Expr> = value.expression_value() else {
        return Ok(false);
    };
    append_output_expression(expression, effects, consumed_inputs, depth)
}

fn append_output_expression(
    value: &Expr,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    depth: u8,
) -> Result<bool, Reject> {
    if depth > MAX_CIL_EXPRESSION_DEPTH {
        return Ok(false);
    }
    match value {
        Expr::Argument(index) => {
            push_effect(effects, PrimitiveEffect::PushArgument(*index))?;
            Ok(true)
        }
        Expr::Local(index) => {
            push_effect(effects, PrimitiveEffect::PushLocal(*index))?;
            Ok(true)
        }
        Expr::Const(value) => {
            push_effect(effects, PrimitiveEffect::PushConst(*value))?;
            Ok(true)
        }
        Expr::VStackTop
        | Expr::VStackAt(_)
        | Expr::VReg(_)
        | Expr::OperandBytes(_)
        | Expr::IpDelta(_) => Ok(false),
        Expr::Binary { op, left, right } => {
            let next_depth: u8 = match depth.checked_add(1) {
                Some(value) => value,
                None => return Ok(false),
            };
            if !append_binary_operand(left, effects, consumed_inputs, next_depth)?
                || !append_binary_operand(right, effects, consumed_inputs, next_depth)?
            {
                return Ok(false);
            }
            push_effect(effects, PrimitiveEffect::Binary(*op))?;
            Ok(true)
        }
    }
}

fn append_binary_operand(
    value: &Expr,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    depth: u8,
) -> Result<bool, Reject> {
    match value {
        Expr::VStackAt(input) => Ok(consumed_inputs.insert(*input)),
        Expr::VStackTop => Ok(false),
        _ => append_output_expression(value, effects, consumed_inputs, depth),
    }
}

fn append_consumed_value(
    value: &CilValue,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    depth: u8,
) -> Result<bool, Reject> {
    match value.stack_input() {
        Some(input) => Ok(consumed_inputs.insert(input)),
        None => append_output_value(value, effects, consumed_inputs, depth),
    }
}

fn push_effect(effects: &mut Vec<PrimitiveEffect>, effect: PrimitiveEffect) -> Result<(), Reject> {
    if effects.len() >= MAX_LOWERED_EFFECTS {
        return Err(Reject::new(
            "lowered handler effects exceed cap",
            vec![MAX_LOWERED_EFFECTS.to_string()],
        ));
    }
    effects.push(effect);
    Ok(())
}

fn expression_contains_stack_input(value: &Expr, depth: u8) -> bool {
    if depth > MAX_CIL_EXPRESSION_DEPTH {
        return true;
    }
    match value {
        Expr::VStackTop | Expr::VStackAt(_) => true,
        Expr::Binary { left, right, .. } => {
            let next_depth: u8 = match depth.checked_add(1) {
                Some(value) => value,
                None => return true,
            };
            expression_contains_stack_input(left, next_depth)
                || expression_contains_stack_input(right, next_depth)
        }
        Expr::VReg(_)
        | Expr::Local(_)
        | Expr::Argument(_)
        | Expr::OperandBytes(_)
        | Expr::Const(_)
        | Expr::IpDelta(_) => false,
    }
}

fn branches_to_next_return(method: &MethodBody, index: usize, instruction: &Instruction) -> bool {
    let target_is_next: bool = matches!(instruction.operand, OperandValue::BrTarget(0));
    let next: Option<&Instruction> = method.instructions.get(index.saturating_add(1));
    target_is_next && next.is_some_and(|value: &Instruction| value.name == "ret")
}

fn lower_branch(
    method: &MethodBody,
    profile: &CilHandlerProfile,
    index: usize,
    instruction: &Instruction,
    cil_stack: &mut Vec<CilValue>,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    effect: PrimitiveEffect,
) -> Result<Option<()>, Reject> {
    if !profile
        .virtual_control_offsets
        .contains(&instruction.offset)
        || !branches_to_next_return(method, index, instruction)
    {
        return Ok(None);
    }
    match &effect {
        PrimitiveEffect::Branch => {
            if !cil_stack.is_empty() {
                return Ok(None);
            }
        }
        PrimitiveEffect::BranchIfTrue | PrimitiveEffect::BranchIfFalse => {
            let condition: CilValue = pop_cil_value(cil_stack)?;
            let Some(input): Option<u16> = condition.stack_input() else {
                return Ok(None);
            };
            if !consumed_inputs.insert(input) {
                return Ok(None);
            }
        }
        PrimitiveEffect::PushArgument(_)
        | PrimitiveEffect::StoreArgument(_)
        | PrimitiveEffect::PushLocal(_)
        | PrimitiveEffect::StoreLocal(_)
        | PrimitiveEffect::PushConst(_)
        | PrimitiveEffect::PushOperandI64
        | PrimitiveEffect::Binary(_)
        | PrimitiveEffect::Return
        | PrimitiveEffect::Opaque => return Ok(None),
    }
    push_effect(effects, effect)?;
    Ok(Some(()))
}

fn lower_return(
    profile: &CilHandlerProfile,
    instruction: &Instruction,
    cil_stack: &mut Vec<CilValue>,
    effects: &mut Vec<PrimitiveEffect>,
    consumed_inputs: &mut BTreeSet<u16>,
    returned: &mut bool,
) -> Result<Option<()>, Reject> {
    match cil_stack.len() {
        0 => {
            *returned = true;
            Ok(Some(()))
        }
        1 => {
            if !profile.virtual_return_offsets.contains(&instruction.offset) {
                return Ok(None);
            }
            let value: CilValue = pop_cil_value(cil_stack)?;
            let Some(input): Option<u16> = value.stack_input() else {
                return Ok(None);
            };
            if !consumed_inputs.insert(input) {
                return Ok(None);
            }
            push_effect(effects, PrimitiveEffect::Return)?;
            *returned = true;
            Ok(Some(()))
        }
        _ => Err(Reject::new(
            "CIL return has an invalid evaluation stack depth",
            vec![cil_stack.len().to_string()],
        )),
    }
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
