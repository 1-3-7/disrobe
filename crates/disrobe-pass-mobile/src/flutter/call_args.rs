use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::NirBlock;

use super::aot_lift::{
    add_imm, bcond, blr_target_reg, fmov_double_immediate, ldr_imm_unsigned, movk, movz, subs_imm,
};
use super::arm64_data::{
    AddSubShiftedReg, BitfieldKind, DivideOp, DivideReg, FloatBinary, FloatBinaryOp, FloatUnary,
    FloatUnaryOp, LogicalImmediate, LogicalOp, LogicalShiftedReg, MultiplyAccumulate, ShiftKind,
    VariableShift, VariableShiftOp, add_sub_shifted_reg, bitfield, divide_reg, float_binary,
    float_unary, integer_to_float, is_zero_register, logical_immediate, logical_shifted_reg, movn,
    multiply_accumulate, variable_shift,
};
use super::disasm::{Arm64FlowKind, Arm64Function, Arm64Instruction};
use super::pool_table::{DartPoolTable, UNRESOLVED_TOKEN, render_double};

pub(super) const DART_ARGUMENT_REGISTERS: [u8; 6] = [1, 2, 3, 5, 6, 7];

const DART_RESULT_REGISTER: u8 = 0;

const DART_POOL_REGISTER: u8 = 27;

const DART_NULL_REGISTER: u8 = 22;

const DART_STACK_REGISTER: u8 = 15;

const DART_FRAME_REGISTER: u8 = 29;

const DART_IC_DATA_REGISTER: u8 = 5;

const DART_TRUE_OFFSET_FROM_NULL: u64 = 0x20;

const DART_FALSE_OFFSET_FROM_NULL: u64 = 0x30;

const ARM64_ZERO_REGISTER: u8 = 31;

const STACK_SLOT_BYTES: u64 = 8;

const MAX_STACK_ARGUMENTS: usize = 32;

const MAX_FRAME_SLOTS: usize = 128;

const MAX_VALUE_DEPTH: usize = 6;

const MAX_TRACKED_CALLS: usize = 1 << 14;

const MAX_MERGE_PREDECESSORS: usize = 64;

const MAX_BOOLEAN_RETURN_INSTRUCTIONS: usize = 64;

const ARM64_IMMEDIATE_SHIFT_BIT: u32 = 1 << 22;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DartComparison {
    left: DartValue,
    right: DartValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConditionalSelectKind {
    Select,
    Increment,
    Invert,
    Negate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DartCondition {
    Equal,
    NotEqual,
    GreaterOrEqual,
    LessThan,
    GreaterThan,
    LessOrEqual,
}

impl DartCondition {
    const fn from_arm64(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Equal),
            1 => Some(Self::NotEqual),
            10 => Some(Self::GreaterOrEqual),
            11 => Some(Self::LessThan),
            12 => Some(Self::GreaterThan),
            13 => Some(Self::LessOrEqual),
            _ => None,
        }
    }

    const fn inverse(self) -> Self {
        match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::GreaterOrEqual => Self::LessThan,
            Self::LessThan => Self::GreaterOrEqual,
            Self::GreaterThan => Self::LessOrEqual,
            Self::LessOrEqual => Self::GreaterThan,
        }
    }

    const fn operator(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::GreaterOrEqual => ">=",
            Self::LessThan => "<",
            Self::GreaterThan => ">",
            Self::LessOrEqual => "<=",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DartBinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    TruncatingDivide,
    Remainder,
    BitAnd,
    BitOr,
    BitXor,
    ShiftLeft,
    ShiftRight,
    UnsignedShiftRight,
    Maximum,
    Minimum,
}

impl DartBinaryOp {
    const fn operator(self) -> Option<&'static str> {
        match self {
            Self::Add => Some("+"),
            Self::Subtract => Some("-"),
            Self::Multiply => Some("*"),
            Self::Divide => Some("/"),
            Self::TruncatingDivide => Some("~/"),
            Self::Remainder => Some("%"),
            Self::BitAnd => Some("&"),
            Self::BitOr => Some("|"),
            Self::BitXor => Some("^"),
            Self::ShiftLeft => Some("<<"),
            Self::ShiftRight => Some(">>"),
            Self::UnsignedShiftRight => Some(">>>"),
            Self::Maximum | Self::Minimum => None,
        }
    }

    const fn method(self) -> &'static str {
        match self {
            Self::Minimum => "min",
            _ => "max",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DartUnaryOp {
    Negate,
    BitNot,
    Absolute,
    SquareRoot,
    ToDouble,
    Truncate { width: u8, signed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DartValue {
    Null,
    Bool(bool),
    Int(i64),
    Double(u64),
    Pool {
        byte_offset: u64,
        float: bool,
    },
    Param(usize),
    CallResult(u64),
    Field {
        base: Box<Self>,
        offset: i64,
    },
    Offset {
        base: Box<Self>,
        delta: i64,
    },
    PcRelative(u64),
    Binary {
        op: DartBinaryOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    Unary {
        op: DartUnaryOp,
        operand: Box<Self>,
    },
    SmiTag(Box<Self>),
    SmiUntag(Box<Self>),
    Select {
        condition: DartCondition,
        comparison: Box<DartComparison>,
        when_true: Box<Self>,
        when_false: Box<Self>,
    },
}

const MAX_VALUE_NODES: usize = 48;

fn node_budget(value: &DartValue, remaining: usize) -> Option<usize> {
    let left: usize = remaining.checked_sub(1)?;
    match value {
        DartValue::Field { base, .. } | DartValue::Offset { base, .. } => node_budget(base, left),
        DartValue::Unary { operand, .. }
        | DartValue::SmiTag(operand)
        | DartValue::SmiUntag(operand) => node_budget(operand, left),
        DartValue::Binary {
            left: lhs,
            right: rhs,
            ..
        } => {
            let after: usize = node_budget(lhs, left)?;
            node_budget(rhs, after)
        }
        DartValue::Select {
            comparison,
            when_true,
            when_false,
            ..
        } => {
            let after_left: usize = node_budget(&comparison.left, left)?;
            let after_right: usize = node_budget(&comparison.right, after_left)?;
            let after_true: usize = node_budget(when_true, after_right)?;
            node_budget(when_false, after_true)
        }
        _ => Some(left),
    }
}

fn bounded(value: DartValue) -> Option<DartValue> {
    node_budget(&value, MAX_VALUE_NODES).map(|_: usize| value)
}

fn truncate_int(number: i64, width: u8, signed: bool) -> Option<i64> {
    if width == 0 || width > 64 {
        return None;
    }
    if width == 64 {
        return Some(number);
    }
    let mask: u64 = (1_u64 << width) - 1;
    let raw: u64 = (number as u64) & mask;
    if signed && raw & (1_u64 << (width - 1)) != 0 {
        Some((raw as i64) - (1_i64 << width))
    } else {
        Some(raw as i64)
    }
}

fn fold_constants(op: DartBinaryOp, left: i64, right: i64) -> Option<i64> {
    match op {
        DartBinaryOp::Add => left.checked_add(right),
        DartBinaryOp::Subtract => left.checked_sub(right),
        DartBinaryOp::Multiply => left.checked_mul(right),
        DartBinaryOp::TruncatingDivide => left.checked_div(right),
        DartBinaryOp::Remainder => left.checked_rem(right),
        DartBinaryOp::BitAnd => Some(left & right),
        DartBinaryOp::BitOr => Some(left | right),
        DartBinaryOp::BitXor => Some(left ^ right),
        DartBinaryOp::ShiftLeft => {
            let shifted: i64 = left.checked_shl(u32::try_from(right).ok()?)?;
            (shifted >> right == left).then_some(shifted)
        }
        DartBinaryOp::ShiftRight => left.checked_shr(u32::try_from(right).ok()?),
        DartBinaryOp::UnsignedShiftRight => {
            let amount: u32 = u32::try_from(right).ok()?;
            (amount < 64).then(|| ((left as u64) >> amount) as i64)
        }
        DartBinaryOp::Maximum => Some(left.max(right)),
        DartBinaryOp::Minimum => Some(left.min(right)),
        DartBinaryOp::Divide => None,
    }
}

fn identity(op: DartBinaryOp, left: &DartValue, right: &DartValue) -> Option<DartValue> {
    if op == DartBinaryOp::Subtract && left == right {
        return Some(DartValue::Int(0));
    }
    if left == &DartValue::Int(0)
        && matches!(
            op,
            DartBinaryOp::Add | DartBinaryOp::BitOr | DartBinaryOp::BitXor
        )
    {
        return Some(right.clone());
    }
    let DartValue::Int(number) = right else {
        return None;
    };
    let neutral: bool = match op {
        DartBinaryOp::Add
        | DartBinaryOp::Subtract
        | DartBinaryOp::BitOr
        | DartBinaryOp::BitXor
        | DartBinaryOp::ShiftLeft
        | DartBinaryOp::ShiftRight
        | DartBinaryOp::UnsignedShiftRight => *number == 0,
        DartBinaryOp::Multiply | DartBinaryOp::TruncatingDivide => *number == 1,
        DartBinaryOp::BitAnd => *number == -1,
        _ => false,
    };
    neutral.then(|| left.clone())
}

fn remainder_idiom(op: DartBinaryOp, left: &DartValue, right: &DartValue) -> Option<DartValue> {
    if op != DartBinaryOp::Subtract {
        return None;
    }
    let DartValue::Binary {
        op: DartBinaryOp::Multiply,
        left: product_left,
        right: product_right,
    } = right
    else {
        return None;
    };
    let divisor: &DartValue = quotient_divisor(product_left, product_right, left)
        .or_else(|| quotient_divisor(product_right, product_left, left))?;
    bounded(DartValue::Binary {
        op: DartBinaryOp::Remainder,
        left: Box::new(left.clone()),
        right: Box::new(divisor.clone()),
    })
}

fn quotient_divisor<'a>(
    quotient: &'a DartValue,
    factor: &'a DartValue,
    dividend: &DartValue,
) -> Option<&'a DartValue> {
    let DartValue::Binary {
        op: DartBinaryOp::TruncatingDivide,
        left: numerator,
        right: denominator,
    } = quotient
    else {
        return None;
    };
    (numerator.as_ref() == dividend && denominator.as_ref() == factor).then_some(factor)
}

fn binary(op: DartBinaryOp, left: DartValue, right: DartValue) -> Option<DartValue> {
    if let (DartValue::Int(a), DartValue::Int(b)) = (&left, &right)
        && let Some(folded) = fold_constants(op, *a, *b)
    {
        return Some(DartValue::Int(folded));
    }
    if op == DartBinaryOp::Subtract && left == DartValue::Int(0) {
        return unary(DartUnaryOp::Negate, right);
    }
    if let Some(simplified) = identity(op, &left, &right) {
        return bounded(simplified);
    }
    if let Some(remainder) = remainder_idiom(op, &left, &right) {
        return Some(remainder);
    }
    bounded(DartValue::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
    })
}

fn unary(op: DartUnaryOp, operand: DartValue) -> Option<DartValue> {
    if let DartValue::Int(number) = operand {
        let folded: Option<i64> = match op {
            DartUnaryOp::Negate => number.checked_neg(),
            DartUnaryOp::BitNot => Some(!number),
            DartUnaryOp::Absolute => number.checked_abs(),
            DartUnaryOp::Truncate { width, signed } => truncate_int(number, width, signed),
            DartUnaryOp::SquareRoot | DartUnaryOp::ToDouble => None,
        };
        if let Some(number) = folded {
            return Some(DartValue::Int(number));
        }
    }
    if let DartValue::Unary {
        op: inner_op,
        operand: inner,
    } = &operand
        && *inner_op == op
        && matches!(op, DartUnaryOp::Truncate { .. })
    {
        return bounded(DartValue::Unary {
            op,
            operand: inner.clone(),
        });
    }
    bounded(DartValue::Unary {
        op,
        operand: Box::new(operand),
    })
}

fn smi_tag(value: DartValue) -> Option<DartValue> {
    match value {
        DartValue::SmiUntag(inner) => Some(*inner),
        DartValue::Int(number) => number.checked_mul(2).map(DartValue::Int),
        other => bounded(DartValue::SmiTag(Box::new(other))),
    }
}

fn smi_untag(value: DartValue) -> Option<DartValue> {
    match value {
        DartValue::SmiTag(inner) => Some(*inner),
        DartValue::Int(number) => Some(DartValue::Int(number >> 1)),
        other => bounded(DartValue::SmiUntag(Box::new(other))),
    }
}

fn shifted_operand(value: DartValue, shift: ShiftKind, amount: u8) -> Option<DartValue> {
    if amount == 0 {
        return Some(value);
    }
    let op: DartBinaryOp = match shift {
        ShiftKind::Lsl => DartBinaryOp::ShiftLeft,
        ShiftKind::Asr => DartBinaryOp::ShiftRight,
        ShiftKind::Lsr => DartBinaryOp::UnsignedShiftRight,
        ShiftKind::Ror => return None,
    };
    binary(op, value, DartValue::Int(i64::from(amount)))
}

fn bitfield_value(kind: BitfieldKind, operand: DartValue) -> Option<DartValue> {
    match kind {
        BitfieldKind::ShiftRight { amount, signed } => binary(
            if signed {
                DartBinaryOp::ShiftRight
            } else {
                DartBinaryOp::UnsignedShiftRight
            },
            operand,
            DartValue::Int(i64::from(amount)),
        ),
        BitfieldKind::ShiftLeft { amount } => binary(
            DartBinaryOp::ShiftLeft,
            operand,
            DartValue::Int(i64::from(amount)),
        ),
        BitfieldKind::Extract {
            lsb: SMI_TAG_BITS,
            width: SMI_COMPRESSED_WIDTH,
            signed: true,
        } => smi_untag(operand),
        BitfieldKind::Extract { lsb, width, signed } => {
            let shifted: DartValue = binary(
                DartBinaryOp::ShiftRight,
                operand,
                DartValue::Int(i64::from(lsb)),
            )?;
            unary(DartUnaryOp::Truncate { width, signed }, shifted)
        }
        BitfieldKind::ExtractInsert {
            lsb: SMI_TAG_BITS,
            width: SMI_COMPRESSED_WIDTH,
            signed: true,
        } => smi_tag(operand),
        BitfieldKind::ExtractInsert { lsb, width, signed } => {
            let truncated: DartValue = unary(DartUnaryOp::Truncate { width, signed }, operand)?;
            binary(
                DartBinaryOp::ShiftLeft,
                truncated,
                DartValue::Int(i64::from(lsb)),
            )
        }
    }
}

const SMI_TAG_BITS: u8 = 1;

const SMI_COMPRESSED_WIDTH: u8 = 31;

#[derive(Debug, Default, Clone)]
pub(super) struct DartCallArguments {
    rendered: BTreeMap<u64, Vec<String>>,
    results: BTreeMap<u64, usize>,
    definitions: BTreeMap<u64, String>,
    stores: BTreeMap<u64, String>,
    returns: BTreeMap<u64, String>,
    comparisons: BTreeMap<u64, (String, String)>,
    copies: BTreeSet<u64>,
    pub(super) recovered_sites: usize,
    pub(super) opaque_sites: usize,
    pub(super) max_parameter: Option<usize>,
    pub(super) lifted_statements: usize,
    pub(super) recovered_returns: usize,
    pub(super) recovered_field_stores: usize,
}

impl DartCallArguments {
    pub(super) fn arguments(&self, address: u64) -> Option<&[String]> {
        self.rendered
            .get(&address)
            .map(|values: &Vec<String>| values.as_slice())
    }

    pub(super) fn result_binding(&self, address: u64) -> Option<usize> {
        self.results.get(&address).copied()
    }

    pub(super) fn definition(&self, address: u64) -> Option<&str> {
        self.definitions
            .get(&address)
            .map(|text: &String| text.as_str())
    }

    pub(super) fn field_store(&self, address: u64) -> Option<&str> {
        self.stores.get(&address).map(|text: &String| text.as_str())
    }

    pub(super) fn return_expression(&self, address: u64) -> Option<&str> {
        self.returns
            .get(&address)
            .map(|text: &String| text.as_str())
    }

    pub(super) fn is_bookkeeping(&self, address: u64) -> bool {
        self.copies.contains(&address)
    }

    pub(super) fn comparison(&self, address: u64) -> Option<(&str, &str)> {
        self.comparisons
            .get(&address)
            .map(|(left, right): &(String, String)| (left.as_str(), right.as_str()))
    }

    pub(super) fn recovered_conditions(&self) -> usize {
        self.comparisons.len()
    }
}

#[derive(Debug, Default, Clone)]
struct TrackedEffects {
    definitions: BTreeMap<u64, DartValue>,
    stores: BTreeMap<u64, (DartValue, i64, DartValue)>,
    returns: BTreeMap<u64, DartValue>,
    comparisons: BTreeMap<u64, DartComparison>,
    copies: BTreeSet<u64>,
}

impl TrackedEffects {
    fn define(&mut self, address: u64, value: Option<DartValue>) {
        if self.definitions.len() >= MAX_TRACKED_EFFECTS {
            return;
        }
        match value {
            Some(value) => {
                self.definitions.insert(address, value);
            }
            None => {
                self.definitions.remove(&address);
            }
        }
    }

    fn bookkeeping(&mut self, address: u64) {
        if self.copies.len() < MAX_TRACKED_EFFECTS {
            self.copies.insert(address);
        }
    }
}

const MAX_TRACKED_EFFECTS: usize = 1 << 16;

#[derive(Debug, Default, Clone)]
struct TrackState {
    integers: BTreeMap<u8, DartValue>,
    floats: BTreeMap<u8, DartValue>,
    written: BTreeSet<u8>,
    stack: BTreeMap<u64, Option<DartValue>>,
    frame: BTreeMap<i64, DartValue>,
    selector_registers: BTreeSet<u8>,
    flags: Option<DartComparison>,
    last_result: Option<DartValue>,
}

impl TrackState {
    fn entry(parameter_count: Option<u8>) -> Self {
        let mut state: Self = Self::default();
        let register_count: usize = parameter_count
            .map_or(DART_ARGUMENT_REGISTERS.len(), |count: u8| {
                usize::from(count).min(DART_ARGUMENT_REGISTERS.len())
            });
        for (position, register) in DART_ARGUMENT_REGISTERS
            .iter()
            .take(register_count)
            .enumerate()
        {
            state.integers.insert(*register, DartValue::Param(position));
        }
        state
    }

    fn define(&mut self, register: u8, value: Option<DartValue>) {
        if register == ARM64_ZERO_REGISTER {
            return;
        }
        if register == DART_STACK_REGISTER {
            self.stack.clear();
        }
        if register == DART_FRAME_REGISTER {
            self.frame.clear();
        }
        self.written.insert(register);
        self.selector_registers.remove(&register);
        if register == DART_RESULT_REGISTER {
            self.last_result.clone_from(&value);
        }
        match value {
            Some(value) => {
                self.integers.insert(register, value);
            }
            None => {
                self.integers.remove(&register);
            }
        }
    }

    fn forget(&mut self, register: u8) {
        self.integers.remove(&register);
        self.selector_registers.remove(&register);
    }

    fn mark_read(&mut self, register: u8) {
        self.written.remove(&register);
    }

    fn define_float(&mut self, register: u8, value: Option<DartValue>) {
        if register == DART_RESULT_REGISTER {
            self.last_result.clone_from(&value);
        }
        match value {
            Some(value) => {
                self.floats.insert(register, value);
            }
            None => {
                self.floats.remove(&register);
            }
        }
    }

    fn consume_call(&mut self, address: u64) {
        self.integers.clear();
        self.floats.clear();
        self.written.clear();
        self.stack.clear();
        self.selector_registers.clear();
        self.flags = None;
        self.last_result = Some(DartValue::CallResult(address));
        self.integers
            .insert(DART_RESULT_REGISTER, DartValue::CallResult(address));
        self.floats
            .insert(DART_RESULT_REGISTER, DartValue::CallResult(address));
    }
}

pub(super) fn recover_boolean_return(
    func: &Arm64Function,
    pool: Option<&DartPoolTable>,
) -> Option<(String, u8)> {
    if func.instructions.is_empty() || func.instructions.len() > MAX_BOOLEAN_RETURN_INSTRUCTIONS {
        return None;
    }
    let mut state: TrackState = TrackState::entry(None);
    let mut comparison: Option<(usize, DartComparison)> = None;
    let mut selected: Option<(DartComparison, DartCondition)> = None;
    let mut producers: BTreeMap<u8, usize> = BTreeMap::new();
    let mut consumed_effects: Vec<bool> = Vec::with_capacity(func.instructions.len());
    for (index, instruction) in func.instructions.iter().enumerate() {
        match instruction.flow {
            Arm64FlowKind::Sequential => {
                if !is_boolean_return_step(instruction.bytes) {
                    return None;
                }
                consumed_effects.push(false);
                if let Some((destination, base, _)) = ldr_imm_unsigned(instruction.bytes) {
                    consume_register_effect(&producers, &mut consumed_effects, base);
                    producers.insert(destination, index);
                } else if let Some((destination, base, _)) = ldur_signed(instruction.bytes) {
                    consume_register_effect(&producers, &mut consumed_effects, base);
                    producers.insert(destination, index);
                } else if let Some((destination, base, _)) = add_imm(instruction.bytes) {
                    consume_register_effect(&producers, &mut consumed_effects, base);
                    producers.insert(destination, index);
                }
                if let Some((31, register, immediate)) = subs_imm(instruction.bytes) {
                    if instruction.bytes & ARM64_IMMEDIATE_SHIFT_BIT != 0 {
                        return None;
                    }
                    consume_register_effect(&producers, &mut consumed_effects, register);
                    comparison = state
                        .integers
                        .get(&register)
                        .cloned()
                        .map(|left: DartValue| DartComparison {
                            left,
                            right: DartValue::Int(immediate as i64),
                        })
                        .map(|comparison: DartComparison| (index, comparison));
                }
                if let Some((kind, 0, true_register, false_register, condition)) =
                    conditional_select(instruction.bytes)
                {
                    if kind != ConditionalSelectKind::Select || index + 2 != func.instructions.len()
                    {
                        return None;
                    }
                    let condition: DartCondition = DartCondition::from_arm64(condition)?;
                    let when_true: &DartValue = state.integers.get(&true_register)?;
                    let when_false: &DartValue = state.integers.get(&false_register)?;
                    let selected_condition: DartCondition = match (when_true, when_false) {
                        (DartValue::Bool(true), DartValue::Bool(false)) => condition,
                        (DartValue::Bool(false), DartValue::Bool(true)) => condition.inverse(),
                        _ => return None,
                    };
                    let (comparison_index, comparison): (usize, DartComparison) =
                        comparison.take()?;
                    if index.saturating_sub(comparison_index) > 3 {
                        return None;
                    }
                    consume_register_effect(&producers, &mut consumed_effects, true_register);
                    consume_register_effect(&producers, &mut consumed_effects, false_register);
                    let comparison_consumed: &mut bool =
                        consumed_effects.get_mut(comparison_index)?;
                    *comparison_consumed = true;
                    let selection_consumed: &mut bool = consumed_effects.get_mut(index)?;
                    *selection_consumed = true;
                    selected = Some((comparison, selected_condition));
                }
                apply_sequential(&mut state, instruction, instruction.bytes);
            }
            Arm64FlowKind::Return if index + 1 == func.instructions.len() => {
                if consumed_effects.iter().any(|consumed: &bool| !consumed) {
                    return None;
                }
                let (comparison, condition): (DartComparison, DartCondition) = selected?;
                let mut consumed: BTreeSet<u64> = BTreeSet::new();
                let mut max_parameter: Option<usize> = None;
                collect_dependencies(&comparison.left, &mut consumed, &mut max_parameter);
                collect_dependencies(&comparison.right, &mut consumed, &mut max_parameter);
                let parameter_count: u8 = max_parameter
                    .and_then(|position: usize| position.checked_add(1))
                    .and_then(|count: usize| u8::try_from(count).ok())
                    .unwrap_or(0);
                return Some((
                    format!(
                        "{} {} {}",
                        render_value(&comparison.left, pool, &BTreeMap::new(), 0),
                        condition.operator(),
                        render_value(&comparison.right, pool, &BTreeMap::new(), 0)
                    ),
                    parameter_count,
                ));
            }
            _ => return None,
        }
    }
    None
}

fn consume_register_effect(
    producers: &BTreeMap<u8, usize>,
    consumed_effects: &mut [bool],
    register: u8,
) {
    if let Some(index) = producers.get(&register)
        && let Some(consumed) = consumed_effects.get_mut(*index)
    {
        *consumed = true;
    }
}

fn is_boolean_return_step(raw: u32) -> bool {
    ldr_imm_unsigned(raw).is_some()
        || ldur_signed(raw).is_some()
        || matches!(subs_imm(raw), Some((31, _, _)))
        || matches!(
            add_imm(raw),
            Some((
                _,
                DART_NULL_REGISTER,
                DART_TRUE_OFFSET_FROM_NULL | DART_FALSE_OFFSET_FROM_NULL
            ))
        )
        || conditional_select(raw).is_some()
}

pub(super) fn recover_call_arguments(
    func: &Arm64Function,
    blocks: &[NirBlock],
    reachable: &BTreeSet<u64>,
    tail_calls: &BTreeSet<u64>,
    pool: Option<&DartPoolTable>,
    parameter_count: Option<u8>,
) -> DartCallArguments {
    let live: Vec<&NirBlock> = blocks
        .iter()
        .filter(|block: &&NirBlock| reachable.contains(&block.start))
        .collect::<Vec<&NirBlock>>();
    let (sites, effects): (BTreeMap<u64, Vec<Option<DartValue>>>, TrackedEffects) =
        track_call_sites(func, &live, tail_calls, parameter_count);
    let mut consumed: BTreeSet<u64> = BTreeSet::new();
    let mut max_parameter: Option<usize> = None;
    for values in sites.values() {
        for value in values.iter().flatten() {
            collect_dependencies(value, &mut consumed, &mut max_parameter);
        }
    }
    for value in effects
        .definitions
        .values()
        .chain(effects.returns.values())
        .chain(
            effects
                .stores
                .values()
                .flat_map(|(base, _, value): &(DartValue, i64, DartValue)| [base, value]),
        )
    {
        collect_dependencies(value, &mut consumed, &mut max_parameter);
    }
    let results: BTreeMap<u64, usize> = consumed
        .iter()
        .enumerate()
        .map(|(index, address): (usize, &u64)| (*address, index))
        .collect::<BTreeMap<u64, usize>>();

    let mut rendered: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut recovered_sites: usize = 0;
    for (address, values) in &sites {
        if values.is_empty() {
            continue;
        }
        let texts: Vec<String> = values
            .iter()
            .map(|value: &Option<DartValue>| match value {
                Some(value) => render_value(value, pool, &results, 0),
                None => UNRESOLVED_TOKEN.to_owned(),
            })
            .collect::<Vec<String>>();
        recovered_sites += 1;
        rendered.insert(*address, texts);
    }
    let opaque_sites: usize = sites.len().saturating_sub(recovered_sites);

    let comparisons: BTreeMap<u64, (String, String)> = effects
        .comparisons
        .iter()
        .map(|(address, comparison): (&u64, &DartComparison)| {
            (
                *address,
                (
                    render_value(&comparison.left, pool, &results, 0),
                    render_value(&comparison.right, pool, &results, 0),
                ),
            )
        })
        .filter(|(_, (left, right)): &(u64, (String, String))| {
            left != UNRESOLVED_TOKEN && right != UNRESOLVED_TOKEN
        })
        .collect::<BTreeMap<u64, (String, String)>>();
    let stores: BTreeMap<u64, String> = effects
        .stores
        .iter()
        .map(
            |(address, (base, offset, value)): (&u64, &(DartValue, i64, DartValue))| {
                (
                    *address,
                    format!(
                        "{}.field@{offset:#x} = {};",
                        render_operand(base, pool, &results, 0),
                        render_value(value, pool, &results, 0)
                    ),
                )
            },
        )
        .collect::<BTreeMap<u64, String>>();
    let returns: BTreeMap<u64, String> = effects
        .returns
        .iter()
        .map(|(address, value): (&u64, &DartValue)| {
            (*address, render_value(value, pool, &results, 0))
        })
        .filter(|(_, text): &(u64, String)| text != UNRESOLVED_TOKEN)
        .collect::<BTreeMap<u64, String>>();

    let haystack: String = consumed_text(&rendered, &returns, &stores, &comparisons);
    let mut definitions: BTreeMap<u64, String> = BTreeMap::new();
    let mut copies: BTreeSet<u64> = effects.copies;
    for (address, value) in &effects.definitions {
        let text: String = render_value(value, pool, &results, 0);
        if text == UNRESOLVED_TOKEN {
            continue;
        }
        if haystack.contains(text.as_str()) {
            copies.insert(*address);
            continue;
        }
        definitions.insert(*address, text);
    }
    let lifted_statements: usize = copies
        .len()
        .saturating_add(stores.len())
        .saturating_add(definitions.len());
    let definitions: BTreeMap<u64, String> = definitions
        .into_iter()
        .enumerate()
        .map(|(index, (address, text)): (usize, (u64, String))| {
            (address, format!("var t{index} = {text};"))
        })
        .collect::<BTreeMap<u64, String>>();

    DartCallArguments {
        rendered,
        results,
        recovered_returns: returns.len(),
        recovered_field_stores: stores.len(),
        definitions,
        stores,
        returns,
        comparisons,
        copies,
        recovered_sites,
        opaque_sites,
        max_parameter,
        lifted_statements,
    }
}

const MAX_CONSUMED_TEXT_BYTES: usize = 1 << 16;

fn consumed_text(
    rendered: &BTreeMap<u64, Vec<String>>,
    returns: &BTreeMap<u64, String>,
    stores: &BTreeMap<u64, String>,
    comparisons: &BTreeMap<u64, (String, String)>,
) -> String {
    let mut haystack: String = String::new();
    let mut push = |text: &str| {
        if haystack.len() < MAX_CONSUMED_TEXT_BYTES {
            haystack.push_str(text);
            haystack.push('\n');
        }
    };
    for values in rendered.values() {
        for value in values {
            push(value);
        }
    }
    for text in returns.values().chain(stores.values()) {
        push(text);
    }
    for (left, right) in comparisons.values() {
        push(left);
        push(right);
    }
    haystack
}

fn collect_dependencies(
    value: &DartValue,
    consumed: &mut BTreeSet<u64>,
    max_parameter: &mut Option<usize>,
) {
    match value {
        DartValue::CallResult(address) => {
            consumed.insert(*address);
        }
        DartValue::Param(position) => {
            *max_parameter =
                Some(max_parameter.map_or(*position, |seen: usize| seen.max(*position)));
        }
        DartValue::Field { base, .. } | DartValue::Offset { base, .. } => {
            collect_dependencies(base, consumed, max_parameter);
        }
        DartValue::Unary { operand, .. }
        | DartValue::SmiTag(operand)
        | DartValue::SmiUntag(operand) => {
            collect_dependencies(operand, consumed, max_parameter);
        }
        DartValue::Binary { left, right, .. } => {
            collect_dependencies(left, consumed, max_parameter);
            collect_dependencies(right, consumed, max_parameter);
        }
        DartValue::Select {
            comparison,
            when_true,
            when_false,
            ..
        } => {
            collect_dependencies(&comparison.left, consumed, max_parameter);
            collect_dependencies(&comparison.right, consumed, max_parameter);
            collect_dependencies(when_true, consumed, max_parameter);
            collect_dependencies(when_false, consumed, max_parameter);
        }
        DartValue::Null
        | DartValue::Bool(_)
        | DartValue::Int(_)
        | DartValue::Double(_)
        | DartValue::Pool { .. }
        | DartValue::PcRelative(_) => {}
    }
}

fn track_call_sites(
    func: &Arm64Function,
    blocks: &[&NirBlock],
    tail_calls: &BTreeSet<u64>,
    parameter_count: Option<u8>,
) -> (BTreeMap<u64, Vec<Option<DartValue>>>, TrackedEffects) {
    let insns: &[Arm64Instruction] = &func.instructions;
    let predecessors: BTreeMap<u64, Vec<u64>> = predecessors_of(blocks);
    let mut exits: BTreeMap<u64, TrackState> = BTreeMap::new();
    let mut sites: BTreeMap<u64, Vec<Option<DartValue>>> = BTreeMap::new();
    let mut effects: TrackedEffects = TrackedEffects::default();
    let entry: Option<u64> = blocks.first().map(|block: &&NirBlock| block.start);

    for block in blocks {
        if sites.len() > MAX_TRACKED_CALLS {
            break;
        }
        let mut state: TrackState = if Some(block.start) == entry {
            TrackState::entry(parameter_count)
        } else {
            entry_state(predecessors.get(&block.start), &exits)
        };
        for insn in insns.iter().filter(|insn: &&Arm64Instruction| {
            insn.address >= block.start && insn.address < block.end
        }) {
            step(&mut state, insn, tail_calls, &mut sites, &mut effects);
        }
        exits.insert(block.start, state);
    }
    (sites, effects)
}

fn entry_state(sources: Option<&Vec<u64>>, exits: &BTreeMap<u64, TrackState>) -> TrackState {
    let Some(sources): Option<&Vec<u64>> = sources else {
        return TrackState::default();
    };
    if sources.is_empty() || sources.len() > MAX_MERGE_PREDECESSORS {
        return TrackState::default();
    }
    let Some(known): Option<Vec<&TrackState>> = sources
        .iter()
        .map(|source: &u64| exits.get(source))
        .collect::<Option<Vec<&TrackState>>>()
    else {
        return TrackState::default();
    };
    merge_states(&known).unwrap_or_default()
}

fn merge_states(states: &[&TrackState]) -> Option<TrackState> {
    let (first, rest): (&&TrackState, &[&TrackState]) = states.split_first()?;
    let mut merged: TrackState = (*first).clone();
    for other in rest {
        retain_agreed(&mut merged.integers, &other.integers);
        retain_agreed(&mut merged.floats, &other.floats);
        retain_agreed(&mut merged.stack, &other.stack);
        retain_agreed(&mut merged.frame, &other.frame);
        merged
            .written
            .retain(|register: &u8| other.written.contains(register));
        merged
            .selector_registers
            .extend(other.selector_registers.iter().copied());
        if merged.flags != other.flags {
            merged.flags = None;
        }
        if merged.last_result != other.last_result {
            merged.last_result = None;
        }
    }
    Some(merged)
}

fn retain_agreed<K: Ord, V: PartialEq>(base: &mut BTreeMap<K, V>, other: &BTreeMap<K, V>) {
    base.retain(|key: &K, value: &mut V| other.get(key) == Some(&*value));
}

fn predecessors_of(blocks: &[&NirBlock]) -> BTreeMap<u64, Vec<u64>> {
    let starts: BTreeSet<u64> = blocks.iter().map(|block: &&NirBlock| block.start).collect();
    let mut sources: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for block in blocks {
        for successor in &block.successors {
            if starts.contains(successor) {
                let entry: &mut Vec<u64> = sources.entry(*successor).or_default();
                if !entry.contains(&block.start) {
                    entry.push(block.start);
                }
            }
        }
    }
    sources
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SequentialEffect {
    Integer(u8),
    Float(u8),
    Bookkeeping,
    Store {
        base: DartValue,
        offset: i64,
        value: DartValue,
    },
    Opaque,
}

fn step(
    state: &mut TrackState,
    insn: &Arm64Instruction,
    tail_calls: &BTreeSet<u64>,
    sites: &mut BTreeMap<u64, Vec<Option<DartValue>>>,
    effects: &mut TrackedEffects,
) {
    let raw: u32 = insn.bytes;
    match insn.flow {
        Arm64FlowKind::DirectCall | Arm64FlowKind::IndirectCall => {
            let indirect: bool = insn.flow == Arm64FlowKind::IndirectCall;
            let arguments: Vec<Option<DartValue>> = collect_arguments(state, indirect, raw);
            sites.insert(insn.address, arguments);
            state.consume_call(insn.address);
            return;
        }
        Arm64FlowKind::DirectBranch => {
            if tail_calls.contains(&insn.address) {
                let arguments: Vec<Option<DartValue>> = collect_arguments(state, false, raw);
                sites.insert(insn.address, arguments);
            }
            return;
        }
        Arm64FlowKind::Return => {
            if let Some(value) = state.last_result.clone()
                && effects.returns.len() < MAX_TRACKED_EFFECTS
            {
                effects.returns.insert(insn.address, value);
            }
            return;
        }
        Arm64FlowKind::ConditionalBranch => {
            let comparison: Option<DartComparison> = if bcond(raw).is_some() {
                state.flags.clone()
            } else {
                compare_and_branch_register(raw).and_then(|register: u8| {
                    read_register(state, register).map(|left: DartValue| DartComparison {
                        left,
                        right: DartValue::Int(0),
                    })
                })
            };
            if let Some(comparison) = comparison
                && effects.comparisons.len() < MAX_TRACKED_EFFECTS
            {
                effects.comparisons.insert(insn.address, comparison);
            }
            return;
        }
        Arm64FlowKind::IndirectBranch | Arm64FlowKind::DecodeError => return,
        Arm64FlowKind::Sequential => {}
    }
    let effect: SequentialEffect = classify_sequential(state, raw);
    apply_sequential(state, insn, raw);
    match effect {
        SequentialEffect::Integer(register) => {
            effects.define(insn.address, state.integers.get(&register).cloned());
        }
        SequentialEffect::Float(register) => {
            effects.define(insn.address, state.floats.get(&register).cloned());
        }
        SequentialEffect::Bookkeeping => effects.bookkeeping(insn.address),
        SequentialEffect::Store {
            base,
            offset,
            value,
        } => {
            if effects.stores.len() < MAX_TRACKED_EFFECTS {
                effects.stores.insert(insn.address, (base, offset, value));
            }
        }
        SequentialEffect::Opaque => {}
    }
}

fn classify_sequential(state: &TrackState, raw: u32) -> SequentialEffect {
    if simd_zero_idiom(raw).is_some() {
        return SequentialEffect::Float((raw & 0x1F) as u8);
    }
    if mov_register(raw).is_some() || compressed_pointer_decompression(raw).is_some() {
        return SequentialEffect::Bookkeeping;
    }
    let group: u32 = (raw >> 25) & 0xF;
    if group & 0b0101 == 0b0100 {
        return classify_memory(state, raw);
    }
    if group & 0b0111 == 0b0111 {
        if is_float_compare(raw) {
            return SequentialEffect::Bookkeeping;
        }
        return SequentialEffect::Float((raw & 0x1F) as u8);
    }
    let destination: u8 = (raw & 0x1F) as u8;
    if is_zero_register(destination) {
        return SequentialEffect::Bookkeeping;
    }
    if destination == DART_STACK_REGISTER || destination == DART_FRAME_REGISTER {
        return SequentialEffect::Bookkeeping;
    }
    if group & 0b1110 == 0b1000 || group & 0b0111 == 0b0101 {
        return SequentialEffect::Integer(destination);
    }
    SequentialEffect::Opaque
}

fn classify_memory(state: &TrackState, raw: u32) -> SequentialEffect {
    let pair: bool = raw & 0x3E00_0000 == 0x2800_0000;
    let load: bool = raw & 0x0040_0000 != 0;
    let simd: bool = raw & 0x0400_0000 != 0;
    let rt: u8 = (raw & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    if rn == DART_STACK_REGISTER || rn == DART_FRAME_REGISTER || rn == DART_THREAD_REGISTER {
        return SequentialEffect::Bookkeeping;
    }
    if load {
        if pair {
            return SequentialEffect::Opaque;
        }
        return if simd {
            SequentialEffect::Float(rt)
        } else {
            SequentialEffect::Integer(rt)
        };
    }
    if pair {
        return SequentialEffect::Opaque;
    }
    let Some(store): Option<FieldStore> = field_store(raw) else {
        return SequentialEffect::Opaque;
    };
    let Some(base): Option<DartValue> = state.integers.get(&store.base).cloned() else {
        return SequentialEffect::Opaque;
    };
    let source: &BTreeMap<u8, DartValue> = if store.float {
        &state.floats
    } else {
        &state.integers
    };
    let value: DartValue = if !store.float && is_zero_register(store.source) {
        DartValue::Int(0)
    } else {
        match source.get(&store.source) {
            Some(value) => value.clone(),
            None => return SequentialEffect::Opaque,
        }
    };
    SequentialEffect::Store {
        base,
        offset: store.offset,
        value,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldStore {
    source: u8,
    base: u8,
    offset: i64,
    float: bool,
}

fn field_store(raw: u32) -> Option<FieldStore> {
    let source: u8 = (raw & 0x1F) as u8;
    let base: u8 = ((raw >> 5) & 0x1F) as u8;
    let unscaled: u32 = raw & 0xFFE0_0C00;
    let scaled: u32 = raw & 0xFFC0_0000;
    let (float, scale): (bool, i64) = match (unscaled, scaled) {
        (0xB800_0000, _) => (false, 0),
        (0xF800_0000, _) => (false, 0),
        (0xFC00_0000, _) => (true, 0),
        (_, 0xB900_0000) => (false, 4),
        (_, 0xF900_0000) => (false, 8),
        (_, 0xFD00_0000) => (true, 8),
        _ => return None,
    };
    let offset: i64 = if scale == 0 {
        let imm9: u32 = (raw >> 12) & 0x1FF;
        if imm9 & 0x100 == 0 {
            i64::from(imm9)
        } else {
            i64::from(imm9) - 512
        }
    } else {
        i64::from((raw >> 10) & 0xFFF).saturating_mul(scale)
    };
    Some(FieldStore {
        source,
        base,
        offset,
        float,
    })
}

const DART_THREAD_REGISTER: u8 = 26;

const COMPARE_AND_BRANCH_MASK: u32 = 0x7E00_0000;

const COMPARE_AND_BRANCH_MATCH: u32 = 0x3400_0000;

fn compare_and_branch_register(raw: u32) -> Option<u8> {
    (raw & COMPARE_AND_BRANCH_MASK == COMPARE_AND_BRANCH_MATCH).then_some((raw & 0x1F) as u8)
}

const NZCV_ARITHMETIC_FORMS: [(u32, u32); 5] = [
    (0x1F80_0000, 0x1100_0000),
    (0x1F20_0000, 0x0B00_0000),
    (0x1F20_0000, 0x0B20_0000),
    (0x1FE0_0000, 0x1A00_0000),
    (0x1FE0_0000, 0x1A40_0000),
];

const NZCV_LOGICAL_FORMS: [(u32, u32); 2] =
    [(0x1F00_0000, 0x0A00_0000), (0x1F80_0000, 0x1200_0000)];

const NZCV_SET_BIT: u32 = 0x2000_0000;

fn writes_nzcv(raw: u32) -> bool {
    if is_float_compare(raw) {
        return true;
    }
    let matches_form = |forms: &[(u32, u32)]| {
        forms
            .iter()
            .any(|(mask, value): &(u32, u32)| raw & mask == *value)
    };
    if raw & NZCV_SET_BIT != 0 && matches_form(&NZCV_ARITHMETIC_FORMS) {
        return true;
    }
    (raw >> 29) & 0x3 == 3 && matches_form(&NZCV_LOGICAL_FORMS)
}

fn apply_sequential(state: &mut TrackState, insn: &Arm64Instruction, raw: u32) {
    if writes_nzcv(raw) {
        state.flags = None;
    }
    if let Some(register) = simd_zero_idiom(raw) {
        state.define_float(register, Some(DartValue::Double(0)));
        return;
    }
    let group: u32 = (raw >> 25) & 0xF;
    if group & 0b0101 == 0b0100 {
        apply_memory(state, raw);
        return;
    }
    if group & 0b0111 == 0b0111 {
        apply_floating_point(state, raw);
        return;
    }
    if group & 0b1110 == 0b1000 {
        apply_immediate(state, insn, raw);
        return;
    }
    if group & 0b0111 == 0b0101 {
        apply_register(state, raw);
    }
}

fn apply_memory(state: &mut TrackState, raw: u32) {
    let pair: bool = raw & 0x3E00_0000 == 0x2800_0000;
    let load: bool = raw & 0x0040_0000 != 0;
    let simd: bool = raw & 0x0400_0000 != 0;
    let rt: u8 = (raw & 0x1F) as u8;
    let rt2: u8 = ((raw >> 10) & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let unsigned_offset: bool = !pair && raw & 0x0100_0000 != 0;
    let writeback: bool = if pair {
        matches!((raw >> 23) & 0x3, 1 | 3)
    } else if unsigned_offset {
        false
    } else {
        matches!((raw >> 10) & 0x3, 1 | 3)
    };

    if !load && !simd {
        state.mark_read(rt);
        if pair {
            state.mark_read(rt2);
        }
    }

    if !load {
        if rn == DART_STACK_REGISTER && !writeback && !simd {
            if let Some((source, _, offset)) = store_to_stack(raw) {
                let value: Option<DartValue> = state.integers.get(&source).cloned();
                record_stack(state, offset, value);
            } else if let Some((first, second, _, offset)) = stp_offset(raw) {
                let low: Option<DartValue> = state.integers.get(&first).cloned();
                let high: Option<DartValue> = state.integers.get(&second).cloned();
                record_stack(state, offset, low);
                record_stack(state, offset.saturating_add(STACK_SLOT_BYTES), high);
            }
        }
        if rn == DART_FRAME_REGISTER && !writeback && !simd {
            record_frame(state, raw, rt, rt2, pair);
        }
        if writeback {
            state.define(rn, None);
        }
        return;
    }

    if simd {
        let value: Option<DartValue> = match ldr_float_pool(raw) {
            Some((_, base, byte_offset)) if base == DART_POOL_REGISTER => Some(DartValue::Pool {
                byte_offset,
                float: true,
            }),
            _ => None,
        };
        state.define_float(rt, value);
        if pair {
            state.define_float(rt2, None);
        }
    } else {
        let value: Option<DartValue> = load_value(state, raw, rn);
        state.define(rt, value);
        if rt == DART_IC_DATA_REGISTER && rn == DART_POOL_REGISTER {
            state.selector_registers.insert(rt);
        }
        if pair {
            state.define(rt2, None);
        }
    }
    if writeback {
        state.define(rn, None);
    }
}

fn load_value(state: &TrackState, raw: u32, rn: u8) -> Option<DartValue> {
    if let Some((_, base, byte_offset)) = ldr_imm_unsigned(raw) {
        if base == DART_POOL_REGISTER {
            return Some(DartValue::Pool {
                byte_offset,
                float: false,
            });
        }
        if base == DART_FRAME_REGISTER {
            return i64::try_from(byte_offset)
                .ok()
                .and_then(|offset: i64| state.frame.get(&offset).cloned());
        }
        if base == DART_STACK_REGISTER && byte_offset == 0 {
            return Some(DartValue::Param(0));
        }
        return field_of(state, base, i64::try_from(byte_offset).ok());
    }
    if let Some((_, base, offset)) = ldur_signed(raw) {
        if base == DART_STACK_REGISTER {
            return None;
        }
        if base == DART_FRAME_REGISTER {
            return state.frame.get(&offset).cloned();
        }
        return field_of(state, base, Some(offset));
    }
    let _ = rn;
    None
}

fn record_frame(state: &mut TrackState, raw: u32, rt: u8, rt2: u8, pair: bool) {
    if state.frame.len() >= MAX_FRAME_SLOTS {
        return;
    }
    let offset: i64 = frame_store_offset(raw, pair);
    let first: Option<DartValue> = state.integers.get(&rt).cloned();
    write_frame(state, offset, first);
    if pair {
        let second: Option<DartValue> = state.integers.get(&rt2).cloned();
        write_frame(
            state,
            offset.saturating_add(STACK_SLOT_BYTES as i64),
            second,
        );
    }
}

fn write_frame(state: &mut TrackState, offset: i64, value: Option<DartValue>) {
    match value {
        Some(value) => {
            state.frame.insert(offset, value);
        }
        None => {
            state.frame.remove(&offset);
        }
    }
}

fn frame_store_offset(raw: u32, pair: bool) -> i64 {
    if pair {
        let imm7: i64 = i64::from((raw >> 15) & 0x7F);
        let signed: i64 = if imm7 & 0x40 != 0 { imm7 - 128 } else { imm7 };
        return signed.saturating_mul(STACK_SLOT_BYTES as i64);
    }
    if raw & 0x3B00_0000 == 0x3900_0000 {
        return i64::from((raw >> 10) & 0xFFF).saturating_mul(STACK_SLOT_BYTES as i64);
    }
    let imm9: u32 = (raw >> 12) & 0x1FF;
    if imm9 & 0x100 != 0 {
        i64::from(imm9) - 512
    } else {
        i64::from(imm9)
    }
}

fn apply_floating_point(state: &mut TrackState, raw: u32) {
    let rd: u8 = (raw & 0x1F) as u8;
    state.forget(rd);
    if let Some((register, bits)) = fmov_double(raw) {
        state.define_float(register, Some(DartValue::Double(bits)));
        return;
    }
    if is_float_compare(raw) {
        state.flags = None;
        return;
    }
    if let Some(decoded) = float_binary(raw) {
        let value: Option<DartValue> = combine_float_binary(state, decoded);
        state.define_float(decoded.rd, value);
        return;
    }
    if let Some(decoded) = float_unary(raw) {
        let value: Option<DartValue> = combine_float_unary(state, decoded);
        state.define_float(decoded.rd, value);
        return;
    }
    if let Some(decoded) = integer_to_float(raw) {
        let value: Option<DartValue> = read_register(state, decoded.rn)
            .filter(|_: &DartValue| decoded.signed)
            .and_then(|operand: DartValue| unary(DartUnaryOp::ToDouble, operand));
        state.define_float(decoded.rd, value);
        return;
    }
    state.define_float(rd, None);
}

fn combine_float_binary(state: &TrackState, decoded: FloatBinary) -> Option<DartValue> {
    let op: DartBinaryOp = match decoded.op {
        FloatBinaryOp::Mul => DartBinaryOp::Multiply,
        FloatBinaryOp::Div => DartBinaryOp::Divide,
        FloatBinaryOp::Add => DartBinaryOp::Add,
        FloatBinaryOp::Sub => DartBinaryOp::Subtract,
        FloatBinaryOp::Max => DartBinaryOp::Maximum,
        FloatBinaryOp::Min => DartBinaryOp::Minimum,
    };
    let left: DartValue = state.floats.get(&decoded.rn).cloned()?;
    let right: DartValue = state.floats.get(&decoded.rm).cloned()?;
    binary(op, left, right)
}

fn combine_float_unary(state: &TrackState, decoded: FloatUnary) -> Option<DartValue> {
    let operand: DartValue = state.floats.get(&decoded.rn).cloned()?;
    match decoded.op {
        FloatUnaryOp::Move => Some(operand),
        FloatUnaryOp::Abs => unary(DartUnaryOp::Absolute, operand),
        FloatUnaryOp::Negate => unary(DartUnaryOp::Negate, operand),
        FloatUnaryOp::SquareRoot => unary(DartUnaryOp::SquareRoot, operand),
    }
}

const SIMD_ZERO_MASK: u32 = 0xFFE0_FC00;

const SIMD_ZERO_MATCH: u32 = 0x6E20_1C00;

const FLOAT_COMPARE_MASK: u32 = 0xFF20_FC17;

const FLOAT_COMPARE_MATCH: u32 = 0x1E20_2000;

fn is_float_compare(raw: u32) -> bool {
    raw & FLOAT_COMPARE_MASK == FLOAT_COMPARE_MATCH
}

fn simd_zero_idiom(raw: u32) -> Option<u8> {
    if raw & SIMD_ZERO_MASK != SIMD_ZERO_MATCH {
        return None;
    }
    let rd: u8 = (raw & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    (rd == rn && rn == rm).then_some(rd)
}

fn apply_immediate(state: &mut TrackState, insn: &Arm64Instruction, raw: u32) {
    if let Some((rd, page)) = adrp(raw, insn.address) {
        state.define(rd, Some(DartValue::PcRelative(page)));
        return;
    }
    if let Some((rd, imm)) = movz(raw) {
        state.define(rd, Some(DartValue::Int(imm as i64)));
        return;
    }
    if let Some((rd, imm, shift)) = movk(raw) {
        let updated: Option<DartValue> = match state.integers.get(&rd) {
            Some(DartValue::Int(prior)) => {
                let cleared: u64 = (*prior as u64) & !(0xFFFF_u64 << shift);
                Some(DartValue::Int((cleared | (imm << shift)) as i64))
            }
            _ => None,
        };
        state.define(rd, updated);
        return;
    }
    if let Some((rd, base, applied)) = add_imm(raw) {
        state.define(
            rd,
            offset_of(state, base, i64::try_from(applied).unwrap_or(0)),
        );
        return;
    }
    if let Some((rd, base, imm)) = sub_imm(raw) {
        state.define(
            rd,
            offset_of(
                state,
                base,
                i64::try_from(imm).unwrap_or(0).saturating_neg(),
            ),
        );
        return;
    }
    if let Some((rd, rn, imm)) = subs_imm(raw) {
        record_immediate_flags(state, rn, imm);
        state.define(rd, None);
        return;
    }
    if let Some((rd, number)) = movn(raw) {
        state.define(rd, Some(DartValue::Int(number)));
        return;
    }
    if let Some(decoded) = logical_immediate(raw) {
        if decoded.sets_flags {
            state.flags = None;
        }
        let value: Option<DartValue> = combine_logical_immediate(state, decoded);
        state.define(decoded.rd, value);
        return;
    }
    if let Some(decoded) = bitfield(raw) {
        let value: Option<DartValue> = read_register(state, decoded.rn)
            .and_then(|operand: DartValue| bitfield_value(decoded.kind, operand))
            .and_then(|value: DartValue| truncate_to_width(value, decoded.sixty_four));
        state.define(decoded.rd, value);
        return;
    }
    state.define((raw & 0x1F) as u8, None);
}

fn record_immediate_flags(state: &mut TrackState, rn: u8, immediate: u64) {
    state.flags = None;
    let Some(left): Option<DartValue> = read_register(state, rn) else {
        return;
    };
    let Ok(right): Result<i64, _> = i64::try_from(immediate) else {
        return;
    };
    state.flags = Some(DartComparison {
        left,
        right: DartValue::Int(right),
    });
}

fn combine_logical_immediate(state: &TrackState, decoded: LogicalImmediate) -> Option<DartValue> {
    let left: DartValue = read_register(state, decoded.rn)?;
    let op: DartBinaryOp = match decoded.op {
        LogicalOp::And => DartBinaryOp::BitAnd,
        LogicalOp::Or => DartBinaryOp::BitOr,
        LogicalOp::Xor => DartBinaryOp::BitXor,
        LogicalOp::AndNot | LogicalOp::OrNot | LogicalOp::XorNot => return None,
    };
    let right: DartValue = DartValue::Int(decoded.mask as i64);
    truncate_to_width(binary(op, left, right)?, decoded.sixty_four)
}

fn apply_register(state: &mut TrackState, raw: u32) {
    if let Some(register) = compressed_pointer_decompression(raw) {
        let value: Option<DartValue> = state.integers.get(&register).cloned();
        state.define(register, value);
        return;
    }
    if let Some((rd, source)) = mov_register(raw) {
        let value: Option<DartValue> = if source == DART_NULL_REGISTER {
            Some(DartValue::Null)
        } else {
            state.integers.get(&source).cloned()
        };
        let selector: bool = state.selector_registers.contains(&source);
        state.define(rd, value);
        if selector {
            state.selector_registers.insert(rd);
        }
        return;
    }
    if let Some(decoded) = add_sub_shifted_reg(raw) {
        if decoded.sets_flags {
            record_register_flags(state, decoded);
        }
        let value: Option<DartValue> = combine_add_sub(state, decoded);
        state.define(decoded.rd, value);
        return;
    }
    if let Some(decoded) = logical_shifted_reg(raw) {
        if decoded.sets_flags {
            state.flags = None;
        }
        let value: Option<DartValue> = combine_logical(state, decoded);
        state.define(decoded.rd, value);
        return;
    }
    if let Some(decoded) = multiply_accumulate(raw) {
        let value: Option<DartValue> = combine_multiply(state, decoded);
        state.define(decoded.rd, value);
        return;
    }
    if let Some(decoded) = divide_reg(raw) {
        let value: Option<DartValue> = combine_divide(state, decoded);
        state.define(decoded.rd, value);
        return;
    }
    if let Some(decoded) = variable_shift(raw) {
        let value: Option<DartValue> = combine_variable_shift(state, decoded);
        state.define(decoded.rd, value);
        return;
    }
    if let Some((kind, rd, rn, rm, code)) = conditional_select(raw) {
        let value: Option<DartValue> = combine_select(state, kind, rn, rm, code);
        state.define(rd, value);
        return;
    }
    state.define((raw & 0x1F) as u8, None);
}

fn read_register(state: &TrackState, register: u8) -> Option<DartValue> {
    if is_zero_register(register) {
        return Some(DartValue::Int(0));
    }
    state.integers.get(&register).cloned()
}

fn truncate_to_width(value: DartValue, sixty_four: bool) -> Option<DartValue> {
    if sixty_four {
        return Some(value);
    }
    unary(
        DartUnaryOp::Truncate {
            width: 32,
            signed: false,
        },
        value,
    )
}

fn record_register_flags(state: &mut TrackState, decoded: AddSubShiftedReg) {
    state.flags = None;
    if !decoded.subtract {
        return;
    }
    let Some(left): Option<DartValue> = read_register(state, decoded.rn) else {
        return;
    };
    let Some(right): Option<DartValue> = read_register(state, decoded.rm) else {
        return;
    };
    let Some(right): Option<DartValue> = shifted_operand(right, decoded.shift, decoded.amount)
    else {
        return;
    };
    state.flags = Some(DartComparison { left, right });
}

fn combine_add_sub(state: &TrackState, decoded: AddSubShiftedReg) -> Option<DartValue> {
    let left: DartValue = read_register(state, decoded.rn)?;
    let right: DartValue = read_register(state, decoded.rm)?;
    let right: DartValue = shifted_operand(right, decoded.shift, decoded.amount)?;
    let op: DartBinaryOp = if decoded.subtract {
        DartBinaryOp::Subtract
    } else {
        DartBinaryOp::Add
    };
    truncate_to_width(binary(op, left, right)?, decoded.sixty_four)
}

fn combine_logical(state: &TrackState, decoded: LogicalShiftedReg) -> Option<DartValue> {
    let left: DartValue = read_register(state, decoded.rn)?;
    let right: DartValue = read_register(state, decoded.rm)?;
    let right: DartValue = shifted_operand(right, decoded.shift, decoded.amount)?;
    let (op, negated): (DartBinaryOp, bool) = match decoded.op {
        LogicalOp::And => (DartBinaryOp::BitAnd, false),
        LogicalOp::Or => (DartBinaryOp::BitOr, false),
        LogicalOp::Xor => (DartBinaryOp::BitXor, false),
        LogicalOp::AndNot => (DartBinaryOp::BitAnd, true),
        LogicalOp::OrNot => (DartBinaryOp::BitOr, true),
        LogicalOp::XorNot => (DartBinaryOp::BitXor, true),
    };
    let right: DartValue = if negated {
        unary(DartUnaryOp::BitNot, right)?
    } else {
        right
    };
    truncate_to_width(binary(op, left, right)?, decoded.sixty_four)
}

fn combine_multiply(state: &TrackState, decoded: MultiplyAccumulate) -> Option<DartValue> {
    let left: DartValue = read_register(state, decoded.rn)?;
    let right: DartValue = read_register(state, decoded.rm)?;
    let accumulator: DartValue = read_register(state, decoded.ra)?;
    let product: DartValue = binary(DartBinaryOp::Multiply, left, right)?;
    let op: DartBinaryOp = if decoded.subtract {
        DartBinaryOp::Subtract
    } else {
        DartBinaryOp::Add
    };
    truncate_to_width(binary(op, accumulator, product)?, decoded.sixty_four)
}

fn combine_divide(state: &TrackState, decoded: DivideReg) -> Option<DartValue> {
    if decoded.op == DivideOp::Unsigned {
        return None;
    }
    let left: DartValue = read_register(state, decoded.rn)?;
    let right: DartValue = read_register(state, decoded.rm)?;
    truncate_to_width(
        binary(DartBinaryOp::TruncatingDivide, left, right)?,
        decoded.sixty_four,
    )
}

fn combine_variable_shift(state: &TrackState, decoded: VariableShift) -> Option<DartValue> {
    let op: DartBinaryOp = match decoded.op {
        VariableShiftOp::Lsl => DartBinaryOp::ShiftLeft,
        VariableShiftOp::Lsr => DartBinaryOp::UnsignedShiftRight,
        VariableShiftOp::Asr => DartBinaryOp::ShiftRight,
        VariableShiftOp::Ror => return None,
    };
    let left: DartValue = read_register(state, decoded.rn)?;
    let right: DartValue = read_register(state, decoded.rm)?;
    truncate_to_width(binary(op, left, right)?, decoded.sixty_four)
}

fn combine_select(
    state: &TrackState,
    kind: ConditionalSelectKind,
    rn: u8,
    rm: u8,
    code: u8,
) -> Option<DartValue> {
    let condition: DartCondition = DartCondition::from_arm64(code)?;
    let comparison: DartComparison = state.flags.clone()?;
    let when_true: DartValue = read_register(state, rn)?;
    let other: DartValue = read_register(state, rm)?;
    let when_false: DartValue = match kind {
        ConditionalSelectKind::Select => other,
        ConditionalSelectKind::Increment => binary(DartBinaryOp::Add, other, DartValue::Int(1))?,
        ConditionalSelectKind::Invert => unary(DartUnaryOp::BitNot, other)?,
        ConditionalSelectKind::Negate => unary(DartUnaryOp::Negate, other)?,
    };
    bounded(DartValue::Select {
        condition,
        comparison: Box::new(comparison),
        when_true: Box::new(when_true),
        when_false: Box::new(when_false),
    })
}

fn compressed_pointer_decompression(raw: u32) -> Option<u8> {
    if raw & 0xFFFF_FC00 != 0x8B1C_8000 {
        return None;
    }
    let destination: u8 = (raw & 0x1F) as u8;
    let source: u8 = ((raw >> 5) & 0x1F) as u8;
    (destination == source).then_some(destination)
}

fn record_stack(state: &mut TrackState, offset: u64, value: Option<DartValue>) {
    if state.stack.len() >= MAX_STACK_ARGUMENTS {
        return;
    }
    state.stack.insert(offset, value);
}

fn field_of(state: &TrackState, base: u8, offset: Option<i64>) -> Option<DartValue> {
    let offset: i64 = offset?;
    let value: DartValue = state.integers.get(&base).cloned()?;
    Some(DartValue::Field {
        base: Box::new(value),
        offset,
    })
}

fn offset_of(state: &TrackState, base: u8, delta: i64) -> Option<DartValue> {
    if base == DART_NULL_REGISTER {
        return match u64::try_from(delta).ok() {
            Some(DART_TRUE_OFFSET_FROM_NULL) => Some(DartValue::Bool(true)),
            Some(DART_FALSE_OFFSET_FROM_NULL) => Some(DartValue::Bool(false)),
            _ => None,
        };
    }
    match state.integers.get(&base) {
        Some(DartValue::Int(value)) => Some(DartValue::Int(value.saturating_add(delta))),
        Some(value) => Some(DartValue::Offset {
            base: Box::new(value.clone()),
            delta,
        }),
        None => None,
    }
}

fn collect_arguments(state: &TrackState, indirect: bool, raw: u32) -> Vec<Option<DartValue>> {
    let dispatch: Option<u8> = indirect.then(|| blr_target_reg(raw)).flatten();
    let mut register_arguments: Vec<Option<DartValue>> = Vec::new();
    let mut last_written: Option<usize> = None;
    for (position, register) in DART_ARGUMENT_REGISTERS.iter().enumerate() {
        let excluded: bool = Some(*register) == dispatch
            || (indirect && state.selector_registers.contains(register));
        if excluded {
            register_arguments.push(None);
            continue;
        }
        if state.written.contains(register) {
            last_written = Some(position);
        }
        register_arguments.push(state.integers.get(register).cloned());
    }
    let mut arguments: Vec<Option<DartValue>> = match last_written {
        Some(position) => register_arguments.get(..=position).unwrap_or(&[]).to_vec(),
        None => Vec::new(),
    };
    arguments.extend(stack_arguments(state));
    arguments
}

fn stack_arguments(state: &TrackState) -> Vec<Option<DartValue>> {
    let mut arguments: Vec<Option<DartValue>> = Vec::with_capacity(state.stack.len());
    for (position, (offset, value)) in state.stack.iter().enumerate() {
        if *offset != position as u64 * STACK_SLOT_BYTES {
            return Vec::new();
        }
        if position >= MAX_STACK_ARGUMENTS {
            return Vec::new();
        }
        arguments.push(value.clone());
    }
    arguments
}

fn render_operand(
    value: &DartValue,
    pool: Option<&DartPoolTable>,
    results: &BTreeMap<u64, usize>,
    depth: usize,
) -> String {
    let rendered: String = render_value(value, pool, results, depth);
    if matches!(value, DartValue::Offset { .. }) {
        return format!("({rendered})");
    }
    rendered
}

fn render_value(
    value: &DartValue,
    pool: Option<&DartPoolTable>,
    results: &BTreeMap<u64, usize>,
    depth: usize,
) -> String {
    if depth > MAX_VALUE_DEPTH {
        return UNRESOLVED_TOKEN.to_owned();
    }
    match value {
        DartValue::Null => "null".to_owned(),
        DartValue::Bool(true) => "true".to_owned(),
        DartValue::Bool(false) => "false".to_owned(),
        DartValue::Int(number) => number.to_string(),
        DartValue::Double(bits) => render_double(f64::from_bits(*bits)),
        DartValue::Pool { byte_offset, float } => render_pool(pool, *byte_offset, *float),
        DartValue::Param(position) => format!("arg{position}"),
        DartValue::CallResult(address) => match results.get(address) {
            Some(index) => format!("v{index}"),
            None => UNRESOLVED_TOKEN.to_owned(),
        },
        DartValue::Field { base, offset } => format!(
            "{}.field@{offset:#x}",
            render_operand(base, pool, results, depth + 1)
        ),
        DartValue::Offset { base, delta } => {
            let rendered: String = render_value(base, pool, results, depth + 1);
            if *delta < 0 {
                format!("{rendered} - {}", delta.unsigned_abs())
            } else {
                format!("{rendered} + {delta}")
            }
        }
        DartValue::PcRelative(address) => format!("pc@{address:#x}"),
        DartValue::Binary { op, left, right } => {
            let rendered_left: String = render_value(left, pool, results, depth + 1);
            let rendered_right: String = render_value(right, pool, results, depth + 1);
            match op.operator() {
                Some(symbol) => format!("({rendered_left} {symbol} {rendered_right})"),
                None => format!("{}({rendered_left}, {rendered_right})", op.method()),
            }
        }
        DartValue::Unary { op, operand } => {
            let rendered: String = render_operand(operand, pool, results, depth + 1);
            match op {
                DartUnaryOp::Negate => format!("-{rendered}"),
                DartUnaryOp::BitNot => format!("~{rendered}"),
                DartUnaryOp::Absolute => format!("{rendered}.abs()"),
                DartUnaryOp::SquareRoot => format!("sqrt({rendered})"),
                DartUnaryOp::ToDouble => format!("{rendered}.toDouble()"),
                DartUnaryOp::Truncate { width, signed } => {
                    let method: &str = if *signed { "toSigned" } else { "toUnsigned" };
                    format!("{rendered}.{method}({width})")
                }
            }
        }
        DartValue::SmiTag(inner) => {
            format!("smiTag({})", render_value(inner, pool, results, depth + 1))
        }
        DartValue::SmiUntag(inner) => {
            format!(
                "smiUntag({})",
                render_value(inner, pool, results, depth + 1)
            )
        }
        DartValue::Select {
            condition,
            comparison,
            when_true,
            when_false,
        } => format!(
            "({} {} {} ? {} : {})",
            render_value(&comparison.left, pool, results, depth + 1),
            condition.operator(),
            render_value(&comparison.right, pool, results, depth + 1),
            render_value(when_true, pool, results, depth + 1),
            render_value(when_false, pool, results, depth + 1),
        ),
    }
}

fn conditional_select(raw: u32) -> Option<(ConditionalSelectKind, u8, u8, u8, u8)> {
    if raw & 0x3FE0_0800 != 0x1A80_0000 {
        return None;
    }
    let kind: ConditionalSelectKind = match ((raw >> 30) & 1, (raw >> 10) & 1) {
        (0, 0) => ConditionalSelectKind::Select,
        (0, 1) => ConditionalSelectKind::Increment,
        (1, 0) => ConditionalSelectKind::Invert,
        (1, 1) => ConditionalSelectKind::Negate,
        _ => return None,
    };
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    let condition: u8 = ((raw >> 12) & 0xF) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((kind, rd, rn, rm, condition))
}

fn render_pool(pool: Option<&DartPoolTable>, byte_offset: u64, float: bool) -> String {
    let Some(table): Option<&DartPoolTable> = pool else {
        return UNRESOLVED_TOKEN.to_owned();
    };
    if let Some(rendered) = table.render_at_offset(byte_offset, float) {
        return rendered;
    }
    match table.slot_index(byte_offset) {
        Some(index) => format!("pool[{index}]"),
        None => UNRESOLVED_TOKEN.to_owned(),
    }
}

fn mov_register(raw: u32) -> Option<(u8, u8)> {
    if raw & 0xFFE0_FFE0 != 0xAA00_03E0 {
        return None;
    }
    let rm: u8 = ((raw >> 16) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rm))
}

fn sub_imm(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFF00_0000 != 0xD100_0000 {
        return None;
    }
    let shift: u32 = (raw >> 22) & 0x3;
    if shift > 1 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rd: u8 = (raw & 0x1F) as u8;
    Some((rd, rn, imm12 << (shift * 12)))
}

fn ldur_signed(raw: u32) -> Option<(u8, u8, i64)> {
    let sized: bool = raw & 0xFFE0_0C00 == 0xF840_0000 || raw & 0xFFE0_0C00 == 0xB840_0000;
    if !sized {
        return None;
    }
    let imm9: u32 = (raw >> 12) & 0x1FF;
    let signed: i64 = if imm9 & 0x100 != 0 {
        i64::from(imm9) - 512
    } else {
        i64::from(imm9)
    };
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rn, signed))
}

fn ldr_float_pool(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFFC0_0000 != 0xFD40_0000 {
        return None;
    }
    let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rn, imm12 * STACK_SLOT_BYTES))
}

fn fmov_double(raw: u32) -> Option<(u8, u64)> {
    let bits: u64 = fmov_double_immediate(raw)?;
    Some(((raw & 0x1F) as u8, bits))
}

fn store_to_stack(raw: u32) -> Option<(u8, u8, u64)> {
    if raw & 0xFFC0_0000 == 0xF900_0000 {
        let imm12: u64 = u64::from((raw >> 10) & 0xFFF);
        let rn: u8 = ((raw >> 5) & 0x1F) as u8;
        let rt: u8 = (raw & 0x1F) as u8;
        return Some((rt, rn, imm12 * STACK_SLOT_BYTES));
    }
    if raw & 0xFFE0_0C00 == 0xF800_0000 {
        let imm9: u32 = (raw >> 12) & 0x1FF;
        if imm9 & 0x100 != 0 {
            return None;
        }
        let rn: u8 = ((raw >> 5) & 0x1F) as u8;
        let rt: u8 = (raw & 0x1F) as u8;
        return Some((rt, rn, u64::from(imm9)));
    }
    None
}

fn stp_offset(raw: u32) -> Option<(u8, u8, u8, u64)> {
    if raw & 0xFFC0_0000 != 0xA900_0000 {
        return None;
    }
    let imm7: u32 = (raw >> 15) & 0x7F;
    if imm7 & 0x40 != 0 {
        return None;
    }
    let rt2: u8 = ((raw >> 10) & 0x1F) as u8;
    let rn: u8 = ((raw >> 5) & 0x1F) as u8;
    let rt: u8 = (raw & 0x1F) as u8;
    Some((rt, rt2, rn, u64::from(imm7) * STACK_SLOT_BYTES))
}

fn adrp(raw: u32, address: u64) -> Option<(u8, u64)> {
    if raw & 0x9F00_0000 != 0x9000_0000 {
        return None;
    }
    let immlo: u64 = u64::from((raw >> 29) & 0x3);
    let immhi: u64 = u64::from((raw >> 5) & 0x7FFFF);
    let combined: u64 = (immhi << 2) | immlo;
    let signed: i64 = if combined & (1 << 20) != 0 {
        (combined as i64) - (1 << 21)
    } else {
        combined as i64
    };
    let page: u64 = (address & !0xFFF).wrapping_add_signed(signed.saturating_mul(0x1000));
    Some(((raw & 0x1F) as u8, page))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::flutter::disasm::disassemble_range;

    use super::*;

    #[test]
    fn decodes_a_real_register_move() {
        assert_eq!(mov_register(0xaa0f03fd), Some((29, 15)));
        assert_eq!(mov_register(0xaa1603e1), Some((1, 22)));
        assert_eq!(mov_register(0xd503201f), None);
    }

    #[test]
    fn decodes_only_exact_dart_compressed_pointer_decompression() {
        assert_eq!(compressed_pointer_decompression(0x8b1c_8000), Some(0));
        assert_eq!(compressed_pointer_decompression(0x8b1c_8021), Some(1));
        assert_eq!(compressed_pointer_decompression(0x8b1b_8000), None);
        assert_eq!(compressed_pointer_decompression(0x8b1c_7c00), None);
        assert_eq!(compressed_pointer_decompression(0x8b1c_8001), None);
        assert_eq!(compressed_pointer_decompression(0xab1c_8000), None);
        assert_eq!(compressed_pointer_decompression(0x0b1c_8000), None);
    }

    #[test]
    fn decodes_a_real_subtract_immediate() {
        assert_eq!(sub_imm(0xd1000401), Some((1, 0, 1)));
        assert_eq!(sub_imm(0xd1000801), Some((1, 0, 2)));
    }

    #[test]
    fn decodes_a_real_unscaled_field_load() {
        assert_eq!(ldur_signed(0xb8407020), Some((0, 1, 7)));
        assert_eq!(ldur_signed(0xf85f83a1), Some((1, 29, -8)));
    }

    #[test]
    fn decodes_a_real_float_pool_load() {
        assert_eq!(ldr_float_pool(0xfd6b9b60), Some((0, 27, 0x5730)));
    }

    #[test]
    fn decodes_a_real_stack_store_and_pair() {
        assert_eq!(store_to_stack(0xf90001e0), Some((0, 15, 0)));
        assert_eq!(stp_offset(0xa90041fe), Some((30, 16, 15, 0)));
        assert_eq!(
            stp_offset(0xa9bf79fd),
            None,
            "the pre-index prologue push is not an argument store"
        );
    }

    #[test]
    fn true_and_false_come_from_the_null_register_offsets() {
        let state: TrackState = TrackState::default();
        assert_eq!(
            offset_of(&state, DART_NULL_REGISTER, 0x20),
            Some(DartValue::Bool(true))
        );
        assert_eq!(
            offset_of(&state, DART_NULL_REGISTER, 0x30),
            Some(DartValue::Bool(false))
        );
        assert_eq!(offset_of(&state, DART_NULL_REGISTER, 0x40), None);
    }

    #[test]
    fn declared_parameter_count_bounds_entry_registers() {
        let one: TrackState = TrackState::entry(Some(1));
        assert_eq!(
            one.integers.get(&DART_ARGUMENT_REGISTERS[0]),
            Some(&DartValue::Param(0))
        );
        assert_eq!(one.integers.get(&DART_ARGUMENT_REGISTERS[1]), None);

        let many: TrackState = TrackState::entry(Some(u8::MAX));
        assert_eq!(many.integers.len(), DART_ARGUMENT_REGISTERS.len());
    }

    #[test]
    fn an_unmodelled_flag_writer_between_the_compare_and_the_select_drops_the_comparison() {
        let modelled: [u32; 4] = [0xf100_081f, 0xeb02_001f, 0xf240_001f, 0x1e60_2000];
        for raw in modelled {
            assert!(
                writes_nzcv(raw),
                "{raw:#010x} sets NZCV and must invalidate a stale comparison"
            );
        }
        let unmodelled: [u32; 4] = [0xb100_0420, 0xba02_0020, 0xfa42_0800, 0x2b02_0020];
        for raw in unmodelled {
            assert!(
                writes_nzcv(raw),
                "{raw:#010x} sets NZCV and must invalidate a stale comparison"
            );
        }
        let harmless: [u32; 4] = [0x9100_0420, 0x8b00_0022, 0x9a80_1041, 0xaa01_03e0];
        for raw in harmless {
            assert!(
                !writes_nzcv(raw),
                "{raw:#010x} does not set NZCV and must not discard a live comparison"
            );
        }
    }

    #[test]
    fn decodes_every_conditional_select_variant() {
        assert_eq!(
            conditional_select(0x9a82_0020),
            Some((ConditionalSelectKind::Select, 0, 1, 2, 0))
        );
        assert_eq!(
            conditional_select(0x9a82_0420),
            Some((ConditionalSelectKind::Increment, 0, 1, 2, 0))
        );
        assert_eq!(
            conditional_select(0xda82_0020),
            Some((ConditionalSelectKind::Invert, 0, 1, 2, 0))
        );
        assert_eq!(
            conditional_select(0xda82_0420),
            Some((ConditionalSelectKind::Negate, 0, 1, 2, 0))
        );
        assert_eq!(conditional_select(0xd65f_03c0), None);
    }

    #[test]
    fn shifted_compare_immediate_abstains_from_boolean_recovery() {
        let words: [u32; 7] = [
            0xf940_01e1,
            0xf840_b022,
            0xf140_045f,
            0x9100_82d0,
            0x9100_c2d1,
            0x9a91_d200,
            0xd65f_03c0,
        ];
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let function: Arm64Function =
            disassemble_range(&bytes, 0x1000, 0, bytes.len(), Some("shifted".to_owned()));

        assert_eq!(recover_boolean_return(&function, None), None);
    }

    #[test]
    fn unrelated_faulting_load_abstains_from_boolean_recovery() {
        let words: [u32; 8] = [
            0xf940_01e1,
            0x9100_82d0,
            0x9100_c2d1,
            0xf840_b022,
            0xf100_005f,
            0xf940_0083,
            0x9a91_d200,
            0xd65f_03c0,
        ];
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let function: Arm64Function = disassemble_range(
            &bytes,
            0x1000,
            0,
            bytes.len(),
            Some("faulting-load".to_owned()),
        );

        assert_eq!(recover_boolean_return(&function, None), None);
    }

    fn state_with(integers: &[(u8, DartValue)]) -> TrackState {
        let mut state: TrackState = TrackState::default();
        for (register, value) in integers {
            state.define(*register, Some(value.clone()));
        }
        state
    }

    #[test]
    fn a_merge_keeps_only_the_values_every_predecessor_agrees_on() {
        let taken: TrackState = state_with(&[
            (1, DartValue::Param(0)),
            (2, DartValue::Int(9)),
            (3, DartValue::Int(4)),
        ]);
        let fallthrough: TrackState =
            state_with(&[(1, DartValue::Param(0)), (2, DartValue::Int(7))]);
        let merged: TrackState =
            merge_states(&[&taken, &fallthrough]).expect("two states merge into one");

        assert_eq!(
            merged.integers.get(&1),
            Some(&DartValue::Param(0)),
            "a register both predecessors set to the same value survives the merge"
        );
        assert_eq!(
            merged.integers.get(&2),
            None,
            "a register the two predecessors disagree about must not keep either branch's value"
        );
        assert_eq!(
            merged.integers.get(&3),
            None,
            "a register only one predecessor sets is unknown on the other path and must not survive"
        );
    }

    #[test]
    fn a_merge_excludes_a_register_any_predecessor_treats_as_a_dispatch_selector() {
        let mut selector_path: TrackState = TrackState::default();
        selector_path
            .selector_registers
            .insert(DART_IC_DATA_REGISTER);
        let value_path: TrackState = TrackState::default();
        let merged: TrackState =
            merge_states(&[&selector_path, &value_path]).expect("two states merge into one");

        assert!(
            merged.selector_registers.contains(&DART_IC_DATA_REGISTER),
            "a register that carries the dispatch selector on any path stays excluded after the merge, because including it would render the other path's value as an argument"
        );
    }

    #[test]
    fn a_merge_keeps_a_comparison_and_a_call_result_only_when_they_agree() {
        let mut left: TrackState = TrackState::default();
        left.flags = Some(DartComparison {
            left: DartValue::Param(0),
            right: DartValue::Int(0),
        });
        left.last_result = Some(DartValue::CallResult(0x100));
        let mut right: TrackState = left.clone();
        let same: TrackState = merge_states(&[&left, &right]).expect("merge");
        assert_eq!(same.flags, left.flags);
        assert_eq!(same.last_result, left.last_result);

        right.last_result = Some(DartValue::CallResult(0x200));
        right.flags = None;
        let differing: TrackState = merge_states(&[&left, &right]).expect("merge");
        assert_eq!(
            differing.flags, None,
            "a comparison only one predecessor established must not survive the merge"
        );
        assert_eq!(
            differing.last_result, None,
            "two predecessors returning different calls leave no known result"
        );
    }

    #[test]
    fn a_block_starts_unknown_until_every_predecessor_has_been_evaluated() {
        let evaluated: TrackState = state_with(&[(1, DartValue::Param(0))]);
        let mut exits: BTreeMap<u64, TrackState> = BTreeMap::new();
        exits.insert(0x10, evaluated);

        let complete: TrackState = entry_state(Some(&vec![0x10]), &exits);
        assert_eq!(
            complete.integers.get(&1),
            Some(&DartValue::Param(0)),
            "one evaluated predecessor is a merge of one and keeps its values"
        );

        let back_edge: TrackState = entry_state(Some(&vec![0x10, 0x20]), &exits);
        assert!(
            back_edge.integers.is_empty(),
            "a loop header whose back edge has not been evaluated cannot know what that path holds and must start unknown, got {:?}",
            back_edge.integers
        );

        let none: TrackState = entry_state(None, &exits);
        assert!(none.integers.is_empty());
    }

    #[test]
    fn a_join_wider_than_the_predecessor_bound_starts_unknown() {
        let mut exits: BTreeMap<u64, TrackState> = BTreeMap::new();
        let mut sources: Vec<u64> = Vec::new();
        for index in 0..=MAX_MERGE_PREDECESSORS {
            let address: u64 = 0x100 + index as u64;
            exits.insert(address, state_with(&[(1, DartValue::Param(0))]));
            sources.push(address);
        }
        assert!(
            entry_state(Some(&sources), &exits).integers.is_empty(),
            "a join wider than the bound refuses rather than merging an input-controlled number of states"
        );
        sources.pop();
        assert_eq!(
            entry_state(Some(&sources), &exits).integers.get(&1),
            Some(&DartValue::Param(0)),
            "the bound itself still merges, so the refusal is the bound and not an off-by-one"
        );
    }

    #[test]
    fn an_address_expression_parenthesises_before_a_field_access_binds() {
        let target: DartValue = DartValue::Field {
            base: Box::new(DartValue::Offset {
                base: Box::new(DartValue::Param(0)),
                delta: 15,
            }),
            offset: 0,
        };
        let results: BTreeMap<u64, usize> = BTreeMap::new();
        assert_eq!(
            render_value(&target, None, &results, 0),
            "(arg0 + 15).field@0x0",
            "a field access on a computed address must bind to the whole address, never to the displacement literal"
        );

        let top_level: DartValue = DartValue::Offset {
            base: Box::new(DartValue::Param(0)),
            delta: -1,
        };
        assert_eq!(
            render_value(&top_level, None, &results, 0),
            "arg0 - 1",
            "an address expression that nothing binds to stays unparenthesised"
        );
    }
}
