use std::collections::{BTreeMap, BTreeSet};

use super::Reject;
use super::budget::Budget;
use super::ir::BinOp;

const MAX_ABSTRACT_STACK: usize = 64;
const MAX_EXPR_DEPTH: u8 = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperandRange {
    pub start: u16,
    pub end: u16,
}

impl OperandRange {
    #[must_use]
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Expr {
    VStackTop,
    VStackAt(u16),
    VReg(u16),
    Local(u16),
    Argument(u16),
    OperandBytes(OperandRange),
    Const(i64),
    IpDelta(i32),
    Binary {
        op: BinOp,
        left: Box<Self>,
        right: Box<Self>,
    },
}

impl Expr {
    pub fn canonicalize(&self, budget: &mut Budget) -> Result<Self, Reject> {
        self.canonicalize_at_depth(budget, 0)
    }

    fn canonicalize_at_depth(&self, budget: &mut Budget, depth: u8) -> Result<Self, Reject> {
        if depth >= MAX_EXPR_DEPTH {
            return Err(Reject::new(
                "symbolic expression depth exceeds cap",
                vec![MAX_EXPR_DEPTH.to_string()],
            ));
        }
        budget.spend(1).map_err(Reject::from_budget_error)?;
        match self {
            Self::Binary { op, left, right } => {
                let next_depth: u8 = match depth.checked_add(1) {
                    Some(value) => value,
                    None => {
                        return Err(Reject::new(
                            "symbolic expression depth overflowed",
                            Vec::new(),
                        ));
                    }
                };
                let canonical_left: Self = left.canonicalize_at_depth(budget, next_depth)?;
                let canonical_right: Self = right.canonicalize_at_depth(budget, next_depth)?;
                Ok(Self::simplify_binary(*op, canonical_left, canonical_right))
            }
            value => Ok(value.clone()),
        }
    }

    pub(crate) fn binary(op: BinOp, left: Self, right: Self) -> Result<Self, Reject> {
        if !left.fits_depth(0) || !right.fits_depth(0) {
            return Err(Reject::new(
                "symbolic expression depth exceeds cap",
                vec![MAX_EXPR_DEPTH.to_string()],
            ));
        }
        Ok(Self::simplify_binary(op, left, right))
    }

    fn fits_depth(&self, depth: u8) -> bool {
        if depth >= MAX_EXPR_DEPTH {
            return false;
        }
        match self {
            Self::Binary { left, right, .. } => {
                let next_depth: u8 = match depth.checked_add(1) {
                    Some(value) => value,
                    None => return false,
                };
                left.fits_depth(next_depth) && right.fits_depth(next_depth)
            }
            _ => true,
        }
    }

    fn simplify_binary(op: BinOp, left: Self, right: Self) -> Self {
        Self::constant_fold(op, &left, &right).map_or_else(
            || Self::simplify_non_constant(op, left, right),
            |value: i64| Self::Const(value),
        )
    }

    const fn constant_fold(op: BinOp, left: &Self, right: &Self) -> Option<i64> {
        match (left, right) {
            (Self::Const(left_value), Self::Const(right_value)) => {
                Some(Self::fold_binary(op, *left_value, *right_value))
            }
            _ => None,
        }
    }

    fn simplify_non_constant(op: BinOp, mut left: Self, mut right: Self) -> Self {
        let left_zero: bool = left.constant_value() == Some(0);
        let right_zero: bool = right.constant_value() == Some(0);
        let left_one: bool = left.constant_value() == Some(1);
        let right_one: bool = right.constant_value() == Some(1);
        let left_all_bits: bool = left.constant_value() == Some(-1);
        let right_all_bits: bool = right.constant_value() == Some(-1);
        if ((op == BinOp::Add || op == BinOp::Sub) && right_zero)
            || (op == BinOp::Mul && right_one)
            || (op == BinOp::And && right_all_bits)
            || ((op == BinOp::Or || op == BinOp::Xor) && right_zero)
        {
            return left;
        }
        if (op == BinOp::Add && left_zero)
            || (op == BinOp::Mul && left_one)
            || (op == BinOp::And && left_all_bits)
            || (op == BinOp::Or && left_zero)
        {
            return right;
        }
        if (op == BinOp::Mul || op == BinOp::And) && (left_zero || right_zero) {
            return Self::Const(0);
        }
        if op.is_commutative() && right < left {
            std::mem::swap(&mut left, &mut right);
        }
        Self::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    const fn fold_binary(op: BinOp, left: i64, right: i64) -> i64 {
        match op {
            BinOp::Add => left.wrapping_add(right),
            BinOp::Sub => left.wrapping_sub(right),
            BinOp::Mul => left.wrapping_mul(right),
            BinOp::And => left & right,
            BinOp::Or => left | right,
            BinOp::Xor => left ^ right,
            BinOp::Ceq => (left == right) as i64,
            BinOp::Clt => (left < right) as i64,
            BinOp::Cgt => (left > right) as i64,
        }
    }

    const fn constant_value(&self) -> Option<i64> {
        match self {
            Self::Const(value) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrimitiveEffect {
    PushArgument(u16),
    StoreArgument(u16),
    PushLocal(u16),
    StoreLocal(u16),
    PushConst(i64),
    PushOperandI64,
    Binary(BinOp),
    AdvanceIp(i32),
    Branch,
    BranchIfTrue,
    BranchIfFalse,
    Return,
    Opaque,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StateLocation {
    Stack,
    Register(u16),
    Local(u16),
    Argument(u16),
    OperandBytes(OperandRange),
    Ip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEffect {
    Fallthrough,
    Br,
    BrTrue,
    BrFalse,
    Ret,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalEffect {
    pub stack_inputs: u16,
    pub stack_outputs: Vec<Expr>,
    pub argument_writes: BTreeMap<u16, Expr>,
    pub local_writes: BTreeMap<u16, Expr>,
    pub register_writes: BTreeMap<u16, Expr>,
    pub instruction_pointer_write: Option<Expr>,
    pub reads: Vec<StateLocation>,
    pub writes: Vec<StateLocation>,
    pub control: ControlEffect,
    pub return_value: Option<Expr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateSummary {
    pub stack_delta: i16,
    pub reads: Vec<StateLocation>,
    pub writes: Vec<StateLocation>,
    pub control: ControlEffect,
}

#[derive(Clone, Debug)]
pub struct AbstractState {
    stack: Vec<Expr>,
    stack_inputs: u16,
    argument_writes: BTreeMap<u16, Expr>,
    local_writes: BTreeMap<u16, Expr>,
    register_writes: BTreeMap<u16, Expr>,
    instruction_pointer_write: Option<Expr>,
    reads: BTreeSet<StateLocation>,
    writes: BTreeSet<StateLocation>,
    control: ControlEffect,
    return_value: Option<Expr>,
    unknown: bool,
}

impl AbstractState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack: Vec::new(),
            stack_inputs: 0,
            argument_writes: BTreeMap::new(),
            local_writes: BTreeMap::new(),
            register_writes: BTreeMap::new(),
            instruction_pointer_write: None,
            reads: BTreeSet::new(),
            writes: BTreeSet::new(),
            control: ControlEffect::Fallthrough,
            return_value: None,
            unknown: false,
        }
    }

    pub fn apply(&mut self, effect: &PrimitiveEffect, budget: &mut Budget) -> Result<(), Reject> {
        budget.spend(1).map_err(Reject::from_budget_error)?;
        match effect {
            PrimitiveEffect::PushArgument(index) => {
                self.reads.insert(StateLocation::Argument(*index));
                self.push(Expr::Argument(*index))?;
            }
            PrimitiveEffect::StoreArgument(index) => {
                let value: Expr = self.pop()?;
                self.argument_writes.insert(*index, value);
                self.writes.insert(StateLocation::Argument(*index));
            }
            PrimitiveEffect::PushLocal(index) => {
                self.reads.insert(StateLocation::Local(*index));
                self.push(Expr::Local(*index))?;
            }
            PrimitiveEffect::StoreLocal(index) => {
                let value: Expr = self.pop()?;
                self.local_writes.insert(*index, value);
                self.writes.insert(StateLocation::Local(*index));
            }
            PrimitiveEffect::PushConst(value) => self.push(Expr::Const(*value))?,
            PrimitiveEffect::PushOperandI64 => {
                let range: OperandRange = OperandRange::new(0, 8);
                self.reads.insert(StateLocation::OperandBytes(range));
                self.push(Expr::OperandBytes(range))?;
            }
            PrimitiveEffect::Binary(op) => {
                let right: Expr = self.pop()?;
                let left: Expr = self.pop()?;
                let value: Expr = Expr::binary(*op, left, right)?;
                self.push(value)?;
            }
            PrimitiveEffect::AdvanceIp(delta) => self.advance_ip(*delta),
            PrimitiveEffect::Branch => self.set_control(ControlEffect::Br),
            PrimitiveEffect::BranchIfTrue => {
                let condition: Expr = self.pop()?;
                if condition != Expr::VStackTop {
                    self.unknown = true;
                }
                self.set_control(ControlEffect::BrTrue);
            }
            PrimitiveEffect::BranchIfFalse => {
                let condition: Expr = self.pop()?;
                if condition != Expr::VStackTop {
                    self.unknown = true;
                }
                self.set_control(ControlEffect::BrFalse);
            }
            PrimitiveEffect::Return => {
                let value: Expr = self.pop()?;
                self.return_value = Some(value);
                self.set_control(ControlEffect::Ret);
            }
            PrimitiveEffect::Opaque => {
                self.unknown = true;
                self.control = ControlEffect::Unknown;
            }
        }
        Ok(())
    }

    pub(crate) fn summary(&self) -> Result<StateSummary, Reject> {
        let output_count: i16 = match i16::try_from(self.stack.len()) {
            Ok(value) => value,
            Err(_) => {
                return Err(Reject::new(
                    "handler stack output exceeds representable range",
                    Vec::new(),
                ));
            }
        };
        let input_count: i16 = match i16::try_from(self.stack_inputs) {
            Ok(value) => value,
            Err(_) => {
                return Err(Reject::new(
                    "handler stack input exceeds representable range",
                    Vec::new(),
                ));
            }
        };
        Ok(StateSummary {
            stack_delta: output_count.saturating_sub(input_count),
            reads: self.reads.iter().cloned().collect(),
            writes: self.writes.iter().cloned().collect(),
            control: self.control,
        })
    }

    pub fn canonical_effect(&self, budget: &mut Budget) -> Result<Option<CanonicalEffect>, Reject> {
        if self.unknown {
            return Ok(None);
        }
        let mut stack_outputs: Vec<Expr> = Vec::with_capacity(self.stack.len());
        for output in &self.stack {
            let canonical: Expr = output.canonicalize(budget)?;
            stack_outputs.push(canonical);
        }
        let mut argument_writes: BTreeMap<u16, Expr> = BTreeMap::new();
        for (index, value) in &self.argument_writes {
            let canonical: Expr = value.canonicalize(budget)?;
            argument_writes.insert(*index, canonical);
        }
        let mut local_writes: BTreeMap<u16, Expr> = BTreeMap::new();
        for (index, value) in &self.local_writes {
            let canonical: Expr = value.canonicalize(budget)?;
            local_writes.insert(*index, canonical);
        }
        let mut register_writes: BTreeMap<u16, Expr> = BTreeMap::new();
        for (index, value) in &self.register_writes {
            let canonical: Expr = value.canonicalize(budget)?;
            register_writes.insert(*index, canonical);
        }
        let instruction_pointer_write: Option<Expr> = match &self.instruction_pointer_write {
            Some(value) => Some(value.canonicalize(budget)?),
            None => None,
        };
        let return_value: Option<Expr> = match &self.return_value {
            Some(value) => Some(value.canonicalize(budget)?),
            None => None,
        };
        Ok(Some(CanonicalEffect {
            stack_inputs: self.stack_inputs,
            stack_outputs,
            argument_writes,
            local_writes,
            register_writes,
            instruction_pointer_write,
            reads: self.reads.iter().cloned().collect(),
            writes: self.writes.iter().cloned().collect(),
            control: self.control,
            return_value,
        }))
    }

    fn push(&mut self, value: Expr) -> Result<(), Reject> {
        if self.stack.len() >= MAX_ABSTRACT_STACK {
            return Err(Reject::new(
                "handler symbolic stack exceeds cap",
                vec![MAX_ABSTRACT_STACK.to_string()],
            ));
        }
        self.stack.push(value);
        self.writes.insert(StateLocation::Stack);
        Ok(())
    }

    fn pop(&mut self) -> Result<Expr, Reject> {
        let popped: Option<Expr> = self.stack.pop();
        if popped.is_some() {
            self.reads.insert(StateLocation::Stack);
            return popped.map_or_else(
                || {
                    Err(Reject::new(
                        "virtual stack pop state changed during analysis",
                        Vec::new(),
                    ))
                },
                |value: Expr| Ok(value),
            );
        }
        self.next_symbolic_input()
    }

    fn next_symbolic_input(&mut self) -> Result<Expr, Reject> {
        if usize::from(self.stack_inputs) >= MAX_ABSTRACT_STACK {
            return Err(Reject::new(
                "handler symbolic stack input exceeds cap",
                vec![MAX_ABSTRACT_STACK.to_string()],
            ));
        }
        let input: Expr = if self.stack_inputs == 0 {
            Expr::VStackTop
        } else {
            Expr::VStackAt(self.stack_inputs)
        };
        self.stack_inputs = self
            .stack_inputs
            .checked_add(1)
            .ok_or_else(|| Reject::new("handler symbolic stack input overflowed", Vec::new()))?;
        self.reads.insert(StateLocation::Stack);
        Ok(input)
    }

    fn advance_ip(&mut self, delta: i32) {
        let next: Option<Expr> = match self.instruction_pointer_write.take() {
            None => Some(Expr::IpDelta(delta)),
            Some(Expr::IpDelta(current)) => current.checked_add(delta).map(Expr::IpDelta),
            Some(
                Expr::VStackTop
                | Expr::VStackAt(_)
                | Expr::VReg(_)
                | Expr::Local(_)
                | Expr::Argument(_)
                | Expr::OperandBytes(_)
                | Expr::Const(_)
                | Expr::Binary { .. },
            ) => None,
        };
        let Some(value): Option<Expr> = next else {
            self.unknown = true;
            self.control = ControlEffect::Unknown;
            return;
        };
        self.instruction_pointer_write = Some(value);
        self.writes.insert(StateLocation::Ip);
    }

    fn set_control(&mut self, control: ControlEffect) {
        if self.control != ControlEffect::Fallthrough {
            self.unknown = true;
            self.control = ControlEffect::Unknown;
            return;
        }
        self.control = control;
        self.writes.insert(StateLocation::Ip);
    }
}

impl Default for AbstractState {
    fn default() -> Self {
        Self::new()
    }
}
