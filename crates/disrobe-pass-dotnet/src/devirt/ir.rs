use std::collections::{BTreeMap, BTreeSet};

use super::budget::Budget;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CilType {
    I4,
    I8,
    R4,
    R8,
    NativeInt,
    Ref,
    Void,
    Unknown,
}

impl CilType {
    #[must_use]
    pub const fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::I4 | Self::I8 | Self::R4 | Self::R8 | Self::NativeInt
        )
    }

    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(self, Self::I4 | Self::I8 | Self::NativeInt)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValueId(u32);

impl ValueId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockId(u32);

impl BlockId {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Ceq,
    Clt,
    Cgt,
}

impl BinOp {
    #[must_use]
    pub const fn is_comparison(self) -> bool {
        matches!(self, Self::Ceq | Self::Clt | Self::Cgt)
    }

    #[must_use]
    pub const fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor | Self::Ceq
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrInstruction {
    Const {
        destination: ValueId,
        value: i64,
    },
    LoadArgument {
        destination: ValueId,
        index: u16,
    },
    StoreArgument {
        index: u16,
        value: ValueId,
    },
    LoadLocal {
        destination: ValueId,
        index: u16,
    },
    StoreLocal {
        index: u16,
        value: ValueId,
    },
    Binary {
        destination: ValueId,
        op: BinOp,
        left: ValueId,
        right: ValueId,
    },
}

impl IrInstruction {
    const fn destination(&self) -> Option<ValueId> {
        match self {
            Self::Const { destination, .. }
            | Self::LoadArgument { destination, .. }
            | Self::LoadLocal { destination, .. }
            | Self::Binary { destination, .. } => Some(*destination),
            Self::StoreArgument { .. } | Self::StoreLocal { .. } => None,
        }
    }

    const fn result_type(&self) -> Option<CilType> {
        match self {
            Self::Const { .. } | Self::LoadArgument { .. } | Self::LoadLocal { .. } => {
                Some(CilType::I8)
            }
            Self::Binary { op, .. } if op.is_comparison() => Some(CilType::I4),
            Self::Binary { .. } => Some(CilType::I8),
            Self::StoreArgument { .. } | Self::StoreLocal { .. } => None,
        }
    }

    fn uses(&self) -> Vec<ValueId> {
        match self {
            Self::Const { .. } | Self::LoadArgument { .. } | Self::LoadLocal { .. } => Vec::new(),
            Self::StoreArgument { value, .. } | Self::StoreLocal { value, .. } => vec![*value],
            Self::Binary { left, right, .. } => vec![*left, *right],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Terminator {
    Br(BlockId),
    CondBr {
        condition: ValueId,
        when_true: BlockId,
        when_false: BlockId,
    },
    Ret(Option<ValueId>),
}

impl Terminator {
    fn uses(&self) -> Vec<ValueId> {
        match self {
            Self::Br(_) => Vec::new(),
            Self::CondBr { condition, .. } => vec![*condition],
            Self::Ret(value) => value
                .as_ref()
                .map_or_else(Vec::new, |value: &ValueId| vec![*value]),
        }
    }

    fn targets(&self) -> Vec<BlockId> {
        match self {
            Self::Br(target) => vec![*target],
            Self::CondBr {
                when_true,
                when_false,
                ..
            } => vec![*when_true, *when_false],
            Self::Ret(_) => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<IrInstruction>,
    pub terminator: Terminator,
}

impl BasicBlock {
    #[must_use]
    pub const fn new(id: u32, instructions: Vec<IrInstruction>, terminator: Terminator) -> Self {
        Self {
            id: BlockId::new(id),
            instructions,
            terminator,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DvIr {
    pub argument_count: u16,
    pub local_count: u16,
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub value_types: BTreeMap<ValueId, CilType>,
}

impl DvIr {
    #[must_use]
    pub fn new(argument_count: u16, local_count: u16, blocks: Vec<BasicBlock>) -> Self {
        let mut value_types: BTreeMap<ValueId, CilType> = BTreeMap::new();
        for block in &blocks {
            for instruction in &block.instructions {
                let result: Option<(ValueId, CilType)> =
                    instruction.destination().zip(instruction.result_type());
                result.map_or_else(
                    || (),
                    |(destination, value_type): (ValueId, CilType)| {
                        value_types.insert(destination, value_type);
                    },
                );
            }
        }
        let entry: BlockId = blocks
            .first()
            .map_or_else(|| BlockId::new(0), |block: &BasicBlock| block.id);
        Self {
            argument_count,
            local_count,
            entry,
            blocks,
            value_types,
        }
    }

    pub fn verify(&self, budget: &mut Budget) -> Result<(), IrVerifyError> {
        if self.blocks.is_empty() {
            return Err(IrVerifyError::new("IR has no blocks"));
        }
        let mut block_ids: BTreeSet<BlockId> = BTreeSet::new();
        for block in &self.blocks {
            Self::spend(budget)?;
            if !block_ids.insert(block.id) {
                return Err(IrVerifyError::new("IR has duplicate block identifiers"));
            }
        }
        if !block_ids.contains(&self.entry) {
            return Err(IrVerifyError::new("IR entry block is absent"));
        }
        let mut definitions: BTreeMap<ValueId, CilType> = BTreeMap::new();
        for block in &self.blocks {
            Self::spend(budget)?;
            for instruction in &block.instructions {
                Self::spend(budget)?;
                Self::verify_instruction(
                    instruction,
                    self.argument_count,
                    self.local_count,
                    &definitions,
                )?;
                match (instruction.destination(), instruction.result_type()) {
                    (Some(destination), Some(value_type)) => {
                        if definitions.insert(destination, value_type).is_some() {
                            return Err(IrVerifyError::new("IR value has multiple definitions"));
                        }
                    }
                    (None, None) => {}
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(IrVerifyError::new(
                            "IR instruction has inconsistent result metadata",
                        ));
                    }
                }
            }
            Self::verify_terminator(&block.terminator, &definitions, &block_ids)?;
        }
        if definitions != self.value_types {
            return Err(IrVerifyError::new(
                "IR value type table does not match definitions",
            ));
        }
        Ok(())
    }

    fn spend(budget: &mut Budget) -> Result<(), IrVerifyError> {
        budget
            .spend(1)
            .map_err(|error: super::budget::BudgetError| IrVerifyError::new(&error.to_string()))
    }

    fn verify_instruction(
        instruction: &IrInstruction,
        argument_count: u16,
        local_count: u16,
        definitions: &BTreeMap<ValueId, CilType>,
    ) -> Result<(), IrVerifyError> {
        match instruction {
            IrInstruction::LoadArgument { index, .. }
            | IrInstruction::StoreArgument { index, .. }
                if *index >= argument_count =>
            {
                return Err(IrVerifyError::new("IR argument index is out of range"));
            }
            IrInstruction::LoadLocal { index, .. } | IrInstruction::StoreLocal { index, .. }
                if *index >= local_count =>
            {
                return Err(IrVerifyError::new("IR local index is out of range"));
            }
            _ => {}
        }
        let uses: Vec<ValueId> = instruction.uses();
        for value in uses {
            if !definitions.contains_key(&value) {
                return Err(IrVerifyError::new("IR use precedes its definition"));
            }
        }
        let binary: Option<(BinOp, ValueId, ValueId)> = match instruction {
            IrInstruction::Binary {
                op, left, right, ..
            } => Some((*op, *left, *right)),
            _ => None,
        };
        binary.map_or(Ok(()), |(op, left, right): (BinOp, ValueId, ValueId)| {
            Self::verify_binary(op, left, right, instruction.result_type(), definitions)
        })?;
        Ok(())
    }

    fn verify_binary(
        op: BinOp,
        left: ValueId,
        right: ValueId,
        result_type: Option<CilType>,
        definitions: &BTreeMap<ValueId, CilType>,
    ) -> Result<(), IrVerifyError> {
        let left_type: CilType = definitions
            .get(&left)
            .copied()
            .ok_or_else(|| IrVerifyError::new("IR binary left operand is undefined"))?;
        let right_type: CilType = definitions
            .get(&right)
            .copied()
            .ok_or_else(|| IrVerifyError::new("IR binary right operand is undefined"))?;
        if left_type != right_type || !left_type.is_numeric() {
            return Err(IrVerifyError::new(
                "IR binary operand types are incompatible",
            ));
        }
        let expected_type: CilType = if op.is_comparison() {
            CilType::I4
        } else {
            left_type
        };
        let actual_type: CilType =
            result_type.ok_or_else(|| IrVerifyError::new("IR binary result type is absent"))?;
        if expected_type != actual_type {
            return Err(IrVerifyError::new("IR binary result type is incompatible"));
        }
        Ok(())
    }

    fn verify_terminator(
        terminator: &Terminator,
        definitions: &BTreeMap<ValueId, CilType>,
        block_ids: &BTreeSet<BlockId>,
    ) -> Result<(), IrVerifyError> {
        let uses: Vec<ValueId> = terminator.uses();
        for value in uses {
            if !definitions.contains_key(&value) {
                return Err(IrVerifyError::new(
                    "IR terminator use precedes its definition",
                ));
            }
        }
        match terminator {
            Terminator::CondBr { condition, .. } => {
                let condition_type: CilType = match definitions.get(condition) {
                    Some(value_type) => *value_type,
                    None => return Err(IrVerifyError::new("IR branch condition is undefined")),
                };
                if !condition_type.is_integer() {
                    return Err(IrVerifyError::new("IR branch condition is not an integer"));
                }
            }
            Terminator::Br(_) | Terminator::Ret(_) => {}
        }
        let targets: Vec<BlockId> = terminator.targets();
        for target in targets {
            if !block_ids.contains(&target) {
                return Err(IrVerifyError::new("IR branch target is absent"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrVerifyError {
    pub reason: String,
}

impl IrVerifyError {
    #[must_use]
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_owned(),
        }
    }
}

impl std::fmt::Display for IrVerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for IrVerifyError {}
