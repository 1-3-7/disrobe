use std::collections::BTreeMap;

use super::Reject;
use super::budget::Budget;
use super::state::PrimitiveEffect;

pub const MAX_OPERAND_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmFlavor {
    Stack,
    Register,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperandEncoding {
    None,
    I64,
    Target,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticHandler {
    pub effects: Vec<PrimitiveEffect>,
    pub operand_encoding: OperandEncoding,
}

impl SyntheticHandler {
    #[must_use]
    pub const fn new(effects: Vec<PrimitiveEffect>, operand_encoding: OperandEncoding) -> Self {
        Self {
            effects,
            operand_encoding,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VInstr {
    pub handler_id: u16,
    pub operand: Vec<u8>,
}

impl VInstr {
    #[must_use]
    pub const fn new(handler_id: u16, operand: Vec<u8>) -> Self {
        Self {
            handler_id,
            operand,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticVmModel {
    pub flavor: VmFlavor,
    pub argument_count: u16,
    pub local_count: u16,
    pub handlers: BTreeMap<u16, SyntheticHandler>,
    pub instructions: Vec<VInstr>,
}

impl SyntheticVmModel {
    #[must_use]
    pub const fn new(
        flavor: VmFlavor,
        argument_count: u16,
        local_count: u16,
        handlers: BTreeMap<u16, SyntheticHandler>,
        instructions: Vec<VInstr>,
    ) -> Self {
        Self {
            flavor,
            argument_count,
            local_count,
            handlers,
            instructions,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedOperand {
    None,
    I64(i64),
    Target(u32),
}

pub trait ProtectorProfile: std::fmt::Debug {
    fn discover_handler_table<'a>(
        &self,
        model: &'a SyntheticVmModel,
    ) -> Result<&'a BTreeMap<u16, SyntheticHandler>, Reject>;

    fn decode_operand(
        &self,
        handler: &SyntheticHandler,
        operand: &[u8],
        budget: &mut Budget,
    ) -> Result<DecodedOperand, Reject>;

    fn flavor(&self) -> VmFlavor;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SyntheticStackProfile;

impl ProtectorProfile for SyntheticStackProfile {
    fn discover_handler_table<'a>(
        &self,
        model: &'a SyntheticVmModel,
    ) -> Result<&'a BTreeMap<u16, SyntheticHandler>, Reject> {
        if model.flavor != self.flavor() {
            return Err(Reject::new(
                "VM flavor is unsupported by the selected profile",
                Vec::new(),
            ));
        }
        Ok(&model.handlers)
    }

    fn decode_operand(
        &self,
        handler: &SyntheticHandler,
        operand: &[u8],
        budget: &mut Budget,
    ) -> Result<DecodedOperand, Reject> {
        if operand.len() > MAX_OPERAND_BYTES {
            return Err(Reject::new(
                "operand exceeds configured byte cap",
                vec![operand.len().to_string(), MAX_OPERAND_BYTES.to_string()],
            ));
        }
        let operand_cost: u64 = match u64::try_from(operand.len()) {
            Ok(value) => value.max(1),
            Err(_) => {
                return Err(Reject::new(
                    "operand length cannot be represented for budgeting",
                    Vec::new(),
                ));
            }
        };
        budget
            .spend(operand_cost)
            .map_err(Reject::from_budget_error)?;
        match handler.operand_encoding {
            OperandEncoding::None => {
                if !operand.is_empty() {
                    return Err(Reject::new(
                        "handler does not accept an operand",
                        vec![operand.len().to_string()],
                    ));
                }
                Ok(DecodedOperand::None)
            }
            OperandEncoding::I64 => {
                let bytes: [u8; 8] = match operand.try_into() {
                    Ok(value) => value,
                    Err(_) => {
                        return Err(Reject::new(
                            "I64 operand has an invalid width",
                            vec![operand.len().to_string()],
                        ));
                    }
                };
                Ok(DecodedOperand::I64(i64::from_le_bytes(bytes)))
            }
            OperandEncoding::Target => {
                let bytes: [u8; 4] = match operand.try_into() {
                    Ok(value) => value,
                    Err(_) => {
                        return Err(Reject::new(
                            "branch target operand has an invalid width",
                            vec![operand.len().to_string()],
                        ));
                    }
                };
                Ok(DecodedOperand::Target(u32::from_le_bytes(bytes)))
            }
        }
    }

    fn flavor(&self) -> VmFlavor {
        VmFlavor::Stack
    }
}
