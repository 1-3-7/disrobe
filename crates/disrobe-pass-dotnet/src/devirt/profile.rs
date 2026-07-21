use std::collections::BTreeMap;

use super::Reject;
use super::budget::Budget;
use super::state::{OperandRange, PrimitiveEffect};

pub const MAX_OPERAND_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CilSlot {
    Argument(u16),
    Local(u16),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CilSlotRole {
    StackPointer,
    InstructionPointer,
    Argument(u16),
    Local(u16),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CilSlotBinding {
    pub slot: CilSlot,
    pub role: CilSlotRole,
}

impl CilSlotBinding {
    #[must_use]
    pub const fn new(slot: CilSlot, role: CilSlotRole) -> Self {
        Self { slot, role }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CilStackAccess {
    pub byte_offset: i32,
    pub virtual_slot: u16,
}

impl CilStackAccess {
    #[must_use]
    pub const fn new(byte_offset: i32, virtual_slot: u16) -> Self {
        Self {
            byte_offset,
            virtual_slot,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CilOperandAccess {
    pub instruction_pointer_offset: i32,
    pub operand_range: OperandRange,
}

impl CilOperandAccess {
    #[must_use]
    pub const fn new(instruction_pointer_offset: i32, operand_range: OperandRange) -> Self {
        Self {
            instruction_pointer_offset,
            operand_range,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CilHandlerProfile {
    slot_bindings: &'static [CilSlotBinding],
    stack_pop_offsets: &'static [CilStackAccess],
    stack_push_offsets: &'static [CilStackAccess],
    operand_accesses: &'static [CilOperandAccess],
    terminal_branches: bool,
    virtual_returns: bool,
}

impl CilHandlerProfile {
    #[must_use]
    pub const fn new(
        slot_bindings: &'static [CilSlotBinding],
        stack_pop_offsets: &'static [CilStackAccess],
        stack_push_offsets: &'static [CilStackAccess],
        operand_accesses: &'static [CilOperandAccess],
    ) -> Self {
        Self {
            slot_bindings,
            stack_pop_offsets,
            stack_push_offsets,
            operand_accesses,
            terminal_branches: false,
            virtual_returns: false,
        }
    }

    #[must_use]
    pub const fn with_terminal_control(
        mut self,
        terminal_branches: bool,
        virtual_returns: bool,
    ) -> Self {
        self.terminal_branches = terminal_branches;
        self.virtual_returns = virtual_returns;
        self
    }

    pub(crate) fn has_unambiguous_core_bindings(&self) -> bool {
        self.count_role(CilSlotRole::StackPointer) == 1
            && self.count_role(CilSlotRole::InstructionPointer) == 1
            && self.slot_bindings.iter().all(|binding: &CilSlotBinding| {
                self.count_slot(binding.slot) == 1 && self.count_role(binding.role) == 1
            })
    }

    pub(crate) fn role_for_slot(&self, slot: CilSlot) -> Option<CilSlotRole> {
        if !self.has_unambiguous_core_bindings() || self.count_slot(slot) != 1 {
            return None;
        }
        self.slot_bindings
            .iter()
            .find_map(|binding: &CilSlotBinding| (binding.slot == slot).then_some(binding.role))
    }

    pub(crate) fn stack_pop_at(&self, byte_offset: i32) -> Option<u16> {
        Self::single_stack_slot(self.stack_pop_offsets, byte_offset)
    }

    pub(crate) fn stack_push_at(&self, byte_offset: i32) -> Option<u16> {
        Self::single_stack_slot(self.stack_push_offsets, byte_offset)
    }

    pub(crate) fn operand_at(&self, instruction_pointer_offset: i32) -> Option<OperandRange> {
        let mut found: Option<OperandRange> = None;
        for access in self.operand_accesses {
            if access.instruction_pointer_offset == instruction_pointer_offset {
                if found.is_some() {
                    return None;
                }
                found = Some(access.operand_range);
            }
        }
        found
    }

    pub(crate) const fn allows_terminal_branches(&self) -> bool {
        self.terminal_branches
    }

    pub(crate) const fn allows_virtual_returns(&self) -> bool {
        self.virtual_returns
    }

    fn count_slot(&self, slot: CilSlot) -> usize {
        self.slot_bindings
            .iter()
            .filter(|binding: &&CilSlotBinding| binding.slot == slot)
            .count()
    }

    fn count_role(&self, role: CilSlotRole) -> usize {
        self.slot_bindings
            .iter()
            .filter(|binding: &&CilSlotBinding| binding.role == role)
            .count()
    }

    fn single_stack_slot(accesses: &[CilStackAccess], byte_offset: i32) -> Option<u16> {
        let mut found: Option<u16> = None;
        for access in accesses {
            if access.byte_offset == byte_offset {
                if found.is_some() {
                    return None;
                }
                found = Some(access.virtual_slot);
            }
        }
        found
    }
}

const KOIVM_SHAPED_CIL_SLOT_BINDINGS: [CilSlotBinding; 2] = [
    CilSlotBinding::new(CilSlot::Argument(0), CilSlotRole::StackPointer),
    CilSlotBinding::new(CilSlot::Local(0), CilSlotRole::InstructionPointer),
];
const KOIVM_SHAPED_CIL_STACK_POPS: [CilStackAccess; 2] =
    [CilStackAccess::new(0, 0), CilStackAccess::new(-8, 1)];
const KOIVM_SHAPED_CIL_STACK_PUSHES: [CilStackAccess; 1] = [CilStackAccess::new(0, 0)];
const KOIVM_SHAPED_CIL_OPERANDS: [CilOperandAccess; 1] =
    [CilOperandAccess::new(1, OperandRange::new(0, 8))];

pub static KOIVM_SHAPED_CIL_HANDLER_PROFILE: CilHandlerProfile = CilHandlerProfile::new(
    &KOIVM_SHAPED_CIL_SLOT_BINDINGS,
    &KOIVM_SHAPED_CIL_STACK_POPS,
    &KOIVM_SHAPED_CIL_STACK_PUSHES,
    &KOIVM_SHAPED_CIL_OPERANDS,
);

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
