use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use gimli::{Dwarf, EndianSlice, Operation, RunTimeEndian};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

pub type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

pub const FRAME_POINTER_DWARF_REGISTER: u16 = 6;
pub const STACK_POINTER_DWARF_REGISTER: u16 = 7;

const RETURN_ADDRESS_SLOT: i64 = 8;
const PUSHED_REGISTER_SLOT: i64 = 8;
const MAX_PROLOGUE_INSTRUCTIONS: usize = 32;
const MAX_EXPRESSION_OPERATIONS: usize = 64;
const MAX_LOCATION_LIST_ENTRIES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum UnlocatedReason {
    NoLocationAttribute,
    LocationUnreadable,
    EmptyExpression,
    RegisterResident,
    StaticAddress,
    StackPointerRelative,
    OtherRegisterRelative,
    FrameIndirect,
    CompositePieces,
    ImplicitValue,
    StackValueOnly,
    EntryValue,
    ImplicitPointer,
    UnmodelledExpression,
    LocationListUnreadable,
    LocationListWithoutFrameOffset,
    FrameBaseAbsent,
    FrameBaseUnreadable,
    FrameBaseNotFramePointer,
    FrameBaseUnmodelled,
    FrameBaseListWithoutFramePointer,
    PrologueWithoutFramePointer,
    PrologueRealignsStack,
    PrologueUndecodable,
    FunctionBytesOutsideImage,
    DisplacementOverflow,
    ScopeOutsideFrameWindow,
    NoTypeAttribute,
    NonIntegerType,
    VariableBudgetExhausted,
}

impl UnlocatedReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLocationAttribute => "no_location_attribute",
            Self::LocationUnreadable => "location_unreadable",
            Self::EmptyExpression => "empty_expression",
            Self::RegisterResident => "register_resident",
            Self::StaticAddress => "static_address",
            Self::StackPointerRelative => "stack_pointer_relative",
            Self::OtherRegisterRelative => "other_register_relative",
            Self::FrameIndirect => "frame_indirect",
            Self::CompositePieces => "composite_pieces",
            Self::ImplicitValue => "implicit_value",
            Self::StackValueOnly => "stack_value_only",
            Self::EntryValue => "entry_value",
            Self::ImplicitPointer => "implicit_pointer",
            Self::UnmodelledExpression => "unmodelled_expression",
            Self::LocationListUnreadable => "location_list_unreadable",
            Self::LocationListWithoutFrameOffset => "location_list_without_frame_offset",
            Self::FrameBaseAbsent => "frame_base_absent",
            Self::FrameBaseUnreadable => "frame_base_unreadable",
            Self::FrameBaseNotFramePointer => "frame_base_not_frame_pointer",
            Self::FrameBaseUnmodelled => "frame_base_unmodelled",
            Self::FrameBaseListWithoutFramePointer => "frame_base_list_without_frame_pointer",
            Self::PrologueWithoutFramePointer => "prologue_without_frame_pointer",
            Self::PrologueRealignsStack => "prologue_realigns_stack",
            Self::PrologueUndecodable => "prologue_undecodable",
            Self::FunctionBytesOutsideImage => "function_bytes_outside_image",
            Self::DisplacementOverflow => "displacement_overflow",
            Self::ScopeOutsideFrameWindow => "scope_outside_frame_window",
            Self::NoTypeAttribute => "no_type_attribute",
            Self::NonIntegerType => "non_integer_type",
            Self::VariableBudgetExhausted => "variable_budget_exhausted",
        }
    }

    #[must_use]
    pub const fn is_unmodelled(self) -> bool {
        matches!(
            self,
            Self::UnmodelledExpression
                | Self::FrameBaseUnmodelled
                | Self::PrologueUndecodable
                | Self::LocationUnreadable
                | Self::LocationListUnreadable
                | Self::FrameBaseUnreadable
        )
    }
}

impl fmt::Display for UnlocatedReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocationSurvey {
    pub versions: BTreeSet<u16>,
    pub subprograms: usize,
    pub subprograms_without_code: usize,
    pub declared: usize,
    pub located: usize,
    pub unlocated: BTreeMap<UnlocatedReason, usize>,
}

impl LocationSurvey {
    pub fn record_version(&mut self, version: u16) {
        self.versions.insert(version);
    }

    pub const fn record_declared(&mut self) {
        self.declared += 1;
    }

    pub const fn record_located(&mut self) {
        self.located += 1;
    }

    pub fn record_unlocated(&mut self, reason: UnlocatedReason) {
        *self.unlocated.entry(reason).or_insert(0) += 1;
    }

    #[must_use]
    pub fn unlocated_total(&self) -> usize {
        self.unlocated.values().sum()
    }

    #[must_use]
    pub fn balances(&self) -> bool {
        self.declared == self.located + self.unlocated_total()
    }

    #[must_use]
    pub fn unmodelled_total(&self) -> usize {
        self.unlocated
            .iter()
            .filter(|(reason, _): &(&UnlocatedReason, &usize)| reason.is_unmodelled())
            .map(|(_, count): (&UnlocatedReason, &usize)| *count)
            .sum()
    }

    #[must_use]
    pub fn count(&self, reason: UnlocatedReason) -> usize {
        self.unlocated.get(&reason).copied().unwrap_or(0)
    }
}

impl fmt::Display for LocationSurvey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let versions: Vec<String> = self
            .versions
            .iter()
            .map(u16::to_string)
            .collect::<Vec<String>>();
        write!(
            formatter,
            "dwarf={} subprograms={} without_code={} declared={} located={} unlocated={}",
            versions.join("+"),
            self.subprograms,
            self.subprograms_without_code,
            self.declared,
            self.located,
            self.unlocated_total()
        )?;
        for (reason, count) in &self.unlocated {
            write!(formatter, " {reason}={count}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcRange {
    pub lo: u64,
    pub hi: u64,
}

impl PcRange {
    #[must_use]
    pub const fn new(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.hi <= self.lo
    }

    #[must_use]
    pub const fn intersect(self, other: Self) -> Option<Self> {
        let lo: u64 = if self.lo > other.lo {
            self.lo
        } else {
            other.lo
        };
        let hi: u64 = if self.hi < other.hi {
            self.hi
        } else {
            other.hi
        };
        if hi <= lo {
            None
        } else {
            Some(Self { lo, hi })
        }
    }

    #[must_use]
    pub const fn span(self) -> u64 {
        self.hi.saturating_sub(self.lo)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameWindow {
    pub displacement: i64,
    pub range: PcRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameBase {
    FramePointer(Vec<FrameWindow>),
    Unusable(UnlocatedReason),
}

impl FrameBase {
    #[must_use]
    pub fn windows(&self) -> &[FrameWindow] {
        match self {
            Self::FramePointer(windows) => windows,
            Self::Unusable(_) => &[],
        }
    }

    #[must_use]
    pub const fn defect(&self) -> Option<UnlocatedReason> {
        match self {
            Self::FramePointer(_) => None,
            Self::Unusable(reason) => Some(*reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSlot {
    pub rbp_disp: i64,
    pub range: PcRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpressionForm {
    Empty,
    FrameOffset(i64),
    Register(u16),
    RegisterOffset { register: u16, offset: i64 },
    CallFrameCfa,
    Address(u64),
    FrameIndirect,
    Composite,
    ImplicitValue,
    StackValue,
    EntryValue,
    ImplicitPointer,
    Unmodelled,
}

impl ExpressionForm {
    #[must_use]
    pub const fn as_variable_defect(self) -> UnlocatedReason {
        match self {
            Self::Empty => UnlocatedReason::EmptyExpression,
            Self::FrameOffset(_) => UnlocatedReason::ScopeOutsideFrameWindow,
            Self::Register(_) => UnlocatedReason::RegisterResident,
            Self::RegisterOffset { register, .. } => {
                if register == STACK_POINTER_DWARF_REGISTER {
                    UnlocatedReason::StackPointerRelative
                } else {
                    UnlocatedReason::OtherRegisterRelative
                }
            }
            Self::CallFrameCfa => UnlocatedReason::OtherRegisterRelative,
            Self::Address(_) => UnlocatedReason::StaticAddress,
            Self::FrameIndirect => UnlocatedReason::FrameIndirect,
            Self::Composite => UnlocatedReason::CompositePieces,
            Self::ImplicitValue => UnlocatedReason::ImplicitValue,
            Self::StackValue => UnlocatedReason::StackValueOnly,
            Self::EntryValue => UnlocatedReason::EntryValue,
            Self::ImplicitPointer => UnlocatedReason::ImplicitPointer,
            Self::Unmodelled => UnlocatedReason::UnmodelledExpression,
        }
    }
}

pub fn function_slice(text: &[u8], text_base: u64, range: PcRange) -> Option<&[u8]> {
    let start: usize = usize::try_from(range.lo.checked_sub(text_base)?).ok()?;
    let end: usize = usize::try_from(range.hi.checked_sub(text_base)?).ok()?;
    if end <= start {
        return None;
    }
    text.get(start..end)
}

pub fn classify_expression(
    unit: &gimli::Unit<Slice<'_>>,
    expression: gimli::Expression<Slice<'_>>,
) -> core::result::Result<ExpressionForm, UnlocatedReason> {
    let mut operations: Vec<Operation<Slice<'_>>> = Vec::new();
    let mut iterator: gimli::OperationIter<Slice<'_>> = expression.operations(unit.encoding());
    loop {
        match iterator.next() {
            Ok(Some(operation)) => {
                if operations.len() >= MAX_EXPRESSION_OPERATIONS {
                    return Ok(ExpressionForm::Unmodelled);
                }
                operations.push(operation);
            }
            Ok(None) => break,
            Err(_) => return Err(UnlocatedReason::LocationUnreadable),
        }
    }
    Ok(shape_of(&operations))
}

fn shape_of(operations: &[Operation<Slice<'_>>]) -> ExpressionForm {
    if operations
        .iter()
        .any(|op: &Operation<Slice<'_>>| matches!(op, Operation::Piece { .. }))
    {
        return ExpressionForm::Composite;
    }
    if operations
        .iter()
        .any(|op: &Operation<Slice<'_>>| matches!(op, Operation::EntryValue { .. }))
    {
        return ExpressionForm::EntryValue;
    }
    if operations
        .iter()
        .any(|op: &Operation<Slice<'_>>| matches!(op, Operation::ImplicitValue { .. }))
    {
        return ExpressionForm::ImplicitValue;
    }
    if operations
        .iter()
        .any(|op: &Operation<Slice<'_>>| matches!(op, Operation::ImplicitPointer { .. }))
    {
        return ExpressionForm::ImplicitPointer;
    }
    if matches!(operations.last(), Some(Operation::StackValue)) {
        return ExpressionForm::StackValue;
    }
    match operations {
        [] => ExpressionForm::Empty,
        [Operation::FrameOffset { offset }] => ExpressionForm::FrameOffset(*offset),
        [Operation::Register { register }] => ExpressionForm::Register(register.0),
        [
            Operation::RegisterOffset {
                register, offset, ..
            },
        ] => ExpressionForm::RegisterOffset {
            register: register.0,
            offset: *offset,
        },
        [Operation::CallFrameCFA] => ExpressionForm::CallFrameCfa,
        [Operation::Address { address }] => ExpressionForm::Address(*address),
        [Operation::FrameOffset { .. }, Operation::Deref { .. }] => ExpressionForm::FrameIndirect,
        _ => ExpressionForm::Unmodelled,
    }
}

pub fn frame_pointer_delta_from_prologue(
    text: &[u8],
    text_base: u64,
    function: PcRange,
) -> core::result::Result<i64, UnlocatedReason> {
    let Some(bytes): Option<&[u8]> = function_slice(text, text_base, function) else {
        return Err(UnlocatedReason::FunctionBytesOutsideImage);
    };
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, function.lo, DecoderOptions::NONE);
    let mut instruction: Instruction = Instruction::default();
    let mut cfa_from_stack_pointer: i64 = RETURN_ADDRESS_SLOT;
    let mut decoded: usize = 0;
    while decoder.can_decode() && decoded < MAX_PROLOGUE_INSTRUCTIONS {
        decoder.decode_out(&mut instruction);
        decoded += 1;
        if instruction.is_invalid() {
            return Err(UnlocatedReason::PrologueUndecodable);
        }
        match instruction.mnemonic() {
            Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Nop => {}
            Mnemonic::Push => {
                cfa_from_stack_pointer = cfa_from_stack_pointer
                    .checked_add(pushed_slot(&instruction)?)
                    .ok_or(UnlocatedReason::DisplacementOverflow)?;
            }
            Mnemonic::Mov if copies_stack_pointer_to_frame_pointer(&instruction) => {
                return Ok(cfa_from_stack_pointer);
            }
            Mnemonic::Lea => {
                let displacement: i64 = frame_pointer_lea_displacement(&instruction)?;
                return cfa_from_stack_pointer
                    .checked_sub(displacement)
                    .ok_or(UnlocatedReason::DisplacementOverflow);
            }
            Mnemonic::Sub if targets_stack_pointer(&instruction) => {
                cfa_from_stack_pointer = cfa_from_stack_pointer
                    .checked_add(stack_pointer_immediate(&instruction)?)
                    .ok_or(UnlocatedReason::DisplacementOverflow)?;
            }
            Mnemonic::And if targets_stack_pointer(&instruction) => {
                return Err(UnlocatedReason::PrologueRealignsStack);
            }
            _ => return Err(UnlocatedReason::PrologueWithoutFramePointer),
        }
    }
    Err(UnlocatedReason::PrologueWithoutFramePointer)
}

fn pushed_slot(instruction: &Instruction) -> core::result::Result<i64, UnlocatedReason> {
    if instruction.op0_kind() != OpKind::Register {
        return Err(UnlocatedReason::PrologueUndecodable);
    }
    if instruction.op_register(0).size() == 8 {
        Ok(PUSHED_REGISTER_SLOT)
    } else {
        Err(UnlocatedReason::PrologueUndecodable)
    }
}

fn copies_stack_pointer_to_frame_pointer(instruction: &Instruction) -> bool {
    instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op_register(0) == Register::RBP
        && instruction.op_register(1) == Register::RSP
}

fn targets_stack_pointer(instruction: &Instruction) -> bool {
    instruction.op0_kind() == OpKind::Register && instruction.op_register(0) == Register::RSP
}

fn frame_pointer_lea_displacement(
    instruction: &Instruction,
) -> core::result::Result<i64, UnlocatedReason> {
    if instruction.op0_kind() != OpKind::Register
        || instruction.op_register(0) != Register::RBP
        || instruction.op1_kind() != OpKind::Memory
        || instruction.memory_base() != Register::RSP
        || instruction.memory_index() != Register::None
    {
        return Err(UnlocatedReason::PrologueWithoutFramePointer);
    }
    Ok(i64::from_ne_bytes(
        instruction.memory_displacement64().to_ne_bytes(),
    ))
}

fn stack_pointer_immediate(
    instruction: &Instruction,
) -> core::result::Result<i64, UnlocatedReason> {
    match instruction.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate64 => Ok(i64::from_ne_bytes(instruction.immediate(1).to_ne_bytes())),
        _ => Err(UnlocatedReason::PrologueUndecodable),
    }
}

fn frame_window_from_form(
    form: ExpressionForm,
    window: PcRange,
    function: PcRange,
    text: &[u8],
    text_base: u64,
) -> core::result::Result<FrameWindow, UnlocatedReason> {
    let displacement: i64 = match form {
        ExpressionForm::CallFrameCfa => {
            frame_pointer_delta_from_prologue(text, text_base, function)?
        }
        ExpressionForm::Register(FRAME_POINTER_DWARF_REGISTER) => 0,
        ExpressionForm::RegisterOffset {
            register: FRAME_POINTER_DWARF_REGISTER,
            offset,
        } => offset,
        ExpressionForm::Register(_) | ExpressionForm::RegisterOffset { .. } => {
            return Err(UnlocatedReason::FrameBaseNotFramePointer);
        }
        _ => return Err(UnlocatedReason::FrameBaseUnmodelled),
    };
    Ok(FrameWindow {
        displacement,
        range: window,
    })
}

pub fn resolve_frame_base(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    function: PcRange,
    text: &[u8],
    text_base: u64,
) -> FrameBase {
    let value: gimli::AttributeValue<Slice<'_>> = match entry.attr_value(gimli::DW_AT_frame_base) {
        Ok(Some(value)) => value,
        Ok(None) => return FrameBase::Unusable(UnlocatedReason::FrameBaseAbsent),
        Err(_) => return FrameBase::Unusable(UnlocatedReason::FrameBaseUnreadable),
    };
    if let gimli::AttributeValue::Exprloc(expression) = value {
        return match classify_expression(unit, expression).and_then(|form: ExpressionForm| {
            frame_window_from_form(form, function, function, text, text_base)
        }) {
            Ok(window) => FrameBase::FramePointer(vec![window]),
            Err(reason) => FrameBase::Unusable(reason),
        };
    }
    let mut list: gimli::LocListIter<Slice<'_>> = match dwarf.attr_locations(unit, value) {
        Ok(Some(list)) => list,
        Ok(None) => return FrameBase::Unusable(UnlocatedReason::FrameBaseUnmodelled),
        Err(_) => return FrameBase::Unusable(UnlocatedReason::FrameBaseUnreadable),
    };
    let mut windows: Vec<FrameWindow> = Vec::new();
    let mut visited: usize = 0;
    while visited < MAX_LOCATION_LIST_ENTRIES {
        visited += 1;
        let entry: gimli::LocationListEntry<Slice<'_>> = match list.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(_) => return FrameBase::Unusable(UnlocatedReason::FrameBaseUnreadable),
        };
        let Some(covered): Option<PcRange> =
            PcRange::new(entry.range.begin, entry.range.end).intersect(function)
        else {
            continue;
        };
        let Ok(form): core::result::Result<ExpressionForm, UnlocatedReason> =
            classify_expression(unit, entry.data)
        else {
            continue;
        };
        if let Ok(window) = frame_window_from_form(form, covered, function, text, text_base) {
            windows.push(window);
        }
    }
    if windows.is_empty() {
        return FrameBase::Unusable(UnlocatedReason::FrameBaseListWithoutFramePointer);
    }
    FrameBase::FramePointer(windows)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlacedOffset {
    ViaFrameBase(i64),
    DirectFramePointer(i64),
}

const fn placed_offset(
    form: ExpressionForm,
) -> core::result::Result<PlacedOffset, UnlocatedReason> {
    match form {
        ExpressionForm::FrameOffset(offset) => Ok(PlacedOffset::ViaFrameBase(offset)),
        ExpressionForm::RegisterOffset {
            register: FRAME_POINTER_DWARF_REGISTER,
            offset,
        } => Ok(PlacedOffset::DirectFramePointer(offset)),
        other => Err(other.as_variable_defect()),
    }
}

fn slots_for_offset(
    windows: &[FrameWindow],
    offset: i64,
    covered: PcRange,
    out: &mut Vec<FrameSlot>,
) -> core::result::Result<(), UnlocatedReason> {
    for window in windows {
        let Some(range): Option<PcRange> = window.range.intersect(covered) else {
            continue;
        };
        let rbp_disp: i64 = window
            .displacement
            .checked_add(offset)
            .ok_or(UnlocatedReason::DisplacementOverflow)?;
        if out.len() < MAX_LOCATION_LIST_ENTRIES {
            out.push(FrameSlot { rbp_disp, range });
        }
    }
    Ok(())
}

fn push_slots(
    placed: PlacedOffset,
    frame: &FrameBase,
    covered: PcRange,
    out: &mut Vec<FrameSlot>,
) -> core::result::Result<(), UnlocatedReason> {
    match placed {
        PlacedOffset::DirectFramePointer(offset) => {
            if !covered.is_empty() && out.len() < MAX_LOCATION_LIST_ENTRIES {
                out.push(FrameSlot {
                    rbp_disp: offset,
                    range: covered,
                });
            }
            Ok(())
        }
        PlacedOffset::ViaFrameBase(offset) => {
            if let Some(defect) = frame.defect() {
                return Err(defect);
            }
            slots_for_offset(frame.windows(), offset, covered, out)
        }
    }
}

pub fn frame_slots(
    dwarf: &Dwarf<Slice<'_>>,
    unit: &gimli::Unit<Slice<'_>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, Slice<'_>>,
    frame: &FrameBase,
    function: PcRange,
) -> core::result::Result<Vec<FrameSlot>, UnlocatedReason> {
    let value: gimli::AttributeValue<Slice<'_>> = match entry.attr_value(gimli::DW_AT_location) {
        Ok(Some(value)) => value,
        Ok(None) => return Err(UnlocatedReason::NoLocationAttribute),
        Err(_) => return Err(UnlocatedReason::LocationUnreadable),
    };
    let mut slots: Vec<FrameSlot> = Vec::new();
    if let gimli::AttributeValue::Exprloc(expression) = value {
        let form: ExpressionForm = classify_expression(unit, expression)?;
        push_slots(placed_offset(form)?, frame, function, &mut slots)?;
        if slots.is_empty() {
            return Err(UnlocatedReason::ScopeOutsideFrameWindow);
        }
        return Ok(slots);
    }
    let mut list: gimli::LocListIter<Slice<'_>> = match dwarf.attr_locations(unit, value) {
        Ok(Some(list)) => list,
        Ok(None) => return Err(UnlocatedReason::UnmodelledExpression),
        Err(_) => return Err(UnlocatedReason::LocationListUnreadable),
    };
    let mut refused: Option<UnlocatedReason> = None;
    let mut visited: usize = 0;
    while visited < MAX_LOCATION_LIST_ENTRIES {
        visited += 1;
        let listed: gimli::LocationListEntry<Slice<'_>> = match list.next() {
            Ok(Some(listed)) => listed,
            Ok(None) => break,
            Err(_) => return Err(UnlocatedReason::LocationListUnreadable),
        };
        let Some(covered): Option<PcRange> =
            PcRange::new(listed.range.begin, listed.range.end).intersect(function)
        else {
            continue;
        };
        let form: ExpressionForm = match classify_expression(unit, listed.data) {
            Ok(form) => form,
            Err(reason) => {
                refused = refused.or(Some(reason));
                continue;
            }
        };
        let placed: PlacedOffset = match placed_offset(form) {
            Ok(placed) => placed,
            Err(reason) => {
                refused = refused.or(Some(reason));
                continue;
            }
        };
        if let Err(reason) = push_slots(placed, frame, covered, &mut slots) {
            refused = refused.or(Some(reason));
        }
    }
    if slots.is_empty() {
        return Err(refused.unwrap_or(UnlocatedReason::LocationListWithoutFrameOffset));
    }
    Ok(slots)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const TEXT_BASE: u64 = 0x1000;

    fn delta(bytes: &[u8]) -> core::result::Result<i64, UnlocatedReason> {
        let range: PcRange = PcRange::new(TEXT_BASE, TEXT_BASE + bytes.len() as u64);
        frame_pointer_delta_from_prologue(bytes, TEXT_BASE, range)
    }

    #[test]
    fn plain_frame_pointer_prologue_puts_the_cfa_two_slots_above_rbp() {
        assert_eq!(delta(&[0x55, 0x48, 0x89, 0xe5, 0xc3]), Ok(16));
    }

    #[test]
    fn control_flow_enforcement_prologue_resolves_the_same_displacement() {
        assert_eq!(
            delta(&[0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0xc3]),
            Ok(16),
            "a leading endbr64 must not hide the frame pointer setup behind it",
        );
    }

    #[test]
    fn callee_saved_pushes_before_the_frame_pointer_raise_the_displacement() {
        assert_eq!(
            delta(&[
                0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x57, 0x55, 0x48, 0x89, 0xe5, 0xc3
            ]),
            Ok(24),
            "push r15 then push rbp leaves the cfa three slots above rbp",
        );
    }

    #[test]
    fn a_frame_pointer_established_by_lea_accounts_for_its_displacement() {
        assert_eq!(
            delta(&[
                0x55, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x6c, 0x24, 0x10, 0xc3
            ]),
            Ok(32),
            "push rbp, sub rsp 0x20, lea rbp [rsp+0x10] leaves the cfa 0x20 above rbp",
        );
    }

    #[test]
    fn an_omitted_frame_pointer_is_named_rather_than_guessed() {
        assert_eq!(
            delta(&[
                0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x83, 0xec, 0x18, 0x89, 0xc8, 0xc3
            ]),
            Err(UnlocatedReason::PrologueWithoutFramePointer),
        );
    }

    #[test]
    fn a_realigned_stack_is_named_rather_than_guessed() {
        assert_eq!(
            delta(&[0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x83, 0xe4, 0xe0, 0xc3]),
            Err(UnlocatedReason::PrologueRealignsStack),
        );
    }

    #[test]
    fn an_empty_function_range_is_named_rather_than_guessed() {
        assert_eq!(
            frame_pointer_delta_from_prologue(&[], TEXT_BASE, PcRange::new(TEXT_BASE, TEXT_BASE)),
            Err(UnlocatedReason::FunctionBytesOutsideImage),
        );
        assert_eq!(
            frame_pointer_delta_from_prologue(
                &[0x55],
                TEXT_BASE,
                PcRange::new(TEXT_BASE - 0x100, TEXT_BASE)
            ),
            Err(UnlocatedReason::FunctionBytesOutsideImage),
        );
    }

    #[test]
    fn an_undecodable_first_byte_is_named_rather_than_guessed() {
        assert_eq!(
            delta(&[0xff, 0xff, 0xff, 0xff]),
            Err(UnlocatedReason::PrologueUndecodable),
        );
    }

    #[test]
    fn a_prologue_longer_than_the_budget_stops_instead_of_running_on() {
        let mut bytes: Vec<u8> = vec![0x90; MAX_PROLOGUE_INSTRUCTIONS + 8];
        bytes.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        assert_eq!(
            delta(&bytes),
            Err(UnlocatedReason::PrologueWithoutFramePointer)
        );
    }

    #[test]
    fn ranges_intersect_only_where_both_cover() {
        assert_eq!(
            PcRange::new(10, 20).intersect(PcRange::new(15, 30)),
            Some(PcRange::new(15, 20))
        );
        assert_eq!(PcRange::new(10, 20).intersect(PcRange::new(20, 30)), None);
        assert_eq!(PcRange::new(10, 10).intersect(PcRange::new(0, 30)), None);
        assert!(PcRange::new(5, 5).is_empty());
        assert_eq!(PcRange::new(5, 9).span(), 4);
    }

    #[test]
    fn a_survey_balances_only_when_every_declaration_is_accounted_for() {
        let mut survey: LocationSurvey = LocationSurvey::default();
        survey.record_declared();
        assert!(!survey.balances());
        survey.record_located();
        assert!(survey.balances());
        survey.record_declared();
        survey.record_unlocated(UnlocatedReason::RegisterResident);
        assert!(survey.balances());
        assert_eq!(survey.count(UnlocatedReason::RegisterResident), 1);
        assert_eq!(survey.unmodelled_total(), 0);
        survey.record_declared();
        survey.record_unlocated(UnlocatedReason::UnmodelledExpression);
        assert_eq!(survey.unmodelled_total(), 1);
        assert!(survey.to_string().contains("register_resident=1"));
    }

    #[test]
    fn every_defect_carries_a_distinct_name() {
        let named: [UnlocatedReason; 6] = [
            UnlocatedReason::RegisterResident,
            UnlocatedReason::StackPointerRelative,
            UnlocatedReason::CompositePieces,
            UnlocatedReason::EntryValue,
            UnlocatedReason::PrologueWithoutFramePointer,
            UnlocatedReason::NonIntegerType,
        ];
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for reason in named {
            assert!(seen.insert(reason.as_str()), "duplicate name {reason}");
        }
    }

    #[test]
    fn a_stack_pointer_frame_base_is_refused_as_not_a_frame_pointer() {
        let refusal: core::result::Result<FrameWindow, UnlocatedReason> = frame_window_from_form(
            ExpressionForm::RegisterOffset {
                register: STACK_POINTER_DWARF_REGISTER,
                offset: 16,
            },
            PcRange::new(0, 1),
            PcRange::new(0, 1),
            &[],
            0,
        );
        assert_eq!(refusal, Err(UnlocatedReason::FrameBaseNotFramePointer));
    }

    #[test]
    fn a_frame_pointer_relative_frame_base_keeps_its_offset() {
        let window: FrameWindow = frame_window_from_form(
            ExpressionForm::RegisterOffset {
                register: FRAME_POINTER_DWARF_REGISTER,
                offset: 16,
            },
            PcRange::new(4, 0x53),
            PcRange::new(0, 0x54),
            &[],
            0,
        )
        .expect("a frame-pointer-relative frame base is usable");
        assert_eq!(window.displacement, 16);
        assert_eq!(window.range, PcRange::new(4, 0x53));
    }

    #[test]
    fn slots_are_produced_only_where_a_window_covers_the_variable() {
        let windows: [FrameWindow; 1] = [FrameWindow {
            displacement: 16,
            range: PcRange::new(0x10, 0x40),
        }];
        let mut slots: Vec<FrameSlot> = Vec::new();
        slots_for_offset(&windows, -24, PcRange::new(0x20, 0x80), &mut slots)
            .expect("no overflow for a small displacement");
        assert_eq!(
            slots,
            vec![FrameSlot {
                rbp_disp: -8,
                range: PcRange::new(0x20, 0x40)
            }]
        );
        let mut outside: Vec<FrameSlot> = Vec::new();
        slots_for_offset(&windows, -24, PcRange::new(0x40, 0x80), &mut outside)
            .expect("no overflow for a small displacement");
        assert!(outside.is_empty());
    }

    #[test]
    fn a_hostile_displacement_reports_overflow_rather_than_wrapping() {
        let windows: [FrameWindow; 1] = [FrameWindow {
            displacement: i64::MAX,
            range: PcRange::new(0, 0x40),
        }];
        let mut slots: Vec<FrameSlot> = Vec::new();
        assert_eq!(
            slots_for_offset(&windows, 1, PcRange::new(0, 0x40), &mut slots),
            Err(UnlocatedReason::DisplacementOverflow)
        );
    }
}
