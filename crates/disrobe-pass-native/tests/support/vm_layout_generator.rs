#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;

use disrobe_pass_native::vm_devirt::layout::ContextRole;

pub const DEFAULT_VALUE_STACK_OFFSET: i64 = 8;
pub const DEFAULT_STACK_POINTER_OFFSET: i64 = 16;

const VALUE_STACK_DISPLACEMENT_AT: usize = 3;
const STACK_POINTER_DISPLACEMENT_AT: usize = 7;

const ARITHMETIC_SHIFT_TEMPLATE: [u8; 46] = [
    0x4c, 0x8b, 0x47, 0x08, 0x4c, 0x8b, 0x4f, 0x10, 0x41, 0x8b, 0x09, 0x49, 0x8b, 0x44, 0xc8, 0xf8,
    0x49, 0x8b, 0x54, 0xc8, 0xf0, 0x48, 0x83, 0xe0, 0x3f, 0x49, 0x89, 0xca, 0x48, 0x89, 0xc1, 0x48,
    0xd3, 0xfa, 0x4b, 0x89, 0x54, 0xd0, 0xf0, 0x41, 0xff, 0xca, 0x45, 0x89, 0x11, 0xc3,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedLayout {
    offsets: BTreeMap<ContextRole, i64>,
}

impl GeneratedLayout {
    #[must_use]
    pub fn offset(&self, role: ContextRole) -> i64 {
        self.offsets[&role]
    }

    #[must_use]
    pub fn roles(&self) -> Vec<ContextRole> {
        self.offsets.keys().copied().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitRefusal {
    DisplacementOutOfRange {
        role: ContextRole,
        offset: i64,
    },
    OverlappingOffsets {
        first: ContextRole,
        second: ContextRole,
    },
}

impl std::fmt::Display for EmitRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DisplacementOutOfRange { role, offset } => write!(
                formatter,
                "{} at {offset} needs a wider displacement than this template encodes",
                role.name()
            ),
            Self::OverlappingOffsets { first, second } => write!(
                formatter,
                "{} and {} were assigned the same context offset",
                first.name(),
                second.name()
            ),
        }
    }
}

#[must_use]
pub fn default_layout() -> GeneratedLayout {
    let mut offsets: BTreeMap<ContextRole, i64> = BTreeMap::new();
    offsets.insert(ContextRole::ValueStack, DEFAULT_VALUE_STACK_OFFSET);
    offsets.insert(ContextRole::StackPointer, DEFAULT_STACK_POINTER_OFFSET);
    GeneratedLayout { offsets }
}

#[must_use]
pub fn layout_from_offsets(value_stack: i64, stack_pointer: i64) -> GeneratedLayout {
    let mut offsets: BTreeMap<ContextRole, i64> = BTreeMap::new();
    offsets.insert(ContextRole::ValueStack, value_stack);
    offsets.insert(ContextRole::StackPointer, stack_pointer);
    GeneratedLayout { offsets }
}

#[must_use]
pub fn layout_for_seed(seed: u64) -> GeneratedLayout {
    let mut state: u64 = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x1234_5678);
    let mut draw = |slots: i64| -> i64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % slots as u64) as i64
    };
    let first: i64 = draw(15) * 8;
    let mut second: i64 = draw(15) * 8;
    if second == first {
        second = (first + 8) % 120;
    }
    let mut offsets: BTreeMap<ContextRole, i64> = BTreeMap::new();
    offsets.insert(ContextRole::ValueStack, first);
    offsets.insert(ContextRole::StackPointer, second);
    GeneratedLayout { offsets }
}

pub fn emit_arithmetic_shift_handler(layout: &GeneratedLayout) -> Result<Vec<u8>, EmitRefusal> {
    let value_stack: i64 = layout.offset(ContextRole::ValueStack);
    let stack_pointer: i64 = layout.offset(ContextRole::StackPointer);
    if value_stack == stack_pointer {
        return Err(EmitRefusal::OverlappingOffsets {
            first: ContextRole::ValueStack,
            second: ContextRole::StackPointer,
        });
    }
    let encoded_stack: i8 = displacement(ContextRole::ValueStack, value_stack)?;
    let encoded_pointer: i8 = displacement(ContextRole::StackPointer, stack_pointer)?;
    let mut body: Vec<u8> = ARITHMETIC_SHIFT_TEMPLATE.to_vec();
    body[VALUE_STACK_DISPLACEMENT_AT] = encoded_stack.cast_unsigned();
    body[STACK_POINTER_DISPLACEMENT_AT] = encoded_pointer.cast_unsigned();
    Ok(body)
}

fn displacement(role: ContextRole, offset: i64) -> Result<i8, EmitRefusal> {
    i8::try_from(offset).map_err(|_| EmitRefusal::DisplacementOutOfRange { role, offset })
}
