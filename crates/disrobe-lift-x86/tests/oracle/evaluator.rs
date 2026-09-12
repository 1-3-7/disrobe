use std::collections::{BTreeMap, BTreeSet};

use disrobe_sleigh::pcode::{PcodeOp, Space, Varnode};

use crate::machine::{
    ADJUST_BIT, CARRY_BIT, DIRECTION_BIT, GPR_COUNT, IMAGE_BASE, MachineState, OVERFLOW_BIT,
    PARITY_BIT, SIGN_BIT, ZERO_BIT,
};

const REGISTER_SPACE_BYTES: usize = 0x1600;
const INSTRUCTION_POINTER_OFFSET: u64 = 0x288;
const MAX_VARNODE_BYTES: u32 = 16;
const PARITY_CONTRACT: &str = "x86_parity8_pure_v1";
const UNDEFINED_CONTRACT: &str = "x86_undefined_flag_pure_v1";
const SIGNED_DIVIDE_CONTRACT: &str = "x86_divide_signed_checked_side_effecting_v1";
const UNSIGNED_DIVIDE_CONTRACT: &str = "x86_divide_unsigned_checked_side_effecting_v1";
const BIT_SCAN_FORWARD_CONTRACT: &str = "x86_bsf_result_pure_v1";
const BIT_SCAN_REVERSE_CONTRACT: &str = "x86_bsr_result_pure_v1";
const POPULATION_COUNT_CONTRACT: &str = "x86_popcount_pure_v1";
const TRAILING_ZERO_CONTRACT: &str = "x86_tzcount_pure_v1";
const LEADING_ZERO_CONTRACT: &str = "x86_lzcount_pure_v1";

const FLAG_OFFSETS: [(u64, u32); 7] = [
    (0x200, CARRY_BIT),
    (0x202, PARITY_BIT),
    (0x204, ADJUST_BIT),
    (0x206, ZERO_BIT),
    (0x207, SIGN_BIT),
    (0x20a, DIRECTION_BIT),
    (0x20b, OVERFLOW_BIT),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Evaluation {
    Completed(Box<MachineState>, BTreeSet<u32>),
    Faulted,
    Unmodeled(String),
}

#[derive(Debug)]
struct Interpreter {
    registers: Vec<u8>,
    unique: BTreeMap<u64, u8>,
    memory: Vec<u8>,
    undefined: BTreeSet<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Step {
    Continued,
    Faulted,
    Unmodeled(String),
}

const fn general_register_offset(index: usize) -> u64 {
    if index < 8 {
        (index as u64) * 8
    } else {
        0x80 + ((index as u64) - 8) * 8
    }
}

pub(crate) fn evaluate(
    operations: &[PcodeOp],
    start: &MachineState,
    next_address: u64,
) -> Evaluation {
    let mut interpreter: Interpreter = Interpreter::load(start);
    for operation in operations {
        match interpreter.step(operation) {
            Step::Continued => {}
            Step::Faulted => return Evaluation::Faulted,
            Step::Unmodeled(reason) => return Evaluation::Unmodeled(reason),
        }
    }
    let state: MachineState = interpreter.store(start, next_address);
    Evaluation::Completed(Box::new(state), interpreter.undefined)
}

impl Interpreter {
    fn load(start: &MachineState) -> Self {
        let mut interpreter: Self = Self {
            registers: vec![0; REGISTER_SPACE_BYTES],
            unique: BTreeMap::new(),
            memory: start.memory.clone(),
            undefined: BTreeSet::new(),
        };
        for index in 0..GPR_COUNT {
            let value: u64 = start.registers.get(index).copied().unwrap_or(0);
            interpreter.write_register_space(general_register_offset(index), 8, u128::from(value));
        }
        for (offset, bit) in FLAG_OFFSETS {
            let value: u128 = u128::from(start.flags.checked_shr(bit).unwrap_or(0) & 1);
            interpreter.write_register_space(offset, 1, value);
        }
        interpreter.write_register_space(INSTRUCTION_POINTER_OFFSET, 8, u128::from(start.rip));
        interpreter
    }

    fn store(&self, start: &MachineState, next_address: u64) -> MachineState {
        let mut state: MachineState = MachineState {
            registers: [0; GPR_COUNT],
            rip: next_address,
            flags: 0,
            memory: self.memory.clone(),
        };
        for index in 0..GPR_COUNT {
            let value: u128 = self.read_register_space(general_register_offset(index), 8);
            if let Some(slot) = state.registers.get_mut(index) {
                *slot = value as u64;
            }
        }
        for (offset, bit) in FLAG_OFFSETS {
            if self.read_register_space(offset, 1) & 1 == 1 {
                state.flags |= 1u16.checked_shl(bit).unwrap_or(0);
            }
        }
        let recorded: u64 = self.read_register_space(INSTRUCTION_POINTER_OFFSET, 8) as u64;
        if recorded != start.rip {
            state.rip = recorded;
        }
        state
    }

    fn read_register_space(&self, offset: u64, size_bytes: u32) -> u128 {
        let Ok(start): Result<usize, _> = usize::try_from(offset) else {
            return 0;
        };
        let mut value: u128 = 0;
        for index in 0..size_bytes.min(MAX_VARNODE_BYTES) {
            let byte: u128 = self
                .registers
                .get(start.saturating_add(index as usize))
                .map_or(0, |slot: &u8| u128::from(*slot));
            value |= byte.checked_shl(index.saturating_mul(8)).unwrap_or(0);
        }
        value
    }

    fn write_register_space(&mut self, offset: u64, size_bytes: u32, value: u128) {
        let Ok(start): Result<usize, _> = usize::try_from(offset) else {
            return;
        };
        for index in 0..size_bytes.min(MAX_VARNODE_BYTES) {
            let shifted: u128 = value.checked_shr(index.saturating_mul(8)).unwrap_or(0);
            if let Some(slot) = self.registers.get_mut(start.saturating_add(index as usize)) {
                *slot = shifted as u8;
            }
        }
    }

    fn read(&self, node: Varnode) -> u128 {
        let mask: u128 = width_mask(node.size_bytes);
        match node.space {
            Space::Constant | Space::Ram => u128::from(node.offset) & mask,
            Space::Register => self.read_register_space(node.offset, node.size_bytes) & mask,
            Space::Unique => {
                let mut value: u128 = 0;
                for index in 0..node.size_bytes.min(MAX_VARNODE_BYTES) {
                    let address: u64 = node.offset.wrapping_add(u64::from(index));
                    let byte: u128 = self
                        .unique
                        .get(&address)
                        .map_or(0, |slot: &u8| u128::from(*slot));
                    value |= byte.checked_shl(index.saturating_mul(8)).unwrap_or(0);
                }
                value & mask
            }
        }
    }

    fn write(&mut self, node: Varnode, value: u128) {
        let masked: u128 = value & width_mask(node.size_bytes);
        match node.space {
            Space::Register => {
                if let Some(bit) = flag_bit(node) {
                    let _: bool = self.undefined.remove(&bit);
                }
                self.write_register_space(node.offset, node.size_bytes, masked);
            }
            Space::Unique => {
                for index in 0..node.size_bytes.min(MAX_VARNODE_BYTES) {
                    let address: u64 = node.offset.wrapping_add(u64::from(index));
                    let byte: u8 = masked.checked_shr(index.saturating_mul(8)).unwrap_or(0) as u8;
                    let _: Option<u8> = self.unique.insert(address, byte);
                }
            }
            Space::Constant | Space::Ram => {}
        }
    }

    fn load_memory(&self, address: u64, size_bytes: u32) -> Option<u128> {
        let start: usize = usize::try_from(address.checked_sub(IMAGE_BASE)?).ok()?;
        let end: usize = start.checked_add(size_bytes as usize)?;
        let slice: &[u8] = self.memory.get(start..end)?;
        let mut value: u128 = 0;
        for (index, byte) in slice.iter().enumerate().take(MAX_VARNODE_BYTES as usize) {
            value |= u128::from(*byte)
                .checked_shl((index as u32).saturating_mul(8))
                .unwrap_or(0);
        }
        Some(value)
    }

    fn store_memory(&mut self, address: u64, size_bytes: u32, value: u128) -> bool {
        if address < IMAGE_BASE {
            return false;
        }
        let Ok(start): Result<usize, _> = usize::try_from(address.wrapping_sub(IMAGE_BASE)) else {
            return false;
        };
        let Some(end): Option<usize> = start.checked_add(size_bytes as usize) else {
            return false;
        };
        let Some(slice): Option<&mut [u8]> = self.memory.get_mut(start..end) else {
            return false;
        };
        for (index, byte) in slice.iter_mut().enumerate() {
            *byte = value
                .checked_shr((index as u32).saturating_mul(8))
                .unwrap_or(0) as u8;
        }
        true
    }

    fn step(&mut self, operation: &PcodeOp) -> Step {
        match operation {
            PcodeOp::Copy { output, input } | PcodeOp::IntZext { output, input } => {
                self.assign(*output, self.read(*input))
            }
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => self.assign(*output, self.read(*left).wrapping_add(self.read(*right))),
            PcodeOp::IntSub {
                output,
                left,
                right,
            } => self.assign(*output, self.read(*left).wrapping_sub(self.read(*right))),
            PcodeOp::IntMult {
                output,
                left,
                right,
            } => self.assign(*output, self.read(*left).wrapping_mul(self.read(*right))),
            PcodeOp::IntAnd {
                output,
                left,
                right,
            } => self.assign(*output, self.read(*left) & self.read(*right)),
            PcodeOp::IntOr {
                output,
                left,
                right,
            } => self.assign(*output, self.read(*left) | self.read(*right)),
            PcodeOp::IntXor {
                output,
                left,
                right,
            } => self.assign(*output, self.read(*left) ^ self.read(*right)),
            PcodeOp::IntNegate { output, input } => {
                self.assign(*output, !self.read(*input) & width_mask(output.size_bytes))
            }
            PcodeOp::IntCarry {
                output,
                left,
                right,
            } => {
                let (sum, wrapped): (u128, bool) =
                    self.read(*left).overflowing_add(self.read(*right));
                let carried: bool = wrapped || sum > width_mask(left.size_bytes);
                self.assign(*output, u128::from(carried))
            }
            PcodeOp::IntSignedCarry {
                output,
                left,
                right,
            } => {
                let bits: u32 = bit_width(left.size_bytes);
                if bits > 64 {
                    return Step::Unmodeled("signed carry wider than 64 bits".to_owned());
                }
                let sum: i128 = signed(self.read(*left), bits) + signed(self.read(*right), bits);
                self.assign(*output, u128::from(!fits_signed(sum, bits)))
            }
            PcodeOp::IntSignedBorrow {
                output,
                left,
                right,
            } => {
                let bits: u32 = bit_width(left.size_bytes);
                if bits > 64 {
                    return Step::Unmodeled("signed borrow wider than 64 bits".to_owned());
                }
                let difference: i128 =
                    signed(self.read(*left), bits) - signed(self.read(*right), bits);
                self.assign(*output, u128::from(!fits_signed(difference, bits)))
            }
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => self.assign(*output, u128::from(self.read(*left) == self.read(*right))),
            PcodeOp::IntNotEqual {
                output,
                left,
                right,
            } => self.assign(*output, u128::from(self.read(*left) != self.read(*right))),
            PcodeOp::IntLess {
                output,
                left,
                right,
            } => self.assign(*output, u128::from(self.read(*left) < self.read(*right))),
            PcodeOp::IntLessEqual {
                output,
                left,
                right,
            } => self.assign(*output, u128::from(self.read(*left) <= self.read(*right))),
            PcodeOp::IntSignedLess {
                output,
                left,
                right,
            } => {
                let bits: u32 = bit_width(left.size_bytes);
                let verdict: bool =
                    signed(self.read(*left), bits) < signed(self.read(*right), bits);
                self.assign(*output, u128::from(verdict))
            }
            PcodeOp::IntSignedLessEqual {
                output,
                left,
                right,
            } => {
                let bits: u32 = bit_width(left.size_bytes);
                let verdict: bool =
                    signed(self.read(*left), bits) <= signed(self.read(*right), bits);
                self.assign(*output, u128::from(verdict))
            }
            PcodeOp::IntLeft {
                output,
                input,
                amount,
            } => {
                let shift: u128 = self.read(*amount);
                let value: u128 = self.read(*input);
                let shifted: u128 = if shift >= u128::from(bit_width(input.size_bytes)) {
                    0
                } else {
                    value.checked_shl(shift as u32).unwrap_or(0)
                };
                self.assign(*output, shifted)
            }
            PcodeOp::IntRight {
                output,
                input,
                amount,
            } => {
                let shift: u128 = self.read(*amount);
                let value: u128 = self.read(*input);
                let shifted: u128 = if shift >= u128::from(bit_width(input.size_bytes)) {
                    0
                } else {
                    value.checked_shr(shift as u32).unwrap_or(0)
                };
                self.assign(*output, shifted)
            }
            PcodeOp::IntSignedRight {
                output,
                input,
                amount,
            } => {
                let bits: u32 = bit_width(input.size_bytes);
                let shift: u128 = self.read(*amount).min(u128::from(bits.saturating_sub(1)));
                let value: i128 = signed(self.read(*input), bits);
                let shifted: i128 = value >> shift;
                self.assign(*output, shifted as u128)
            }
            PcodeOp::IntDiv {
                output,
                left,
                right,
            } => {
                let divisor: u128 = self.read(*right);
                if divisor == 0 {
                    return Step::Faulted;
                }
                self.assign(*output, self.read(*left) / divisor)
            }
            PcodeOp::IntRem {
                output,
                left,
                right,
            } => {
                let divisor: u128 = self.read(*right);
                if divisor == 0 {
                    return Step::Faulted;
                }
                self.assign(*output, self.read(*left) % divisor)
            }
            PcodeOp::IntSignedDiv {
                output,
                left,
                right,
            } => {
                let bits: u32 = bit_width(left.size_bytes);
                let divisor: i128 = signed(self.read(*right), bits);
                if divisor == 0 {
                    return Step::Faulted;
                }
                let Some(quotient): Option<i128> =
                    signed(self.read(*left), bits).checked_div(divisor)
                else {
                    return Step::Faulted;
                };
                self.assign(*output, quotient as u128)
            }
            PcodeOp::IntSignedRem {
                output,
                left,
                right,
            } => {
                let bits: u32 = bit_width(left.size_bytes);
                let divisor: i128 = signed(self.read(*right), bits);
                if divisor == 0 {
                    return Step::Faulted;
                }
                let Some(rest): Option<i128> = signed(self.read(*left), bits).checked_rem(divisor)
                else {
                    return Step::Faulted;
                };
                self.assign(*output, rest as u128)
            }
            PcodeOp::IntSext { output, input } => {
                let bits: u32 = bit_width(input.size_bytes);
                self.assign(*output, signed(self.read(*input), bits) as u128)
            }
            PcodeOp::BoolAnd {
                output,
                left,
                right,
            } => {
                let verdict: bool = self.read(*left) != 0 && self.read(*right) != 0;
                self.assign(*output, u128::from(verdict))
            }
            PcodeOp::BoolOr {
                output,
                left,
                right,
            } => {
                let verdict: bool = self.read(*left) != 0 || self.read(*right) != 0;
                self.assign(*output, u128::from(verdict))
            }
            PcodeOp::BoolXor {
                output,
                left,
                right,
            } => {
                let verdict: bool = (self.read(*left) != 0) != (self.read(*right) != 0);
                self.assign(*output, u128::from(verdict))
            }
            PcodeOp::BoolNegate { output, input } => {
                self.assign(*output, u128::from(self.read(*input) == 0))
            }
            PcodeOp::Subpiece {
                output,
                input,
                byte_offset,
            } => {
                let shift: u32 = (self.read(*byte_offset) as u32).saturating_mul(8);
                let value: u128 = self.read(*input).checked_shr(shift).unwrap_or(0);
                self.assign(*output, value)
            }
            PcodeOp::Piece { output, high, low } => {
                let shift: u32 = bit_width(low.size_bytes);
                let combined: u128 = self
                    .read(*high)
                    .checked_shl(shift)
                    .unwrap_or(0)
                    .wrapping_add(self.read(*low));
                self.assign(*output, combined)
            }
            PcodeOp::Load {
                output,
                space,
                pointer,
            } => {
                if *space != Space::Ram {
                    return Step::Unmodeled(format!("load from {space}"));
                }
                let address: u64 = self.read(*pointer) as u64;
                let Some(value): Option<u128> = self.load_memory(address, output.size_bytes) else {
                    return Step::Faulted;
                };
                self.assign(*output, value)
            }
            PcodeOp::Store {
                space,
                pointer,
                value,
            } => {
                if *space != Space::Ram {
                    return Step::Unmodeled(format!("store to {space}"));
                }
                let address: u64 = self.read(*pointer) as u64;
                let payload: u128 = self.read(*value);
                if self.store_memory(address, value.size_bytes, payload) {
                    Step::Continued
                } else {
                    Step::Faulted
                }
            }
            PcodeOp::Branch { target }
            | PcodeOp::Call { target }
            | PcodeOp::BranchIndirect { target }
            | PcodeOp::CallIndirect { target } => {
                self.assign_instruction_pointer(self.read(*target) as u64)
            }
            PcodeOp::CBranch { target, condition } => {
                if self.read(*condition) == 0 {
                    Step::Continued
                } else {
                    self.assign_instruction_pointer(self.read(*target) as u64)
                }
            }
            PcodeOp::Return { target } => target.map_or(Step::Continued, |node: Varnode| {
                self.assign_instruction_pointer(self.read(node) as u64)
            }),
            PcodeOp::CallOther {
                name,
                output,
                inputs,
            } => self.contract(name, *output, inputs),
            PcodeOp::FloatAdd { .. }
            | PcodeOp::FloatDiv { .. }
            | PcodeOp::FloatEqual { .. }
            | PcodeOp::FloatLess { .. }
            | PcodeOp::FloatLessEqual { .. }
            | PcodeOp::FloatMult { .. }
            | PcodeOp::FloatSqrt { .. }
            | PcodeOp::FloatSub { .. }
            | PcodeOp::FloatToFloat { .. }
            | PcodeOp::FloatTrunc { .. }
            | PcodeOp::IntToFloat { .. } => Step::Unmodeled("floating point".to_owned()),
        }
    }

    fn assign(&mut self, output: Varnode, value: u128) -> Step {
        self.write(output, value);
        Step::Continued
    }

    fn assign_instruction_pointer(&mut self, value: u64) -> Step {
        self.write_register_space(INSTRUCTION_POINTER_OFFSET, 8, u128::from(value));
        Step::Continued
    }

    fn contract(&mut self, name: &str, output: Option<Varnode>, inputs: &[Varnode]) -> Step {
        match name {
            PARITY_CONTRACT => {
                let Some(target): Option<Varnode> = output else {
                    return Step::Unmodeled("parity without an output".to_owned());
                };
                let value: u128 = inputs.first().map_or(0, |node: &Varnode| self.read(*node));
                let parity: bool = (value & 0xff).count_ones().is_multiple_of(2);
                self.assign(target, u128::from(parity))
            }
            UNDEFINED_CONTRACT => {
                let Some(target): Option<Varnode> = output else {
                    return Step::Unmodeled("undefined flag without an output".to_owned());
                };
                let Some(bit): Option<u32> = flag_bit(target) else {
                    return Step::Unmodeled("undefined flag outside the tracked set".to_owned());
                };
                let _: bool = self.undefined.insert(bit);
                Step::Continued
            }
            SIGNED_DIVIDE_CONTRACT | UNSIGNED_DIVIDE_CONTRACT => {
                self.divide(name == SIGNED_DIVIDE_CONTRACT, output, inputs)
            }
            BIT_SCAN_FORWARD_CONTRACT
            | BIT_SCAN_REVERSE_CONTRACT
            | POPULATION_COUNT_CONTRACT
            | TRAILING_ZERO_CONTRACT
            | LEADING_ZERO_CONTRACT => self.scan(name, output, inputs),
            other => Step::Unmodeled(other.to_owned()),
        }
    }

    fn scan(&mut self, name: &str, output: Option<Varnode>, inputs: &[Varnode]) -> Step {
        let (Some(target), [source]) = (output, inputs) else {
            return Step::Unmodeled(format!("{name} reached through an opaque operand"));
        };
        let bits: u32 = bit_width(source.size_bytes);
        let value: u128 = self.read(*source);
        let empty: bool = value == 0;
        let scanned: u128 = if empty {
            match name {
                POPULATION_COUNT_CONTRACT => 0,
                _ => u128::from(bits),
            }
        } else {
            match name {
                POPULATION_COUNT_CONTRACT => u128::from(value.count_ones()),
                BIT_SCAN_FORWARD_CONTRACT | TRAILING_ZERO_CONTRACT => {
                    u128::from(value.trailing_zeros())
                }
                BIT_SCAN_REVERSE_CONTRACT => {
                    u128::from(127u32.saturating_sub(value.leading_zeros()))
                }
                _ => u128::from(
                    value
                        .leading_zeros()
                        .saturating_sub(128u32.saturating_sub(bits)),
                ),
            }
        };
        if let Some(bit) = flag_bit(target) {
            let raised: bool = match bit {
                ZERO_BIT if matches!(name, TRAILING_ZERO_CONTRACT | LEADING_ZERO_CONTRACT) => {
                    scanned == 0
                }
                ZERO_BIT | CARRY_BIT => empty,
                other => return Step::Unmodeled(format!("{name} writing flag {other}")),
            };
            return self.assign(target, u128::from(raised));
        }
        if empty && matches!(name, BIT_SCAN_FORWARD_CONTRACT | BIT_SCAN_REVERSE_CONTRACT) {
            return Step::Unmodeled(
                "a bit scan over a zero source leaves the destination undefined".to_owned(),
            );
        }
        self.assign(target, scanned)
    }

    fn divide(
        &mut self,
        signed_division: bool,
        output: Option<Varnode>,
        inputs: &[Varnode],
    ) -> Step {
        let (Some(target), Some(high), Some(low), Some(divisor), Some(selector)) = (
            output,
            inputs.first(),
            inputs.get(1),
            inputs.get(2),
            inputs.get(3),
        ) else {
            return Step::Unmodeled("divide contract shape".to_owned());
        };
        let bits: u32 = bit_width(low.size_bytes);
        let dividend: u128 = (self.read(*high).checked_shl(bits).unwrap_or(0)) | self.read(*low);
        let raw_divisor: u128 = self.read(*divisor);
        let remainder_wanted: bool = self.read(*selector) != 0;
        let produced: Option<u128> = if signed_division {
            signed_divide(dividend, raw_divisor, bits, remainder_wanted)
        } else {
            unsigned_divide(dividend, raw_divisor, bits, remainder_wanted)
        };
        let Some(value): Option<u128> = produced else {
            return Step::Faulted;
        };
        self.assign(target, value)
    }
}

const fn unsigned_divide(
    dividend: u128,
    divisor: u128,
    bits: u32,
    remainder: bool,
) -> Option<u128> {
    if divisor == 0 {
        return None;
    }
    let quotient: u128 = dividend / divisor;
    if quotient > width_mask_bits(bits) {
        return None;
    }
    if remainder {
        Some(dividend % divisor)
    } else {
        Some(quotient)
    }
}

fn signed_divide(dividend: u128, divisor: u128, bits: u32, remainder: bool) -> Option<u128> {
    let wide_bits: u32 = bits.checked_mul(2)?;
    let signed_dividend: i128 = signed(dividend, wide_bits);
    let signed_divisor: i128 = signed(divisor, bits);
    if signed_divisor == 0 {
        return None;
    }
    let quotient: i128 = signed_dividend.checked_div(signed_divisor)?;
    let boundary: i128 = 1i128.checked_shl(bits.checked_sub(1)?)?;
    if quotient < -boundary || quotient >= boundary {
        return None;
    }
    if remainder {
        let rest: i128 = signed_dividend.checked_rem(signed_divisor)?;
        Some((rest as u128) & width_mask_bits(bits))
    } else {
        Some((quotient as u128) & width_mask_bits(bits))
    }
}

fn flag_bit(node: Varnode) -> Option<u32> {
    if node.space != Space::Register || node.size_bytes != 1 {
        return None;
    }
    FLAG_OFFSETS
        .iter()
        .find(|(offset, _): &&(u64, u32)| *offset == node.offset)
        .map(|(_, bit): &(u64, u32)| *bit)
}

const fn bit_width(size_bytes: u32) -> u32 {
    if size_bytes >= MAX_VARNODE_BYTES {
        128
    } else {
        size_bytes * 8
    }
}

const fn width_mask(size_bytes: u32) -> u128 {
    width_mask_bits(bit_width(size_bytes))
}

const fn width_mask_bits(bits: u32) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        match 1u128.checked_shl(bits) {
            Some(value) => value - 1,
            None => u128::MAX,
        }
    }
}

fn signed(value: u128, bits: u32) -> i128 {
    let masked: u128 = value & width_mask_bits(bits);
    if bits >= 128 {
        return masked as i128;
    }
    let boundary: u128 = 1u128.checked_shl(bits.saturating_sub(1)).unwrap_or(0);
    if masked & boundary == 0 {
        masked as i128
    } else {
        (masked as i128).wrapping_sub(1i128.checked_shl(bits).unwrap_or(0))
    }
}

const fn fits_signed(value: i128, bits: u32) -> bool {
    let Some(boundary): Option<i128> = 1i128.checked_shl(bits.saturating_sub(1)) else {
        return true;
    };
    value >= -boundary && value < boundary
}
