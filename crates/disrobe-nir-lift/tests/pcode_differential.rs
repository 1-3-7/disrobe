#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use disrobe_nir::{NirFunction, NirInstr, NirOp, SourceLang, ValueOp};
use disrobe_nir_lift::{PcodeLiftConfig, RegisterCell, lower_pcode_block};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

const fn node(space: Space, offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space,
    }
}

fn program() -> Vec<PcodeOp> {
    let rax: Varnode = node(Space::Register, 0, 8);
    let rcx: Varnode = node(Space::Register, 8, 8);
    let cf: Varnode = node(Space::Register, 0x200, 1);
    let of: Varnode = node(Space::Register, 0x20b, 1);
    let zf: Varnode = node(Space::Register, 0x206, 1);
    let sum: Varnode = node(Space::Unique, 0, 8);
    let mixed: Varnode = node(Space::Unique, 8, 8);
    let difference: Varnode = node(Space::Unique, 16, 8);
    let shifted_left: Varnode = node(Space::Unique, 24, 8);
    let shifted_right: Varnode = node(Space::Unique, 32, 8);
    let masked: Varnode = node(Space::Unique, 40, 8);
    let fragment: Varnode = node(Space::Unique, 48, 4);
    let widened: Varnode = node(Space::Unique, 56, 8);
    let joined: Varnode = node(Space::Unique, 64, 8);
    let loaded: Varnode = node(Space::Unique, 72, 4);
    let stored: Varnode = node(Space::Unique, 80, 4);
    vec![
        PcodeOp::IntAdd {
            output: sum,
            left: rax,
            right: rcx,
        },
        PcodeOp::IntCarry {
            output: cf,
            left: rax,
            right: rcx,
        },
        PcodeOp::IntSignedCarry {
            output: of,
            left: rax,
            right: rcx,
        },
        PcodeOp::IntXor {
            output: mixed,
            left: sum,
            right: node(Space::Constant, 0xa5a5_3c3c_f0f0_9696, 8),
        },
        PcodeOp::IntSub {
            output: difference,
            left: mixed,
            right: rcx,
        },
        PcodeOp::IntLeft {
            output: shifted_left,
            input: difference,
            amount: node(Space::Constant, 7, 4),
        },
        PcodeOp::IntRight {
            output: shifted_right,
            input: shifted_left,
            amount: node(Space::Constant, 3, 4),
        },
        PcodeOp::IntAnd {
            output: masked,
            left: shifted_right,
            right: node(Space::Constant, 0xffff_ffff_00ff_ff00, 8),
        },
        PcodeOp::Subpiece {
            output: fragment,
            input: masked,
            byte_offset: node(Space::Constant, 2, 4),
        },
        PcodeOp::IntZext {
            output: widened,
            input: fragment,
        },
        PcodeOp::IntEqual {
            output: zf,
            left: widened,
            right: node(Space::Constant, 0, 8),
        },
        PcodeOp::Piece {
            output: joined,
            high: fragment,
            low: node(Space::Constant, 0x1122_3344, 4),
        },
        PcodeOp::Load {
            output: loaded,
            space: Space::Ram,
            pointer: node(Space::Constant, 0x90, 8),
        },
        PcodeOp::IntXor {
            output: stored,
            left: loaded,
            right: fragment,
        },
        PcodeOp::Store {
            space: Space::Ram,
            pointer: node(Space::Constant, 0x80, 8),
            value: stored,
        },
        PcodeOp::Copy {
            output: node(Space::Register, 0, 4),
            input: stored,
        },
        PcodeOp::IntZext {
            output: rax,
            input: node(Space::Register, 0, 4),
        },
        PcodeOp::Copy {
            output: node(Space::Register, 9, 1),
            input: cf,
        },
        PcodeOp::Copy {
            output: node(Space::Register, 0x288, 8),
            input: joined,
        },
    ]
}

fn decoded(operations: &[PcodeOp]) -> DecodedBlock {
    let instruction: PcodeInstr = PcodeInstr {
        address: 0x1000,
        bytes: vec![0x90],
        length: 1,
        mnemonic: "differential".to_owned(),
        ops: operations.to_vec(),
        operands: String::new(),
        status: DecodeStatus::Supported,
    };
    DecodedBlock {
        consumed: 1,
        instructions: vec![instruction],
        ordered_ops: operations.to_vec(),
    }
}

#[derive(Clone, Debug, Default)]
struct PcodeState {
    bytes: BTreeMap<(Space, u64), u8>,
}

impl PcodeState {
    fn read(&self, value: Varnode) -> u64 {
        if value.space == Space::Constant {
            return pcode_truncate(value.offset, value.size_bytes);
        }
        let mut result: u64 = 0;
        for index in 0..value.size_bytes {
            let address: u64 = value.offset.saturating_add(u64::from(index));
            let byte: u64 = u64::from(
                self.bytes
                    .get(&(value.space, address))
                    .copied()
                    .unwrap_or(0),
            );
            result |= byte.checked_shl(index.saturating_mul(8)).unwrap_or(0);
        }
        result
    }

    fn write(&mut self, value: Varnode, result: u64) {
        for index in 0..value.size_bytes {
            let shift: u32 = index.saturating_mul(8);
            let byte: u8 =
                u8::try_from(result.checked_shr(shift).unwrap_or(0) & 0xff).expect("masked byte");
            let address: u64 = value.offset.saturating_add(u64::from(index));
            self.bytes.insert((value.space, address), byte);
        }
    }

    fn read_memory(&self, address: u64, size: u32) -> u64 {
        self.read(node(Space::Ram, address, size))
    }

    fn write_memory(&mut self, address: u64, size: u32, value: u64) {
        self.write(node(Space::Ram, address, size), value);
    }
}

fn execute_pcode(operations: &[PcodeOp], state: &mut PcodeState) {
    for operation in operations {
        match operation {
            PcodeOp::Copy { output, input } => {
                let result: u64 = state.read(*input);
                state.write(*output, result);
            }
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => {
                let result: u64 = state.read(*left).wrapping_add(state.read(*right));
                state.write(*output, pcode_truncate(result, output.size_bytes));
            }
            PcodeOp::IntSub {
                output,
                left,
                right,
            } => {
                let result: u64 = state.read(*left).wrapping_sub(state.read(*right));
                state.write(*output, pcode_truncate(result, output.size_bytes));
            }
            PcodeOp::IntAnd {
                output,
                left,
                right,
            } => state.write(*output, state.read(*left) & state.read(*right)),
            PcodeOp::IntXor {
                output,
                left,
                right,
            } => state.write(*output, state.read(*left) ^ state.read(*right)),
            PcodeOp::IntLeft {
                output,
                input,
                amount,
            } => {
                let bits: u32 = output.size_bytes.saturating_mul(8);
                let shift: u32 = u32::try_from(state.read(*amount)).unwrap_or(u32::MAX);
                let result: u64 = if shift >= bits {
                    0
                } else {
                    state.read(*input).checked_shl(shift).unwrap_or(0)
                };
                state.write(*output, pcode_truncate(result, output.size_bytes));
            }
            PcodeOp::IntRight {
                output,
                input,
                amount,
            } => {
                let bits: u32 = output.size_bytes.saturating_mul(8);
                let shift: u32 = u32::try_from(state.read(*amount)).unwrap_or(u32::MAX);
                let result: u64 = if shift >= bits {
                    0
                } else {
                    state.read(*input).checked_shr(shift).unwrap_or(0)
                };
                state.write(*output, result);
            }
            PcodeOp::IntCarry {
                output,
                left,
                right,
            } => {
                let bits: u32 = left.size_bytes.saturating_mul(8);
                let result: u128 = u128::from(state.read(*left)) + u128::from(state.read(*right));
                let carry: u64 = u64::from(result.checked_shr(bits).unwrap_or(0) != 0);
                state.write(*output, carry);
            }
            PcodeOp::IntSignedCarry {
                output,
                left,
                right,
            } => {
                let lhs: i128 = pcode_signed_value(state.read(*left), left.size_bytes);
                let rhs: i128 = pcode_signed_value(state.read(*right), right.size_bytes);
                let sum: i128 = lhs.saturating_add(rhs);
                let (minimum, maximum): (i128, i128) = pcode_signed_bounds(left.size_bytes);
                state.write(*output, u64::from(sum < minimum || sum > maximum));
            }
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => state.write(*output, u64::from(state.read(*left) == state.read(*right))),
            PcodeOp::IntZext { output, input } => state.write(*output, state.read(*input)),
            PcodeOp::Subpiece {
                output,
                input,
                byte_offset,
            } => {
                let shift: u32 = u32::try_from(state.read(*byte_offset))
                    .unwrap_or(u32::MAX)
                    .saturating_mul(8);
                let result: u64 = state.read(*input).checked_shr(shift).unwrap_or(0);
                state.write(*output, pcode_truncate(result, output.size_bytes));
            }
            PcodeOp::Piece { output, high, low } => {
                let shift: u32 = low.size_bytes.saturating_mul(8);
                let result: u64 =
                    state.read(*high).checked_shl(shift).unwrap_or(0) | state.read(*low);
                state.write(*output, pcode_truncate(result, output.size_bytes));
            }
            PcodeOp::Load {
                output,
                space,
                pointer,
            } => {
                assert_eq!(*space, Space::Ram);
                let result: u64 = state.read_memory(state.read(*pointer), output.size_bytes);
                state.write(*output, result);
            }
            PcodeOp::Store {
                space,
                pointer,
                value,
            } => {
                assert_eq!(*space, Space::Ram);
                state.write_memory(state.read(*pointer), value.size_bytes, state.read(*value));
            }
            unsupported => panic!("unexpected p-code in differential program: {unsupported:?}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct NirState {
    values: BTreeMap<String, (u64, u32)>,
    memory: BTreeMap<u64, u8>,
}

impl NirState {
    fn value(&self, text: &str) -> u64 {
        if let Some(hex) = text.strip_prefix("0x") {
            return u64::from_str_radix(hex, 16).expect("valid lowered constant");
        }
        self.values
            .get(text)
            .map_or(0, |entry: &(u64, u32)| entry.0)
    }

    fn assign(&mut self, name: &str, value: u64, size: u32) {
        self.values
            .insert(name.to_owned(), (nir_truncate(value, size), size));
    }

    fn load(&self, address: u64, size: u32) -> u64 {
        let mut result: u64 = 0;
        for index in 0..size {
            let byte: u64 = u64::from(
                self.memory
                    .get(&address.saturating_add(u64::from(index)))
                    .copied()
                    .unwrap_or(0),
            );
            result |= byte.checked_shl(index.saturating_mul(8)).unwrap_or(0);
        }
        result
    }

    fn store(&mut self, address: u64, size: u32, value: u64) {
        for index in 0..size {
            let shift: u32 = index.saturating_mul(8);
            let byte: u8 =
                u8::try_from(value.checked_shr(shift).unwrap_or(0) & 0xff).expect("masked byte");
            self.memory
                .insert(address.saturating_add(u64::from(index)), byte);
        }
    }
}

fn execute_nir(function: &NirFunction, state: &mut NirState) {
    for instruction in &function.instructions {
        execute_nir_instruction(instruction, state);
    }
}

fn execute_nir_instruction(instruction: &NirInstr, state: &mut NirState) {
    match &instruction.op {
        NirOp::Copy { src, size } => {
            let destination: &str = destination(instruction);
            state.assign(destination, state.value(src), *size);
        }
        NirOp::Value {
            op,
            inputs,
            input_sizes,
            size,
        } => {
            let destination: &str = destination(instruction);
            let result: u64 = evaluate_nir_value(*op, inputs, input_sizes, *size, state);
            state.assign(destination, result, *size);
        }
        NirOp::RawLoad { addr, size } => {
            let destination: &str = destination(instruction);
            state.assign(destination, state.load(state.value(addr), *size), *size);
        }
        NirOp::RawStore { addr, value, size } => {
            state.store(state.value(addr), *size, state.value(value));
        }
        NirOp::Subpiece { src, offset, size } => {
            let destination: &str = destination(instruction);
            let shift: u32 = offset.saturating_mul(8);
            let result: u64 = state.value(src).checked_shr(shift).unwrap_or(0);
            state.assign(destination, result, *size);
        }
        NirOp::Piece {
            high,
            low,
            low_size,
            size,
            ..
        } => {
            let destination: &str = destination(instruction);
            let result: u64 = state
                .value(high)
                .checked_shl(low_size.saturating_mul(8))
                .unwrap_or(0)
                | state.value(low);
            state.assign(destination, result, *size);
        }
        NirOp::Deposit {
            cell,
            value,
            offset,
            size,
            cell_size,
            zero_upper,
        } => {
            let shift: u32 = offset.saturating_mul(8);
            let fragment_mask: u64 = nir_mask(*size).checked_shl(shift).unwrap_or(0);
            let inserted: u64 = state.value(value).checked_shl(shift).unwrap_or(0) & fragment_mask;
            let retained: u64 = if *zero_upper {
                0
            } else {
                state.value(cell) & !fragment_mask
            };
            state.assign(cell, retained | inserted, *cell_size);
        }
        NirOp::Nop
        | NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Store
        | NirOp::Call { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. }
        | NirOp::IndirectCall
        | NirOp::ExternCall { .. }
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Phi
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::Unmodeled { .. }
        | NirOp::CallOther { .. } => {}
    }
}

fn evaluate_nir_value(
    op: ValueOp,
    inputs: &[String],
    input_sizes: &[u32],
    size: u32,
    state: &NirState,
) -> u64 {
    let first: u64 = inputs
        .first()
        .map_or(0, |value: &String| state.value(value));
    let second: u64 = inputs.get(1).map_or(0, |value: &String| state.value(value));
    match op {
        ValueOp::IntAdd => nir_truncate(first.wrapping_add(second), size),
        ValueOp::IntSub => nir_truncate(first.wrapping_sub(second), size),
        ValueOp::IntAnd => first & second,
        ValueOp::IntXor => first ^ second,
        ValueOp::IntLeft => {
            let width: u32 = size.saturating_mul(8);
            let amount: u32 = u32::try_from(second).unwrap_or(u32::MAX);
            if amount < width {
                nir_truncate(first.checked_shl(amount).unwrap_or(0), size)
            } else {
                0
            }
        }
        ValueOp::IntRight => {
            let width: u32 = size.saturating_mul(8);
            let amount: u32 = u32::try_from(second).unwrap_or(u32::MAX);
            if amount < width {
                first.checked_shr(amount).unwrap_or(0)
            } else {
                0
            }
        }
        ValueOp::IntCarry => {
            let width: u32 = input_sizes.first().copied().unwrap_or(0).saturating_mul(8);
            let wide: u128 = u128::from(first).wrapping_add(u128::from(second));
            u64::from(wide & (u128::from(1_u64).checked_shl(width).unwrap_or(0)) != 0)
        }
        ValueOp::IntSignedCarry => {
            let input_size: u32 = input_sizes.first().copied().unwrap_or(0);
            let sign: u64 = 1_u64
                .checked_shl(input_size.saturating_mul(8).saturating_sub(1))
                .unwrap_or(0);
            let result: u64 = nir_truncate(first.wrapping_add(second), input_size);
            u64::from(((first ^ result) & (second ^ result) & sign) != 0)
        }
        ValueOp::IntEqual => u64::from(first == second),
        ValueOp::IntZext => nir_truncate(first, size),
        unsupported => panic!("unexpected lowered value operation: {unsupported:?}"),
    }
}

fn destination(instruction: &NirInstr) -> &str {
    instruction
        .operands
        .first()
        .map(String::as_str)
        .expect("lowered definition has destination")
}

const fn nir_mask(size: u32) -> u64 {
    let bits: u32 = size.saturating_mul(8);
    if bits >= 64 {
        u64::MAX
    } else {
        match 1_u64.checked_shl(bits) {
            Some(value) => value.saturating_sub(1),
            None => 0,
        }
    }
}

const fn nir_truncate(value: u64, size: u32) -> u64 {
    value & nir_mask(size)
}

fn pcode_truncate(value: u64, size: u32) -> u64 {
    let bits: u32 = size.saturating_mul(8);
    let wide_mask: u128 = if bits >= 64 {
        u128::from(u64::MAX)
    } else {
        u128::from(1_u8)
            .checked_shl(bits)
            .unwrap_or(0)
            .saturating_sub(1)
    };
    let narrowed: u64 = u64::try_from(wide_mask).unwrap_or(u64::MAX);
    value & narrowed
}

fn pcode_signed_value(value: u64, size: u32) -> i128 {
    let bits: u32 = size.saturating_mul(8);
    let sign: u64 = 1_u64.checked_shl(bits.saturating_sub(1)).unwrap_or(0);
    if value & sign == 0 {
        i128::from(value)
    } else {
        i128::from(value) - i128::from(1_u64).checked_shl(bits).unwrap_or(0)
    }
}

fn pcode_signed_bounds(size: u32) -> (i128, i128) {
    let shift: u32 = size.saturating_mul(8).saturating_sub(1);
    let magnitude: i128 = i128::from(1_u8).checked_shl(shift).unwrap_or(0);
    (magnitude.saturating_neg(), magnitude.saturating_sub(1))
}

fn next_random(state: &mut u64) -> u64 {
    let mut value: u64 = *state;
    value ^= value.checked_shl(13).unwrap_or(0);
    value ^= value.checked_shr(7).unwrap_or(0);
    value ^= value.checked_shl(17).unwrap_or(0);
    *state = value;
    value
}

#[test]
fn lowered_nir_matches_independent_pcode_semantics_on_random_states() {
    let operations: Vec<PcodeOp> = program();
    let config: PcodeLiftConfig = PcodeLiftConfig::new(
        SourceLang::NativeX86,
        vec![
            RegisterCell::new(0, 8, "rax", None),
            RegisterCell::new(8, 8, "rcx", Some(4)),
            RegisterCell::new(0x200, 1, "cf", None),
            RegisterCell::new(0x206, 1, "zf", None),
            RegisterCell::new(0x20b, 1, "of", None),
            RegisterCell::new(0x288, 8, "rip", None),
        ],
    );
    let lowered: NirFunction =
        lower_pcode_block(&decoded(&operations), "differential", &config).expect("lower program");
    let mut random: u64 = 0x6a09_e667_f3bc_c909;
    for iteration in 0_u32..4096 {
        let initial_rax: u64 = next_random(&mut random);
        let initial_rcx: u64 = next_random(&mut random);
        let initial_memory: u64 = next_random(&mut random);
        let mut pcode: PcodeState = PcodeState::default();
        pcode.write(node(Space::Register, 0, 8), initial_rax);
        pcode.write(node(Space::Register, 8, 8), initial_rcx);
        pcode.write_memory(0x90, 8, initial_memory);
        let mut nir: NirState = NirState::default();
        nir.assign("rax", initial_rax, 8);
        nir.assign("rcx", initial_rcx, 8);
        nir.assign("cf", 0, 1);
        nir.assign("zf", 0, 1);
        nir.assign("of", 0, 1);
        nir.assign("rip", 0, 8);
        nir.store(0x90, 8, initial_memory);
        execute_pcode(&operations, &mut pcode);
        execute_nir(&lowered, &mut nir);
        for (register, varnode) in [
            ("rax", node(Space::Register, 0, 8)),
            ("rcx", node(Space::Register, 8, 8)),
            ("cf", node(Space::Register, 0x200, 1)),
            ("zf", node(Space::Register, 0x206, 1)),
            ("of", node(Space::Register, 0x20b, 1)),
            ("rip", node(Space::Register, 0x288, 8)),
        ] {
            assert_eq!(
                nir.value(register),
                pcode.read(varnode),
                "register mismatch at iteration {iteration}: {register}"
            );
        }
        for address in 0x80_u64..0x98 {
            assert_eq!(
                nir.memory.get(&address).copied().unwrap_or(0),
                pcode
                    .bytes
                    .get(&(Space::Ram, address))
                    .copied()
                    .unwrap_or(0),
                "memory mismatch at iteration {iteration}, address {address:#x}"
            );
        }
    }
}
