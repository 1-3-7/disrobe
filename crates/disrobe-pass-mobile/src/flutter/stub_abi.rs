use std::collections::{BTreeMap, BTreeSet};

use super::aot_lift::{add_imm, ldr_imm_unsigned, movk, movz};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DartStubInput {
    Integer(u8),
    Float(u8),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DartStubInputs {
    by_target: BTreeMap<u64, Vec<DartStubInput>>,
}

impl DartStubInputs {
    pub(super) fn classify(image: &[u8], targets: &BTreeSet<u64>) -> Self {
        let code: StubCode<'_> = StubCode { image };
        let by_target: BTreeMap<u64, Vec<DartStubInput>> = targets
            .iter()
            .filter_map(|target: &u64| code.inputs(*target).map(|inputs| (*target, inputs)))
            .collect::<BTreeMap<u64, Vec<DartStubInput>>>();
        Self { by_target }
    }

    pub(super) fn inputs(&self, target: u64) -> Option<&[DartStubInput]> {
        self.by_target
            .get(&target)
            .map(|inputs: &Vec<DartStubInput>| inputs.as_slice())
    }
}

const SP_REG: u8 = 15;

const FP_REG: u8 = 29;

const LR_REG: u8 = 30;

const THR_REG: u8 = 26;

const PP_REG: u8 = 27;

const NULL_REG: u8 = 22;

const CODE_REG: u8 = 24;

const ZERO_REG: u8 = 31;

const RUNTIME_ENTRY_REG: u8 = 5;

const RUNTIME_ARGUMENT_COUNT_REG: u8 = 4;

const WRITE_BARRIER_OBJECT_REG: u8 = 1;

const WRITE_BARRIER_VALUE_REG: u8 = 0;

const ALLOCATE_TAGS_REG: u8 = 2;

const ALLOCATE_TYPE_ARGUMENTS_REG: u8 = 1;

const SUSPEND_ARGUMENT_REG: u8 = 0;

const SUSPEND_TYPE_ARGUMENTS_REG: u8 = 1;

const SUSPEND_FRAME_SIZE_REG: u8 = 2;

const SUSPEND_STATE_REG: u8 = 3;

const TYPED_DATA_LENGTH_REG: u8 = 4;

const TYPED_DATA_SIZE_REG: u8 = 2;

const DART_RESERVED_CPU_REGISTERS: u32 = (1 << SP_REG)
    | (1 << FP_REG)
    | (1 << 16)
    | (1 << 17)
    | (1 << PP_REG)
    | (1 << THR_REG)
    | (1 << LR_REG)
    | (1 << 28)
    | (1 << NULL_REG)
    | (1 << ZERO_REG)
    | (1 << 18)
    | (1 << 21);

const PUSH_WORD_MASK: u32 = 0xFFFF_FFE0;

const PUSH_WORD: u32 = 0xF81F_8DE0;

const PUSH_PAIR_MASK: u32 = 0xFFFF_83E0;

const PUSH_X_PAIR: u32 = 0xA9BF_01E0;

const PUSH_Q_PAIR: u32 = 0xADBF_01E0;

const ENTER_FRAME: [u32; 2] = [0xA9BF_79FD, 0xAA0F_03FD];

const LEAVE_FRAME: [u32; 2] = [0xAA1D_03EF, 0xA8C1_79FD];

const CALL_LR: u32 = 0xD63F_03C0;

const RETURN: u32 = 0xD65F_03C0;

const MOV_FRAME_SIZE_FROM_FP: u32 = 0xAA1D_03E2;

const SUB_SP_FROM_FRAME_SIZE: u32 = 0xCB0F_0042;

const TRY_ALLOCATE_MASK: u32 = 0xFFC0_7FFF;

const TRY_ALLOCATE_RESULT_TEMP: u32 = 0xA940_0740;

const BRANCH_IF_NOT_SMI_MASK: u32 = 0xFFF8_001F;

const BRANCH_IF_TYPED_DATA_LENGTH_NOT_SMI: u32 = 0x3700_0000 | TYPED_DATA_SIZE_REG as u32;

const FLOAT_STORE_FORMS: [(u32, u32); 4] = [
    (0xFFC0_0000, 0xFD00_0000),
    (0xFFC0_0000, 0x3D80_0000),
    (0xFFE0_0C00, 0xFC00_0000),
    (0xFFE0_0C00, 0x3C80_0000),
];

const MAX_REGISTER_SAVES: usize = 32;

const MAX_STUB_ARGUMENT_STEPS: usize = 16;

const MAX_ALLOCATOR_WORDS: usize = 64;

const MAX_TAG_WORDS: usize = 4;

const TRY_ALLOCATE_BRANCH_INDEX: u64 = 3;

struct StubCode<'a> {
    image: &'a [u8],
}

#[derive(Debug, Default)]
struct StubFrame {
    pushes: Vec<u8>,
    floats: Vec<u8>,
    written: BTreeSet<u8>,
}

impl StubCode<'_> {
    fn word(&self, address: u64) -> Option<u32> {
        let start: usize = usize::try_from(address).ok()?;
        let end: usize = start.checked_add(4)?;
        let bytes: &[u8] = self.image.get(start..end)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn word_at(&self, address: u64, index: u64) -> Option<u32> {
        self.word(address.checked_add(index.checked_mul(4)?)?)
    }

    fn inputs(&self, target: u64) -> Option<Vec<DartStubInput>> {
        self.write_barrier_wrapper(target)
            .or_else(|| self.allocation_stub_for_class(target))
            .or_else(|| self.inline_allocation_stub(target))
            .or_else(|| self.suspend_stub(target))
            .or_else(|| self.runtime_call_stub(target))
    }

    fn write_barrier_wrapper(&self, target: u64) -> Option<Vec<DartStubInput>> {
        if self.word_at(target, 0)? != PUSH_WORD | u32::from(LR_REG)
            || self.word_at(target, 1)? != PUSH_WORD | u32::from(WRITE_BARRIER_OBJECT_REG)
        {
            return None;
        }
        let (destination, object): (u8, u8) = mov_register(self.word_at(target, 2)?)?;
        if destination != WRITE_BARRIER_OBJECT_REG || !is_dart_available(object) {
            return None;
        }
        if !loads_thread_entry(self.word_at(target, 3)?, LR_REG)
            || self.word_at(target, 4)? != CALL_LR
        {
            return None;
        }
        Some(vec![
            DartStubInput::Integer(object),
            DartStubInput::Integer(WRITE_BARRIER_VALUE_REG),
        ])
    }

    fn allocation_stub_for_class(&self, target: u64) -> Option<Vec<DartStubInput>> {
        let (tags, _): (u8, u64) = movz(self.word_at(target, 0)?)?;
        if tags != ALLOCATE_TAGS_REG {
            return None;
        }
        let mut index: u64 = 1;
        while matches!(
            movk(self.word_at(target, index)?),
            Some((ALLOCATE_TAGS_REG, _, _))
        ) {
            index += 1;
            if index > MAX_TAG_WORDS as u64 {
                return None;
            }
        }
        let at: u64 = target.checked_add(index * 4)?;
        let raw: u32 = self.word(at)?;
        if let Some(helper) = branch_target(raw, at) {
            return self.allocate_object_helper_inputs(helper);
        }
        if mov_register(raw)? != (ALLOCATE_TYPE_ARGUMENTS_REG, NULL_REG) {
            return None;
        }
        let (entry, base, _): (u8, u8, u64) = ldr_imm_unsigned(self.word_at(at, 1)?)?;
        (base == THR_REG && indirect_branch_register(self.word_at(at, 2)?) == Some(entry))
            .then(Vec::new)
    }

    fn allocate_object_helper_inputs(&self, helper: u64) -> Option<Vec<DartStubInput>> {
        for index in 2..MAX_ALLOCATOR_WORDS as u64 {
            let Some(register) = indirect_branch_register(self.word_at(helper, index)?) else {
                continue;
            };
            if !loads_thread_entry(self.word_at(helper, index - 1)?, register) {
                return None;
            }
            let before: u32 = self.word_at(helper, index - 2)?;
            if before == RETURN {
                return Some(vec![DartStubInput::Integer(ALLOCATE_TYPE_ARGUMENTS_REG)]);
            }
            return (mov_register(before)? == (ALLOCATE_TYPE_ARGUMENTS_REG, NULL_REG))
                .then(Vec::new);
        }
        None
    }

    fn inline_allocation_stub(&self, target: u64) -> Option<Vec<DartStubInput>> {
        let first: u32 = self.word_at(target, 0)?;
        let slow: u64 = if first & TRY_ALLOCATE_MASK == TRY_ALLOCATE_RESULT_TEMP {
            let at: u64 = target.checked_add(TRY_ALLOCATE_BRANCH_INDEX * 4)?;
            conditional_branch_target(self.word(at)?, at)?
        } else if mov_register(first)? == (TYPED_DATA_SIZE_REG, TYPED_DATA_LENGTH_REG) {
            let at: u64 = target.checked_add(4)?;
            let raw: u32 = self.word(at)?;
            if raw & BRANCH_IF_NOT_SMI_MASK != BRANCH_IF_TYPED_DATA_LENGTH_NOT_SMI {
                return None;
            }
            test_branch_target(raw, at)?
        } else {
            return None;
        };
        if slow <= target {
            return None;
        }
        let inputs: Vec<DartStubInput> = self.runtime_call_stub(slow)?;
        if mov_register(first) == Some((TYPED_DATA_SIZE_REG, TYPED_DATA_LENGTH_REG))
            && inputs != [DartStubInput::Integer(TYPED_DATA_LENGTH_REG)]
        {
            return None;
        }
        Some(inputs)
    }

    fn suspend_stub(&self, target: u64) -> Option<Vec<DartStubInput>> {
        if frame_load(self.word_at(target, 0)?)? != SUSPEND_STATE_REG {
            return None;
        }
        let frame_size: u32 = self.word_at(target, 1)?;
        let computes_frame_size: bool = frame_size == MOV_FRAME_SIZE_FROM_FP
            || matches!(
                add_imm(frame_size),
                Some((SUSPEND_FRAME_SIZE_REG, FP_REG, _))
            );
        if !computes_frame_size
            || self.word_at(target, 2)? != SUB_SP_FROM_FRAME_SIZE
            || [self.word_at(target, 3)?, self.word_at(target, 4)?] != ENTER_FRAME
        {
            return None;
        }
        let mut inputs: Vec<DartStubInput> = vec![DartStubInput::Integer(SUSPEND_ARGUMENT_REG)];
        if self.word_at(target, 5)? == PUSH_WORD | u32::from(SUSPEND_TYPE_ARGUMENTS_REG) {
            inputs.push(DartStubInput::Integer(SUSPEND_TYPE_ARGUMENTS_REG));
        }
        Some(inputs)
    }

    fn runtime_call_stub(&self, target: u64) -> Option<Vec<DartStubInput>> {
        let mut frame: StubFrame = StubFrame::default();
        let mut at: u64 = self.stub_frame_entry(target, &mut frame)?;
        if [self.word(at)?, self.word(at.checked_add(4)?)?] != ENTER_FRAME {
            return None;
        }
        at = at.checked_add(8)?;
        for _ in 0..MAX_STUB_ARGUMENT_STEPS {
            let raw: u32 = self.word(at)?;
            if !frame.record_argument_step(raw) {
                break;
            }
            at = at.checked_add(4)?;
        }
        let raw: u32 = self.word(at)?;
        let pushes: Vec<u8> = if loads_thread_entry(raw, RUNTIME_ENTRY_REG) {
            let (count_register, count): (u8, u64) = movz(self.word_at(at, 1)?)?;
            if count_register != RUNTIME_ARGUMENT_COUNT_REG
                || !loads_thread_entry(self.word_at(at, 2)?, LR_REG)
                || self.word_at(at, 3)? != CALL_LR
            {
                return None;
            }
            let count: usize = usize::try_from(count).ok()?;
            let arguments: &[u8] = match frame.pushes.split_first() {
                Some((first, rest))
                    if frame.pushes.len() == count + 1
                        && (*first == NULL_REG || *first == ZERO_REG) =>
                {
                    rest
                }
                _ => &frame.pushes,
            };
            if arguments.len() != count {
                return None;
            }
            arguments.to_vec()
        } else if loads_thread_entry(raw, LR_REG) && self.word_at(at, 1)? == CALL_LR {
            if frame.pushes.is_empty() {
                return None;
            }
            frame.pushes.clone()
        } else {
            return None;
        };
        let mut inputs: Vec<DartStubInput> = frame
            .floats
            .iter()
            .map(|register: &u8| DartStubInput::Float(*register))
            .collect::<Vec<DartStubInput>>();
        for register in pushes {
            if register == NULL_REG || register == ZERO_REG || frame.written.contains(&register) {
                continue;
            }
            if !is_dart_available(register) {
                return None;
            }
            inputs.push(DartStubInput::Integer(register));
        }
        Some(inputs)
    }

    fn stub_frame_entry(&self, target: u64, frame: &mut StubFrame) -> Option<u64> {
        let first: u32 = self.word(target)?;
        if first == PUSH_WORD | u32::from(LR_REG) {
            let mut at: u64 = target.checked_add(4)?;
            let mut saves: usize = 0;
            loop {
                let raw: u32 = self.word(at)?;
                let masked: u32 = raw & PUSH_PAIR_MASK;
                if masked != PUSH_X_PAIR && masked != PUSH_Q_PAIR {
                    break;
                }
                saves += 1;
                if saves > MAX_REGISTER_SAVES {
                    return None;
                }
                at = at.checked_add(4)?;
            }
            if saves == 0 || !loads_thread_entry(self.word(at)?, CODE_REG) {
                return None;
            }
            frame.written.insert(CODE_REG);
            return at.checked_add(4);
        }
        if let Some(register) = frame_load(first) {
            let at: u64 = target.checked_add(4)?;
            if [self.word(at)?, self.word(at.checked_add(4)?)?] != LEAVE_FRAME {
                return None;
            }
            frame.written.insert(register);
            return at.checked_add(8);
        }
        Some(target)
    }
}

impl StubFrame {
    fn record_argument_step(&mut self, raw: u32) -> bool {
        if raw & PUSH_WORD_MASK == PUSH_WORD {
            self.pushes.push((raw & 0x1F) as u8);
            return true;
        }
        if raw & PUSH_PAIR_MASK == PUSH_X_PAIR {
            self.pushes.push(((raw >> 10) & 0x1F) as u8);
            self.pushes.push((raw & 0x1F) as u8);
            return true;
        }
        if let Some((destination, base, _)) = ldr_imm_unsigned(raw)
            && base == PP_REG
        {
            self.written.insert(destination);
            return true;
        }
        if let Some((destination, _)) = movz(raw) {
            self.written.insert(destination);
            return true;
        }
        if let Some((destination, _, _)) = movk(raw) {
            return self.written.contains(&destination);
        }
        if let Some(register) = thread_float_store(raw) {
            self.floats.push(register);
            return true;
        }
        false
    }
}

fn is_dart_available(register: u8) -> bool {
    register < 32 && DART_RESERVED_CPU_REGISTERS & (1 << register) == 0
}

fn loads_thread_entry(raw: u32, register: u8) -> bool {
    matches!(ldr_imm_unsigned(raw), Some((destination, THR_REG, _)) if destination == register)
}

fn mov_register(raw: u32) -> Option<(u8, u8)> {
    if raw & 0xFFE0_FFE0 != 0xAA00_03E0 {
        return None;
    }
    Some(((raw & 0x1F) as u8, ((raw >> 16) & 0x1F) as u8))
}

fn frame_load(raw: u32) -> Option<u8> {
    if raw & 0xFFE0_0C00 != 0xF840_0000 || ((raw >> 5) & 0x1F) as u8 != FP_REG {
        return None;
    }
    Some((raw & 0x1F) as u8)
}

fn thread_float_store(raw: u32) -> Option<u8> {
    let stores: bool = FLOAT_STORE_FORMS
        .iter()
        .any(|(mask, value): &(u32, u32)| raw & mask == *value);
    (stores && ((raw >> 5) & 0x1F) as u8 == THR_REG).then_some((raw & 0x1F) as u8)
}

fn indirect_branch_register(raw: u32) -> Option<u8> {
    (raw & 0xFFFF_FC1F == 0xD61F_0000).then_some(((raw >> 5) & 0x1F) as u8)
}

fn branch_target(raw: u32, address: u64) -> Option<u64> {
    if raw & 0xFC00_0000 != 0x1400_0000 {
        return None;
    }
    relative_target(address, raw & 0x03FF_FFFF, 26)
}

fn conditional_branch_target(raw: u32, address: u64) -> Option<u64> {
    if raw & 0xFF00_0010 != 0x5400_0000 {
        return None;
    }
    relative_target(address, (raw >> 5) & 0x7_FFFF, 19)
}

fn test_branch_target(raw: u32, address: u64) -> Option<u64> {
    relative_target(address, (raw >> 5) & 0x3FFF, 14)
}

fn relative_target(address: u64, field: u32, bits: u32) -> Option<u64> {
    let shift: u32 = 32 - bits;
    let words: i64 = i64::from(((field << shift) as i32) >> shift);
    address.checked_add_signed(words.checked_mul(4)?)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn image(words: &[(u64, u32)]) -> Vec<u8> {
        let end: usize = words
            .iter()
            .map(|(address, _): &(u64, u32)| usize::try_from(*address).unwrap() + 4)
            .max()
            .unwrap_or(0);
        let mut bytes: Vec<u8> = vec![0; end];
        for (address, word) in words {
            let at: usize = usize::try_from(*address).unwrap();
            bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    fn sequence(start: u64, words: &[u32]) -> Vec<(u64, u32)> {
        words
            .iter()
            .enumerate()
            .map(|(index, word): (usize, &u32)| (start + 4 * index as u64, *word))
            .collect::<Vec<(u64, u32)>>()
    }

    fn inputs(words: &[(u64, u32)], target: u64) -> Option<Vec<DartStubInput>> {
        let bytes: Vec<u8> = image(words);
        let stubs: DartStubInputs = DartStubInputs::classify(&bytes, &BTreeSet::from([target]));
        stubs.inputs(target).map(<[DartStubInput]>::to_vec)
    }

    const fn mov(destination: u32, source: u32) -> u32 {
        0xAA00_03E0 | (source << 16) | destination
    }

    const fn ldr_thread(destination: u32, offset: u32) -> u32 {
        0xF940_0000 | ((offset / 8) << 10) | (26 << 5) | destination
    }

    const fn ldr_pool(destination: u32, offset: u32) -> u32 {
        0xF940_0000 | ((offset / 8) << 10) | (27 << 5) | destination
    }

    const fn push(register: u32) -> u32 {
        PUSH_WORD | register
    }

    const fn push_pair(first: u32, second: u32) -> u32 {
        PUSH_X_PAIR | (second << 10) | first
    }

    const fn movz_word(destination: u32, value: u32) -> u32 {
        0xD280_0000 | (value << 5) | destination
    }

    const fn movk_word(destination: u32, value: u32) -> u32 {
        0xF2A0_0000 | (value << 5) | destination
    }

    const fn b_word(from: u64, to: u64) -> u32 {
        0x1400_0000 | ((((to as i64 - from as i64) / 4) as u32) & 0x03FF_FFFF)
    }

    const fn b_ls_word(from: u64, to: u64) -> u32 {
        0x5400_0009 | (((((to as i64 - from as i64) / 4) as u32) & 0x7_FFFF) << 5)
    }

    const fn br(register: u32) -> u32 {
        0xD61F_0000 | (register << 5)
    }

    #[test]
    fn a_write_barrier_wrapper_reads_its_object_register_and_the_value_register() {
        let words: Vec<(u64, u32)> = sequence(
            0x40,
            &[push(30), push(1), mov(1, 6), ldr_thread(30, 0x200), CALL_LR],
        );
        assert_eq!(
            inputs(&words, 0x40),
            Some(vec![DartStubInput::Integer(6), DartStubInput::Integer(0)])
        );
    }

    #[test]
    fn a_wrapper_for_a_reserved_register_is_not_a_write_barrier_wrapper() {
        let words: Vec<(u64, u32)> = sequence(
            0x40,
            &[
                push(30),
                push(1),
                mov(1, 22),
                ldr_thread(30, 0x200),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x40), None);
    }

    fn allocator(start: u64, parameterized: bool) -> Vec<(u64, u32)> {
        let tail: u32 = if parameterized { RETURN } else { mov(1, 22) };
        sequence(
            start,
            &[0xD503_201F, 0xD503_201F, tail, ldr_thread(3, 0x238), br(3)],
        )
    }

    #[test]
    fn a_class_allocation_stub_takes_type_arguments_only_when_its_allocator_does() {
        for (parameterized, expected) in
            [(false, Vec::new()), (true, vec![DartStubInput::Integer(1)])]
        {
            let mut words: Vec<(u64, u32)> = sequence(
                0x0,
                &[movz_word(2, 0xC11C), movk_word(2, 0x8B), b_word(0x8, 0x100)],
            );
            words.extend(allocator(0x100, parameterized));
            assert_eq!(inputs(&words, 0x0), Some(expected));
        }
    }

    #[test]
    fn a_class_allocation_stub_whose_allocator_tail_is_unrecognised_stays_unknown() {
        let mut words: Vec<(u64, u32)> = sequence(0x0, &[movz_word(2, 0x1C), b_word(0x4, 0x100)]);
        words.extend(sequence(
            0x100,
            &[
                0xD503_201F,
                0xD503_201F,
                mov(1, 5),
                ldr_thread(3, 0x238),
                br(3),
            ],
        ));
        assert_eq!(inputs(&words, 0x0), None);
    }

    #[test]
    fn a_throw_stub_reads_the_pushed_exception_and_not_the_result_slot() {
        let words: Vec<(u64, u32)> = sequence(
            0x80,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push(22),
                push(0),
                ldr_thread(5, 0x490),
                movz_word(4, 1),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x80), Some(vec![DartStubInput::Integer(0)]));
    }

    #[test]
    fn a_runtime_stub_whose_pushes_disagree_with_its_argument_count_stays_unknown() {
        let words: Vec<(u64, u32)> = sequence(
            0x80,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push(0),
                ldr_thread(5, 0x490),
                movz_word(4, 2),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x80), None);
    }

    #[test]
    fn a_shared_slow_path_stub_with_no_runtime_arguments_takes_none() {
        let words: Vec<(u64, u32)> = sequence(
            0x0,
            &[
                push(30),
                push_pair(24, 25),
                push_pair(0, 1),
                ldr_thread(24, 0x118),
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                ldr_thread(5, 0x450),
                movz_word(4, 0),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x0), Some(Vec::new()));
    }

    #[test]
    fn a_shared_slow_path_stub_reads_each_pushed_runtime_argument() {
        let words: Vec<(u64, u32)> = sequence(
            0x0,
            &[
                push(30),
                push_pair(0, 1),
                ldr_thread(24, 0xE8),
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push(9),
                ldr_thread(5, 0x4E0),
                movz_word(4, 1),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x0), Some(vec![DartStubInput::Integer(9)]));
    }

    #[test]
    fn a_return_stub_reads_the_return_value_but_not_the_state_it_loads_itself() {
        let words: Vec<(u64, u32)> = sequence(
            0x0,
            &[
                0xF85F_83A2,
                LEAVE_FRAME[0],
                LEAVE_FRAME[1],
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push_pair(0, 2),
                ldr_thread(30, 0x648),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x0), Some(vec![DartStubInput::Integer(0)]));
    }

    #[test]
    fn an_init_stub_reads_the_pushed_type_arguments_but_not_its_pool_load() {
        let words: Vec<(u64, u32)> = sequence(
            0x0,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                ldr_pool(4, 0x48),
                push(0),
                ldr_thread(30, 0x628),
                CALL_LR,
            ],
        );
        assert_eq!(inputs(&words, 0x0), Some(vec![DartStubInput::Integer(0)]));
    }

    #[test]
    fn a_suspend_stub_reads_its_operand_and_pushed_type_arguments() {
        for (extra, expected) in [
            (0xD503_201F, vec![DartStubInput::Integer(0)]),
            (
                push(1),
                vec![DartStubInput::Integer(0), DartStubInput::Integer(1)],
            ),
        ] {
            let words: Vec<(u64, u32)> = sequence(
                0x0,
                &[
                    0xF85F_83A3,
                    MOV_FRAME_SIZE_FROM_FP,
                    SUB_SP_FROM_FRAME_SIZE,
                    ENTER_FRAME[0],
                    ENTER_FRAME[1],
                    extra,
                ],
            );
            assert_eq!(inputs(&words, 0x0), Some(expected));
        }
    }

    fn zero_argument_runtime_slow_path(start: u64) -> Vec<(u64, u32)> {
        sequence(
            start,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push(22),
                ldr_thread(5, 0x300),
                movz_word(4, 0),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        )
    }

    #[test]
    fn a_box_allocation_stub_takes_no_arguments() {
        let mut words: Vec<(u64, u32)> = sequence(
            0x0,
            &[0xA946_0740, 0x9100_4000, 0xEB00_003F, b_ls_word(0xC, 0x40)],
        );
        words.extend(zero_argument_runtime_slow_path(0x40));
        assert_eq!(inputs(&words, 0x0), Some(Vec::new()));
    }

    #[test]
    fn a_box_stub_reads_the_float_value_it_stores_for_the_runtime() {
        let mut words: Vec<(u64, u32)> = sequence(
            0x0,
            &[0xA946_0740, 0x9100_4000, 0xEB00_003F, b_ls_word(0xC, 0x40)],
        );
        words.extend(sequence(
            0x40,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push(22),
                0xFD00_0340 | (0x10 << 10),
                ldr_thread(5, 0x300),
                movz_word(4, 0),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        ));
        assert_eq!(inputs(&words, 0x0), Some(vec![DartStubInput::Float(0)]));
    }

    #[test]
    fn a_typed_data_allocation_stub_reads_its_length_register() {
        let mut words: Vec<(u64, u32)> = sequence(0x0, &[mov(2, 4), 0x3700_0000 | (0xF << 5) | 2]);
        words.extend(sequence(
            0x40,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                push(31),
                movz_word(16, 0xE8),
                push(16),
                push(4),
                ldr_thread(5, 0x320),
                movz_word(4, 2),
                ldr_thread(30, 0x210),
                CALL_LR,
            ],
        ));
        assert_eq!(inputs(&words, 0x0), Some(vec![DartStubInput::Integer(4)]));
    }

    #[test]
    fn an_ordinary_dart_function_is_not_a_stub() {
        let words: Vec<(u64, u32)> = sequence(
            0x0,
            &[
                ENTER_FRAME[0],
                ENTER_FRAME[1],
                ldr_thread(16, 0x48),
                0xEB10_01FF,
                RETURN,
            ],
        );
        assert_eq!(inputs(&words, 0x0), None);
    }

    #[test]
    fn a_target_outside_the_image_is_not_classified() {
        assert_eq!(inputs(&sequence(0x0, &[RETURN]), 0x1000), None);
    }
}
