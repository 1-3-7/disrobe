use std::fmt::Write as _;

use disrobe_core::rng::{SeededRng, seeded};
use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, Instruction, Mnemonic, OpCodeInfo, OpCodeOperandKind,
    OpKind, Register,
};
use rand::RngExt as _;

use crate::machine::{
    CODE_ADDRESS, DATA_BASE, GPR_COUNT, IMAGE_BASE, IMAGE_BYTES, MachineState, OBSERVED_FLAGS,
    STACK_POINTER,
};

pub(crate) const MASTER_SEED: u64 = 0x6469_7372_6f62_6521;
pub(crate) const CASES_PER_ENCODING: u32 = 12;
pub(crate) const MAX_CASES: usize = 32_768;

const DATA_WINDOW_START: u64 = DATA_BASE;
const DATA_WINDOW_END: u64 = DATA_BASE + 0xf00;
const ACCESS_HEADROOM: u64 = 0x40;
const BIT_INDEX_LIMIT: u64 = 0x1ff;
const SHIFT_COUNTS: [u64; 12] = [0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 255];
const EDGE_TARGETS: [u64; 4] = [0, 8, 16, 24];
const RETURN_TARGET: u64 = CODE_ADDRESS + 0x40;
const BRANCH_TARGETS: [u64; 4] = [
    CODE_ADDRESS + 0x10,
    CODE_ADDRESS + 0x40,
    CODE_ADDRESS + 0x100,
    CODE_ADDRESS + 0x7f0,
];

#[derive(Clone, Debug)]
pub(crate) struct Case {
    pub(crate) code: Code,
    pub(crate) mnemonic: String,
    pub(crate) seed: u64,
    pub(crate) bytes: Vec<u8>,
    pub(crate) state: MachineState,
    pub(crate) next_address: u64,
    pub(crate) patch: Vec<(u64, Vec<u8>)>,
}

impl Case {
    pub(crate) fn code_name(&self) -> String {
        format!("{:?}", self.code)
    }

    pub(crate) fn render_request(&self, index: usize) -> String {
        let registers: String = self
            .state
            .registers
            .iter()
            .map(|value: &u64| format!("{value:x}"))
            .collect::<Vec<String>>()
            .join(",");
        let encoded: String = hex_bytes(&self.bytes);
        let patched: String = if self.patch.is_empty() {
            "-".to_owned()
        } else {
            self.patch
                .iter()
                .map(|(address, bytes): &(u64, Vec<u8>)| {
                    format!("{address:x}:{}", hex_bytes(bytes))
                })
                .collect::<Vec<String>>()
                .join(",")
        };
        format!(
            "{index}\t{encoded}\t{registers}\t{:x}\t{:x}\t{patched}",
            self.state.flags, self.state.rip
        )
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::new(), |mut text: String, byte: &u8| {
            let _: Result<(), std::fmt::Error> = write!(text, "{byte:02x}");
            text
        })
}

pub(crate) fn base_image() -> Vec<u8> {
    let mut image: Vec<u8> = vec![0; IMAGE_BYTES];
    let mut generator: SeededRng = seeded(MASTER_SEED ^ 0x00d1_5205);
    let data_start: usize = (DATA_BASE - IMAGE_BASE) as usize;
    for slot in image.iter_mut().skip(data_start) {
        *slot = generator.random::<u8>();
    }
    let patterns: [[u8; 8]; 4] = [
        [0, 0, 0, 0, 0, 0, 0, 0],
        [0xff; 8],
        [0, 0, 0, 0, 0, 0, 0, 0x80],
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    ];
    for (slot, pattern) in patterns.iter().enumerate() {
        let start: usize = data_start + slot * 8;
        if let Some(window) = image.get_mut(start..start + 8) {
            window.copy_from_slice(pattern);
        }
    }
    let return_slot: usize = (STACK_POINTER - IMAGE_BASE) as usize;
    if let Some(window) = image.get_mut(return_slot..return_slot + 8) {
        window.copy_from_slice(&RETURN_TARGET.to_le_bytes());
    }
    image
}

pub(crate) fn build_cases(image: &[u8]) -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    for (position, code) in Code::values().enumerate() {
        if cases.len() >= MAX_CASES {
            break;
        }
        for attempt in 0..CASES_PER_ENCODING {
            let seed: u64 = case_seed(position as u64, u64::from(attempt));
            if let Some(case) = build_case(code, seed, image) {
                cases.push(case);
            }
        }
    }
    cases
}

const fn case_seed(code_index: u64, attempt: u64) -> u64 {
    let mut value: u64 = MASTER_SEED
        ^ code_index.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ attempt.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

const fn reads_a_volatile_source(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Rdtsc
            | Mnemonic::Rdtscp
            | Mnemonic::Rdpmc
            | Mnemonic::Rdrand
            | Mnemonic::Rdseed
            | Mnemonic::Rdpid
            | Mnemonic::Rdpru
            | Mnemonic::Cpuid
    )
}

fn build_case(code: Code, seed: u64, image: &[u8]) -> Option<Case> {
    let info: &OpCodeInfo = code.op_code();
    if !info.is_instruction() || !info.mode64() || reads_a_volatile_source(code.mnemonic()) {
        return None;
    }
    let mut generator: SeededRng = seeded(seed);
    let planned: Instruction = plan_instruction(code, info, &mut generator)?;
    let mut encoder: Encoder = Encoder::new(64);
    let length: usize = encoder.encode(&planned, CODE_ADDRESS).ok()?;
    let bytes: Vec<u8> = encoder.take_buffer();
    if bytes.len() != length || bytes.is_empty() {
        return None;
    }
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, &bytes, CODE_ADDRESS, DecoderOptions::NONE);
    let decoded: Instruction = decoder.decode();
    if decoded.code() != code || decoded.len() != bytes.len() {
        return None;
    }
    let mut memory: Vec<u8> = image.to_vec();
    let code_start: usize = (CODE_ADDRESS - IMAGE_BASE) as usize;
    memory
        .get_mut(code_start..code_start + bytes.len())?
        .copy_from_slice(&bytes);
    let mut state: MachineState = MachineState::new(memory);
    state.rip = CODE_ADDRESS;
    seed_registers(&mut state, &mut generator);
    let mut patch: Vec<(u64, Vec<u8>)> = Vec::new();
    constrain(&decoded, &mut state, &mut generator, &mut patch)?;
    Some(Case {
        code,
        mnemonic: format!("{:?}", code.mnemonic()).to_lowercase(),
        seed,
        bytes,
        state,
        next_address: CODE_ADDRESS + length as u64,
        patch,
    })
}

fn seed_registers(state: &mut MachineState, generator: &mut SeededRng) {
    let profile: u8 = generator.random::<u8>() % 6;
    for index in 0..GPR_COUNT {
        let value: u64 = match profile {
            0 => 0,
            1 => u64::MAX,
            2 => 0x8000_0000_0000_0000,
            3 => 0x7fff_ffff_ffff_ffff,
            _ => generator.random::<u64>(),
        };
        if let Some(slot) = state.registers.get_mut(index) {
            *slot = value;
        }
    }
    state.flags = generator.random::<u16>() & OBSERVED_FLAGS;
}

fn plan_instruction(
    code: Code,
    info: &OpCodeInfo,
    generator: &mut SeededRng,
) -> Option<Instruction> {
    let mut instruction: Instruction = Instruction::default();
    instruction.set_code(code);
    let counted: bool = uses_count_immediate(code.mnemonic());
    let shape: MemoryShape = MemoryShape::choose(generator);
    let target: u64 = choose_target(generator);
    let mut memory_used: bool = false;
    for index in 0..info.op_count() {
        let kind: OpCodeOperandKind = info.op_kind(index);
        let allow_memory: bool = !memory_used && generator.random::<u8>() % 3 != 0;
        let placed: Placement = set_operand(
            &mut instruction,
            index,
            kind,
            generator,
            counted,
            allow_memory,
            shape,
            target,
        )?;
        if placed == Placement::Memory {
            memory_used = true;
        }
    }
    Some(instruction)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Placement {
    Operand,
    Memory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryShape {
    Base,
    BaseDisplacement8,
    BaseDisplacement32,
    BaseIndex,
    BaseIndexScale2,
    BaseIndexScale4,
    BaseIndexScale8,
    InstructionPointer,
    Absolute,
    NarrowBaseIndex,
}

impl MemoryShape {
    fn choose(generator: &mut SeededRng) -> Self {
        match generator.random::<u8>() % 10 {
            0 => Self::Base,
            1 => Self::BaseDisplacement8,
            2 => Self::BaseDisplacement32,
            3 => Self::BaseIndex,
            4 => Self::BaseIndexScale2,
            5 => Self::BaseIndexScale4,
            6 => Self::BaseIndexScale8,
            7 => Self::InstructionPointer,
            8 => Self::Absolute,
            _ => Self::NarrowBaseIndex,
        }
    }
}

fn choose_target(generator: &mut SeededRng) -> u64 {
    let selector: u8 = generator.random::<u8>() % 8;
    EDGE_TARGETS.get(selector as usize).map_or_else(
        || {
            let span: u64 = DATA_WINDOW_END - DATA_WINDOW_START - ACCESS_HEADROOM * 2;
            DATA_WINDOW_START + ACCESS_HEADROOM + (generator.random::<u64>() % span)
        },
        |offset: &u64| DATA_WINDOW_START + offset,
    )
}

const fn uses_count_immediate(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Shld
            | Mnemonic::Shrd
            | Mnemonic::Bt
            | Mnemonic::Bts
            | Mnemonic::Btr
            | Mnemonic::Btc
    )
}

fn choose_register(size: u32, generator: &mut SeededRng) -> Register {
    const POOL8: [Register; 20] = [
        Register::AL,
        Register::CL,
        Register::DL,
        Register::BL,
        Register::SPL,
        Register::BPL,
        Register::SIL,
        Register::DIL,
        Register::R8L,
        Register::R9L,
        Register::R10L,
        Register::R11L,
        Register::R12L,
        Register::R13L,
        Register::R14L,
        Register::R15L,
        Register::AH,
        Register::CH,
        Register::DH,
        Register::BH,
    ];
    const POOL16: [Register; 16] = [
        Register::AX,
        Register::CX,
        Register::DX,
        Register::BX,
        Register::SP,
        Register::BP,
        Register::SI,
        Register::DI,
        Register::R8W,
        Register::R9W,
        Register::R10W,
        Register::R11W,
        Register::R12W,
        Register::R13W,
        Register::R14W,
        Register::R15W,
    ];
    const POOL32: [Register; 16] = [
        Register::EAX,
        Register::ECX,
        Register::EDX,
        Register::EBX,
        Register::ESP,
        Register::EBP,
        Register::ESI,
        Register::EDI,
        Register::R8D,
        Register::R9D,
        Register::R10D,
        Register::R11D,
        Register::R12D,
        Register::R13D,
        Register::R14D,
        Register::R15D,
    ];
    const POOL64: [Register; 16] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSP,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    let draw: usize = generator.random::<u64>() as usize;
    match size {
        1 => POOL8[draw % POOL8.len()],
        2 => POOL16[draw % POOL16.len()],
        4 => POOL32[draw % POOL32.len()],
        _ => POOL64[draw % POOL64.len()],
    }
}

const fn base_pool(narrow: bool) -> [Register; 7] {
    if narrow {
        [
            Register::EAX,
            Register::ECX,
            Register::EDX,
            Register::EBX,
            Register::EBP,
            Register::ESI,
            Register::EDI,
        ]
    } else {
        [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RBX,
            Register::RBP,
            Register::RSI,
            Register::RDI,
        ]
    }
}

const fn index_pool(narrow: bool) -> [Register; 6] {
    if narrow {
        [
            Register::EAX,
            Register::ECX,
            Register::EDX,
            Register::R8D,
            Register::R9D,
            Register::R10D,
        ]
    } else {
        [
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
        ]
    }
}

fn apply_memory(
    instruction: &mut Instruction,
    index: u32,
    shape: MemoryShape,
    target: u64,
    generator: &mut SeededRng,
) {
    instruction.set_op_kind(index, OpKind::Memory);
    instruction.set_memory_base(Register::None);
    instruction.set_memory_index(Register::None);
    instruction.set_memory_index_scale(1);
    instruction.set_memory_displacement64(0);
    instruction.set_memory_displ_size(0);
    let narrow: bool = shape == MemoryShape::NarrowBaseIndex;
    let bases: [Register; 7] = base_pool(narrow);
    let indexes: [Register; 6] = index_pool(narrow);
    let base: Register = bases[generator.random::<u64>() as usize % bases.len()];
    let scaled_index: Register = indexes[generator.random::<u64>() as usize % indexes.len()];
    match shape {
        MemoryShape::Base => {
            instruction.set_memory_base(base);
        }
        MemoryShape::BaseDisplacement8 => {
            instruction.set_memory_base(base);
            instruction.set_memory_displacement64(0x18);
            instruction.set_memory_displ_size(1);
        }
        MemoryShape::BaseDisplacement32 => {
            instruction.set_memory_base(base);
            instruction.set_memory_displacement64(0x1234);
            instruction.set_memory_displ_size(4);
        }
        MemoryShape::BaseIndex | MemoryShape::NarrowBaseIndex => {
            instruction.set_memory_base(base);
            instruction.set_memory_index(scaled_index);
            instruction.set_memory_index_scale(1);
        }
        MemoryShape::BaseIndexScale2 => {
            instruction.set_memory_base(base);
            instruction.set_memory_index(scaled_index);
            instruction.set_memory_index_scale(2);
            instruction.set_memory_displacement64(0x20);
            instruction.set_memory_displ_size(1);
        }
        MemoryShape::BaseIndexScale4 => {
            instruction.set_memory_base(base);
            instruction.set_memory_index(scaled_index);
            instruction.set_memory_index_scale(4);
        }
        MemoryShape::BaseIndexScale8 => {
            instruction.set_memory_base(base);
            instruction.set_memory_index(scaled_index);
            instruction.set_memory_index_scale(8);
            instruction.set_memory_displacement64(0x100);
            instruction.set_memory_displ_size(4);
        }
        MemoryShape::InstructionPointer => {
            instruction.set_memory_base(Register::RIP);
            instruction.set_memory_displacement64(target);
            instruction.set_memory_displ_size(4);
        }
        MemoryShape::Absolute => {
            instruction.set_memory_displacement64(target);
            instruction.set_memory_displ_size(4);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn set_operand(
    instruction: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
    generator: &mut SeededRng,
    counted: bool,
    allow_memory: bool,
    shape: MemoryShape,
    target: u64,
) -> Option<Placement> {
    if let Some(size) = fixed_register_width(kind) {
        instruction.set_op_kind(index, OpKind::Register);
        instruction.set_op_register(index, choose_register(size, generator));
        return Some(Placement::Operand);
    }
    if let Some(size) = flexible_register_width(kind) {
        if allow_memory {
            apply_memory(instruction, index, shape, target, generator);
            return Some(Placement::Memory);
        }
        instruction.set_op_kind(index, OpKind::Register);
        instruction.set_op_register(index, choose_register(size, generator));
        return Some(Placement::Operand);
    }
    let implicit: Option<Register> = match kind {
        OpCodeOperandKind::al => Some(Register::AL),
        OpCodeOperandKind::ax => Some(Register::AX),
        OpCodeOperandKind::eax => Some(Register::EAX),
        OpCodeOperandKind::rax => Some(Register::RAX),
        OpCodeOperandKind::cl => Some(Register::CL),
        OpCodeOperandKind::dx => Some(Register::DX),
        _ => None,
    };
    if let Some(selected) = implicit {
        instruction.set_op_kind(index, OpKind::Register);
        instruction.set_op_register(index, selected);
        return Some(Placement::Operand);
    }
    match kind {
        OpCodeOperandKind::mem | OpCodeOperandKind::sibmem => {
            apply_memory(instruction, index, shape, target, generator);
            return Some(Placement::Memory);
        }
        OpCodeOperandKind::mem_offs => {
            instruction.set_op_kind(index, OpKind::Memory);
            instruction.set_memory_base(Register::None);
            instruction.set_memory_index(Register::None);
            instruction.set_memory_displacement64(target);
            instruction.set_memory_displ_size(8);
            return Some(Placement::Memory);
        }
        OpCodeOperandKind::seg_rSI => {
            instruction.set_op_kind(index, OpKind::MemorySegRSI);
            return Some(Placement::Operand);
        }
        OpCodeOperandKind::seg_rDI => {
            instruction.set_op_kind(index, OpKind::MemorySegRDI);
            return Some(Placement::Operand);
        }
        OpCodeOperandKind::es_rDI => {
            instruction.set_op_kind(index, OpKind::MemoryESRDI);
            return Some(Placement::Operand);
        }
        OpCodeOperandKind::br16_1
        | OpCodeOperandKind::br16_2
        | OpCodeOperandKind::br64_1
        | OpCodeOperandKind::br64_4 => {
            let selection: usize = generator.random::<u64>() as usize % BRANCH_TARGETS.len();
            instruction.set_op_kind(index, OpKind::NearBranch64);
            instruction.set_near_branch64(BRANCH_TARGETS[selection]);
            return Some(Placement::Operand);
        }
        _ => {}
    }
    set_immediate(instruction, index, kind, generator, counted)?;
    Some(Placement::Operand)
}

fn set_immediate(
    instruction: &mut Instruction,
    index: u32,
    kind: OpCodeOperandKind,
    generator: &mut SeededRng,
    counted: bool,
) -> Option<()> {
    let raw: u64 = if counted {
        SHIFT_COUNTS[generator.random::<u64>() as usize % SHIFT_COUNTS.len()]
    } else {
        generator.random::<u64>()
    };
    match kind {
        OpCodeOperandKind::imm8 => {
            instruction.set_op_kind(index, OpKind::Immediate8);
            instruction.set_immediate8(raw as u8);
        }
        OpCodeOperandKind::imm8_const_1 => {
            instruction.set_op_kind(index, OpKind::Immediate8);
            instruction.set_immediate8(1);
        }
        OpCodeOperandKind::imm8sex16 => {
            instruction.set_op_kind(index, OpKind::Immediate8to16);
            instruction.set_immediate8to16(i16::from(raw as i8));
        }
        OpCodeOperandKind::imm8sex32 => {
            instruction.set_op_kind(index, OpKind::Immediate8to32);
            instruction.set_immediate8to32(i32::from(raw as i8));
        }
        OpCodeOperandKind::imm8sex64 => {
            instruction.set_op_kind(index, OpKind::Immediate8to64);
            instruction.set_immediate8to64(i64::from(raw as i8));
        }
        OpCodeOperandKind::imm16 => {
            instruction.set_op_kind(index, OpKind::Immediate16);
            instruction.set_immediate16(raw as u16);
        }
        OpCodeOperandKind::imm32 => {
            instruction.set_op_kind(index, OpKind::Immediate32);
            instruction.set_immediate32(raw as u32);
        }
        OpCodeOperandKind::imm32sex64 => {
            instruction.set_op_kind(index, OpKind::Immediate32to64);
            instruction.set_immediate32to64(i64::from(raw as i32));
        }
        OpCodeOperandKind::imm64 => {
            instruction.set_op_kind(index, OpKind::Immediate64);
            instruction.set_immediate64(raw);
        }
        _ => return None,
    }
    Some(())
}

const fn fixed_register_width(kind: OpCodeOperandKind) -> Option<u32> {
    match kind {
        OpCodeOperandKind::r8_reg | OpCodeOperandKind::r8_opcode => Some(1),
        OpCodeOperandKind::r16_reg | OpCodeOperandKind::r16_rm | OpCodeOperandKind::r16_opcode => {
            Some(2)
        }
        OpCodeOperandKind::r32_reg
        | OpCodeOperandKind::r32_rm
        | OpCodeOperandKind::r32_opcode
        | OpCodeOperandKind::r32_reg_mem => Some(4),
        OpCodeOperandKind::r64_reg
        | OpCodeOperandKind::r64_rm
        | OpCodeOperandKind::r64_opcode
        | OpCodeOperandKind::r64_reg_mem => Some(8),
        _ => None,
    }
}

const fn flexible_register_width(kind: OpCodeOperandKind) -> Option<u32> {
    match kind {
        OpCodeOperandKind::r8_or_mem => Some(1),
        OpCodeOperandKind::r16_or_mem => Some(2),
        OpCodeOperandKind::r32_or_mem => Some(4),
        OpCodeOperandKind::r64_or_mem => Some(8),
        _ => None,
    }
}

pub(crate) fn register_slot(selected: Register) -> Option<usize> {
    let full: Register = selected.full_register();
    let slot: usize = match full {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return None,
    };
    Some(slot)
}

fn set_slot(state: &mut MachineState, selected: Register, value: u64) {
    if let Some(slot) = register_slot(selected)
        && let Some(cell) = state.registers.get_mut(slot)
    {
        *cell = value;
    }
}

fn slot_value(state: &MachineState, selected: Register) -> u64 {
    register_slot(selected)
        .and_then(|slot: usize| state.registers.get(slot).copied())
        .unwrap_or(0)
}

fn constrain(
    instruction: &Instruction,
    state: &mut MachineState,
    generator: &mut SeededRng,
    patch: &mut Vec<(u64, Vec<u8>)>,
) -> Option<()> {
    set_slot(state, Register::RSP, STACK_POINTER);
    if instruction.mnemonic() == Mnemonic::Leave {
        set_slot(state, Register::RBP, STACK_POINTER);
    }
    if instruction.is_string_instruction() {
        set_slot(state, Register::RSI, DATA_BASE + 0x400);
        set_slot(state, Register::RDI, DATA_BASE + 0x800);
    }
    if let Some(count_register) = count_operand(instruction) {
        let chosen: u64 = SHIFT_COUNTS[generator.random::<u64>() as usize % SHIFT_COUNTS.len()];
        let previous: u64 = slot_value(state, count_register);
        set_slot(state, count_register, (previous & !0xff) | chosen);
    }
    if let Some(bit_register) = bit_index_operand(instruction) {
        if register_slot(bit_register) == register_slot(instruction.memory_base())
            || register_slot(bit_register) == register_slot(instruction.memory_index())
        {
            return None;
        }
        let clamped: u64 = generator.random::<u64>() & BIT_INDEX_LIMIT;
        set_slot(state, bit_register, clamped);
    }
    let memory_operand: Option<u32> = (0..instruction.op_count())
        .find(|operand: &u32| instruction.op_kind(*operand) == OpKind::Memory);
    if memory_operand.is_some() {
        solve_memory(instruction, state, generator)?;
    }
    if let Some(target) = indirect_branch_operand(instruction) {
        match target {
            IndirectTarget::Register(selected) => set_slot(state, selected, RETURN_TARGET),
            IndirectTarget::Memory => {
                let address: u64 = effective_address(instruction, state);
                if !state.write_memory(address, 8, RETURN_TARGET) {
                    return None;
                }
                patch.push((address, RETURN_TARGET.to_le_bytes().to_vec()));
            }
        }
    }
    Some(())
}

#[derive(Clone, Copy, Debug)]
enum IndirectTarget {
    Register(Register),
    Memory,
}

fn indirect_branch_operand(instruction: &Instruction) -> Option<IndirectTarget> {
    if !matches!(instruction.mnemonic(), Mnemonic::Jmp | Mnemonic::Call) {
        return None;
    }
    match instruction.op_kind(0) {
        OpKind::Register => Some(IndirectTarget::Register(instruction.op_register(0))),
        OpKind::Memory => Some(IndirectTarget::Memory),
        _ => None,
    }
}

fn count_operand(instruction: &Instruction) -> Option<Register> {
    (!matches!(
        instruction.mnemonic(),
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    ))
    .then(|| {
        (0..instruction.op_count())
            .filter(|operand: &u32| instruction.op_kind(*operand) == OpKind::Register)
            .map(|operand: u32| instruction.op_register(operand))
            .find(|selected: &Register| *selected == Register::CL)
    })
    .flatten()
}

fn bit_index_operand(instruction: &Instruction) -> Option<Register> {
    if !matches!(
        instruction.mnemonic(),
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    ) || instruction.op_kind(0) != OpKind::Memory
        || instruction.op_kind(1) != OpKind::Register
    {
        return None;
    }
    Some(instruction.op_register(1))
}

fn solve_memory(
    instruction: &Instruction,
    state: &mut MachineState,
    generator: &mut SeededRng,
) -> Option<()> {
    if instruction.is_ip_rel_memory_operand() {
        return in_window(instruction.ip_rel_memory_address()).then_some(());
    }
    let base: Register = instruction.memory_base();
    let index: Register = instruction.memory_index();
    let scale: u64 = u64::from(instruction.memory_index_scale());
    let displacement: u64 = instruction.memory_displacement64();
    let narrow: bool = memory_is_narrow(base, index);
    if base == Register::None {
        return in_window(effective_address(instruction, state)).then_some(());
    }
    if register_slot(base) == register_slot(index) {
        return None;
    }
    let target: u64 = choose_target(generator);
    let index_value: u64 = if index == Register::None {
        0
    } else {
        let raw: u64 = slot_value(state, index);
        if narrow { raw & 0xffff_ffff } else { raw }
    };
    let solved: u64 = target
        .wrapping_sub(index_value.wrapping_mul(scale))
        .wrapping_sub(displacement);
    let stored: u64 = if narrow { solved & 0xffff_ffff } else { solved };
    set_slot(state, base, stored);
    let produced: u64 = effective_address(instruction, state);
    in_window(produced).then_some(())
}

const fn memory_is_narrow(base: Register, index: Register) -> bool {
    matches!(
        base,
        Register::EAX
            | Register::ECX
            | Register::EDX
            | Register::EBX
            | Register::ESP
            | Register::EBP
            | Register::ESI
            | Register::EDI
            | Register::R8D
            | Register::R9D
            | Register::R10D
            | Register::R11D
            | Register::R12D
            | Register::R13D
            | Register::R14D
            | Register::R15D
    ) || matches!(
        index,
        Register::EAX
            | Register::ECX
            | Register::EDX
            | Register::R8D
            | Register::R9D
            | Register::R10D
    )
}

pub(crate) fn effective_address(instruction: &Instruction, state: &MachineState) -> u64 {
    if instruction.is_ip_rel_memory_operand() {
        return instruction.ip_rel_memory_address();
    }
    let base: Register = instruction.memory_base();
    let index: Register = instruction.memory_index();
    let narrow: bool = memory_is_narrow(base, index);
    let base_value: u64 = if base == Register::None {
        0
    } else {
        slot_value(state, base)
    };
    let index_value: u64 = if index == Register::None {
        0
    } else {
        slot_value(state, index)
    };
    let raw: u64 = base_value
        .wrapping_add(index_value.wrapping_mul(u64::from(instruction.memory_index_scale())))
        .wrapping_add(instruction.memory_displacement64());
    if narrow { raw & 0xffff_ffff } else { raw }
}

const fn in_window(address: u64) -> bool {
    address >= DATA_WINDOW_START && address.saturating_add(ACCESS_HEADROOM) < DATA_WINDOW_END
}
