use disrobe_sleigh::pcode::{DecodeStatus, PcodeOp, Space, Varnode};
use iced_x86::{
    Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register, UsedMemory,
};

use crate::registers::{AF, CF, DF, MXCSR, OF, PF, SF, UniqueAllocator, ZF, constant, register};

use super::{
    ContractSpec, emit_sub_flags, fallback_with_contract, used_memory_pointer, write_register,
};

const CONDITIONALLY_PRESERVED_FLAGS: [Varnode; 6] = [CF, PF, AF, ZF, SF, OF];

pub(super) fn lift_opaque_family(
    instruction: &Instruction,
    mnemonic: &str,
    allocator: &mut UniqueAllocator,
    information: &mut InstructionInfoFactory,
) -> Option<(DecodeStatus, Vec<PcodeOp>)> {
    if is_atomic(instruction) {
        let width: u32 = u32::try_from(instruction.memory_size().size()).ok()?;
        let invocation_name: String = format!("x86_atomic_{mnemonic}_side_effecting_v1");
        let result_name: String = format!("x86_atomic_{mnemonic}_result_pure_v1");
        let specification: ContractSpec = ContractSpec {
            invocation_name,
            result_name,
            effectful: true,
            additional_inputs: vec![
                constant(u64::from(width), 4),
                constant(u64::from(instruction.has_lock_prefix()), 1),
            ],
            additional_outputs: Vec::new(),
        };
        return Some(fallback_with_contract(
            instruction,
            mnemonic,
            allocator,
            information,
            Some(specification),
        ));
    }
    if let Some(shape) = string_shape(instruction)
        && (instruction.has_rep_prefix() || instruction.has_repne_prefix())
    {
        let prefix: &str = repeat_prefix(shape.kind, instruction)?;
        let summary: &str = match shape.kind {
            StringKind::Movs => "reads_writes_mem",
            StringKind::Stos => "writes_mem",
            StringKind::Lods | StringKind::Cmps | StringKind::Scas => "reads_mem",
        };
        let invocation_name: String = format!("x86_{prefix}_{mnemonic}_{summary}_v1");
        let result_name: String = format!("x86_{prefix}_{mnemonic}_result_pure_v1");
        let mut additional_inputs: Vec<Varnode> = vec![
            DF,
            constant(u64::from(shape.width), 4),
            constant(repeat_code(prefix), 1),
        ];
        if matches!(shape.kind, StringKind::Cmps | StringKind::Scas) {
            additional_inputs.extend(CONDITIONALLY_PRESERVED_FLAGS);
        }
        let specification: ContractSpec = ContractSpec {
            invocation_name,
            result_name,
            effectful: true,
            additional_inputs,
            additional_outputs: Vec::new(),
        };
        return Some(fallback_with_contract(
            instruction,
            mnemonic,
            allocator,
            information,
            Some(specification),
        ));
    }
    if scalar_float_contract(instruction.mnemonic()) {
        let invocation_name: String = format!("x86_scalar_{mnemonic}_side_effecting_v1");
        let result_name: String = format!("x86_scalar_{mnemonic}_result_pure_v1");
        let specification: ContractSpec = ContractSpec {
            invocation_name,
            result_name,
            effectful: true,
            additional_inputs: vec![MXCSR],
            additional_outputs: vec![MXCSR],
        };
        return Some(fallback_with_contract(
            instruction,
            mnemonic,
            allocator,
            information,
            Some(specification),
        ));
    }
    if let Some(specification) = scalar_contract(instruction) {
        return Some(fallback_with_contract(
            instruction,
            mnemonic,
            allocator,
            information,
            Some(specification),
        ));
    }
    None
}

pub(super) fn lift_string_iteration(
    instruction: &Instruction,
    allocator: &mut UniqueAllocator,
    information: &mut InstructionInfoFactory,
) -> Option<Vec<PcodeOp>> {
    let shape: StringShape = string_shape(instruction)?;
    if instruction.has_rep_prefix() || instruction.has_repne_prefix() {
        return None;
    }
    let details: &iced_x86::InstructionInfo = information.info(instruction);
    let memory: Vec<UsedMemory> = details.used_memory().to_vec();
    let mut ops: Vec<PcodeOp> = Vec::new();
    match shape.kind {
        StringKind::Movs => {
            let source: UsedMemory = indexed_memory(&memory, true, OpAccess::Read)?;
            let target: UsedMemory = indexed_memory(&memory, false, OpAccess::Write)?;
            let source_pointer: Varnode = used_memory_pointer(&source, allocator, &mut ops)?;
            let target_pointer: Varnode = used_memory_pointer(&target, allocator, &mut ops)?;
            let value: Varnode = load(source_pointer, shape.width, allocator, &mut ops)?;
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer: target_pointer,
                value,
            });
            update_index(target.base(), shape.width, allocator, &mut ops)?;
            update_index(source.base(), shape.width, allocator, &mut ops)?;
        }
        StringKind::Stos => {
            let target: UsedMemory = indexed_memory(&memory, false, OpAccess::Write)?;
            let pointer: Varnode = used_memory_pointer(&target, allocator, &mut ops)?;
            let value: Varnode = register(accumulator(shape.width)?)?;
            ops.push(PcodeOp::Store {
                space: Space::Ram,
                pointer,
                value,
            });
            update_index(target.base(), shape.width, allocator, &mut ops)?;
        }
        StringKind::Lods => {
            let source: UsedMemory = indexed_memory(&memory, true, OpAccess::Read)?;
            let pointer: Varnode = used_memory_pointer(&source, allocator, &mut ops)?;
            let value: Varnode = load(pointer, shape.width, allocator, &mut ops)?;
            write_register(accumulator(shape.width)?, value, allocator, &mut ops)?;
            update_index(source.base(), shape.width, allocator, &mut ops)?;
        }
        StringKind::Cmps => {
            let source: UsedMemory = indexed_memory(&memory, true, OpAccess::Read)?;
            let target: UsedMemory = indexed_memory(&memory, false, OpAccess::Read)?;
            let source_pointer: Varnode = used_memory_pointer(&source, allocator, &mut ops)?;
            let target_pointer: Varnode = used_memory_pointer(&target, allocator, &mut ops)?;
            let left: Varnode = load(source_pointer, shape.width, allocator, &mut ops)?;
            let right: Varnode = load(target_pointer, shape.width, allocator, &mut ops)?;
            let result: Varnode = allocator.allocate(shape.width)?;
            ops.push(PcodeOp::IntSub {
                output: result,
                left,
                right,
            });
            emit_sub_flags(instruction, left, right, result, allocator, &mut ops)?;
            update_index(target.base(), shape.width, allocator, &mut ops)?;
            update_index(source.base(), shape.width, allocator, &mut ops)?;
        }
        StringKind::Scas => {
            let target: UsedMemory = indexed_memory(&memory, false, OpAccess::Read)?;
            let pointer: Varnode = used_memory_pointer(&target, allocator, &mut ops)?;
            let left: Varnode = register(accumulator(shape.width)?)?;
            let right: Varnode = load(pointer, shape.width, allocator, &mut ops)?;
            let result: Varnode = allocator.allocate(shape.width)?;
            ops.push(PcodeOp::IntSub {
                output: result,
                left,
                right,
            });
            emit_sub_flags(instruction, left, right, result, allocator, &mut ops)?;
            update_index(target.base(), shape.width, allocator, &mut ops)?;
        }
    }
    Some(ops)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringKind {
    Movs,
    Stos,
    Lods,
    Cmps,
    Scas,
}

#[derive(Clone, Copy, Debug)]
struct StringShape {
    kind: StringKind,
    width: u32,
}

fn string_shape(instruction: &Instruction) -> Option<StringShape> {
    if !instruction.is_string_instruction() {
        return None;
    }
    let shape: StringShape = match instruction.mnemonic() {
        Mnemonic::Movsb => StringShape {
            kind: StringKind::Movs,
            width: 1,
        },
        Mnemonic::Movsw => StringShape {
            kind: StringKind::Movs,
            width: 2,
        },
        Mnemonic::Movsd => StringShape {
            kind: StringKind::Movs,
            width: 4,
        },
        Mnemonic::Movsq => StringShape {
            kind: StringKind::Movs,
            width: 8,
        },
        Mnemonic::Stosb => StringShape {
            kind: StringKind::Stos,
            width: 1,
        },
        Mnemonic::Stosw => StringShape {
            kind: StringKind::Stos,
            width: 2,
        },
        Mnemonic::Stosd => StringShape {
            kind: StringKind::Stos,
            width: 4,
        },
        Mnemonic::Stosq => StringShape {
            kind: StringKind::Stos,
            width: 8,
        },
        Mnemonic::Lodsb => StringShape {
            kind: StringKind::Lods,
            width: 1,
        },
        Mnemonic::Lodsw => StringShape {
            kind: StringKind::Lods,
            width: 2,
        },
        Mnemonic::Lodsd => StringShape {
            kind: StringKind::Lods,
            width: 4,
        },
        Mnemonic::Lodsq => StringShape {
            kind: StringKind::Lods,
            width: 8,
        },
        Mnemonic::Cmpsb => StringShape {
            kind: StringKind::Cmps,
            width: 1,
        },
        Mnemonic::Cmpsw => StringShape {
            kind: StringKind::Cmps,
            width: 2,
        },
        Mnemonic::Cmpsd => StringShape {
            kind: StringKind::Cmps,
            width: 4,
        },
        Mnemonic::Cmpsq => StringShape {
            kind: StringKind::Cmps,
            width: 8,
        },
        Mnemonic::Scasb => StringShape {
            kind: StringKind::Scas,
            width: 1,
        },
        Mnemonic::Scasw => StringShape {
            kind: StringKind::Scas,
            width: 2,
        },
        Mnemonic::Scasd => StringShape {
            kind: StringKind::Scas,
            width: 4,
        },
        Mnemonic::Scasq => StringShape {
            kind: StringKind::Scas,
            width: 8,
        },
        _ => return None,
    };
    Some(shape)
}

const fn repeat_prefix(kind: StringKind, instruction: &Instruction) -> Option<&'static str> {
    if instruction.has_repne_prefix() {
        return Some("repne");
    }
    if instruction.has_rep_prefix() {
        return if matches!(kind, StringKind::Cmps | StringKind::Scas) {
            Some("repe")
        } else {
            Some("rep")
        };
    }
    None
}

const fn repeat_code(prefix: &str) -> u64 {
    match prefix.as_bytes() {
        b"rep" => 1,
        b"repe" => 2,
        b"repne" => 3,
        _ => 0,
    }
}

fn indexed_memory(memory: &[UsedMemory], source: bool, access: OpAccess) -> Option<UsedMemory> {
    memory
        .iter()
        .find(|usage: &&UsedMemory| {
            usage.access() == access && is_source_index(usage.base()) == source
        })
        .copied()
}

const fn is_source_index(selected: Register) -> bool {
    matches!(selected, Register::SI | Register::ESI | Register::RSI)
}

const fn accumulator(width: u32) -> Option<Register> {
    match width {
        1 => Some(Register::AL),
        2 => Some(Register::AX),
        4 => Some(Register::EAX),
        8 => Some(Register::RAX),
        _ => None,
    }
}

fn load(
    pointer: Varnode,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let output: Varnode = allocator.allocate(width)?;
    ops.push(PcodeOp::Load {
        output,
        space: Space::Ram,
        pointer,
    });
    Some(output)
}

fn update_index(
    selected: Register,
    width: u32,
    allocator: &mut UniqueAllocator,
    ops: &mut Vec<PcodeOp>,
) -> Option<()> {
    let input: Varnode = register(selected)?;
    let direction: Varnode = allocator.allocate(input.size_bytes)?;
    let backward: Varnode = allocator.allocate(input.size_bytes)?;
    let forward: Varnode = allocator.allocate(input.size_bytes)?;
    let result: Varnode = allocator.allocate(input.size_bytes)?;
    let doubled_width: u32 = width.checked_mul(2)?;
    ops.push(PcodeOp::IntZext {
        output: direction,
        input: DF,
    });
    ops.push(PcodeOp::IntMult {
        output: backward,
        left: direction,
        right: constant(u64::from(doubled_width), input.size_bytes),
    });
    ops.push(PcodeOp::IntAdd {
        output: forward,
        left: input,
        right: constant(u64::from(width), input.size_bytes),
    });
    ops.push(PcodeOp::IntSub {
        output: result,
        left: forward,
        right: backward,
    });
    write_register(selected, result, allocator, ops)
}

fn is_atomic(instruction: &Instruction) -> bool {
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Lfence | Mnemonic::Mfence | Mnemonic::Sfence
    ) {
        return true;
    }
    let has_memory: bool = (0..instruction.op_count())
        .any(|operand: u32| instruction.op_kind(operand) == OpKind::Memory);
    instruction.has_lock_prefix()
        || (has_memory
            && matches!(
                instruction.mnemonic(),
                Mnemonic::Xchg | Mnemonic::Cmpxchg | Mnemonic::Cmpxchg8b | Mnemonic::Cmpxchg16b
            ))
}

const fn scalar_float_contract(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Addss
            | Mnemonic::Addsd
            | Mnemonic::Subss
            | Mnemonic::Subsd
            | Mnemonic::Mulss
            | Mnemonic::Mulsd
            | Mnemonic::Divss
            | Mnemonic::Divsd
            | Mnemonic::Sqrtss
            | Mnemonic::Sqrtsd
            | Mnemonic::Comiss
            | Mnemonic::Comisd
            | Mnemonic::Ucomiss
            | Mnemonic::Ucomisd
            | Mnemonic::Cvtsi2ss
            | Mnemonic::Cvtsi2sd
            | Mnemonic::Cvtss2si
            | Mnemonic::Cvtsd2si
            | Mnemonic::Cvttss2si
            | Mnemonic::Cvttsd2si
            | Mnemonic::Cvtss2sd
            | Mnemonic::Cvtsd2ss
    )
}

fn scalar_contract(instruction: &Instruction) -> Option<ContractSpec> {
    let (stem, result_name, memory_summary): (String, String, Option<&'static str>) =
        match instruction.mnemonic() {
            Mnemonic::Bsf if instruction.op_count() == 2 => (
                "bsf".to_owned(),
                "x86_bsf_result_pure_v1".to_owned(),
                (instruction.op_kind(1) == OpKind::Memory).then_some("reads_mem"),
            ),
            Mnemonic::Bsr if instruction.op_count() == 2 => (
                "bsr".to_owned(),
                "x86_bsr_result_pure_v1".to_owned(),
                (instruction.op_kind(1) == OpKind::Memory).then_some("reads_mem"),
            ),
            Mnemonic::Popcnt if instruction.op_count() == 2 => (
                "popcount".to_owned(),
                "x86_popcount_pure_v1".to_owned(),
                (instruction.op_kind(1) == OpKind::Memory).then_some("reads_mem"),
            ),
            Mnemonic::Tzcnt if instruction.op_count() == 2 => (
                "tzcount".to_owned(),
                "x86_tzcount_pure_v1".to_owned(),
                (instruction.op_kind(1) == OpKind::Memory).then_some("reads_mem"),
            ),
            Mnemonic::Lzcnt if instruction.op_count() == 2 => (
                "lzcount".to_owned(),
                "x86_lzcount_pure_v1".to_owned(),
                (instruction.op_kind(1) == OpKind::Memory).then_some("reads_mem"),
            ),
            _ => return None,
        };
    let effectful: bool = memory_summary.is_some();
    let invocation_name: String = memory_summary.map_or_else(
        || result_name.clone(),
        |summary: &'static str| format!("x86_{stem}_{summary}_v1"),
    );
    Some(ContractSpec {
        invocation_name,
        result_name,
        effectful,
        additional_inputs: Vec::new(),
        additional_outputs: Vec::new(),
    })
}
