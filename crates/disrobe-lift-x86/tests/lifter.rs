use std::collections::BTreeSet;

use disrobe_lift_x86::{X86PcodeLifter, decode_block_x86};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

fn single(bytes: &[u8], address: u64) -> PcodeInstr {
    let block: DecodedBlock = decode_block_x86(bytes, address, 64);
    assert_eq!(block.consumed, bytes.len());
    assert_eq!(block.instructions.len(), 1);
    block.instructions[0].clone()
}

#[test]
fn mov_register_to_register_uses_shared_varnodes() {
    let instruction: PcodeInstr = single(&[0x48, 0x89, 0xd8], 0x1000);
    assert_eq!(instruction.status, DecodeStatus::Supported);
    assert_eq!(instruction.mnemonic, "mov");
    assert_eq!(instruction.length, 3);
    assert_eq!(instruction.operands, "rax,rbx");
    assert_eq!(
        instruction.ops,
        vec![PcodeOp::Copy {
            output: Varnode {
                offset: 0,
                size_bytes: 8,
                space: Space::Register,
            },
            input: Varnode {
                offset: 0x18,
                size_bytes: 8,
                space: Space::Register,
            },
        }]
    );
}

#[test]
fn add_emits_all_six_flag_effects() {
    let instruction: PcodeInstr = single(&[0x48, 0x01, 0xd8], 0x2000);
    let carry: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntCarry { output, .. } if output.offset == 0x200 && output.size_bytes == 1)
    });
    let overflow: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntSignedCarry { output, .. } if output.offset == 0x20b && output.size_bytes == 1)
    });
    let zero: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntEqual { output, .. } if output.offset == 0x206 && output.size_bytes == 1)
    });
    let sign: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntSignedLess { output, .. } if output.offset == 0x207 && output.size_bytes == 1)
    });
    let auxiliary: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntNotEqual { output, .. } if output.offset == 0x204 && output.size_bytes == 1)
    });
    let parity: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, output: Some(output), .. } if name == "x86_parity8_pure_v1" && output.offset == 0x202 && output.size_bytes == 1)
    });
    assert!(carry && overflow && zero && sign && auxiliary && parity);
}

#[test]
fn sib_memory_load_builds_an_explicit_pointer() {
    let instruction: PcodeInstr = single(&[0x48, 0x8b, 0x44, 0x8b, 0x10], 0x3000);
    let scale: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntMult { right, .. } if right.space == Space::Constant && right.offset == 4)
    });
    let load: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Load { output, space: Space::Ram, pointer } if output.size_bytes == 8 && pointer.space == Space::Unique)
    });
    assert!(scale && load);
}

#[test]
fn rip_relative_lea_uses_the_absolute_next_ip_target() {
    let instruction: PcodeInstr = single(&[0x48, 0x8d, 0x05, 0x34, 0x12, 0x00, 0x00], 0x4000);
    assert_eq!(
        instruction.ops,
        vec![PcodeOp::Copy {
            output: Varnode {
                offset: 0,
                size_bytes: 8,
                space: Space::Register,
            },
            input: Varnode {
                offset: 0x523b,
                size_bytes: 8,
                space: Space::Constant,
            },
        }]
    );
}

#[test]
fn conditional_branch_uses_the_zero_flag() {
    let instruction: PcodeInstr = single(&[0x75, 0x02], 0x5000);
    let negated: Option<Varnode> =
        instruction
            .ops
            .iter()
            .find_map(|operation: &PcodeOp| match operation {
                PcodeOp::BoolNegate { output, input } if input.offset == 0x206 => Some(*output),
                _ => None,
            });
    assert!(negated.is_some());
    let Some(condition): Option<Varnode> = negated else {
        return;
    };
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CBranch { target, condition: branch_condition } if target.space == Space::Ram && target.offset == 0x5004 && *branch_condition == condition)
    }));
}

#[test]
fn unmodeled_vector_instruction_has_typed_inputs_and_outputs() {
    let instruction: PcodeInstr = single(&[0x66, 0x0f, 0x6f, 0xc1], 0x6000);
    assert_eq!(instruction.status, DecodeStatus::CallOther);
    let token: Option<Varnode> =
        instruction
            .ops
            .iter()
            .find_map(|operation: &PcodeOp| match operation {
                PcodeOp::CallOther {
                    name,
                    output: Some(output),
                    ..
                } if name == "x86_unmodeled_movdqa_side_effecting_v1" => Some(*output),
                _ => None,
            });
    assert!(matches!(token, Some(output) if output.space == Space::Unique));
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, output: Some(output), inputs } if name == "x86_unmodeled_movdqa_result_pure_v1" && output.space == Space::Register && output.size_bytes == 16 && token.is_some_and(|value: Varnode| inputs.first() == Some(&value)))
    }));
}

#[test]
fn truncated_instruction_is_explicit() {
    let instruction: PcodeInstr = single(&[0x48], 0x7000);
    assert_eq!(instruction.status, DecodeStatus::Truncated);
    assert_eq!(instruction.mnemonic, ".byte");
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_decode_truncated_side_effecting_v1")
    }));
}

#[test]
fn unsupported_bitness_is_explicit() {
    let block: DecodedBlock = decode_block_x86(&[0x90], 0x8000, 32);
    assert_eq!(block.consumed, 1);
    assert_eq!(block.instructions.len(), 1);
    assert_eq!(block.instructions[0].status, DecodeStatus::SpecError);
    assert_eq!(block.instructions[0].mnemonic, ".invalid_bitness");
}

#[test]
fn instruction_limit_emits_a_zero_length_marker() {
    let lifter: X86PcodeLifter = X86PcodeLifter::new(64).with_limits(3, 1);
    let block: DecodedBlock = lifter.decode_block(&[0x90, 0x90, 0x90], 0x9000);
    assert_eq!(block.consumed, 1);
    assert_eq!(block.instructions.len(), 2);
    assert_eq!(block.instructions[0].status, DecodeStatus::Supported);
    assert_eq!(block.instructions[1].length, 0);
    assert_eq!(block.instructions[1].status, DecodeStatus::SpecError);
    assert!(block.instructions[1].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_decode_limit_side_effecting_v1")
    }));
}

#[test]
fn curated_scalar_forms_are_modeled() {
    let cases: [(&[u8], &str); 29] = [
        (&[0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00], "mov"),
        (&[0x0f, 0xb6, 0x03], "movzx"),
        (&[0x48, 0x0f, 0xbe, 0x03], "movsx"),
        (&[0x50], "push"),
        (&[0x5b], "pop"),
        (&[0x48, 0x93], "xchg"),
        (&[0x48, 0x29, 0xd8], "sub"),
        (&[0x48, 0x11, 0xd8], "adc"),
        (&[0x48, 0x19, 0xd8], "sbb"),
        (&[0x48, 0x21, 0xd8], "and"),
        (&[0x48, 0x09, 0xd8], "or"),
        (&[0x48, 0x31, 0xd8], "xor"),
        (&[0x48, 0x39, 0xd8], "cmp"),
        (&[0x48, 0x85, 0xd8], "test"),
        (&[0x48, 0xff, 0xc0], "inc"),
        (&[0x48, 0xff, 0xc8], "dec"),
        (&[0x48, 0xf7, 0xd8], "neg"),
        (&[0x48, 0xf7, 0xd0], "not"),
        (&[0x48, 0xd1, 0xe0], "shl"),
        (&[0x48, 0xd1, 0xe8], "shr"),
        (&[0x48, 0xd1, 0xf8], "sar"),
        (&[0x48, 0x0f, 0xaf, 0xc3], "imul"),
        (&[0x48, 0xf7, 0xe3], "mul"),
        (&[0xeb, 0x02], "jmp"),
        (&[0xff, 0xe0], "jmp"),
        (&[0xe8, 0x00, 0x00, 0x00, 0x00], "call"),
        (&[0xff, 0xd0], "call"),
        (&[0xc3], "ret"),
        (&[0xc9], "leave"),
    ];
    for (index, (bytes, mnemonic)) in cases.into_iter().enumerate() {
        let address: u64 = 0xa000_u64.wrapping_add(u64::try_from(index).unwrap_or(u64::MAX) * 32);
        let instruction: PcodeInstr = single(bytes, address);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::Supported, "{bytes:02x?}");
    }
    for (bytes, mnemonic) in [
        (&[0x90_u8][..], "nop"),
        (&[0xf3, 0x0f, 0x1e, 0xfa][..], "endbr64"),
    ] {
        let instruction: PcodeInstr = single(bytes, 0xb000);
        assert_eq!(instruction.mnemonic, mnemonic);
        assert_eq!(instruction.status, DecodeStatus::Supported);
        assert!(instruction.ops.is_empty());
    }
}

#[test]
fn extension_moves_use_typed_extension_ops() {
    let zero: PcodeInstr = single(&[0x0f, 0xb6, 0x03], 0xc000);
    assert!(zero.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntZext { output, input } if output.size_bytes == 4 && input.size_bytes == 1)
    }));
    let sign: PcodeInstr = single(&[0x48, 0x0f, 0xbe, 0x03], 0xc100);
    assert!(sign.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntSext { output, input } if output.size_bytes == 8 && input.size_bytes == 1)
    }));
}

#[test]
fn thirty_two_bit_register_writes_zero_extend_the_full_register() {
    let instruction: PcodeInstr = single(&[0x89, 0xd8], 0xc200);
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntZext { output, input } if output.space == Space::Register && output.offset == 0 && output.size_bytes == 8 && input.space == Space::Register && input.offset == 0 && input.size_bytes == 4)
    }));
}

#[test]
fn compare_and_test_do_not_write_their_left_operand() {
    for bytes in [&[0x48, 0x39, 0xd8][..], &[0x48, 0x85, 0xd8][..]] {
        let instruction: PcodeInstr = single(bytes, 0xc300);
        let writes_rax: bool = instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Copy { output, .. } if output.space == Space::Register && output.offset == 0 && output.size_bytes == 8)
        });
        assert!(!writes_rax, "{bytes:02x?}");
    }
}

#[test]
fn increment_preserves_carry_and_logic_marks_auxiliary_undefined() {
    let increment: PcodeInstr = single(&[0x48, 0xff, 0xc0], 0xc400);
    let writes_carry: bool = increment.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Copy { output, .. } | PcodeOp::IntCarry { output, .. } | PcodeOp::CallOther { output: Some(output), .. } if output.offset == 0x200)
    });
    assert!(!writes_carry);
    let logic: PcodeInstr = single(&[0x48, 0x31, 0xd8], 0xc500);
    assert!(logic.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Copy { output, input } if output.offset == 0x200 && input.space == Space::Constant && input.offset == 0)
    }));
    assert!(logic.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Copy { output, input } if output.offset == 0x20b && input.space == Space::Constant && input.offset == 0)
    }));
    assert!(logic.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, output: Some(output), .. } if name == "x86_undefined_flag_pure_v1" && output.offset == 0x204)
    }));
}

#[test]
fn shifts_emit_result_carry_and_overflow_effects() {
    for bytes in [
        &[0x48, 0xd1, 0xe0][..],
        &[0x48, 0xd1, 0xe8][..],
        &[0x48, 0xd1, 0xf8][..],
    ] {
        let instruction: PcodeInstr = single(bytes, 0xc600);
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(
                operation,
                PcodeOp::IntLeft { .. } | PcodeOp::IntRight { .. } | PcodeOp::IntSignedRight { .. }
            )
        }));
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::IntNotEqual { output, .. } | PcodeOp::IntSignedLess { output, .. } if output.offset == 0x200)
        }));
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Copy { output, .. } | PcodeOp::BoolXor { output, .. } if output.offset == 0x20b)
        }));
    }
}

#[test]
fn stack_and_call_effects_are_ordered_before_transfer() {
    let push: PcodeInstr = single(&[0x50], 0xc700);
    let push_store: usize = push
        .ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::Store { .. }))
        .unwrap_or(usize::MAX);
    let push_update: usize = push
        .ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::IntSub { output, .. } if output.offset == 0x20))
        .unwrap_or(usize::MAX);
    assert!(push_update < push_store);
    let pop_memory: PcodeInstr = single(&[0x8f, 0x04, 0x24], 0xc780);
    assert_eq!(pop_memory.status, DecodeStatus::Supported);
    let pop_update: usize = pop_memory
        .ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::IntAdd { output, .. } if output.offset == 0x20))
        .unwrap_or(usize::MAX);
    let pop_store: usize = pop_memory
        .ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::Store { pointer, .. } if pointer.offset == 0x20))
        .unwrap_or(usize::MAX);
    assert!(pop_update < pop_store);
    let call: PcodeInstr = single(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0xc800);
    let transfer: usize = call
        .ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::Call { .. }))
        .unwrap_or(usize::MAX);
    let store: usize = call
        .ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::Store { .. }))
        .unwrap_or(usize::MAX);
    assert!(store < transfer);
    let return_instruction: PcodeInstr = single(&[0xc3], 0xc900);
    assert!(matches!(
        return_instruction.ops.last(),
        Some(PcodeOp::Return { target: Some(_) })
    ));
}

#[test]
fn memory_store_uses_an_explicit_store_op() {
    let instruction: PcodeInstr = single(&[0x48, 0x89, 0x18], 0xca00);
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Store { space: Space::Ram, pointer, value } if pointer.size_bytes == 8 && value.offset == 0x18)
    }));
}

#[test]
fn division_uses_a_checked_typed_contract() {
    for (bytes, signed, name) in [
        (
            &[0x48, 0xf7, 0xf3][..],
            false,
            "x86_divide_unsigned_checked_side_effecting_v1",
        ),
        (
            &[0x48, 0xf7, 0xfb][..],
            true,
            "x86_divide_signed_checked_side_effecting_v1",
        ),
        (
            &[0x48, 0xf7, 0xf0][..],
            false,
            "x86_divide_unsigned_checked_side_effecting_v1",
        ),
        (
            &[0x48, 0xf7, 0xf2][..],
            false,
            "x86_divide_unsigned_checked_side_effecting_v1",
        ),
    ] {
        let instruction: PcodeInstr = single(bytes, 0xcb00);
        assert_eq!(instruction.status, DecodeStatus::CallOther);
        let outputs: Vec<Varnode> = instruction
            .ops
            .iter()
            .filter_map(|operation: &PcodeOp| match operation {
                PcodeOp::CallOther {
                    name: operation_name,
                    output,
                    inputs,
                } if operation_name == name && inputs.len() >= 3 => *output,
                _ => None,
            })
            .collect();
        assert!(outputs.iter().any(|output: &Varnode| output.offset == 0));
        assert!(outputs.iter().any(|output: &Varnode| output.offset == 0x10));
        let inputs: Vec<Vec<Varnode>> = instruction
            .ops
            .iter()
            .filter_map(|operation: &PcodeOp| match operation {
                PcodeOp::CallOther {
                    name: operation_name,
                    inputs,
                    ..
                } if operation_name == name => Some(inputs.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(inputs.len(), 2);
        assert_eq!(&inputs[0][..3], &inputs[1][..3]);
        assert!(
            inputs[0][..3]
                .iter()
                .all(|input: &Varnode| input.space == Space::Unique)
        );
        assert_eq!(signed, instruction.mnemonic == "idiv");
    }
}

#[test]
fn string_atomic_and_system_forms_have_memory_or_side_effect_summaries() {
    for (bytes, expected_name) in [
        (&[0xf3, 0xa4][..], "x86_rep_movsb_reads_writes_mem_v1"),
        (
            &[0xf0, 0x48, 0x01, 0x18][..],
            "x86_atomic_add_side_effecting_v1",
        ),
        (&[0x0f, 0x05][..], "x86_unmodeled_syscall_side_effecting_v1"),
    ] {
        let instruction: PcodeInstr = single(bytes, 0xcc00);
        assert_eq!(instruction.status, DecodeStatus::CallOther);
        assert!(
            instruction.ops.iter().any(|operation: &PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. } if name == expected_name)
            }),
            "expected {expected_name}, got {:?}",
            instruction.ops
        );
    }
    let locked_add: PcodeInstr = single(&[0xf0, 0x48, 0x01, 0x18], 0xcc08);
    let effect_count: usize = locked_add
        .ops
        .iter()
        .filter(|operation: &&PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_atomic_add_side_effecting_v1")
        })
        .count();
    assert_eq!(effect_count, 1);
    let effect_token: Option<Varnode> =
        locked_add
            .ops
            .iter()
            .find_map(|operation: &PcodeOp| match operation {
                PcodeOp::CallOther {
                    name,
                    output: Some(output),
                    ..
                } if name == "x86_atomic_add_side_effecting_v1" => Some(*output),
                _ => None,
            });
    assert!(matches!(effect_token, Some(token) if token.space == Space::Unique));
    assert!(locked_add.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, output: Some(_), inputs } if name == "x86_atomic_add_result_pure_v1" && effect_token.is_some_and(|token: Varnode| inputs.first() == Some(&token)))
    }));
    let rotate: PcodeInstr = single(&[0x48, 0xc1, 0xc0, 0x05], 0xcc10);
    assert_eq!(rotate.status, DecodeStatus::CallOther);
    assert!(rotate.ops.iter().any(|operation: &PcodeOp| {
        matches!(
            operation,
            PcodeOp::CallOther { name, inputs, .. }
                if name == "x86_unmodeled_rol_pure_v1"
                    && inputs.iter().any(|input: &Varnode| {
                        input.space == Space::Constant
                            && input.offset == 5
                            && input.size_bytes == 1
                    })
        )
    }));
}

#[test]
fn all_setcc_and_cmovcc_conditions_are_modeled() {
    let set_cases: [(&[u8], &str); 16] = [
        (&[0x0f, 0x90, 0xc0], "seto"),
        (&[0x0f, 0x91, 0xc0], "setno"),
        (&[0x0f, 0x92, 0xc0], "setb"),
        (&[0x0f, 0x93, 0xc0], "setae"),
        (&[0x0f, 0x94, 0xc0], "sete"),
        (&[0x0f, 0x95, 0xc0], "setne"),
        (&[0x0f, 0x96, 0xc0], "setbe"),
        (&[0x0f, 0x97, 0xc0], "seta"),
        (&[0x0f, 0x98, 0xc0], "sets"),
        (&[0x0f, 0x99, 0xc0], "setns"),
        (&[0x0f, 0x9a, 0xc0], "setp"),
        (&[0x0f, 0x9b, 0xc0], "setnp"),
        (&[0x0f, 0x9c, 0xc0], "setl"),
        (&[0x0f, 0x9d, 0xc0], "setge"),
        (&[0x0f, 0x9e, 0xc0], "setle"),
        (&[0x0f, 0x9f, 0xc0], "setg"),
    ];
    for (bytes, mnemonic) in set_cases {
        let instruction: PcodeInstr = single(bytes, 0xd400);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::Supported, "{bytes:02x?}");
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Copy { output, .. } if output.space == Space::Register && output.offset == 0 && output.size_bytes == 1)
        }));
    }

    let cmov_cases: [(&[u8], &str); 16] = [
        (&[0x48, 0x0f, 0x40, 0xc3], "cmovo"),
        (&[0x48, 0x0f, 0x41, 0xc3], "cmovno"),
        (&[0x48, 0x0f, 0x42, 0xc3], "cmovb"),
        (&[0x48, 0x0f, 0x43, 0xc3], "cmovae"),
        (&[0x48, 0x0f, 0x44, 0xc3], "cmove"),
        (&[0x48, 0x0f, 0x45, 0xc3], "cmovne"),
        (&[0x48, 0x0f, 0x46, 0xc3], "cmovbe"),
        (&[0x48, 0x0f, 0x47, 0xc3], "cmova"),
        (&[0x48, 0x0f, 0x48, 0xc3], "cmovs"),
        (&[0x48, 0x0f, 0x49, 0xc3], "cmovns"),
        (&[0x48, 0x0f, 0x4a, 0xc3], "cmovp"),
        (&[0x48, 0x0f, 0x4b, 0xc3], "cmovnp"),
        (&[0x48, 0x0f, 0x4c, 0xc3], "cmovl"),
        (&[0x48, 0x0f, 0x4d, 0xc3], "cmovge"),
        (&[0x48, 0x0f, 0x4e, 0xc3], "cmovle"),
        (&[0x48, 0x0f, 0x4f, 0xc3], "cmovg"),
    ];
    for (bytes, mnemonic) in cmov_cases {
        let instruction: PcodeInstr = single(bytes, 0xd500);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::Supported, "{bytes:02x?}");
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Copy { output, .. } if output.space == Space::Register && output.offset == 0 && output.size_bytes == 8)
        }));
        assert!(!instruction.ops.iter().any(PcodeOp::is_callother));
    }

    let memory_source: PcodeInstr = single(&[0x48, 0x0f, 0x45, 0x03], 0xd600);
    assert_eq!(memory_source.status, DecodeStatus::Supported);
    assert!(
        memory_source
            .ops
            .iter()
            .any(|operation: &PcodeOp| matches!(operation, PcodeOp::Load { .. }))
    );
}

#[test]
fn bit_and_extended_integer_families_use_exact_or_named_contracts() {
    let exact_cases: [(&[u8], &str); 18] = [
        (&[0x48, 0x0f, 0xa3, 0xc8], "bt"),
        (&[0x48, 0x0f, 0xab, 0xc8], "bts"),
        (&[0x48, 0x0f, 0xb3, 0xc8], "btr"),
        (&[0x48, 0x0f, 0xbb, 0xc8], "btc"),
        (&[0x48, 0x0f, 0xc8], "bswap"),
        (&[0x48, 0x0f, 0xc1, 0xd8], "xadd"),
        (&[0x66, 0x98], "cbw"),
        (&[0x98], "cwde"),
        (&[0x48, 0x98], "cdqe"),
        (&[0x66, 0x99], "cwd"),
        (&[0x99], "cdq"),
        (&[0x48, 0x99], "cqo"),
        (&[0x48, 0x63, 0xc3], "movsxd"),
        (&[0x48, 0x0f, 0xaf, 0xc3], "imul"),
        (&[0x48, 0x6b, 0xc3, 0x07], "imul"),
        (&[0x48, 0x0f, 0xa4, 0xd8, 0x04], "shld"),
        (&[0x48, 0x0f, 0xac, 0xd8, 0x04], "shrd"),
        (&[0x0f, 0xc8], "bswap"),
    ];
    for (bytes, mnemonic) in exact_cases {
        let instruction: PcodeInstr = single(bytes, 0xd700);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::Supported, "{bytes:02x?}");
    }

    let opaque_cases: [(&[u8], &str, &str); 8] = [
        (&[0x48, 0x0f, 0xbc, 0xc3], "bsf", "x86_bsf_result_pure_v1"),
        (&[0x48, 0x0f, 0xbd, 0xc3], "bsr", "x86_bsr_result_pure_v1"),
        (
            &[0xf3, 0x48, 0x0f, 0xb8, 0xc3],
            "popcnt",
            "x86_popcount_pure_v1",
        ),
        (
            &[0xf3, 0x48, 0x0f, 0xbc, 0xc3],
            "tzcnt",
            "x86_tzcount_pure_v1",
        ),
        (
            &[0xf3, 0x48, 0x0f, 0xbd, 0xc3],
            "lzcnt",
            "x86_lzcount_pure_v1",
        ),
        (&[0x48, 0xd3, 0xe0], "shl", "x86_shift_shl_pure_v1"),
        (&[0x48, 0x0f, 0xa5, 0xd8], "shld", "x86_shift_shld_pure_v1"),
        (&[0x48, 0x0f, 0xad, 0xd8], "shrd", "x86_shift_shrd_pure_v1"),
    ];
    for (bytes, mnemonic, contract) in opaque_cases {
        let instruction: PcodeInstr = single(bytes, 0xd800);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::CallOther, "{bytes:02x?}");
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == contract)
        }));
    }

    let memory_contracts: [(&[u8], &str); 4] = [
        (&[0x48, 0x0f, 0xbc, 0x00], "x86_bsf_reads_mem_v1"),
        (&[0xf3, 0x48, 0x0f, 0xb8, 0x00], "x86_popcount_reads_mem_v1"),
        (&[0x48, 0xd3, 0x20], "x86_shift_shl_reads_writes_mem_v1"),
        (
            &[0x48, 0x0f, 0xa5, 0x18],
            "x86_shift_shld_reads_writes_mem_v1",
        ),
    ];
    for (bytes, contract) in memory_contracts {
        let instruction: PcodeInstr = single(bytes, 0xd880);
        assert_eq!(instruction.status, DecodeStatus::CallOther, "{bytes:02x?}");
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(
                operation,
                PcodeOp::CallOther {
                    name,
                    output: Some(output),
                    ..
                } if name == contract && output.space == Space::Unique
            )
        }));
    }

    let bit_test: PcodeInstr = single(&[0x48, 0x0f, 0xa3, 0xc8], 0xd900);
    assert!(bit_test.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntNotEqual { output, .. } if output.space == Space::Register && output.offset == 0x200)
    }));

    let aliased_xadd: PcodeInstr = single(&[0x48, 0x0f, 0xc1, 0x00], 0xd910);
    let load_pointer: Option<Varnode> =
        aliased_xadd
            .ops
            .iter()
            .find_map(|operation: &PcodeOp| match operation {
                PcodeOp::Load { pointer, .. } => Some(*pointer),
                _ => None,
            });
    let store_pointer: Option<Varnode> =
        aliased_xadd
            .ops
            .iter()
            .find_map(|operation: &PcodeOp| match operation {
                PcodeOp::Store { pointer, .. } => Some(*pointer),
                _ => None,
            });
    assert!(
        matches!(load_pointer, Some(pointer) if pointer.space == Space::Register && pointer.offset == 0)
    );
    assert!(matches!(store_pointer, Some(pointer) if pointer.space == Space::Unique));
    assert!(aliased_xadd.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Copy { output, input } if Some(*output) == store_pointer && Some(*input) == load_pointer)
    }));

    let dynamic_shift: PcodeInstr = single(&[0x48, 0xd3, 0xe0], 0xd920);
    let shift_inputs: BTreeSet<u64> = dynamic_shift
        .ops
        .iter()
        .filter_map(|operation: &PcodeOp| match operation {
            PcodeOp::Copy { input, .. } if input.space == Space::Register => Some(input.offset),
            _ => None,
        })
        .collect();
    assert!(
        [0x200_u64, 0x202, 0x204, 0x206, 0x207, 0x20b]
            .into_iter()
            .all(|offset: u64| shift_inputs.contains(&offset))
    );

    let single_shrd: PcodeInstr = single(&[0x48, 0x0f, 0xac, 0xd8, 0x01], 0xd930);
    assert!(single_shrd.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::BoolXor { output, .. } if output.space == Space::Register && output.offset == 0x20b)
    }));
}

#[test]
fn scalar_sse_moves_and_bitwise_ops_are_exact() {
    let cases: [(&[u8], &str); 15] = [
        (&[0xf3, 0x0f, 0x10, 0xc1], "movss"),
        (&[0xf2, 0x0f, 0x10, 0xc1], "movsd"),
        (&[0x0f, 0x28, 0xc1], "movaps"),
        (&[0x0f, 0x10, 0xc1], "movups"),
        (&[0x66, 0x0f, 0x6e, 0xc3], "movd"),
        (&[0x66, 0x0f, 0x7e, 0xc3], "movd"),
        (&[0x66, 0x48, 0x0f, 0x6e, 0xc3], "movq"),
        (&[0x66, 0x48, 0x0f, 0x7e, 0xc3], "movq"),
        (&[0xf3, 0x0f, 0x7e, 0xc1], "movq"),
        (&[0x66, 0x0f, 0xef, 0xc1], "pxor"),
        (&[0x0f, 0x57, 0xc1], "xorps"),
        (&[0x66, 0x0f, 0x57, 0xc1], "xorpd"),
        (&[0x0f, 0x54, 0xc1], "andps"),
        (&[0x0f, 0x56, 0xc1], "orps"),
        (&[0xf3, 0x0f, 0x11, 0x00], "movss"),
    ];
    for (bytes, mnemonic) in cases {
        let instruction: PcodeInstr = single(bytes, 0xda00);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::Supported, "{bytes:02x?}");
    }

    let memory_load: PcodeInstr = single(&[0xf3, 0x0f, 0x10, 0x00], 0xdb00);
    let written_lanes: BTreeSet<u64> = memory_load
        .ops
        .iter()
        .filter_map(|operation: &PcodeOp| match operation {
            PcodeOp::Copy { output, .. }
                if output.space == Space::Register && output.size_bytes == 4 =>
            {
                Some(output.offset)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        written_lanes,
        BTreeSet::from([0x1200, 0x1204, 0x1208, 0x120c])
    );

    let aligned_load: PcodeInstr = single(&[0x0f, 0x28, 0x00], 0xdb10);
    assert_eq!(aligned_load.status, DecodeStatus::CallOther);
    assert!(aligned_load.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_aligned_movaps_reads_mem_v1")
    }));
    assert!(!aligned_load.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Load { .. } | PcodeOp::Store { .. })
    }));

    let aligned_store: PcodeInstr = single(&[0x0f, 0x29, 0x00], 0xdb20);
    assert_eq!(aligned_store.status, DecodeStatus::CallOther);
    assert!(aligned_store.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_aligned_movaps_writes_mem_v1")
    }));
    assert!(!aligned_store.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Load { .. } | PcodeOp::Store { .. })
    }));
}

#[test]
fn mxcsr_sensitive_scalar_sse_ops_use_typed_contracts() {
    let cases: [(&[u8], &str); 28] = [
        (&[0xf3, 0x0f, 0x58, 0xc1], "addss"),
        (&[0xf2, 0x0f, 0x58, 0xc1], "addsd"),
        (&[0xf3, 0x0f, 0x5c, 0xc1], "subss"),
        (&[0xf2, 0x0f, 0x5c, 0xc1], "subsd"),
        (&[0xf3, 0x0f, 0x59, 0xc1], "mulss"),
        (&[0xf2, 0x0f, 0x59, 0xc1], "mulsd"),
        (&[0xf3, 0x0f, 0x5e, 0xc1], "divss"),
        (&[0xf2, 0x0f, 0x5e, 0xc1], "divsd"),
        (&[0xf3, 0x0f, 0x51, 0xc1], "sqrtss"),
        (&[0xf2, 0x0f, 0x51, 0xc1], "sqrtsd"),
        (&[0x0f, 0x2f, 0xc1], "comiss"),
        (&[0x66, 0x0f, 0x2f, 0xc1], "comisd"),
        (&[0x0f, 0x2e, 0xc1], "ucomiss"),
        (&[0x66, 0x0f, 0x2e, 0xc1], "ucomisd"),
        (&[0xf3, 0x0f, 0x2a, 0xc3], "cvtsi2ss"),
        (&[0xf2, 0x0f, 0x2a, 0xc3], "cvtsi2sd"),
        (&[0xf3, 0x48, 0x0f, 0x2a, 0xc3], "cvtsi2ss"),
        (&[0xf2, 0x48, 0x0f, 0x2a, 0xc3], "cvtsi2sd"),
        (&[0xf3, 0x0f, 0x2d, 0xc1], "cvtss2si"),
        (&[0xf2, 0x0f, 0x2d, 0xc1], "cvtsd2si"),
        (&[0xf3, 0x48, 0x0f, 0x2d, 0xc1], "cvtss2si"),
        (&[0xf2, 0x48, 0x0f, 0x2d, 0xc1], "cvtsd2si"),
        (&[0xf3, 0x0f, 0x2c, 0xc1], "cvttss2si"),
        (&[0xf2, 0x0f, 0x2c, 0xc1], "cvttsd2si"),
        (&[0xf3, 0x48, 0x0f, 0x2c, 0xc1], "cvttss2si"),
        (&[0xf2, 0x48, 0x0f, 0x2c, 0xc1], "cvttsd2si"),
        (&[0xf3, 0x0f, 0x5a, 0xc1], "cvtss2sd"),
        (&[0xf2, 0x0f, 0x5a, 0xc1], "cvtsd2ss"),
    ];
    for (bytes, mnemonic) in cases {
        let instruction: PcodeInstr = single(bytes, 0xdc00);
        let expected: String = format!("x86_scalar_{mnemonic}_side_effecting_v1");
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::CallOther, "{bytes:02x?}");
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == &expected)
        }));
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Copy { input, .. } if input.space == Space::Register && input.offset == 0x1094 && input.size_bytes == 4)
        }));
    }
}

#[test]
fn string_iteration_and_repeat_contracts_are_distinct() {
    let exact_cases: [(&[u8], &str); 5] = [
        (&[0x48, 0xa5], "movsq"),
        (&[0x48, 0xab], "stosq"),
        (&[0x48, 0xad], "lodsq"),
        (&[0x48, 0xa7], "cmpsq"),
        (&[0x48, 0xaf], "scasq"),
    ];
    for (bytes, mnemonic) in exact_cases {
        let instruction: PcodeInstr = single(bytes, 0xdd00);
        assert_eq!(instruction.mnemonic, mnemonic, "{bytes:02x?}");
        assert_eq!(instruction.status, DecodeStatus::Supported, "{bytes:02x?}");
    }

    let repeat_cases: [(&[u8], &str); 5] = [
        (&[0xf3, 0xa4], "x86_rep_movsb_reads_writes_mem_v1"),
        (&[0xf3, 0x48, 0xab], "x86_rep_stosq_writes_mem_v1"),
        (&[0xf3, 0x48, 0xad], "x86_rep_lodsq_reads_mem_v1"),
        (&[0xf3, 0xa6], "x86_repe_cmpsb_reads_mem_v1"),
        (&[0xf2, 0xae], "x86_repne_scasb_reads_mem_v1"),
    ];
    for (bytes, contract) in repeat_cases {
        let instruction: PcodeInstr = single(bytes, 0xde00);
        assert_eq!(instruction.status, DecodeStatus::CallOther, "{bytes:02x?}");
        assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == contract)
        }));
        assert!(!instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Load { .. } | PcodeOp::Store { .. })
        }));
        let copied_registers: BTreeSet<u64> = instruction
            .ops
            .iter()
            .filter_map(|operation: &PcodeOp| match operation {
                PcodeOp::Copy { input, .. } if input.space == Space::Register => Some(input.offset),
                _ => None,
            })
            .collect();
        assert!(copied_registers.contains(&0x20a));
    }

    let repeating_compare: PcodeInstr = single(&[0xf3, 0xa6], 0xde10);
    let comparison_inputs: BTreeSet<u64> = repeating_compare
        .ops
        .iter()
        .filter_map(|operation: &PcodeOp| match operation {
            PcodeOp::Copy { input, .. } if input.space == Space::Register => Some(input.offset),
            _ => None,
        })
        .collect();
    assert!(
        [0x200_u64, 0x202, 0x204, 0x206, 0x207, 0x20a, 0x20b]
            .into_iter()
            .all(|offset: u64| comparison_inputs.contains(&offset))
    );
}

#[test]
fn atomic_forms_use_one_ordering_boundary_without_plain_memory_ops() {
    let cases: [(&[u8], &str); 6] = [
        (
            &[0xf0, 0x48, 0x01, 0x18],
            "x86_atomic_add_side_effecting_v1",
        ),
        (
            &[0xf0, 0x48, 0x0f, 0xc1, 0x18],
            "x86_atomic_xadd_side_effecting_v1",
        ),
        (&[0x48, 0x87, 0x18], "x86_atomic_xchg_side_effecting_v1"),
        (
            &[0x48, 0x0f, 0xb1, 0x18],
            "x86_atomic_cmpxchg_side_effecting_v1",
        ),
        (
            &[0x0f, 0xc7, 0x0f],
            "x86_atomic_cmpxchg8b_side_effecting_v1",
        ),
        (
            &[0x48, 0x0f, 0xc7, 0x0f],
            "x86_atomic_cmpxchg16b_side_effecting_v1",
        ),
    ];
    for (bytes, contract) in cases {
        let instruction: PcodeInstr = single(bytes, 0xdf00);
        assert_eq!(instruction.status, DecodeStatus::CallOther, "{bytes:02x?}");
        let boundaries: usize = instruction
            .ops
            .iter()
            .filter(|operation: &&PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. } if name == contract)
            })
            .count();
        assert_eq!(boundaries, 1, "{bytes:02x?}");
        assert!(!instruction.ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::Load { .. } | PcodeOp::Store { .. })
        }));
    }
}

#[test]
fn addresses_wrap_at_the_declared_address_size() {
    let instruction: PcodeInstr = single(&[0x67, 0x0f, 0x10, 0x44, 0x88, 0x10], 0xcc20);
    assert_eq!(instruction.status, DecodeStatus::Supported);
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntAdd { output, left, right } if output.size_bytes == 4 && left.size_bytes == 4 && right.size_bytes == 4)
    }));
    assert!(instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntZext { output, input } if output.size_bytes == 8 && input.size_bytes == 4)
    }));
    let absolute: PcodeInstr = single(
        &[0x67, 0x0f, 0x10, 0x04, 0x25, 0xff, 0xff, 0xff, 0xff],
        0xcc28,
    );
    assert_eq!(absolute.status, DecodeStatus::Supported);
    assert!(absolute.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntZext { output, input } if output.size_bytes == 8 && input.space == Space::Constant && input.offset == 0xffff_ffff && input.size_bytes == 4)
    }));
    let absolute64: PcodeInstr = single(&[0x0f, 0x10, 0x04, 0x25, 0xff, 0xff, 0xff, 0xff], 0xcc30);
    assert_eq!(absolute64.status, DecodeStatus::Supported);
    assert!(absolute64.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Load { pointer, .. } if pointer.space == Space::Constant && pointer.offset == u64::MAX && pointer.size_bytes == 8)
    }));
}

#[test]
fn only_leaveq_uses_the_modeled_stack_width() {
    let leaveq: PcodeInstr = single(&[0xc9], 0xcc30);
    assert_eq!(leaveq.status, DecodeStatus::Supported);
    let leavew: PcodeInstr = single(&[0x66, 0xc9], 0xcc40);
    assert_eq!(leavew.status, DecodeStatus::CallOther);
    assert!(leavew.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_unmodeled_leave_reads_mem_v1")
    }));
}

#[test]
fn lea_ignores_segment_bases_and_memory_exchange_is_atomic() {
    let lea: PcodeInstr = single(&[0x64, 0x48, 0x8d, 0x00], 0xcd00);
    assert_eq!(lea.status, DecodeStatus::Supported);
    assert!(!lea.ops.iter().any(|operation: &PcodeOp| {
        matches!(
            operation,
            PcodeOp::IntAdd { left, right, .. }
                if left.offset == 0x110 || right.offset == 0x110
        )
    }));
    let exchange: PcodeInstr = single(&[0x48, 0x87, 0x18], 0xce00);
    assert_eq!(exchange.status, DecodeStatus::CallOther);
    assert!(exchange.ops.iter().any(|operation: &PcodeOp| {
        matches!(
            operation,
            PcodeOp::CallOther { name, .. }
                if name == "x86_atomic_xchg_side_effecting_v1"
        )
    }));
    let self_exchange: PcodeInstr = single(&[0x87, 0xc0], 0xce10);
    assert_eq!(self_exchange.status, DecodeStatus::Supported);
    assert!(self_exchange.ops.iter().any(|operation: &PcodeOp| {
        matches!(
            operation,
            PcodeOp::IntZext { output, input }
                if output.offset == 0
                    && output.size_bytes == 8
                    && input.offset == 0
                    && input.size_bytes == 4
        )
    }));
}

#[test]
fn byte_multiply_and_divide_use_the_accumulator_pair() {
    let multiply: PcodeInstr = single(&[0xf6, 0xe3], 0xcf00);
    assert_eq!(multiply.status, DecodeStatus::Supported);
    let written: Vec<Varnode> = multiply
        .ops
        .iter()
        .filter_map(|operation: &PcodeOp| match operation {
            PcodeOp::Copy { output, .. } if output.space == Space::Register => Some(*output),
            _ => None,
        })
        .collect();
    assert!(
        written
            .iter()
            .any(|output: &Varnode| output.offset == 0 && output.size_bytes == 1)
    );
    assert!(
        written
            .iter()
            .any(|output: &Varnode| output.offset == 1 && output.size_bytes == 1)
    );
    let divide: PcodeInstr = single(&[0xf6, 0xf3], 0xd000);
    assert_eq!(divide.status, DecodeStatus::CallOther);
    let outputs: Vec<Varnode> = divide
        .ops
        .iter()
        .filter_map(|operation: &PcodeOp| match operation {
            PcodeOp::CallOther { output, .. } => *output,
            _ => None,
        })
        .collect();
    assert!(
        outputs
            .iter()
            .any(|output: &Varnode| output.offset == 0 && output.size_bytes == 1)
    );
    assert!(
        outputs
            .iter()
            .any(|output: &Varnode| output.offset == 1 && output.size_bytes == 1)
    );
}

#[test]
fn malformed_and_bounded_inputs_remain_explicit() {
    for value in 0_u16..=u16::from(u8::MAX) {
        let byte: u8 = u8::try_from(value).unwrap_or(u8::MAX);
        let block: DecodedBlock = decode_block_x86(&[byte], 0xd100, 64);
        assert_eq!(block.consumed, 1);
        assert!(!block.instructions.is_empty());
        assert!(block.instructions.iter().all(|instruction: &PcodeInstr| {
            matches!(
                instruction.status,
                DecodeStatus::Supported
                    | DecodeStatus::CallOther
                    | DecodeStatus::NoMatch
                    | DecodeStatus::Truncated
            )
        }));
    }
    for bytes in [
        &[0x0f_u8][..],
        &[0x62, 0xf1, 0x7c][..],
        &[0xc4, 0xe1][..],
        &[0xf0, 0x48][..],
        &[0x64, 0x67, 0x48, 0x8b][..],
    ] {
        let block: DecodedBlock = decode_block_x86(bytes, 0xd200, 64);
        assert_eq!(block.consumed, bytes.len());
        assert!(!block.instructions.is_empty());
        assert!(block.instructions.iter().any(|instruction: &PcodeInstr| {
            matches!(
                instruction.status,
                DecodeStatus::NoMatch | DecodeStatus::Truncated
            )
        }));
    }
    let bytes: [u8; 128] = [0x90; 128];
    let bounded: DecodedBlock = X86PcodeLifter::new(64)
        .with_limits(17, 64)
        .decode_block(&bytes, 0xd300);
    assert_eq!(bounded.consumed, 17);
    assert_eq!(bounded.instructions.len(), 18);
    assert_eq!(
        bounded
            .instructions
            .last()
            .map(|instruction: &PcodeInstr| instruction.status),
        Some(DecodeStatus::SpecError)
    );
}
