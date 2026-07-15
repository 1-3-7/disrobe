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
fn string_lock_and_system_forms_have_memory_or_side_effect_summaries() {
    for (bytes, expected_name) in [
        (&[0xf3, 0xa4][..], "x86_unmodeled_movsb_writes_mem_v1"),
        (
            &[0xf0, 0x48, 0x01, 0x18][..],
            "x86_unmodeled_add_side_effecting_v1",
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
            matches!(operation, PcodeOp::CallOther { name, .. } if name == "x86_unmodeled_add_side_effecting_v1")
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
                } if name == "x86_unmodeled_add_side_effecting_v1" => Some(*output),
                _ => None,
            });
    assert!(matches!(effect_token, Some(token) if token.space == Space::Unique));
    assert!(locked_add.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, output: Some(_), inputs } if name == "x86_unmodeled_add_result_pure_v1" && effect_token.is_some_and(|token: Varnode| inputs.first() == Some(&token)))
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
fn fallback_addresses_wrap_at_the_declared_address_size() {
    let instruction: PcodeInstr = single(&[0x67, 0x0f, 0x10, 0x44, 0x88, 0x10], 0xcc20);
    assert_eq!(instruction.status, DecodeStatus::CallOther);
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
    assert!(absolute.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntZext { output, input } if output.size_bytes == 8 && input.space == Space::Constant && input.offset == 0xffff_ffff && input.size_bytes == 4)
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
                if name == "x86_unmodeled_xchg_side_effecting_v1"
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
