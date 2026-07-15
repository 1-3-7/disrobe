use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language, decode_block_for_language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp};
use disrobe_sleigh::syntax::Endian;

#[test]
fn decodes_a32_and_thumb_with_variable_instruction_widths() {
    let a32_words: [u32; 4] = [0xe081_0182, 0xe593_200c, 0xe301_5234, 0xe12f_ff1e];
    let a32_bytes: Vec<u8> = a32_words.into_iter().flat_map(u32::to_le_bytes).collect();
    let a32: DecodedBlock =
        decode_block_for_language(Language::Arm32(ArmMode::A32), &a32_bytes, 0x1000);
    assert_eq!(a32.consumed, a32_bytes.len());
    assert_eq!(
        a32.instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
            .collect::<Vec<&str>>(),
        ["add", "ldr", "movw", "bx"]
    );
    assert!(
        a32.instructions
            .iter()
            .all(|instruction: &PcodeInstr| instruction.status == DecodeStatus::Supported)
    );

    let thumb_bytes: [u8; 12] = [
        0x88, 0x18, 0x2a, 0x20, 0x41, 0xf2, 0x34, 0x24, 0xc5, 0xf2, 0x78, 0x64,
    ];
    let thumb: DecodedBlock =
        decode_block_for_language(Language::Arm32(ArmMode::Thumb), &thumb_bytes, 0x2000);
    assert_eq!(thumb.consumed, thumb_bytes.len());
    assert_eq!(
        thumb
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| (instruction.mnemonic.as_str(), instruction.length))
            .collect::<Vec<(&str, usize)>>(),
        [("adds", 2), ("movs", 2), ("movw", 4), ("movt", 4)]
    );
    assert!(
        thumb
            .instructions
            .iter()
            .all(|instruction: &PcodeInstr| instruction.status == DecodeStatus::Supported)
    );
}

#[test]
fn decodes_mips32_in_both_byte_orders() {
    let words: [u32; 6] = [
        0x0064_1020,
        0x2528_fff4,
        0x8cc5_0010,
        0xad07_ffec,
        0x3c09_1234,
        0x014b_0018,
    ];
    for endian in [Endian::Little, Endian::Big] {
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|word: &u32| match endian {
                Endian::Little => word.to_le_bytes(),
                Endian::Big => word.to_be_bytes(),
            })
            .collect();
        let block: DecodedBlock =
            decode_block_for_language(Language::Mips32(endian), &bytes, 0x3000);
        assert_eq!(block.consumed, bytes.len());
        assert_eq!(
            block
                .instructions
                .iter()
                .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
                .collect::<Vec<&str>>(),
            ["add", "addiu", "lw", "sw", "lui", "mult"]
        );
        assert_eq!(block.instructions[0].status, DecodeStatus::CallOther);
        assert!(block.instructions[0].ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::CallOther { name, .. } if name == "mips_overflow_trap")
        }));
        assert!(
            block.instructions[1..]
                .iter()
                .all(|instruction: &PcodeInstr| instruction.status == DecodeStatus::Supported)
        );
    }
}

#[test]
fn schedules_mips_delay_slot_effects_before_the_transfer() {
    let words: [u32; 3] = [0x1043_0001, 0x2484_0001, 0x00e8_3821];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let block: DecodedBlock =
        decode_block_for_language(Language::Mips32(Endian::Little), &bytes, 0x4000);
    assert_eq!(block.instructions.len(), 3);
    assert_eq!(block.instructions[0].mnemonic, "beq");
    assert_eq!(block.instructions[1].mnemonic, "addiu");
    let slot_add: usize = block
        .ordered_ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::IntAdd { output, .. } if output.offset == 0x10))
        .unwrap_or(usize::MAX);
    let transfer: usize = block
        .ordered_ops
        .iter()
        .position(|operation: &PcodeOp| matches!(operation, PcodeOp::CBranch { .. }))
        .unwrap_or(0);
    assert!(slot_add < transfer, "{:#?}", block.ordered_ops);
}

#[test]
fn rejects_missing_mips_delay_slots_and_truncated_instructions() {
    let branch: [u8; 4] = 0x1043_0001_u32.to_le_bytes();
    let missing: DecodedBlock =
        decode_block_for_language(Language::Mips32(Endian::Little), &branch, 0x5000);
    assert_eq!(missing.instructions.len(), 1);
    assert_eq!(missing.instructions[0].status, DecodeStatus::Unsupported);
    assert!(
        missing.instructions[0]
            .ops
            .iter()
            .any(|operation: &PcodeOp| {
                matches!(operation, PcodeOp::CallOther { name, .. } if name == "missing_delay_slot")
            })
    );

    for (language, bytes) in [
        (Language::Arm32(ArmMode::A32), vec![0, 1, 2]),
        (Language::Arm32(ArmMode::Thumb), vec![0]),
        (Language::Mips32(Endian::Big), vec![0, 1, 2]),
    ] {
        let block: DecodedBlock = decode_block_for_language(language, &bytes, 0);
        assert_eq!(block.instructions.len(), 1);
        assert_eq!(block.instructions[0].status, DecodeStatus::Truncated);
    }
}

#[test]
fn rejects_unimplemented_blx_encodings() {
    let a32: DecodedBlock = decode_block_for_language(
        Language::Arm32(ArmMode::A32),
        &[0x00, 0x00, 0x00, 0xfa],
        0x6000,
    );
    assert_ne!(a32.instructions[0].status, DecodeStatus::Supported);
    assert!(!matches!(a32.instructions[0].mnemonic.as_str(), "b" | "bx"));

    let thumb: DecodedBlock =
        decode_block_for_language(Language::Arm32(ArmMode::Thumb), &[0x80, 0x47], 0x6000);
    assert_eq!(thumb.instructions[0].mnemonic, "blx");
    assert_eq!(thumb.instructions[0].status, DecodeStatus::Unsupported);
}

#[test]
fn thumb_pc_reads_and_writes_use_thumb_pipeline_semantics() {
    let read: DecodedBlock =
        decode_block_for_language(Language::Arm32(ArmMode::Thumb), &[0x78, 0x46], 0x7000);
    assert!(matches!(
        read.instructions[0].ops.as_slice(),
        [PcodeOp::Copy { input, .. }]
            if input.space == disrobe_sleigh::pcode::Space::Constant && input.offset == 0x7004
    ));

    for bytes in [[0x87, 0x46], [0x87, 0x44]] {
        let write: DecodedBlock =
            decode_block_for_language(Language::Arm32(ArmMode::Thumb), &bytes, 0x7100);
        assert!(matches!(
            write.instructions[0].ops.last(),
            Some(PcodeOp::BranchIndirect { .. })
        ));
        assert!(write.instructions[0].ops.iter().any(|operation: &PcodeOp| {
            matches!(operation, PcodeOp::IntAnd { right, .. } if right.space == disrobe_sleigh::pcode::Space::Constant && right.offset == 0xffff_fffe)
        }));
    }
}

#[test]
fn arm_pop_emits_writeback_before_return() {
    for (mode, bytes) in [
        (ArmMode::A32, vec![0xf0, 0x80, 0xbd, 0xe8]),
        (ArmMode::Thumb, vec![0xf0, 0xbd]),
    ] {
        let block: DecodedBlock = decode_block_for_language(Language::Arm32(mode), &bytes, 0x8000);
        assert_eq!(block.instructions[0].mnemonic, "pop");
        assert!(matches!(
            block.instructions[0].ops.last(),
            Some(PcodeOp::Return { .. })
        ));
    }
}

#[test]
fn mips_trapping_arithmetic_keeps_the_trap_when_r0_discards_the_result() {
    let bytes: [u8; 4] = 0x0109_0020_u32.to_le_bytes();
    let block: DecodedBlock =
        decode_block_for_language(Language::Mips32(Endian::Little), &bytes, 0x9000);
    assert_eq!(block.instructions[0].mnemonic, "add");
    assert_eq!(block.instructions[0].status, DecodeStatus::CallOther);
    assert!(block.instructions[0].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::CallOther { name, .. } if name == "mips_overflow_trap")
    }));
}
