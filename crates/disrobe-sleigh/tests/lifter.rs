use disrobe_sleigh::coverage::{
    DECODE_STATUSES, DecodeReport, StatusCounts, decode_block_with_coverage, status_name,
};
use disrobe_sleigh::decode_block;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp};

#[test]
fn lifts_common_scalar_instructions_to_width_explicit_pcode() {
    let words: [u32; 10] = [
        0x8b01_0000,
        0x9100_4000,
        0xd100_4000,
        0xaa00_03e2,
        0xd280_0aa1,
        0xd37f_f800,
        0xca01_0000,
        0xf940_0000,
        0xf900_0041,
        0xd65f_03c0,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let instructions: Vec<PcodeInstr> = decode_block(&bytes, 0x1000);
    assert_eq!(instructions.len(), words.len());
    assert!(
        instructions.iter().all(|instruction| {
            instruction.status == DecodeStatus::Supported && instruction.length == 4
        }),
        "{instructions:#?}"
    );
    assert!(matches!(
        instructions[0].ops.as_slice(),
        [PcodeOp::IntAdd { .. }]
    ));
    assert!(
        instructions[3]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::Copy { .. }))
    );
    assert!(
        instructions[5]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::IntLeft { .. }))
    );
    assert!(
        instructions[7]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::Load { .. }))
    );
    assert!(
        instructions[8]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::Store { .. }))
    );
    assert!(matches!(
        instructions[9].ops.as_slice(),
        [PcodeOp::Return { .. }]
    ));
}

#[test]
fn lifts_flags_conditions_calls_and_pair_memory_forms() {
    let words: [u32; 10] = [
        0x7100_001f,
        0x5400_0061,
        0x1a80_1020,
        0x3400_0040,
        0x9400_0002,
        0xa9bf_7bfd,
        0xa8c1_7bfd,
        0xd61f_0020,
        0xd63f_0020,
        0xd63f_03c0,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let instructions: Vec<PcodeInstr> = decode_block(&bytes, 0x2000);
    assert!(
        instructions.iter().all(|instruction| {
            instruction.status == DecodeStatus::Supported && instruction.length == 4
        }),
        "{instructions:#?}"
    );
    assert!(
        instructions[0]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::IntEqual { .. }))
    );
    assert!(
        instructions[1]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::CBranch { .. }))
    );
    assert!(
        instructions[2]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::IntMult { .. }))
    );
    assert!(
        instructions[4]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::Call { .. }))
    );
    assert!(instructions[4].ops.iter().any(|operation| {
        matches!(
            operation,
            PcodeOp::Copy { output, input }
                if output.space == disrobe_sleigh::pcode::Space::Register
                    && input.space == disrobe_sleigh::pcode::Space::Constant
                    && input.offset == 0x2014
        )
    }));
    assert_eq!(
        instructions[5]
            .ops
            .iter()
            .filter(|operation| matches!(operation, PcodeOp::Store { .. }))
            .count(),
        2
    );
    assert_eq!(
        instructions[6]
            .ops
            .iter()
            .filter(|operation| matches!(operation, PcodeOp::Load { .. }))
            .count(),
        2
    );
    assert!(
        instructions[7]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::BranchIndirect { .. }))
    );
    assert!(
        instructions[8]
            .ops
            .iter()
            .any(|operation| matches!(operation, PcodeOp::CallIndirect { .. }))
    );
    assert!(instructions[8].ops.iter().any(|operation| {
        matches!(
            operation,
            PcodeOp::Copy { output, input }
                if output.space == disrobe_sleigh::pcode::Space::Register
                    && input.space == disrobe_sleigh::pcode::Space::Constant
                    && input.offset == 0x2024
        )
    }));
    assert!(matches!(
        instructions[9].ops.as_slice(),
        [
            PcodeOp::Copy {
                output: saved_target,
                input: original_x30,
            },
            PcodeOp::Copy {
                output: link,
                input: return_address,
            },
            PcodeOp::CallIndirect { target },
        ] if saved_target.space == disrobe_sleigh::pcode::Space::Unique
            && original_x30.space == disrobe_sleigh::pcode::Space::Register
            && link == original_x30
            && return_address.space == disrobe_sleigh::pcode::Space::Constant
            && return_address.offset == 0x2028
            && target == saved_target
    ));
}

#[test]
fn reports_named_callother_unmatched_and_truncated_inputs() {
    let words: [u32; 3] = [0x8b01_0000, 0xd400_0001, 0xffff_ffff];
    let mut bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0x3000);
    assert_eq!(report.instructions.len(), 4);
    assert_eq!(report.coverage.total, 4);
    assert_eq!(report.coverage.matched, 2);
    assert_eq!(report.coverage.callother_ops, 2);
    assert_eq!(report.coverage.unsupported, 0);
    assert!((report.coverage.decode_coverage_percent() - 50.0).abs() < f64::EPSILON);
    assert!(matches!(
        report.instructions[1].ops.as_slice(),
        [PcodeOp::CallOther { name, .. }] if name == "CallSupervisor"
    ));
    assert_eq!(report.instructions[2].status, DecodeStatus::NoMatch);
    assert_eq!(report.instructions[3].status, DecodeStatus::Truncated);
}

#[test]
fn direct_control_flow_uses_ram_space_targets() {
    let words: [u32; 4] = [0x1400_0001, 0x9400_0001, 0x5400_0020, 0xb400_0020];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let instructions: Vec<PcodeInstr> = decode_block(&bytes, 0x4000);
    assert_eq!(instructions.len(), words.len());
    for instruction in instructions {
        let target_space: Option<disrobe_sleigh::pcode::Space> =
            instruction
                .ops
                .iter()
                .find_map(|operation: &PcodeOp| match operation {
                    PcodeOp::Branch { target }
                    | PcodeOp::Call { target }
                    | PcodeOp::CBranch { target, .. } => Some(target.space),
                    _ => None,
                });
        assert_eq!(target_space, Some(disrobe_sleigh::pcode::Space::Ram));
    }
}

#[test]
fn address_arithmetic_wraps_at_the_u64_boundary() {
    let backward: Vec<PcodeInstr> = decode_block(&0x17ff_ffff_u32.to_le_bytes(), 0);
    assert!(matches!(
        backward[0].ops.as_slice(),
        [PcodeOp::Branch { target }]
            if target.offset == u64::MAX - 3
                && target.space == disrobe_sleigh::pcode::Space::Ram
    ));

    let call: Vec<PcodeInstr> =
        decode_block(&0x9400_0001_u32.to_le_bytes(), u64::MAX.saturating_sub(3));
    assert!(call[0].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Copy { input, .. } if input.offset == 0)
    }));
    assert!(call[0].ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::Call { target } if target.offset == 0)
    }));

    let words: [u32; 2] = [0xd503_201f, 0xd503_201f];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let block: Vec<PcodeInstr> = decode_block(&bytes, u64::MAX.saturating_sub(3));
    assert_eq!(block[0].address, u64::MAX - 3);
    assert_eq!(block[1].address, 0);
}

#[test]
fn empty_input_has_zero_coverage_without_nan() {
    let report: DecodeReport = decode_block_with_coverage(&[], 0);
    assert!(report.instructions.is_empty());
    assert!(report.coverage.decode_coverage_percent().abs() < f64::EPSILON);
    assert!(report.coverage.callother_percent().abs() < f64::EPSILON);
    assert!(report.coverage.unsupported_percent().abs() < f64::EPSILON);
    assert!(report.unlifted.is_empty());
}

#[test]
fn every_decode_status_lands_in_its_own_bucket() {
    let words: [u32; 3] = [0x8b01_0000, 0xd400_0001, 0xffff_ffff];
    let mut bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0x3000);
    let counts: StatusCounts = report.coverage.status;

    assert_eq!(counts.supported, 1);
    assert_eq!(counts.callother, 1);
    assert_eq!(counts.no_match, 1);
    assert_eq!(counts.truncated, 1);
    assert_eq!(counts.ambiguous, 0);
    assert_eq!(counts.spec_error, 0);
    assert_eq!(counts.unsupported, 0);

    assert_eq!(
        counts.total(),
        report.coverage.total,
        "the seven buckets must account for every decoded instruction"
    );
    for status in DECODE_STATUSES {
        let counted: usize = report
            .instructions
            .iter()
            .filter(|instruction: &&PcodeInstr| instruction.status == status)
            .count();
        assert_eq!(
            counts.count_of(status),
            counted,
            "{} bucket disagrees with the instruction stream",
            status_name(status)
        );
    }
}

#[test]
fn a_matched_constructor_is_not_a_modelled_instruction() {
    let words: [u32; 3] = [0x8b01_0000, 0xd400_0001, 0xffff_ffff];
    let mut bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0x3000);

    assert!((report.coverage.decode_coverage_percent() - 50.0).abs() < f64::EPSILON);
    assert!((report.coverage.semantic_percent() - 25.0).abs() < f64::EPSILON);
    assert!(
        report.coverage.semantic_percent() < report.coverage.decode_coverage_percent(),
        "a block holding a supervisor call must not read as fully recovered"
    );
    assert!((report.coverage.status_percent(DecodeStatus::NoMatch) - 25.0).abs() < f64::EPSILON);
}

#[test]
fn the_unlifted_histogram_names_only_instructions_that_were_not_modelled() {
    let words: [u32; 3] = [0x8b01_0000, 0xd400_0001, 0xffff_ffff];
    let mut bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0x3000);

    let counted: usize = report.unlifted.values().copied().sum();
    assert_eq!(
        counted, 3,
        "three of the four instructions were not modelled: {:?}",
        report.unlifted
    );
    let modelled: &str = report.instructions[0].mnemonic.as_str();
    assert!(
        !report.unlifted.contains_key(modelled),
        "the modelled instruction {modelled} must not appear as unlifted"
    );
    for instruction in &report.instructions {
        if instruction.status.supported() {
            continue;
        }
        assert!(
            report.unlifted.contains_key(&instruction.mnemonic),
            "{} decoded as {} but is missing from the histogram",
            instruction.mnemonic,
            status_name(instruction.status)
        );
    }
}

#[test]
fn a_repeated_unlifted_mnemonic_is_counted_once_with_its_occurrences() {
    let words: [u32; 3] = [0xffff_ffff, 0xffff_ffff, 0xffff_ffff];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0x5000);

    assert_eq!(report.coverage.total, 3);
    assert_eq!(report.coverage.status.no_match, 3);
    assert_eq!(
        report.unlifted.len(),
        1,
        "one repeated mnemonic must be one entry, not three: {:?}",
        report.unlifted
    );
    assert_eq!(report.unlifted.values().copied().sum::<usize>(), 3);
}
