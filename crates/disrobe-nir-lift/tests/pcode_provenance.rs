#![allow(clippy::expect_used)]

use disrobe_lift_x86::decode_block_x86;
use disrobe_nir::{NirArtifact, NirFunction, NirOp, SourceLang, SourceOffset};
use disrobe_nir_lift::{
    PcodeArch, PcodeLiftConfig, ProvenanceLiftError, lower_for_arch_with_provenance,
    lower_pcode_block_with_provenance, lower_x86_64, lower_x86_64_with_provenance,
};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

#[test]
fn variable_length_native_instructions_reemit_once_with_memory_image_offsets() {
    let bytes: [u8; 6] = [0x48, 0x39, 0xc8, 0x7e, 0x02, 0xc3];
    let artifact: NirArtifact =
        lower_x86_64_with_provenance(&bytes, 0x1400, "probe").expect("lift with provenance");

    assert_eq!(
        artifact.reemit_original_bytes(0).expect("original bytes"),
        bytes
    );
    assert_eq!(artifact.source_units().len(), 3);
    assert_eq!(
        artifact.source_units()[0].offset(),
        SourceOffset::MemoryImage(0x1400)
    );
    assert_eq!(
        artifact.source_units()[1].offset(),
        SourceOffset::MemoryImage(0x1403)
    );
    assert_eq!(
        artifact.source_units()[2].offset(),
        SourceOffset::MemoryImage(0x1405)
    );
    assert!(artifact.source_units()[0].instruction_count() > 1);
}

#[test]
fn fixed_native_encodings_reemit_through_the_architecture_table() {
    let aarch64: [u8; 4] = 0xd65f_03c0_u32.to_le_bytes();
    let aarch64_artifact: NirArtifact =
        lower_for_arch_with_provenance(PcodeArch::AArch64, &aarch64, 0x2000, "fixed")
            .expect("fixed-width provenance");
    assert_eq!(
        aarch64_artifact
            .reemit_original_bytes(0)
            .expect("aarch64 bytes"),
        aarch64
    );
    assert_eq!(aarch64_artifact.source_units().len(), 1);
}

#[test]
fn overlapping_source_addresses_fail_closed_until_decoder_identity_is_available() {
    let source_instruction: PcodeInstr = PcodeInstr {
        address: 0x1000,
        bytes: vec![0x90],
        length: 1,
        mnemonic: "nop".to_owned(),
        ops: Vec::new(),
        operands: String::new(),
        status: DecodeStatus::Supported,
    };
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![source_instruction.clone(), source_instruction],
        ordered_ops: Vec::new(),
    };
    let result: Result<NirArtifact, ProvenanceLiftError> =
        lower_pcode_block_with_provenance(&block, "overlap", &PcodeLiftConfig::x86_64());
    assert!(matches!(
        result,
        Err(ProvenanceLiftError::DuplicateSourceAddress { address: 0x1000 })
    ));
}

#[test]
fn delay_slot_reordering_requires_source_identity_before_provenance() {
    let source_instruction: PcodeInstr = PcodeInstr {
        address: 0x1000,
        bytes: vec![0x00, 0x00, 0x00, 0x00],
        length: 4,
        mnemonic: "nop".to_owned(),
        ops: Vec::new(),
        operands: String::new(),
        status: DecodeStatus::Supported,
    };
    let block: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions: vec![source_instruction],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig =
        PcodeLiftConfig::new(SourceLang::NativeX86, Vec::new()).with_branch_delay_slots();
    let result: Result<NirArtifact, ProvenanceLiftError> =
        lower_pcode_block_with_provenance(&block, "delay", &config);
    assert!(matches!(result, Err(ProvenanceLiftError::DelaySlots)));
}

fn source_instruction(address: u64, bytes: Vec<u8>, length: usize) -> PcodeInstr {
    PcodeInstr {
        address,
        bytes,
        length,
        mnemonic: "nop".to_owned(),
        ops: Vec::new(),
        operands: String::new(),
        status: DecodeStatus::Supported,
    }
}

const fn node(space: Space, offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space,
    }
}

#[test]
fn declared_instruction_length_must_match_owned_bytes() {
    let instruction: PcodeInstr = source_instruction(0x1000, vec![0x90], 2);
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![instruction],
        ordered_ops: Vec::new(),
    };
    assert!(matches!(
        lower_pcode_block_with_provenance(&block, "length", &PcodeLiftConfig::x86_64()),
        Err(ProvenanceLiftError::SourceByteLength {
            address: 0x1000,
            declared: 2,
            actual: 1
        })
    ));
}

#[test]
fn source_instruction_addresses_must_be_contiguous() {
    let first: PcodeInstr = source_instruction(0x1000, vec![0x90], 1);
    let second: PcodeInstr = source_instruction(0x1002, vec![0xc3], 1);
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![first, second],
        ordered_ops: Vec::new(),
    };
    assert!(matches!(
        lower_pcode_block_with_provenance(&block, "gap", &PcodeLiftConfig::x86_64()),
        Err(ProvenanceLiftError::SourceAddressGap {
            expected: 0x1001,
            actual: 0x1002
        })
    ));
}

#[test]
fn decoded_consumed_length_must_equal_source_byte_sum() {
    let instruction: PcodeInstr = source_instruction(0x1000, vec![0x90], 1);
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![instruction],
        ordered_ops: Vec::new(),
    };
    assert!(matches!(
        lower_pcode_block_with_provenance(&block, "consumed", &PcodeLiftConfig::x86_64()),
        Err(ProvenanceLiftError::ConsumedBytes {
            declared: 2,
            actual: 1
        })
    ));
}

#[test]
fn source_layout_validation_precedes_lowering_work() {
    let instruction: PcodeInstr = source_instruction(0x1000, vec![0x90], 2);
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![instruction],
        ordered_ops: Vec::new(),
    };
    assert!(matches!(
        lower_pcode_block_with_provenance(&block, "invalid name", &PcodeLiftConfig::x86_64()),
        Err(ProvenanceLiftError::SourceByteLength {
            address: 0x1000,
            declared: 2,
            actual: 1
        })
    ));
}

#[test]
fn configured_source_unit_ceiling_refuses_a_small_oversize_block() {
    let first: PcodeInstr = source_instruction(0x1000, vec![0x90], 1);
    let second: PcodeInstr = source_instruction(0x1001, vec![0xc3], 1);
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![first, second],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::x86_64().with_limits(1, 1);
    assert!(matches!(
        lower_pcode_block_with_provenance(&block, "limited", &config),
        Err(ProvenanceLiftError::Lift(
            disrobe_nir_lift::LiftError::PcodeInstructionLimit { limit: 1 }
        ))
    ));
}

#[test]
fn eliminated_source_instructions_keep_zero_output_provenance() {
    let first_op: PcodeOp = PcodeOp::Return { target: None };
    let dead_op: PcodeOp = PcodeOp::IntEqual {
        output: node(Space::Register, 0x206, 1),
        left: node(Space::Constant, 1, 8),
        right: node(Space::Constant, 1, 8),
    };
    let mut first: PcodeInstr = source_instruction(0x1000, vec![0xc3], 1);
    first.ops.push(first_op.clone());
    let mut dead: PcodeInstr = source_instruction(0x1001, vec![0x90], 1);
    dead.ops.push(dead_op.clone());
    let block: DecodedBlock = DecodedBlock {
        consumed: 2,
        instructions: vec![first, dead],
        ordered_ops: vec![first_op, dead_op],
    };
    let artifact: NirArtifact =
        lower_pcode_block_with_provenance(&block, "eliminated", &PcodeLiftConfig::x86_64())
            .expect("lower with eliminated source instruction");

    assert_eq!(artifact.source_units()[1].instruction_count(), 0);
    assert_eq!(
        artifact.reemit_original_bytes(0).expect("original bytes"),
        [0xc3, 0x90]
    );
}

#[test]
fn folded_condition_codes_remain_mapped_to_source_instructions() {
    let bytes: [u8; 6] = [0x48, 0x39, 0xc8, 0x7e, 0x02, 0xc3];
    let block: DecodedBlock = decode_block_x86(&bytes, 0x1400, 64);
    let artifact: NirArtifact = lower_pcode_block_with_provenance(
        &block,
        "folded",
        &PcodeLiftConfig::x86_64().with_condition_code_folding(),
    )
    .expect("lower with folded condition codes");
    let function: &NirFunction = &artifact.module().functions[0];
    let mapped_instructions: u32 = artifact
        .source_units()
        .iter()
        .map(disrobe_nir::SourceUnit::instruction_count)
        .sum();

    assert_eq!(
        usize::try_from(mapped_instructions).expect("bounded instruction count"),
        function.instructions.len()
    );
    assert!(artifact.source_units()[1].instruction_count() >= 2);
    assert!(
        function
            .instructions
            .iter()
            .any(|instruction| matches!(instruction.op, NirOp::CondBranch { .. }))
    );
    assert_eq!(
        artifact.reemit_original_bytes(0).expect("original bytes"),
        bytes
    );
}

#[test]
fn legacy_x86_result_matches_the_artifact_consumer_contract() {
    let bytes: [u8; 6] = [0x48, 0x39, 0xc8, 0x7e, 0x02, 0xc3];
    let block: DecodedBlock = decode_block_x86(&bytes, 0x1400, 64);
    let direct: NirFunction =
        disrobe_nir_lift::lower_pcode_block(&block, "probe", &PcodeLiftConfig::x86_64())
            .expect("direct compatibility result");
    let legacy: NirFunction = lower_x86_64(&bytes, 0x1400, "probe").expect("legacy lift");
    let artifact: NirArtifact =
        lower_x86_64_with_provenance(&bytes, 0x1400, "probe").expect("artifact lift");

    assert_eq!(legacy, direct);
    assert_eq!(artifact.module().functions, [legacy]);
    assert_eq!(
        artifact.module().source_hash,
        *blake3::hash(&bytes).as_bytes()
    );
}
