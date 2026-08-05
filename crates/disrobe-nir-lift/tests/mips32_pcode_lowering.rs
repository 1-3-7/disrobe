#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use disrobe_nir::{CallOtherEffect, NirFunction, NirInstr, NirOp, ValueOp};
use disrobe_nir_lift::{LiftError, PcodeArch, PcodeLiftConfig, RegisterCell, lower_mips32};
use disrobe_sleigh::syntax::Endian;

const MIPS32_CANONICAL_CELLS: usize = 451;

const SPEC_OFFSETS: [(&str, u64, u32); 10] = [
    ("zero", 0x0000, 4),
    ("at", 0x0004, 4),
    ("v0", 0x0008, 4),
    ("v1", 0x000c, 4),
    ("a0", 0x0010, 4),
    ("a3", 0x001c, 4),
    ("gp", 0x0070, 4),
    ("sp", 0x0074, 4),
    ("ra", 0x007c, 4),
    ("pc", 0x0080, 4),
];

const LITTLE_ENDIAN_OFFSETS: [(&str, u64, u32); 5] = [
    ("f0", 0x1000, 4),
    ("f1", 0x1004, 4),
    ("f31", 0x107c, 4),
    ("lo", 0x3000, 4),
    ("hi", 0x3004, 4),
];

const BIG_ENDIAN_OFFSETS: [(&str, u64, u32); 5] = [
    ("f0", 0x1004, 4),
    ("f1", 0x1000, 4),
    ("f31", 0x1078, 4),
    ("hi", 0x3000, 4),
    ("lo", 0x3004, 4),
];

fn lower(words: &[u32], endian: Endian, address: u64) -> NirFunction {
    let bytes: Vec<u8> = words
        .iter()
        .flat_map(|word: &u32| match endian {
            Endian::Little => word.to_le_bytes(),
            Endian::Big => word.to_be_bytes(),
        })
        .collect();
    lower_mips32(&bytes, address, "probe", endian).expect("lower the mips32 block")
}

fn callother_names(function: &NirFunction) -> Vec<String> {
    function
        .instructions
        .iter()
        .filter_map(|instruction: &NirInstr| match &instruction.op {
            NirOp::CallOther { effect } => Some(effect.name.clone()),
            _ => None,
        })
        .collect()
}

fn defined_registers(function: &NirFunction) -> Vec<String> {
    function
        .instructions
        .iter()
        .filter_map(|instruction: &NirInstr| instruction.operands.first().cloned())
        .collect()
}

#[test]
fn mips32_register_cells_carry_the_offsets_the_compiled_spec_declares() {
    for endian in [Endian::Big, Endian::Little] {
        let config: PcodeLiftConfig =
            PcodeLiftConfig::mips32(endian).expect("build the mips32 lift config");
        let cells: BTreeMap<String, (u64, u32)> = config
            .registers()
            .iter()
            .map(|cell: &RegisterCell| (cell.name.clone(), (cell.offset, cell.size)))
            .collect();
        assert_eq!(
            cells.len(),
            MIPS32_CANONICAL_CELLS,
            "the canonical mips32 cell count is pinned for {endian:?}"
        );
        let ordered: [(&str, u64, u32); 5] = match endian {
            Endian::Big => BIG_ENDIAN_OFFSETS,
            Endian::Little => LITTLE_ENDIAN_OFFSETS,
        };
        for (name, offset, size) in SPEC_OFFSETS.into_iter().chain(ordered) {
            assert_eq!(
                cells.get(name).copied(),
                Some((offset, size)),
                "{name} must resolve to the offset the compiled spec declares for {endian:?}"
            );
        }
        assert!(
            !cells.contains_key("ac0") && !cells.contains_key("f0_1"),
            "a wider accumulator alias must yield to the architectural halves it contains"
        );
        assert!(
            config.is_discarded_register("zero"),
            "a write to the zero register is architecturally discarded"
        );
    }
}

#[test]
fn both_byte_orders_are_selected_through_the_architecture_table() {
    assert_eq!(
        PcodeArch::from_label("mips32-be"),
        Some(PcodeArch::Mips32Be)
    );
    assert_eq!(
        PcodeArch::from_label("mips32-le"),
        Some(PcodeArch::Mips32Le)
    );
    for arch in [PcodeArch::Mips32Be, PcodeArch::Mips32Le] {
        let config: PcodeLiftConfig = arch.config().expect("table row builds its config");
        assert_eq!(config.registers().len(), MIPS32_CANONICAL_CELLS);
    }
}

#[test]
fn the_same_words_lift_identically_in_both_byte_orders() {
    let words: [u32; 6] = [
        0x0064_1020,
        0x2528_fff4,
        0x8cc5_0010,
        0xad07_ffec,
        0x3c09_1234,
        0x014b_0018,
    ];
    let little: NirFunction = lower(&words, Endian::Little, 0x3000);
    let big: NirFunction = lower(&words, Endian::Big, 0x3000);
    let little_mnemonics: Vec<&str> = little
        .instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.mnemonic.as_str())
        .collect();
    let big_mnemonics: Vec<&str> = big
        .instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.mnemonic.as_str())
        .collect();
    assert_eq!(little_mnemonics, big_mnemonics);
    assert!(
        little_mnemonics.contains(&"LOAD") && little_mnemonics.contains(&"STORE"),
        "the load and store forms must lift: {little_mnemonics:?}"
    );
}

#[test]
fn a_multiply_writes_the_architectural_hi_and_lo_rather_than_a_wider_alias() {
    let lowered: NirFunction = lower(&[0x014b_0018], Endian::Little, 0x3000);
    let defined: Vec<String> = defined_registers(&lowered);
    assert!(
        defined.iter().any(|name: &String| name == "lo")
            && defined.iter().any(|name: &String| name == "hi"),
        "mult must write hi and lo by their architectural names: {defined:?}"
    );
}

#[test]
fn a_delay_slot_executes_before_the_transfer_it_follows() {
    let lowered: NirFunction = lower(
        &[0x1043_0001, 0x2484_0001, 0x00e8_3821],
        Endian::Little,
        0x4000,
    );
    let slot_position: usize = lowered
        .instructions
        .iter()
        .position(|instruction: &NirInstr| {
            matches!(
                &instruction.op,
                NirOp::Value {
                    op: ValueOp::IntAdd,
                    ..
                }
            ) && instruction
                .operands
                .first()
                .is_some_and(|out: &String| out == "a0")
        })
        .expect("the delay slot addiu must survive lowering");
    let transfer_position: usize = lowered
        .instructions
        .iter()
        .position(|instruction: &NirInstr| matches!(instruction.op, NirOp::CondBranch { .. }))
        .expect("the branch must lower to a conditional branch");
    assert!(
        slot_position < transfer_position,
        "the delay slot must execute before the transfer: {:?}",
        lowered
            .instructions
            .iter()
            .map(|instruction: &NirInstr| (instruction.address, instruction.mnemonic.clone()))
            .collect::<Vec<(u64, String)>>()
    );
    let scheduled_at: u64 = lowered.instructions[slot_position].address;
    assert_eq!(
        scheduled_at, 0x4000,
        "the slot effect belongs to the transfer instruction, not to its own address"
    );
    let residue: &NirInstr = lowered
        .instructions
        .iter()
        .find(|instruction: &&NirInstr| instruction.address == 0x4004)
        .expect("the slot address must still appear in the lifted function");
    assert_eq!(residue.mnemonic, "addiu");
    assert_eq!(
        residue.op,
        NirOp::Nop,
        "the slot must not execute a second time at its own address"
    );
}

#[test]
fn a_transfer_without_a_delay_slot_surfaces_as_a_reported_gap() {
    let lowered: NirFunction = lower(&[0x1043_0001], Endian::Little, 0x5000);
    assert_eq!(callother_names(&lowered), vec!["missing_delay_slot"]);
    assert!(
        !lowered
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::CondBranch { .. })),
        "a refused transfer must not still emit a branch"
    );
}

#[test]
fn a_transfer_inside_a_delay_slot_surfaces_as_a_reported_gap() {
    let lowered: NirFunction = lower(
        &[0x1043_0001, 0x1043_0001, 0x0000_0000],
        Endian::Little,
        0x6000,
    );
    let names: Vec<String> = callother_names(&lowered);
    assert_eq!(
        names,
        vec!["nested_delay_transfer", "nested_delay_transfer"],
        "both halves of a nested transfer must report the gap"
    );
    for instruction in &lowered.instructions {
        let NirOp::CallOther { effect } = &instruction.op else {
            continue;
        };
        let effect: &CallOtherEffect = effect;
        assert!(
            effect.unknown_registers,
            "a refused decode must not claim it left the register file alone"
        );
    }
}

#[test]
fn a_likely_branch_is_declined_by_name_rather_than_executed_unconditionally() {
    let lowered: NirFunction = lower(
        &[0x5043_0001, 0x2484_0001, 0x00e8_3821],
        Endian::Little,
        0x7000,
    );
    assert_eq!(
        callother_names(&lowered),
        vec!["unsupported_beql"],
        "an annulling branch must be declined by name, never modelled as an ordinary branch"
    );
    assert!(
        !lowered
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::CondBranch { .. })),
        "a declined likely branch must not emit a conditional branch it cannot annul"
    );
}

#[test]
fn a_write_to_the_zero_register_is_discarded() {
    let lowered: NirFunction = lower(
        &[0x0085_0021, 0x03e0_0008, 0x0000_0000],
        Endian::Little,
        0x8000,
    );
    let defined: Vec<String> = defined_registers(&lowered);
    assert!(
        !defined.iter().any(|name: &String| name == "zero"),
        "addu into the zero register must define nothing: {defined:?}"
    );
    let discarded: &NirInstr = lowered
        .instructions
        .iter()
        .find(|instruction: &&NirInstr| instruction.address == 0x8000)
        .expect("the discarded write must still occupy its address");
    assert_eq!(discarded.mnemonic, "addu");
    assert_eq!(discarded.op, NirOp::Nop);
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "jr ra must lower to a return"
    );
}

#[test]
fn an_undecodable_word_reports_a_gap_instead_of_emitting_source() {
    let lowered: NirFunction = lower(&[0x7fff_ffff], Endian::Little, 0x9000);
    assert_eq!(callother_names(&lowered), vec!["mips_decode_unmatched"]);
}

#[test]
fn a_big_endian_image_read_as_little_endian_does_not_decode_as_the_same_program() {
    let words: [u32; 6] = [
        0x0064_1020,
        0x2528_fff4,
        0x8cc5_0010,
        0xad07_ffec,
        0x3c09_1234,
        0x014b_0018,
    ];
    let correct: NirFunction = lower(&words, Endian::Big, 0x3000);
    assert!(
        correct
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::RawLoad { .. })),
        "the correctly ordered image must lift its load"
    );
    let misread_bytes: Vec<u8> = words
        .iter()
        .flat_map(|word: &u32| word.to_be_bytes())
        .collect();
    let error: LiftError = lower_mips32(&misread_bytes, 0x3000, "probe", Endian::Little)
        .expect_err("a big-endian image read as little-endian must not lift as a program");
    let LiftError::InvalidPcode {
        address, reason, ..
    } = &error
    else {
        panic!("expected a typed p-code error, got {error}");
    };
    assert_eq!(*address, 0x300c);
    assert!(
        reason.contains("no P-code semantics"),
        "the refusal must name the missing semantics: {reason}"
    );
}
