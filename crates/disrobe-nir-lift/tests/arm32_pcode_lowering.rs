#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use disrobe_nir::{NirFunction, NirInstr, NirOp, SourceLang};
use disrobe_nir_lift::{
    LiftError, LiftGap, LiftGaps, PcodeArch, PcodeLiftConfig, RegisterCell, block_gaps,
    lower_pcode_block,
};
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use disrobe_sleigh::syntax::Endian;

const ARM32_CANONICAL_CELLS: usize = 64;

const SPEC_OFFSETS: [(&str, u64, u32); 26] = [
    ("contextreg", 0x0000, 8),
    ("r0", 0x0020, 4),
    ("r1", 0x0024, 4),
    ("r2", 0x0028, 4),
    ("r3", 0x002c, 4),
    ("r4", 0x0030, 4),
    ("r5", 0x0034, 4),
    ("r6", 0x0038, 4),
    ("r7", 0x003c, 4),
    ("r8", 0x0040, 4),
    ("r9", 0x0044, 4),
    ("r10", 0x0048, 4),
    ("r11", 0x004c, 4),
    ("r12", 0x0050, 4),
    ("sp", 0x0054, 4),
    ("lr", 0x0058, 4),
    ("pc", 0x005c, 4),
    ("NG", 0x0060, 1),
    ("ZR", 0x0061, 1),
    ("CY", 0x0062, 1),
    ("OV", 0x0063, 1),
    ("shift_carry", 0x0068, 1),
    ("cpsr", 0x0070, 4),
    ("mult_addr", 0x0080, 4),
    ("fpsr", 0x00a0, 4),
    ("cr0", 0x0200, 4),
];

fn arm32_cells() -> BTreeMap<String, (u64, u32)> {
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    config
        .registers()
        .iter()
        .map(|cell: &RegisterCell| (cell.name.clone(), (cell.offset, cell.size)))
        .collect()
}

#[test]
fn arm32_register_cells_carry_the_offsets_the_compiled_spec_declares() {
    let cells: BTreeMap<String, (u64, u32)> = arm32_cells();
    assert_eq!(
        cells.len(),
        ARM32_CANONICAL_CELLS,
        "the canonical arm32 cell count is pinned: {:?}",
        cells.keys().collect::<Vec<&String>>()
    );
    for (name, offset, size) in SPEC_OFFSETS {
        assert_eq!(
            cells.get(name).copied(),
            Some((offset, size)),
            "{name} must resolve to the offset the compiled spec declares"
        );
    }
}

#[test]
fn arm32_cells_never_overlap_so_an_alias_resolves_to_one_owner() {
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let mut ranges: Vec<(u64, u64, String)> = config
        .registers()
        .iter()
        .map(|cell: &RegisterCell| {
            (
                cell.offset,
                cell.offset.saturating_add(u64::from(cell.size)),
                cell.name.clone(),
            )
        })
        .collect();
    ranges.sort_unstable();
    for window in ranges.windows(2) {
        let [(_, first_end, first_name), (second_start, _, second_name)] = window else {
            continue;
        };
        assert!(
            first_end <= second_start,
            "{first_name} and {second_name} overlap, so a varnode would have two owners"
        );
    }
    assert!(
        !config
            .registers()
            .iter()
            .any(|cell: &RegisterCell| cell.name == "mult_dat16"),
        "the wider alias must yield to the narrower definition it contains"
    );
}

#[test]
fn arm32_discards_the_condition_flags_it_folds() {
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    for flag in ["NG", "ZR", "CY", "OV", "tmpNG", "shift_carry"] {
        assert!(
            config.is_discarded_register(flag),
            "{flag} is a condition-code bit, not an observable value"
        );
    }
    assert!(!config.is_discarded_register("r0"));
}

#[test]
fn the_architecture_table_is_indexed_by_its_own_discriminant() {
    let mut seen: Vec<&'static str> = Vec::new();
    for arch in PcodeArch::all() {
        let label: &'static str = arch
            .label()
            .expect("every architecture in the table resolves to its own row");
        assert_eq!(
            PcodeArch::from_label(label),
            Some(arch),
            "{label} must round-trip through the table"
        );
        seen.push(label);
    }
    assert_eq!(
        seen,
        [
            "x86-64",
            "aarch64",
            "arm32-a32",
            "arm32-thumb",
            "mips32-be",
            "mips32-le"
        ],
        "adding an architecture is one table row, and the row order defines the discriminant"
    );
    assert_eq!(PcodeArch::from_label("sparc"), None);
}

#[test]
fn every_table_row_builds_its_lift_config() {
    for arch in PcodeArch::all() {
        let config: PcodeLiftConfig = arch
            .config()
            .unwrap_or_else(|error: LiftError| panic!("{arch:?} config: {error}"));
        assert!(
            !config.registers().is_empty(),
            "{arch:?} must carry a register map"
        );
    }
}

#[test]
fn a_register_varnode_outside_every_cell_is_refused_rather_than_guessed() {
    let unmapped: Varnode = Varnode {
        offset: 0x4000,
        size_bytes: 4,
        space: Space::Register,
    };
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions: vec![PcodeInstr {
            address: 0x1000,
            bytes: vec![0x00, 0x00, 0x00, 0x00],
            length: 4,
            mnemonic: "probe".to_owned(),
            operands: String::new(),
            ops: vec![PcodeOp::Copy {
                output: unmapped,
                input: Varnode {
                    offset: 1,
                    size_bytes: 4,
                    space: Space::Constant,
                },
            }],
            status: DecodeStatus::Supported,
        }],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let error: LiftError = lower_pcode_block(&decoded, "probe", &config)
        .expect_err("an offset the spec never declares must not be silently accepted");
    let LiftError::InvalidPcode { reason, .. } = &error else {
        panic!("expected a typed p-code error, got {error}");
    };
    assert!(
        reason.contains("no containing canonical cell"),
        "the refusal must name the missing cell: {reason}"
    );
}

#[test]
fn a_hand_built_a32_block_lowers_over_the_spec_derived_register_map() {
    let link_register: Varnode = Varnode {
        offset: 0x0058,
        size_bytes: 4,
        space: Space::Register,
    };
    let first_argument: Varnode = Varnode {
        offset: 0x0020,
        size_bytes: 4,
        space: Space::Register,
    };
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 8,
        instructions: vec![
            PcodeInstr {
                address: 0x1000,
                bytes: vec![0x01, 0x00, 0xa0, 0xe3],
                length: 4,
                mnemonic: "mov".to_owned(),
                operands: "r0, #1".to_owned(),
                ops: vec![PcodeOp::Copy {
                    output: first_argument,
                    input: Varnode {
                        offset: 1,
                        size_bytes: 4,
                        space: Space::Constant,
                    },
                }],
                status: DecodeStatus::Supported,
            },
            PcodeInstr {
                address: 0x1004,
                bytes: vec![0x1e, 0xff, 0x2f, 0xe1],
                length: 4,
                mnemonic: "bx".to_owned(),
                operands: "lr".to_owned(),
                ops: vec![PcodeOp::Return {
                    target: Some(link_register),
                }],
                status: DecodeStatus::Supported,
            },
        ],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "a32_probe", &config).expect("lower the a32 block");
    assert_eq!(lowered.address, 0x1000);
    assert_eq!(lowered.end, 0x1008);
    assert_eq!(lowered.source.lang, SourceLang::NativeArm);
    assert!(
        lowered.instructions.iter().any(|instruction: &NirInstr| {
            instruction
                .operands
                .iter()
                .any(|operand: &String| operand == "r0")
        }),
        "the argument register must resolve to its spec name: {:?}",
        lowered.instructions
    );
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "bx lr must lower to a return"
    );
}

#[test]
fn an_undecoded_word_reports_a_gap_instead_of_emitting_source() {
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions: vec![PcodeInstr {
            address: 0x3000,
            bytes: vec![0xff, 0xff, 0xff, 0xf7],
            length: 4,
            mnemonic: ".inst".to_owned(),
            operands: "0xf7ffffff".to_owned(),
            ops: vec![PcodeOp::CallOther {
                name: "decode_unmatched_0xf7ffffff".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::NoMatch,
        }],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "gap_probe", &config).expect("lower the gap block");
    let gap: &NirInstr = lowered
        .instructions
        .first()
        .expect("the gap must still occupy an instruction slot");
    let NirOp::CallOther { effect } = &gap.op else {
        panic!("an undecoded word must surface as an unmodelled effect, got {gap:?}");
    };
    assert_eq!(effect.name, "decode_unmatched_0xf7ffffff");
    assert!(
        effect.unknown_registers,
        "an undecoded word must not claim it left the register file alone"
    );
}

#[test]
fn a_supported_instruction_without_semantics_never_reaches_the_gap_path() {
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions: vec![PcodeInstr {
            address: 0x4000,
            bytes: vec![0x00, 0xf0, 0x20, 0xe3],
            length: 4,
            mnemonic: "nop".to_owned(),
            operands: String::new(),
            ops: Vec::new(),
            status: DecodeStatus::Supported,
        }],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "nop_probe", &config).expect("lower the nop block");
    assert_eq!(lowered.instructions.len(), 1);
    let only: &NirInstr = &lowered.instructions[0];
    assert_eq!(only.mnemonic, "nop");
    assert_eq!(only.op, NirOp::Nop);
}

#[test]
fn a_non_supported_instruction_without_semantics_is_refused() {
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 4,
        instructions: vec![PcodeInstr {
            address: 0x5000,
            bytes: vec![0x00, 0x00, 0x00, 0x00],
            length: 4,
            mnemonic: ".inst".to_owned(),
            operands: String::new(),
            ops: Vec::new(),
            status: DecodeStatus::Unsupported,
        }],
        ordered_ops: Vec::new(),
    };
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let error: LiftError = lower_pcode_block(&decoded, "bad_probe", &config)
        .expect_err("an unsupported instruction with no semantics must not lift to a no-op");
    let LiftError::InvalidPcode { reason, .. } = &error else {
        panic!("expected a typed p-code error, got {error}");
    };
    assert!(reason.contains("no P-code semantics"), "{reason}");
}

#[test]
fn the_architecture_table_resolves_the_sleigh_language_each_row_decodes() {
    for (language, expected) in [
        (Language::AArch64, Some(PcodeArch::AArch64)),
        (Language::Arm32(ArmMode::A32), Some(PcodeArch::Arm32A32)),
        (Language::Arm32(ArmMode::Thumb), Some(PcodeArch::Arm32Thumb)),
        (Language::Mips32(Endian::Big), Some(PcodeArch::Mips32Be)),
        (Language::Mips32(Endian::Little), Some(PcodeArch::Mips32Le)),
        (Language::PowerPc32Be, None),
    ] {
        assert_eq!(
            PcodeArch::for_language(language),
            expected,
            "{language:?} must resolve through the table rather than a hand-written match"
        );
    }
}

fn undecodable_a32_run(count: usize) -> DecodedBlock {
    let mut instructions: Vec<PcodeInstr> = Vec::with_capacity(count);
    for index in 0..count {
        let step: u64 = u64::try_from(index).expect("the run index fits an address");
        let address: u64 = 0x1000_u64 + step * 4;
        instructions.push(PcodeInstr {
            address,
            bytes: vec![0xff, 0xff, 0xff, 0xf7],
            length: 4,
            mnemonic: ".inst".to_owned(),
            operands: "0xf7ffffff".to_owned(),
            ops: vec![PcodeOp::CallOther {
                name: "decode_unmatched_0xf7ffffff".to_owned(),
                output: None,
                inputs: Vec::new(),
            }],
            status: DecodeStatus::NoMatch,
        });
    }
    DecodedBlock {
        consumed: count.saturating_mul(4),
        instructions,
        ordered_ops: Vec::new(),
    }
}

#[test]
fn a_long_undecodable_run_reports_its_true_total_even_when_the_sample_is_capped() {
    const RUN: usize = 5000;
    let block: DecodedBlock = undecodable_a32_run(RUN);
    let gaps: LiftGaps = block_gaps(&block);
    assert_eq!(
        gaps.total(),
        RUN,
        "the reported total must count every word the decoder could not model"
    );
    assert!(
        gaps.is_truncated(),
        "a capped sample must declare that it is a sample"
    );
    assert!(
        gaps.reported().len() < gaps.total(),
        "the sample is capped, so it cannot be the whole set"
    );
    assert!(
        gaps.reported()
            .iter()
            .all(|gap: &LiftGap| gap.status == DecodeStatus::NoMatch),
        "every sampled gap must carry the decode status that produced it"
    );
    assert_eq!(
        gaps.mnemonics().first().copied(),
        Some(".inst"),
        "the sample must name the mnemonic it could not model"
    );
}

#[test]
fn a_partly_undecodable_a32_block_names_the_word_it_could_not_model() {
    let first_argument: Varnode = Varnode {
        offset: 0x0020,
        size_bytes: 4,
        space: Space::Register,
    };
    let link_register: Varnode = Varnode {
        offset: 0x0058,
        size_bytes: 4,
        space: Space::Register,
    };
    let decoded: DecodedBlock = DecodedBlock {
        consumed: 12,
        instructions: vec![
            PcodeInstr {
                address: 0x1000,
                bytes: vec![0x01, 0x00, 0xa0, 0xe3],
                length: 4,
                mnemonic: "mov".to_owned(),
                operands: "r0, #1".to_owned(),
                ops: vec![PcodeOp::Copy {
                    output: first_argument,
                    input: Varnode {
                        offset: 1,
                        size_bytes: 4,
                        space: Space::Constant,
                    },
                }],
                status: DecodeStatus::Supported,
            },
            PcodeInstr {
                address: 0x1004,
                bytes: vec![0xff, 0xff, 0xff, 0xf7],
                length: 4,
                mnemonic: ".inst".to_owned(),
                operands: "0xf7ffffff".to_owned(),
                ops: vec![PcodeOp::CallOther {
                    name: "decode_unmatched_0xf7ffffff".to_owned(),
                    output: None,
                    inputs: Vec::new(),
                }],
                status: DecodeStatus::NoMatch,
            },
            PcodeInstr {
                address: 0x1008,
                bytes: vec![0x1e, 0xff, 0x2f, 0xe1],
                length: 4,
                mnemonic: "bx".to_owned(),
                operands: "lr".to_owned(),
                ops: vec![PcodeOp::Return {
                    target: Some(link_register),
                }],
                status: DecodeStatus::Supported,
            },
        ],
        ordered_ops: Vec::new(),
    };
    let gaps: LiftGaps = block_gaps(&decoded);
    assert_eq!(gaps.total(), 1, "exactly one word resisted the decoder");
    assert!(
        !gaps.is_truncated(),
        "a single gap fits the sample, so nothing is hidden"
    );
    assert_eq!(gaps.mnemonics(), [".inst"]);
    assert_eq!(
        gaps.reported().first().map(|gap: &LiftGap| gap.address),
        Some(0x1004),
        "the gap must name where recovery stopped being complete"
    );
    let config: PcodeLiftConfig = PcodeLiftConfig::arm32().expect("build the arm32 lift config");
    let lowered: NirFunction =
        lower_pcode_block(&decoded, "partial", &config).expect("the modelled words still lift");
    assert!(
        lowered
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "the words around the gap must still recover"
    );
}
