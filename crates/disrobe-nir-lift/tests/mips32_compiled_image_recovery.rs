#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_nir::{
    HirFunction, NirFunction, NirInstr, NirOp, SurfaceFunction, ValueOp, emit_pseudo_source,
    structurize_function, surfacify_function,
};
use disrobe_nir_lift::{
    ArchLift, LiftError, LiftGap, LiftGaps, PcodeArch, block_gaps, lower_arm32, lower_mips32,
};
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Varnode};
use disrobe_sleigh::syntax::Endian;

const BE_ORACLE_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/mips32be_oracle_o2.text");
const BE_ORACLE_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/mips32be_oracle_o2.mnemonics");
const LE_ORACLE_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/mips32le_oracle_o2.text");
const LE_ORACLE_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/mips32le_oracle_o2.mnemonics");
const BE_FORMS_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/mips32be_forms.text");
const BE_FORMS_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/mips32be_forms.mnemonics");
const LE_FORMS_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/mips32le_forms.text");
const LE_FORMS_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/mips32le_forms.mnemonics");
const A32_ORACLE_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_a32_oracle_o2.text");

const IMAGE_BASE: u64 = 0x1000;
const MIX_INSTRUCTIONS: usize = 7;
const MIX_BYTES: usize = MIX_INSTRUCTIONS * 4;
const MIX_TRANSFER: u64 = IMAGE_BASE + 0x14;
const MIX_DELAY_SLOT: u64 = IMAGE_BASE + 0x18;

struct CompiledImage {
    label: &'static str,
    endian: Endian,
    text: &'static [u8],
    listing: &'static str,
    trapping: &'static [&'static str],
}

const COMPILED_IMAGES: [CompiledImage; 4] = [
    CompiledImage {
        label: "mips32be-o2",
        endian: Endian::Big,
        text: BE_ORACLE_TEXT,
        listing: BE_ORACLE_LISTING,
        trapping: &[],
    },
    CompiledImage {
        label: "mips32le-o2",
        endian: Endian::Little,
        text: LE_ORACLE_TEXT,
        listing: LE_ORACLE_LISTING,
        trapping: &[],
    },
    CompiledImage {
        label: "mips32be-forms",
        endian: Endian::Big,
        text: BE_FORMS_TEXT,
        listing: BE_FORMS_LISTING,
        trapping: &["add", "sub", "div"],
    },
    CompiledImage {
        label: "mips32le-forms",
        endian: Endian::Little,
        text: LE_FORMS_TEXT,
        listing: LE_FORMS_LISTING,
        trapping: &["add", "sub", "div"],
    },
];

const ORACLE_IMAGES: [CompiledImage; 2] = [
    CompiledImage {
        label: "mips32be-o2",
        endian: Endian::Big,
        text: BE_ORACLE_TEXT,
        listing: BE_ORACLE_LISTING,
        trapping: &[],
    },
    CompiledImage {
        label: "mips32le-o2",
        endian: Endian::Little,
        text: LE_ORACLE_TEXT,
        listing: LE_ORACLE_LISTING,
        trapping: &[],
    },
];

fn listed_mnemonics(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty())
        .collect()
}

fn arch_for(endian: Endian) -> PcodeArch {
    PcodeArch::for_language(Language::Mips32(endian))
        .unwrap_or_else(|| panic!("{endian:?} must resolve through the architecture table"))
}

fn lift(label: &str, endian: Endian, text: &[u8]) -> ArchLift {
    lower_mips32(text, IMAGE_BASE, "recovered", endian)
        .unwrap_or_else(|error| panic!("{label} must lift: {error}"))
}

fn decode(label: &str, endian: Endian, text: &[u8]) -> DecodedBlock {
    arch_for(endian)
        .decode(text, IMAGE_BASE)
        .unwrap_or_else(|error| panic!("{label} must decode: {error}"))
}

fn machine_addresses(function: &NirFunction) -> BTreeSet<u64> {
    function
        .instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.address)
        .collect()
}

fn value_ops(function: &NirFunction) -> BTreeSet<&'static str> {
    function
        .instructions
        .iter()
        .filter_map(|instruction: &NirInstr| match instruction.op {
            NirOp::Value { op, .. } => Some(ValueOp::mnemonic(op)),
            _ => None,
        })
        .collect()
}

fn pseudo_source(function: &NirFunction) -> (SurfaceFunction, String) {
    let hir: HirFunction = structurize_function(function);
    let surface: SurfaceFunction = surfacify_function(&hir);
    let emitted: String = emit_pseudo_source(&surface).expect("emit pseudo source");
    (surface, emitted)
}

fn mix_body(text: &'static [u8]) -> &'static [u8] {
    text.get(..MIX_BYTES)
        .expect("the committed image holds the first compiled function")
}

fn accumulate_body(text: &'static [u8]) -> &'static [u8] {
    text.get(MIX_BYTES..)
        .expect("the committed image holds the second compiled function")
}

#[test]
fn every_instruction_the_reference_disassembly_lists_reaches_a_lifted_slot() {
    for image in &COMPILED_IMAGES {
        let lifted: ArchLift = lift(image.label, image.endian, image.text);
        assert_eq!(
            lifted.consumed,
            image.text.len(),
            "{} left undecoded bytes behind",
            image.label
        );
        assert_eq!(
            lifted.gaps.mnemonics(),
            image.trapping,
            "{} must report exactly the instructions whose trap it models only as an opaque effect",
            image.label
        );
        assert!(
            lifted
                .gaps
                .reported()
                .iter()
                .all(|gap: &LiftGap| gap.status == DecodeStatus::CallOther),
            "{} must not report an instruction it failed to recognise: {:?}",
            image.label,
            lifted.gaps.reported()
        );
        let decoded: Vec<u64> = decode(image.label, image.endian, image.text)
            .instructions
            .iter()
            .map(|instruction: &PcodeInstr| instruction.address)
            .collect();
        assert_eq!(
            decoded.len(),
            listed_mnemonics(image.listing).len(),
            "{} must split into the instructions the reference disassembly lists",
            image.label
        );
        let boundaries: BTreeSet<u64> = decoded.into_iter().collect();
        let lifted_addresses: BTreeSet<u64> = machine_addresses(&lifted.function);
        assert!(
            lifted_addresses.is_subset(&boundaries),
            "{} lifted an address that is not an instruction boundary: {:?}",
            image.label,
            lifted_addresses
                .difference(&boundaries)
                .collect::<Vec<&u64>>()
        );
        assert_eq!(
            lifted.function.address, IMAGE_BASE,
            "{} must start at the image base",
            image.label
        );
        let image_end: u64 = IMAGE_BASE
            .checked_add(u64::try_from(image.text.len()).expect("the image length fits an address"))
            .expect("the image end fits an address");
        assert_eq!(
            lifted.function.end, image_end,
            "{} must cover its whole image",
            image.label
        );
    }
}

#[test]
fn the_compiled_mix_body_recovers_the_operations_its_source_performs() {
    for image in &ORACLE_IMAGES {
        assert_eq!(
            listed_mnemonics(image.listing)
                .get(MIX_INSTRUCTIONS - 1)
                .copied(),
            Some("addu"),
            "{} must still end its first compiled function where this slice ends",
            image.label
        );
        let lifted: ArchLift = lift(image.label, image.endian, mix_body(image.text));
        let performed: BTreeSet<&'static str> = value_ops(&lifted.function);
        for expected in ["INT_SUB", "INT_ADD", "INT_XOR"] {
            assert!(
                performed.contains(expected),
                "{} performs {expected}, so recovery must too: {performed:?}",
                image.label
            );
        }
        assert!(
            lifted
                .function
                .instructions
                .iter()
                .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::RawStore { .. })),
            "{} stores the exclusive or through its pointer argument",
            image.label
        );
        assert!(
            lifted
                .function
                .instructions
                .iter()
                .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::RawLoad { .. })),
            "{} loads the element it adds to the result",
            image.label
        );
        let (_surface, emitted): (SurfaceFunction, String) = pseudo_source(&lifted.function);
        for fragment in ["^", "store(", "return"] {
            assert!(
                emitted.contains(fragment),
                "{} must keep {fragment} in the recovered source:\n{emitted}",
                image.label
            );
        }
    }
}

#[test]
fn the_compiled_counted_loop_recovers_as_a_loop_in_pseudo_source() {
    for image in &ORACLE_IMAGES {
        let lifted: ArchLift = lift(image.label, image.endian, accumulate_body(image.text));
        let (surface, emitted): (SurfaceFunction, String) = pseudo_source(&lifted.function);
        assert!(
            surface.structured,
            "{} must structure its counted loop:\n{emitted}",
            image.label
        );
        for fragment in ["while", "break", "if (", "mem["] {
            assert!(
                emitted.contains(fragment),
                "{} must recover {fragment} from its counted loop:\n{emitted}",
                image.label
            );
        }
    }
}

#[test]
fn a_delay_slot_of_a_compiled_transfer_executes_before_the_transfer() {
    for image in &ORACLE_IMAGES {
        let listing: Vec<&str> = listed_mnemonics(image.listing);
        assert_eq!(
            (
                listing.get(MIX_INSTRUCTIONS - 2).copied(),
                listing.get(MIX_INSTRUCTIONS - 1).copied()
            ),
            (Some("jr"), Some("addu")),
            "{} must still place an addu in the delay slot of its return",
            image.label
        );
        let lifted: ArchLift = lift(image.label, image.endian, mix_body(image.text));
        let slot_position: usize = lifted
            .function
            .instructions
            .iter()
            .position(|instruction: &NirInstr| {
                instruction.address == MIX_TRANSFER
                    && matches!(
                        &instruction.op,
                        NirOp::Value {
                            op: ValueOp::IntAdd,
                            ..
                        }
                    )
            })
            .unwrap_or_else(|| {
                panic!(
                    "{} must schedule the delay slot addu at the transfer address {MIX_TRANSFER:#x}: {:?}",
                    image.label,
                    lifted_order(&lifted.function)
                )
            });
        let return_position: usize = lifted
            .function
            .instructions
            .iter()
            .position(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return))
            .unwrap_or_else(|| panic!("{} must lower jr ra to a return", image.label));
        assert!(
            slot_position < return_position,
            "{} must run the delay slot before the transfer it follows: {:?}",
            image.label,
            lifted_order(&lifted.function)
        );
        let residue: &NirInstr = lifted
            .function
            .instructions
            .iter()
            .find(|instruction: &&NirInstr| instruction.address == MIX_DELAY_SLOT)
            .unwrap_or_else(|| {
                panic!(
                    "{} must still account for the slot address {MIX_DELAY_SLOT:#x}",
                    image.label
                )
            });
        assert_eq!(residue.mnemonic, "addu");
        assert_eq!(
            residue.op,
            NirOp::Nop,
            "{} must not execute the slot a second time at its own address",
            image.label
        );
    }
}

#[test]
fn mips32_pseudo_source_carries_no_more_residue_than_arm32() {
    let mips: ArchLift = lift("mips32be-o2", Endian::Big, mix_body(BE_ORACLE_TEXT));
    let (_surface, emitted): (SurfaceFunction, String) = pseudo_source(&mips.function);
    for leaked in ["addu;", "sll;", "RETURN;", "CBRANCH;", "BRANCH;"] {
        assert!(
            !emitted.contains(leaked),
            "mips32 declares a native source language, so the structurer must suppress {leaked} \
             rather than emitting it as a statement:\n{emitted}"
        );
    }
    assert!(
        emitted.contains("return"),
        "suppressing residue must not remove the function's real return:\n{emitted}"
    );

    let arm: ArchLift = lower_arm32(
        A32_ORACLE_TEXT
            .get(..MIX_BYTES)
            .expect("the committed arm image holds its first function"),
        IMAGE_BASE,
        "recovered",
        ArmMode::A32,
    )
    .expect("the arm32 body lifts");
    let (_arm_surface, arm_emitted): (SurfaceFunction, String) = pseudo_source(&arm.function);
    assert!(
        !arm_emitted.contains("RETURN;"),
        "arm32 must keep suppressing the same residue:\n{arm_emitted}"
    );
}

#[test]
fn a_mips32_instruction_is_given_native_effects_rather_than_an_unknown_row() {
    use disrobe_nir::{EffectContext, EffectRow, SourceLang, derive_effect_row};

    let mips: ArchLift = lift("mips32be-o2", Endian::Big, mix_body(BE_ORACLE_TEXT));
    let context: EffectContext = EffectContext::new();
    let mut modelled: usize = 0;
    for instruction in &mips.function.instructions {
        assert_eq!(
            instruction.source.lang,
            SourceLang::NativeMips,
            "every lifted mips instruction must name its own source language"
        );
        let row: EffectRow = derive_effect_row(instruction, &context);
        if !row.is_unknown() {
            modelled = modelled.saturating_add(1);
        }
    }
    assert!(
        modelled > 0,
        "a compiled mips body must produce modelled effect rows, not an unknown row for every \
         instruction"
    );
}

#[test]
fn a_stream_that_ends_mid_instruction_names_its_tail_instead_of_dropping_it() {
    for (label, endian, tail) in [
        ("mips32be-half-word-tail", Endian::Big, 2_usize),
        ("mips32le-half-word-tail", Endian::Little, 2),
        ("mips32be-single-byte-tail", Endian::Big, 1),
        ("mips32le-single-byte-tail", Endian::Little, 1),
    ] {
        let source: &[u8] = match endian {
            Endian::Big => BE_ORACLE_TEXT,
            Endian::Little => LE_ORACLE_TEXT,
        };
        let bytes: &[u8] = source
            .get(..MIX_BYTES.saturating_add(tail))
            .expect("the committed image holds a partial trailing instruction");
        let block: DecodedBlock = decode(label, endian, bytes);
        assert_eq!(
            block.consumed,
            bytes.len(),
            "{label} must account for every byte it was given"
        );
        let last: &PcodeInstr = block
            .instructions
            .last()
            .unwrap_or_else(|| panic!("{label} must still split into instruction slots"));
        assert_eq!(
            last.length, tail,
            "{label} must end on a slot holding exactly the undecodable tail"
        );
        assert_eq!(
            last.status,
            DecodeStatus::Truncated,
            "{label} must name its tail as truncated rather than claim it decoded"
        );
        let gaps: LiftGaps = block_gaps(&block);
        assert_eq!(
            gaps.total(),
            1,
            "{label} must report exactly the tail it could not decode: {:?}",
            gaps.mnemonics()
        );
        let refusal: LiftError = lower_mips32(bytes, IMAGE_BASE, "recovered", endian)
            .expect_err("a machine instruction without semantics is refused, not guessed");
        assert!(
            matches!(refusal, LiftError::InvalidPcode { .. }),
            "{label} must refuse with a typed p-code error, got {refusal}"
        );
    }
}

#[test]
fn lifting_the_same_image_twice_produces_the_same_function() {
    for image in &COMPILED_IMAGES {
        let first: ArchLift = lift(image.label, image.endian, image.text);
        let second: ArchLift = lift(image.label, image.endian, image.text);
        assert_eq!(
            first, second,
            "{} must lower deterministically",
            image.label
        );
    }
}

#[test]
fn a_compiled_image_read_in_the_wrong_byte_order_reports_what_it_cannot_model() {
    let correct: ArchLift = lift("mips32be-o2", Endian::Big, BE_ORACLE_TEXT);
    assert_eq!(
        correct.gaps.total(),
        0,
        "every word of the correctly ordered image matches an instruction: {:?}",
        correct.gaps.mnemonics()
    );
    let misread: ArchLift = lift("mips32be-o2-as-le", Endian::Little, BE_ORACLE_TEXT);
    assert!(
        !misread.gaps.is_empty(),
        "a big-endian image read as little-endian must report the words it cannot model"
    );
    assert!(
        misread.gaps.total() <= misread.function.instructions.len(),
        "a reported gap total must not exceed the slots the lift produced"
    );
    assert_ne!(
        correct.function, misread.function,
        "a misread byte order must not recover the same program"
    );
}

#[test]
fn a_set_on_less_than_zero_extends_a_one_byte_comparison() {
    for (mnemonic, word) in [
        ("slt", 0x035b_c82a_u32),
        ("sltu", 0x035b_c82b),
        ("slti", 0x2b39_0005),
        ("sltiu", 0x2f39_0005),
    ] {
        let bytes: [u8; 4] = word.to_be_bytes();
        let block: DecodedBlock = decode(mnemonic, Endian::Big, &bytes);
        let comparison: &PcodeOp = block
            .ordered_ops
            .first()
            .unwrap_or_else(|| panic!("{mnemonic} must lower to a comparison"));
        let (output, expected_signed): (Varnode, bool) = match comparison {
            PcodeOp::IntSignedLess { output, .. } => (*output, true),
            PcodeOp::IntLess { output, .. } => (*output, false),
            other => panic!("{mnemonic} must compare, got {other:?}"),
        };
        assert_eq!(
            expected_signed,
            matches!(mnemonic, "slt" | "slti"),
            "{mnemonic} must choose its comparison by signedness"
        );
        assert_eq!(
            output.size_bytes, 1,
            "{mnemonic} must compare into a one-byte boolean, not the destination register"
        );
        let widened: &PcodeOp = block
            .ordered_ops
            .get(1)
            .unwrap_or_else(|| panic!("{mnemonic} must widen its comparison"));
        let PcodeOp::IntZext { output, input } = widened else {
            panic!("{mnemonic} must zero extend its comparison, got {widened:?}");
        };
        assert_eq!(
            input.size_bytes, 1,
            "{mnemonic} must widen the one-byte comparison it produced"
        );
        assert_eq!(
            output.size_bytes, 4,
            "{mnemonic} must write a full register"
        );
        assert_eq!(
            block.ordered_ops.len(),
            2,
            "{mnemonic} is exactly a comparison and a widening"
        );
        let lifted: ArchLift = lift(mnemonic, Endian::Big, &bytes);
        assert_eq!(
            lifted.gaps.total(),
            0,
            "{mnemonic} must lift without reporting a gap"
        );
    }
}

fn lifted_order(function: &NirFunction) -> Vec<(u64, String)> {
    function
        .instructions
        .iter()
        .map(|instruction: &NirInstr| (instruction.address, instruction.mnemonic.clone()))
        .collect()
}
