#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use disrobe_nir::{NirArtifact, NirInstr, NirOp, SourceOffset, SourceUnit, ValueOp};
use disrobe_nir_lift::{
    ArchLift, LiftError, PcodeArch, PcodeLiftConfig, lower_arch, lower_pcode_block,
    lower_pcode_block_with_provenance,
};
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr};

const THUMB_FORMS_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_thumb_forms.text");
const THUMB_FORMS_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/arm32_thumb_forms.mnemonics");
const THUMB_ORACLE_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_thumb_oracle_o2.text");
const THUMB_ORACLE_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/arm32_thumb_oracle_o2.mnemonics");

const IMAGE_BASE: u64 = 0x1000;
const LOWERING_BOUND: Duration = Duration::from_secs(30);
const SWEEP_BOUND: Duration = Duration::from_mins(3);

const NARROW_BYTES: usize = 2;
const WIDE_BYTES: usize = 4;

const WIDE_ONLY_MNEMONICS: [&str; 3] = ["movw", "movt", "bl"];
const NARROW_ONLY_MNEMONICS: [&str; 3] = ["cbz", "cbnz", "bx"];

const MIXED_SLICE: std::ops::Range<usize> = 0x0e..0x18;
const MIXED_LISTING: std::ops::Range<usize> = 7..10;

const WIDTH_BOUNDARY_SWEEP: std::ops::RangeInclusive<u32> = 0xe000..=0xffff;
const SWEEP_NARROW_ACCEPTED: usize = 2048;
const SWEEP_WIDE_ACCEPTED: usize = 2048;

struct ThumbImage {
    label: &'static str,
    text: &'static [u8],
    listing: &'static str,
}

const THUMB_IMAGES: [ThumbImage; 2] = [
    ThumbImage {
        label: "thumb-forms",
        text: THUMB_FORMS_TEXT,
        listing: THUMB_FORMS_LISTING,
    },
    ThumbImage {
        label: "thumb-o2",
        text: THUMB_ORACLE_TEXT,
        listing: THUMB_ORACLE_LISTING,
    },
];

fn reference_mnemonics(listing: &str) -> Vec<&str> {
    listing.split_whitespace().collect()
}

fn within_bound<T: Send + 'static>(
    label: &str,
    bound: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sender, receiver): (Sender<T>, Receiver<T>) = mpsc::channel();
    let worker: JoinHandle<()> = thread::spawn(move || {
        drop(sender.send(work()));
    });
    match receiver.recv_timeout(bound) {
        Ok(value) => {
            drop(worker);
            value
        }
        Err(RecvTimeoutError::Timeout) => panic!("{label} did not finish within {bound:?}"),
        Err(RecvTimeoutError::Disconnected) => {
            panic!("{label} panicked before it produced a result")
        }
    }
}

fn bounded_decode(label: &'static str, text: &'static [u8], arch: PcodeArch) -> DecodedBlock {
    within_bound(label, LOWERING_BOUND, move || {
        arch.decode(text, IMAGE_BASE)
            .unwrap_or_else(|error| panic!("{label} must decode: {error}"))
    })
}

fn bounded_lift(label: &'static str, text: &'static [u8], arch: PcodeArch) -> ArchLift {
    within_bound(label, LOWERING_BOUND, move || {
        lower_arch(arch, text, IMAGE_BASE, "recovered")
            .unwrap_or_else(|error| panic!("{label} must lift: {error}"))
    })
}

fn bounded_provenance(
    label: &'static str,
    text: &'static [u8],
    arch: PcodeArch,
) -> (NirArtifact, Vec<u8>) {
    within_bound(label, LOWERING_BOUND, move || {
        let config: PcodeLiftConfig = arch
            .config()
            .unwrap_or_else(|error| panic!("{label} must select a lift configuration: {error}"));
        let block: DecodedBlock = arch
            .decode(text, IMAGE_BASE)
            .unwrap_or_else(|error| panic!("{label} must decode for provenance: {error}"));
        let artifact: NirArtifact = lower_pcode_block_with_provenance(&block, "recovered", &config)
            .unwrap_or_else(|error| panic!("{label} must lift with provenance: {error}"));
        let reemitted: Vec<u8> = artifact
            .reemit_original_bytes(0)
            .unwrap_or_else(|error| panic!("{label} must re-emit its source bytes: {error}"));
        (artifact, reemitted)
    })
}

fn decoded_mnemonics(block: &DecodedBlock) -> Vec<&str> {
    block
        .instructions
        .iter()
        .map(|instruction: &PcodeInstr| instruction.mnemonic.as_str())
        .collect()
}

fn unit_width(label: &str, unit: &SourceUnit) -> usize {
    unit.original_bytes()
        .unwrap_or_else(|| panic!("{label} must keep its original source bytes"))
        .len()
}

fn value_ops(function_instructions: &[NirInstr]) -> BTreeSet<&'static str> {
    function_instructions
        .iter()
        .filter_map(|instruction: &NirInstr| match instruction.op {
            NirOp::Value { op, .. } => Some(ValueOp::mnemonic(op)),
            _ => None,
        })
        .collect()
}

fn operand_words(function_instructions: &[NirInstr]) -> BTreeSet<String> {
    let mut words: BTreeSet<String> = BTreeSet::new();
    for instruction in function_instructions {
        words.extend(instruction.operands.iter().cloned());
        if let NirOp::Copy { src, .. } = &instruction.op {
            words.insert(src.clone());
        }
    }
    words
}

#[test]
fn each_thumb_slot_carries_the_mnemonic_the_reference_disassembly_records_at_that_index() {
    for image in &THUMB_IMAGES {
        let block: DecodedBlock = bounded_decode(image.label, image.text, PcodeArch::Arm32Thumb);
        let reference: Vec<&str> = reference_mnemonics(image.listing);
        assert_eq!(
            decoded_mnemonics(&block),
            reference,
            "{} must split into the exact instruction sequence the reference disassembly lists",
            image.label
        );
        assert_eq!(
            block.consumed,
            image.text.len(),
            "{} must account for every byte",
            image.label
        );
        assert!(
            block
                .instructions
                .iter()
                .all(|instruction: &PcodeInstr| instruction.status == DecodeStatus::Supported),
            "{} carries an encoding this lane does not claim",
            image.label
        );
    }
}

#[test]
fn thumb_provenance_tiles_every_halfword_of_a_mixed_width_image() {
    for image in &THUMB_IMAGES {
        let (artifact, reemitted): (NirArtifact, Vec<u8>) =
            bounded_provenance(image.label, image.text, PcodeArch::Arm32Thumb);
        let reference: Vec<&str> = reference_mnemonics(image.listing);
        let units: &[SourceUnit] = artifact.source_units();
        assert_eq!(
            units.len(),
            reference.len(),
            "{} must produce one source unit per listed instruction",
            image.label
        );
        let mut cursor: usize = 0;
        let mut widths: BTreeSet<usize> = BTreeSet::new();
        for (index, unit) in units.iter().enumerate() {
            let width: usize = unit_width(image.label, unit);
            assert!(
                width == NARROW_BYTES || width == WIDE_BYTES,
                "{} slot {index} claims {width} bytes, which is not a Thumb encoding width",
                image.label
            );
            let expected_address: u64 = IMAGE_BASE
                .checked_add(u64::try_from(cursor).expect("the image length fits an address"))
                .expect("the slot address fits an address");
            assert_eq!(
                unit.offset(),
                SourceOffset::MemoryImage(expected_address),
                "{} slot {index} must start where the previous slot ended",
                image.label
            );
            assert_eq!(
                unit.original_bytes(),
                image.text.get(cursor..cursor.saturating_add(width)),
                "{} slot {index} must own the image bytes at its own offset",
                image.label
            );
            widths.insert(width);
            cursor = cursor.saturating_add(width);
        }
        assert_eq!(
            cursor,
            image.text.len(),
            "{} must tile its whole image without a gap or an overlap",
            image.label
        );
        assert_eq!(
            widths,
            BTreeSet::from([NARROW_BYTES, WIDE_BYTES]),
            "{} must exercise both Thumb encoding widths",
            image.label
        );
        assert_eq!(
            reemitted, image.text,
            "{} must re-emit its input bytes exactly",
            image.label
        );
    }
}

#[test]
fn a_thumb_mnemonic_with_only_one_architectural_width_keeps_that_width() {
    let mut wide_seen: usize = 0;
    let mut narrow_seen: usize = 0;
    for image in &THUMB_IMAGES {
        let (artifact, _reemitted): (NirArtifact, Vec<u8>) =
            bounded_provenance(image.label, image.text, PcodeArch::Arm32Thumb);
        let reference: Vec<&str> = reference_mnemonics(image.listing);
        for (index, unit) in artifact.source_units().iter().enumerate() {
            let mnemonic: &str = reference.get(index).unwrap_or_else(|| {
                panic!("{} slot {index} must have a reference name", image.label)
            });
            let width: usize = unit_width(image.label, unit);
            if WIDE_ONLY_MNEMONICS.contains(&mnemonic) {
                wide_seen = wide_seen.saturating_add(1);
                assert_eq!(
                    width, WIDE_BYTES,
                    "{} slot {index} decodes {mnemonic}, which has no narrow Thumb encoding",
                    image.label
                );
            }
            if NARROW_ONLY_MNEMONICS.contains(&mnemonic) {
                narrow_seen = narrow_seen.saturating_add(1);
                assert_eq!(
                    width, NARROW_BYTES,
                    "{} slot {index} decodes {mnemonic}, which has no wide Thumb encoding",
                    image.label
                );
            }
        }
    }
    assert!(
        wide_seen >= 3,
        "the committed images must exercise the wide-only encodings, saw {wide_seen}"
    );
    assert!(
        narrow_seen >= 3,
        "the committed images must exercise the narrow-only encodings, saw {narrow_seen}"
    );
}

#[test]
fn every_accepted_first_halfword_claims_the_width_its_top_five_bits_declare() {
    const FILLER: [u8; 2] = [0x00, 0xd0];
    let (narrow, wide): (usize, usize) = within_bound("thumb-halfword-sweep", SWEEP_BOUND, || {
        let mut narrow: usize = 0;
        let mut wide: usize = 0;
        for encoded in WIDTH_BOUNDARY_SWEEP {
            let halfword: u16 = u16::try_from(encoded).expect("the sweep stays inside a halfword");
            let low: [u8; 2] = halfword.to_le_bytes();
            let bytes: [u8; 4] = [low[0], low[1], FILLER[0], FILLER[1]];
            let block: DecodedBlock = PcodeArch::Arm32Thumb
                .decode(&bytes, IMAGE_BASE)
                .unwrap_or_else(|error| panic!("halfword {halfword:#06x} must decode: {error}"));
            let first: &PcodeInstr = block
                .instructions
                .first()
                .unwrap_or_else(|| panic!("halfword {halfword:#06x} must fill a slot"));
            if first.status != DecodeStatus::Supported {
                continue;
            }
            let wide_encoding: bool = matches!(halfword >> 11, 0b11101..=0b11111);
            let declared: usize = if wide_encoding {
                WIDE_BYTES
            } else {
                NARROW_BYTES
            };
            assert_eq!(
                first.length, declared,
                "halfword {halfword:#06x} decodes as {} but claims {} bytes",
                first.mnemonic, first.length
            );
            assert_eq!(
                first.bytes.len(),
                declared,
                "halfword {halfword:#06x} must own exactly the bytes its width declares"
            );
            assert_eq!(
                block.consumed,
                bytes.len(),
                "halfword {halfword:#06x} must leave the rest of the stream accounted for"
            );
            if wide_encoding {
                wide = wide.saturating_add(1);
            } else {
                narrow = narrow.saturating_add(1);
            }
        }
        (narrow, wide)
    });
    assert!(
        narrow >= SWEEP_NARROW_ACCEPTED && wide >= SWEEP_WIDE_ACCEPTED,
        "the boundary sweep must keep accepting the encodings it graded, saw {narrow} narrow and \
         {wide} wide"
    );
}

#[test]
fn a_single_compressed_thumb_instruction_lowers_to_the_move_it_encodes() {
    const MOVS_R0_1: &[u8] = &[0x01, 0x20];
    let lifted: ArchLift = bounded_lift("thumb-movs", MOVS_R0_1, PcodeArch::Arm32Thumb);
    assert_eq!(lifted.consumed, MOVS_R0_1.len());
    assert_eq!(lifted.decoded, 1, "one halfword is one instruction");
    assert_eq!(lifted.gaps.total(), 0, "{:?}", lifted.gaps.mnemonics());
    let words: BTreeSet<String> = operand_words(&lifted.function.instructions);
    assert!(
        words.contains("0x1"),
        "movs r0, #1 must move the immediate the encoding carries: {words:?}"
    );
    assert!(
        words.contains("r0"),
        "movs r0, #1 must write the register the encoding names: {words:?}"
    );
}

#[test]
fn a_single_wide_thumb_instruction_stays_one_instruction_instead_of_two_halfwords() {
    const MOVW_R4_0X1234: &[u8] = &[0x41, 0xf2, 0x34, 0x24];
    let block: DecodedBlock = bounded_decode("thumb-movw", MOVW_R4_0X1234, PcodeArch::Arm32Thumb);
    assert_eq!(
        decoded_mnemonics(&block),
        ["movw"],
        "a wide encoding must not split into two narrow slots"
    );
    assert_eq!(block.instructions[0].length, WIDE_BYTES);
    assert_eq!(block.consumed, MOVW_R4_0X1234.len());
    let lifted: ArchLift = bounded_lift("thumb-movw", MOVW_R4_0X1234, PcodeArch::Arm32Thumb);
    assert_eq!(lifted.gaps.total(), 0, "{:?}", lifted.gaps.mnemonics());
    let words: BTreeSet<String> = operand_words(&lifted.function.instructions);
    assert!(
        words.contains("0x1234"),
        "movw r4, #0x1234 must recover the split immediate its two halfwords encode: {words:?}"
    );
    assert!(
        words.contains("r4"),
        "movw r4, #0x1234 must write the register the second halfword names: {words:?}"
    );
}

#[test]
fn a_mixed_width_block_re_emits_its_exact_input_bytes() {
    let text: &'static [u8] = THUMB_FORMS_TEXT
        .get(MIXED_SLICE)
        .expect("the committed image holds the mixed-width slice");
    let expected: Vec<&str> = reference_mnemonics(THUMB_FORMS_LISTING)
        .get(MIXED_LISTING)
        .expect("the reference listing names the mixed-width slice")
        .to_vec();
    let block: DecodedBlock = bounded_decode("thumb-mixed", text, PcodeArch::Arm32Thumb);
    assert_eq!(
        decoded_mnemonics(&block),
        expected,
        "the mixed-width slice must decode to the names the reference disassembly records"
    );
    let (artifact, reemitted): (NirArtifact, Vec<u8>) =
        bounded_provenance("thumb-mixed", text, PcodeArch::Arm32Thumb);
    let widths: Vec<usize> = artifact
        .source_units()
        .iter()
        .map(|unit: &SourceUnit| unit_width("thumb-mixed", unit))
        .collect();
    assert_eq!(
        widths,
        [WIDE_BYTES, WIDE_BYTES, NARROW_BYTES],
        "the mixed-width slice must keep two wide encodings ahead of one narrow encoding"
    );
    assert_eq!(
        reemitted, text,
        "the mixed-width slice must re-emit exactly"
    );
}

#[test]
fn a_thumb_encoding_without_semantics_is_named_rather_than_guessed() {
    const BLX_THEN_BX: &[u8] = &[0x80, 0x47, 0x70, 0x47];
    let lifted: ArchLift = bounded_lift("thumb-blx", BLX_THEN_BX, PcodeArch::Arm32Thumb);
    assert_eq!(lifted.consumed, BLX_THEN_BX.len());
    assert_eq!(
        lifted.gaps.mnemonics(),
        ["blx"],
        "an interworking call must be reported under its real mnemonic"
    );
    assert!(
        !lifted
            .function
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(
                instruction.op,
                NirOp::Call { .. } | NirOp::Branch { .. } | NirOp::CondBranch { .. }
            )),
        "an unmodelled interworking call must not be guessed into a same-mode transfer"
    );
    assert!(
        lifted
            .function
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "the instruction after the gap must still recover: {:?}",
        lifted.function.instructions
    );
}

#[test]
fn a_thumb_loop_whose_flags_cross_its_own_back_edge_terminates() {
    const COUNTDOWN: &[u8] = &[0x01, 0x28, 0x01, 0x38, 0xfd, 0xd1, 0x70, 0x47];
    let block: DecodedBlock = bounded_decode("thumb-loop", COUNTDOWN, PcodeArch::Arm32Thumb);
    assert_eq!(
        decoded_mnemonics(&block),
        ["cmp", "subs", "bne", "bx"],
        "the loop body must decode as the encodings it holds"
    );
    let lifted: ArchLift = bounded_lift("thumb-loop", COUNTDOWN, PcodeArch::Arm32Thumb);
    assert_eq!(lifted.gaps.total(), 0, "{:?}", lifted.gaps.mnemonics());
    let performed: BTreeSet<&'static str> = value_ops(&lifted.function.instructions);
    assert!(
        performed.contains("INT_SUB"),
        "the loop body decrements its counter: {performed:?}"
    );
    let targets: Vec<Option<u64>> = lifted
        .function
        .instructions
        .iter()
        .filter_map(|instruction: &NirInstr| match instruction.op {
            NirOp::CondBranch { target } => Some(target),
            _ => None,
        })
        .collect();
    assert_eq!(
        targets,
        [Some(IMAGE_BASE.saturating_add(2))],
        "the conditional branch must close the loop on its own body"
    );
}

#[test]
fn a_thumb_block_past_its_configured_ceiling_returns_a_typed_refusal() {
    const COUNTDOWN: &[u8] = &[0x01, 0x28, 0x01, 0x38, 0xfd, 0xd1, 0x70, 0x47];
    let block: DecodedBlock = bounded_decode("thumb-ceiling", COUNTDOWN, PcodeArch::Arm32Thumb);
    let base: PcodeLiftConfig = PcodeArch::Arm32Thumb
        .config()
        .expect("the architecture table supplies a thumb register file");
    let instruction_limited: PcodeLiftConfig = base.clone().with_limits(2, 1_048_576);
    let refusal: LiftError = lower_pcode_block(&block, "bounded", &instruction_limited)
        .expect_err("a block past the instruction ceiling is refused, not lowered");
    assert!(
        matches!(refusal, LiftError::PcodeInstructionLimit { limit: 2 }),
        "the refusal must name the instruction ceiling, got {refusal}"
    );
    let operation_limited: PcodeLiftConfig = base.with_limits(65_536, 1);
    let refusal: LiftError = lower_pcode_block(&block, "bounded", &operation_limited)
        .expect_err("a block past the operation ceiling is refused, not lowered");
    assert!(
        matches!(refusal, LiftError::PcodeOperationLimit { limit: 1 }),
        "the refusal must name the operation ceiling, got {refusal}"
    );
}

#[test]
fn a_wide_thumb_mnemonic_without_semantics_becomes_a_gap_instead_of_discarding_the_function() {
    const LDRB_W_THEN_BX: &[u8] = &[0x92, 0xF8, 0x00, 0x30, 0x70, 0x47];
    let lifted: ArchLift = bounded_lift("thumb-wide-gap", LDRB_W_THEN_BX, PcodeArch::Arm32Thumb);
    assert_eq!(
        lifted.consumed,
        LDRB_W_THEN_BX.len(),
        "a wide form the lifter cannot model must cost its own instruction and nothing else"
    );
    assert_eq!(
        lifted.gaps.mnemonics(),
        ["ldrb.w"],
        "the gap must carry the qualified mnemonic the reference disassembler prints, not a stem"
    );
    assert!(
        lifted
            .function
            .instructions
            .iter()
            .any(|instruction: &NirInstr| matches!(instruction.op, NirOp::Return)),
        "the instruction after a wide-form gap must still recover; a mnemonic carrying a dot once \
         made the effect name an invalid identifier and cost the whole function: {:?}",
        lifted.function.instructions
    );
}
