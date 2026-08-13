#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_nir::{
    HirFunction, NirFunction, NirInstr, NirOp, SurfaceFunction, ValueOp, emit_pseudo_source,
    structurize_function, surfacify_function,
};
use disrobe_nir_lift::{ArchLift, PcodeArch, lower_arm32};
use disrobe_sleigh::lifter::{ArmMode, DecodedBlock, Language};
use disrobe_sleigh::pcode::PcodeInstr;

const A32_ORACLE_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_a32_oracle_o2.text");
const A32_ORACLE_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/arm32_a32_oracle_o2.mnemonics");
const THUMB_ORACLE_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_thumb_oracle_o2.text");
const THUMB_ORACLE_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/arm32_thumb_oracle_o2.mnemonics");
const A32_FORMS_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_a32_forms.text");
const A32_FORMS_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/arm32_a32_forms.mnemonics");
const THUMB_FORMS_TEXT: &[u8] =
    include_bytes!("../../disrobe-sleigh/tests/corpus/arm32_thumb_forms.text");
const THUMB_FORMS_LISTING: &str =
    include_str!("../../disrobe-sleigh/tests/corpus/arm32_thumb_forms.mnemonics");

const IMAGE_BASE: u64 = 0x1000;
const A32_MIX_INSTRUCTIONS: usize = 7;
const A32_MIX_BYTES: usize = A32_MIX_INSTRUCTIONS * 4;

struct CompiledImage {
    label: &'static str,
    mode: ArmMode,
    text: &'static [u8],
    listing: &'static str,
}

const COMPILED_IMAGES: [CompiledImage; 4] = [
    CompiledImage {
        label: "a32-o2",
        mode: ArmMode::A32,
        text: A32_ORACLE_TEXT,
        listing: A32_ORACLE_LISTING,
    },
    CompiledImage {
        label: "thumb-o2",
        mode: ArmMode::Thumb,
        text: THUMB_ORACLE_TEXT,
        listing: THUMB_ORACLE_LISTING,
    },
    CompiledImage {
        label: "a32-forms",
        mode: ArmMode::A32,
        text: A32_FORMS_TEXT,
        listing: A32_FORMS_LISTING,
    },
    CompiledImage {
        label: "thumb-forms",
        mode: ArmMode::Thumb,
        text: THUMB_FORMS_TEXT,
        listing: THUMB_FORMS_LISTING,
    },
];

fn listed_mnemonics(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty())
        .collect()
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

fn operand_words(function: &NirFunction) -> BTreeSet<String> {
    let mut words: BTreeSet<String> = BTreeSet::new();
    for instruction in &function.instructions {
        words.extend(instruction.operands.iter().cloned());
        if let NirOp::Copy { src, .. } = &instruction.op {
            words.insert(src.clone());
        }
    }
    words
}

fn lift(label: &str, mode: ArmMode, text: &[u8]) -> ArchLift {
    lower_arm32(text, IMAGE_BASE, "recovered", mode)
        .unwrap_or_else(|error| panic!("{label} must lift: {error}"))
}

fn decoded_addresses(label: &str, mode: ArmMode, text: &[u8]) -> Vec<u64> {
    let arch: PcodeArch = PcodeArch::for_language(Language::Arm32(mode))
        .unwrap_or_else(|| panic!("{label} must resolve through the architecture table"));
    let block: DecodedBlock = arch
        .decode(text, IMAGE_BASE)
        .unwrap_or_else(|error| panic!("{label} must decode: {error}"));
    block
        .instructions
        .iter()
        .map(|instruction: &PcodeInstr| instruction.address)
        .collect()
}

fn pseudo_source(function: &NirFunction) -> (SurfaceFunction, String) {
    let hir: HirFunction = structurize_function(function);
    let surface: SurfaceFunction = surfacify_function(&hir);
    let emitted: String = emit_pseudo_source(&surface).expect("emit pseudo source");
    (surface, emitted)
}

#[test]
fn every_instruction_the_reference_disassembly_lists_reaches_a_lifted_slot() {
    for image in &COMPILED_IMAGES {
        let lifted: ArchLift = lift(image.label, image.mode, image.text);
        assert_eq!(
            lifted.consumed,
            image.text.len(),
            "{} left undecoded bytes behind",
            image.label
        );
        assert_eq!(
            lifted.gaps.total(),
            0,
            "{} reported gaps the reference disassembly does not have: {:?}",
            image.label,
            lifted.gaps.mnemonics()
        );
        let decoded: Vec<u64> = decoded_addresses(image.label, image.mode, image.text);
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
fn the_compiled_a32_body_recovers_the_operations_its_source_performs() {
    assert_eq!(
        listed_mnemonics(A32_ORACLE_LISTING)
            .get(A32_MIX_INSTRUCTIONS - 1)
            .copied(),
        Some("bx"),
        "the first compiled function must still end where this slice ends"
    );
    let text: &[u8] = A32_ORACLE_TEXT
        .get(..A32_MIX_BYTES)
        .expect("the committed image holds the first function");
    let lifted: ArchLift = lift("a32-o2-first", ArmMode::A32, text);
    let performed: BTreeSet<&'static str> = value_ops(&lifted.function);
    for expected in ["INT_LEFT", "INT_XOR", "INT_SUB", "INT_ADD"] {
        assert!(
            performed.contains(expected),
            "the compiled body performs {expected}, so recovery must too: {performed:?}"
        );
    }
    assert!(
        lifted
            .function
            .instructions
            .iter()
            .any(
                |instruction: &NirInstr| matches!(instruction.op, NirOp::RawStore { .. })
                    || instruction.writes_memory
            ),
        "the compiled body stores through its pointer argument"
    );
    let (_surface, emitted): (SurfaceFunction, String) = pseudo_source(&lifted.function);
    assert!(
        emitted.contains('^'),
        "the recovered source must keep the exclusive or:\n{emitted}"
    );
    assert!(
        emitted.contains("<<"),
        "the recovered source must keep the shift:\n{emitted}"
    );
    assert!(
        emitted.contains("return"),
        "the recovered source must keep the return:\n{emitted}"
    );
}

#[test]
fn a_program_counter_read_carries_the_pipeline_bias_its_mode_defines() {
    for (label, mode, bytes, biased) in [
        (
            "a32",
            ArmMode::A32,
            [0x0f, 0x00, 0xa0, 0xe1].as_slice(),
            "0x1008",
        ),
        ("thumb", ArmMode::Thumb, [0x78, 0x46].as_slice(), "0x1004"),
    ] {
        let lifted: ArchLift = lift(label, mode, bytes);
        let words: BTreeSet<String> = operand_words(&lifted.function);
        assert!(
            words.contains(biased),
            "{label} must read the program counter as {biased}: {words:?}"
        );
        assert!(
            !words.contains("0x1000"),
            "{label} must not read the program counter as the instruction address: {words:?}"
        );
    }
}

#[test]
fn an_interworking_branch_is_reported_as_a_gap_rather_than_modelled_in_one_mode() {
    for (label, bytes) in [
        ("blx-immediate", [0x00, 0x00, 0x00, 0xfa].as_slice()),
        ("blx-register", [0x30, 0xff, 0x2f, 0xe1].as_slice()),
    ] {
        let lifted: ArchLift = lift(label, ArmMode::A32, bytes);
        assert_eq!(
            lifted.gaps.total(),
            1,
            "{label} switches instruction set, so it must be named as a gap"
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
            "{label} must not lower to a same-mode transfer"
        );
    }
}
