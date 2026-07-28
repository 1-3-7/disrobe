use super::*;
use crate::fixtures::minimal_elf64;
use crate::test_support::{pe64_text_base, pe64_with_text};

const TEXT_VA: u32 = 0x1000;

fn image(text: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = text.to_vec();
    while body.len() % 16 != 0 {
        body.push(0xCC);
    }
    pe64_with_text(&body, TEXT_VA)
}

fn features_of(text: &[u8]) -> Vec<FunctionFeatures> {
    extract_function_features(&image(text)).expect("real PE image extracts")
}

fn all_references(features: &[FunctionFeatures]) -> Vec<DataReference> {
    features
        .iter()
        .flat_map(|entry: &FunctionFeatures| entry.references().iter().cloned())
        .collect()
}

fn aarch64_insn(address: u64, mnemonic: &str, word: u32) -> DisasmInstruction {
    DisasmInstruction {
        offset: address,
        bytes: word.to_le_bytes().to_vec(),
        mnemonic: mnemonic.to_owned(),
        ..DisasmInstruction::default()
    }
}

fn words_of(body: &[DisasmInstruction]) -> Vec<Option<u32>> {
    body.iter().map(instruction_word).collect()
}

#[test]
fn a_non_object_input_is_refused() {
    let error: Error = extract_function_features(b"this is not a binary").expect_err("refuse");
    assert!(matches!(
        error,
        Error::ObjectParse(_) | Error::UnknownFormat | Error::UnsupportedArch(_)
    ));
}

#[test]
fn an_empty_input_is_refused() {
    assert!(extract_function_features(&[]).is_err());
}

#[test]
fn a_truncated_object_is_refused() {
    let full: Vec<u8> = minimal_elf64();
    for keep in [1usize, 4, 16, 40, 63] {
        let truncated: &[u8] = full.get(..keep.min(full.len())).unwrap_or(&full);
        assert!(
            extract_function_features(truncated).is_err(),
            "a {keep}-byte prefix of an ELF must be refused, never panic"
        );
    }
}

#[test]
fn a_function_referencing_nothing_reports_an_empty_reference_set() {
    let features: Vec<FunctionFeatures> = features_of(&[0x31, 0xC0, 0xC3]);
    assert_eq!(features.len(), 1, "one discovered function: {features:?}");
    let only: &FunctionFeatures = &features[0];
    assert_eq!(only.id(), FunctionId::from(pe64_text_base() + 0x1000));
    assert!(only.references().is_empty(), "no reference may be invented");
    assert!(!only.has_anchor());
}

#[test]
fn an_unusual_wide_immediate_is_recorded_as_a_constant() {
    let mut text: Vec<u8> = vec![0x48, 0xB8];
    text.extend_from_slice(&0x9e37_79b9_7f4a_7c15_u64.to_le_bytes());
    text.push(0xC3);
    assert_eq!(
        all_references(&features_of(&text)),
        vec![DataReference::UnusualConstant(0x9e37_79b9_7f4a_7c15)]
    );
}

#[test]
fn an_ordinary_immediate_is_left_out_by_the_admissibility_filter() {
    let mut text: Vec<u8> = vec![0x48, 0xB8];
    text.extend_from_slice(&0xffff_ffff_u64.to_le_bytes());
    text.push(0xC3);
    assert!(all_references(&features_of(&text)).is_empty());
}

#[test]
fn a_stack_frame_immediate_is_not_a_constant() {
    let text: [u8; 8] = [0x48, 0x81, 0xEC, 0x28, 0x01, 0x00, 0x00, 0xC3];
    assert!(
        all_references(&features_of(&text)).is_empty(),
        "sub rsp, 0x128 is frame arithmetic, not a data reference"
    );
}

#[test]
fn an_immediate_inside_the_mapped_image_is_not_a_constant() {
    let mut text: Vec<u8> = vec![0x48, 0xB8];
    text.extend_from_slice(&(pe64_text_base() + 0x1004).to_le_bytes());
    text.push(0xC3);
    assert!(
        all_references(&features_of(&text)).is_empty(),
        "an immediate inside the image is an address, not a constant"
    );
}

#[test]
fn a_packed_ascii_immediate_is_not_a_constant() {
    let mut text: Vec<u8> = vec![0x48, 0xB8];
    text.extend_from_slice(b"hello wo");
    text.push(0xC3);
    assert!(all_references(&features_of(&text)).is_empty());
    assert!(is_packed_ascii(0x6f77_206f_6c6c_6568));
    assert!(!is_packed_ascii(0x9e37_79b9));
    assert!(!is_packed_ascii(0x41));
}

#[test]
fn an_image_without_import_data_reports_no_imported_calls() {
    let text: [u8; 6] = [0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
    assert!(
        all_references(&features_of(&text))
            .iter()
            .all(|reference: &DataReference| !matches!(reference, DataReference::ImportedCall(_))),
        "a call with no import descriptor must never be named"
    );
}

#[test]
fn an_adrp_pairs_only_with_an_add_on_its_own_register() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "adrp", 0x9000_0008),
        aarch64_insn(0x1004, "add", 0x9104_8D08),
    ];
    let words: Vec<Option<u32>> = words_of(&body);
    assert_eq!(paired_low_bits(8, &body, &words, 0), vec![0x123]);
    assert!(
        paired_low_bits(9, &body, &words, 0).is_empty(),
        "an add on x8 may not complete an adrp into x9"
    );
}

#[test]
fn an_adrp_pairing_stops_at_a_branch_and_at_a_redefinition() {
    let after_branch: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "adrp", 0x9000_0008),
        aarch64_insn(0x1004, "b", 0x1400_0002),
        aarch64_insn(0x1008, "add", 0x9104_8D08),
    ];
    assert!(paired_low_bits(8, &after_branch, &words_of(&after_branch), 0).is_empty());

    let after_redefinition: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "adrp", 0x9000_0008),
        aarch64_insn(0x1004, "movz", 0xD280_0008),
        aarch64_insn(0x1008, "add", 0x9104_8D08),
    ];
    assert!(
        paired_low_bits(8, &after_redefinition, &words_of(&after_redefinition), 0).is_empty(),
        "a write to x8 invalidates the page held in x8"
    );
}

#[test]
fn a_wide_move_chain_folds_into_one_value() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "movz", 0xD2A2_4680),
        aarch64_insn(0x1004, "movk", 0xF297_DDE0),
        aarch64_insn(0x1008, "mul", 0x9B00_7C00),
    ];
    assert_eq!(
        fold_wide_move(&body, &words_of(&body), 0),
        (Some(0x1234_beef), 2)
    );
}

#[test]
fn a_wide_move_chain_that_runs_into_a_branch_is_dropped() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "movz", 0xD2A2_4680),
        aarch64_insn(0x1004, "b", 0x1400_0002),
    ];
    assert_eq!(fold_wide_move(&body, &words_of(&body), 0), (None, 1));
}

#[test]
fn a_wide_move_chain_ignores_a_movk_on_another_register() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "movz", 0xD2A2_4680),
        aarch64_insn(0x1004, "movk", 0xF297_DDE1),
        aarch64_insn(0x1008, "mul", 0x9B00_7C00),
    ];
    assert_eq!(
        fold_wide_move(&body, &words_of(&body), 0),
        (Some(0x1234_0000), 1)
    );
}

#[test]
fn a_conditional_branch_mnemonic_is_recognized_in_both_renderings() {
    for mnemonic in ["b.eq", "beq", "b", "bl", "cbz", "ret", "tbnz"] {
        assert!(is_branch(mnemonic), "{mnemonic} must abort a forward scan");
    }
    for mnemonic in ["bic", "bfi", "add", "movk", "ldr"] {
        assert!(!is_branch(mnemonic), "{mnemonic} is not a branch");
    }
}
