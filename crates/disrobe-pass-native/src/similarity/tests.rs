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

fn tail_context<'a>(
    index: &'a ImageIndex,
    entries: &'a BTreeSet<u64>,
    positions: &'a BTreeMap<u64, usize>,
) -> TailContext<'a> {
    TailContext::new(index, entries, Some(positions))
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
fn a_forward_conditional_branch_builds_a_three_block_graph() {
    let text: [u8; 12] = [
        0x85, 0xC0, 0x74, 0x04, 0x48, 0xFF, 0xC0, 0xC3, 0x48, 0xFF, 0xC8, 0xC3,
    ];
    let features: Vec<FunctionFeatures> = features_of(&text);
    assert_eq!(features.len(), 1, "one discovered function: {features:?}");
    let graph: &ControlFlowGraph = features[0]
        .structure()
        .expect("a fully resolved body carries a structure");
    assert_eq!(graph.block_count(), 3, "test, taken arm, fallthrough arm");
    assert_eq!(graph.entry(), 0);
    assert_eq!(graph.blocks()[0].successors().len(), 2);
    assert_eq!(
        graph.blocks()[0].categories(),
        [InstructionCategory::Compare, InstructionCategory::Branch]
    );
    assert!(
        features[0].structural_key().is_some(),
        "three blocks clear the distinguishing minimum"
    );
    assert_eq!(
        graph.instruction_mix().count(InstructionCategory::Return),
        2,
        "both arms return"
    );
}

#[test]
fn an_unbounded_indirect_branch_yields_no_structure_at_all() {
    let text: [u8; 5] = [0x85, 0xC0, 0x48, 0xFF, 0xE0];
    let features: Vec<FunctionFeatures> = features_of(&text);
    assert_eq!(features.len(), 1, "one discovered function: {features:?}");
    assert!(
        features[0].structure().is_none(),
        "a jump whose target cannot be bounded must produce no graph, not a partial one"
    );
}

#[test]
fn padding_behind_the_return_stays_out_of_the_graph() {
    let text: [u8; 3] = [0x31, 0xC0, 0xC3];
    let features: Vec<FunctionFeatures> = features_of(&text);
    let graph: &ControlFlowGraph = features[0]
        .structure()
        .expect("a returning body carries a structure");
    assert_eq!(graph.block_count(), 1);
    assert_eq!(
        graph.instruction_mix().total(),
        2,
        "the trailing 0xCC alignment fill is not part of the function"
    );
    assert!(
        features[0].structural_key().is_none(),
        "one block cannot distinguish a function"
    );
}

#[test]
fn an_aarch64_body_partitions_from_its_encoded_branch_targets() {
    let body: Vec<DisasmInstruction> = vec![
        DisasmInstruction {
            offset: 0x1000,
            bytes: 0xF100_001F_u32.to_le_bytes().to_vec(),
            mnemonic: "cmp".to_owned(),
            operands: vec!["x0".to_owned(), "#0".to_owned()],
            ..DisasmInstruction::default()
        },
        DisasmInstruction {
            offset: 0x1004,
            bytes: 0x5400_0040_u32.to_le_bytes().to_vec(),
            mnemonic: "b.eq".to_owned(),
            operands: vec!["$+0x8".to_owned()],
            ..DisasmInstruction::default()
        },
        DisasmInstruction {
            offset: 0x1008,
            bytes: 0xD65F_03C0_u32.to_le_bytes().to_vec(),
            mnemonic: "ret".to_owned(),
            operands: Vec::new(),
            ..DisasmInstruction::default()
        },
        DisasmInstruction {
            offset: 0x100C,
            bytes: 0xD65F_03C0_u32.to_le_bytes().to_vec(),
            mnemonic: "ret".to_owned(),
            operands: Vec::new(),
            ..DisasmInstruction::default()
        },
    ];
    let graph: ControlFlowGraph =
        aarch64_structure(&body).expect("a resolved aarch64 body carries a structure");
    assert_eq!(graph.block_count(), 3);
    assert_eq!(graph.blocks()[0].successors().len(), 2);
    assert_eq!(
        graph.blocks()[0].categories(),
        [InstructionCategory::Compare, InstructionCategory::Branch]
    );
}

#[test]
fn an_aarch64_branch_leaving_the_body_yields_no_structure() {
    let body: Vec<DisasmInstruction> = vec![
        DisasmInstruction {
            offset: 0x1000,
            bytes: 0x1400_0002_u32.to_le_bytes().to_vec(),
            mnemonic: "b".to_owned(),
            operands: vec!["some_label".to_owned()],
            ..DisasmInstruction::default()
        },
        DisasmInstruction {
            offset: 0x1004,
            bytes: 0xD65F_03C0_u32.to_le_bytes().to_vec(),
            mnemonic: "ret".to_owned(),
            operands: Vec::new(),
            ..DisasmInstruction::default()
        },
    ];
    assert!(aarch64_structure(&body).is_none());
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
fn a_direct_call_to_a_discovered_function_is_recorded_as_a_call_target() {
    let text: [u8; 9] = [0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x31, 0xC0, 0xC3];
    let features: Vec<FunctionFeatures> = features_of(&text);
    let entry: u64 = pe64_text_base() + 0x1000;
    assert_eq!(features.len(), 2, "a caller and a callee: {features:?}");
    assert_eq!(
        features[0].call_targets(),
        &BTreeSet::from([FunctionId::from(entry + 6)])
    );
    assert!(
        features[1].call_targets().is_empty(),
        "the callee itself calls nothing"
    );
}

#[test]
fn an_indirect_call_yields_no_call_target() {
    let text: [u8; 3] = [0xFF, 0xD0, 0xC3];
    let features: Vec<FunctionFeatures> = features_of(&text);
    assert!(
        features
            .iter()
            .all(|entry: &FunctionFeatures| entry.call_targets().is_empty()),
        "a call through a register names no function that can be resolved statically"
    );
}

#[test]
fn a_call_leaving_the_mapped_image_yields_no_call_target() {
    let text: [u8; 6] = [0xE8, 0x00, 0x10, 0x00, 0x00, 0xC3];
    let features: Vec<FunctionFeatures> = features_of(&text);
    assert!(
        features
            .iter()
            .all(|entry: &FunctionFeatures| entry.call_targets().is_empty()),
        "a target that is not the entry of a discovered function may not become an edge"
    );
}

#[test]
fn a_branch_with_link_decodes_its_own_displacement() {
    assert_eq!(
        aarch64_branch_link_target(0x1000, 0x9400_0004),
        Some(0x1010)
    );
    assert_eq!(
        aarch64_branch_link_target(0x1000, 0x97FF_FFFF),
        Some(0x0FFC)
    );
    assert_eq!(
        aarch64_branch_link_target(0x1000, 0xD65F_03C0),
        None,
        "a return is not a call"
    );
    assert_eq!(
        aarch64_branch_link_target(0x1000, 0x95FF_FFFF),
        Some(0x0800_0FFC)
    );
    assert_eq!(
        aarch64_branch_link_target(0x0800_0000, 0x9600_0000),
        Some(0)
    );
    assert_eq!(aarch64_branch_link_target(u64::MAX - 3, 0x9400_0001), None);
}

#[test]
fn an_aarch64_call_is_recorded_only_when_its_target_is_a_known_function() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "bl", 0x9400_0004),
        aarch64_insn(0x1004, "bl", 0x9400_0100),
        aarch64_insn(0x1008, "blr", 0xD63F_0000),
        aarch64_insn(0x100C, "ret", 0xD65F_03C0),
    ];
    let entries: BTreeSet<u64> = BTreeSet::from([0x1000, 0x1010]);
    let index: ImageIndex = ImageIndex::default();
    let positions: BTreeMap<u64, usize> =
        instruction_positions(&body).expect("distinct instruction offsets");

    assert_eq!(
        aarch64_call_targets(&body, tail_context(&index, &entries, &positions)),
        BTreeSet::from([FunctionId::from(0x1010)]),
        "only the resolved call into a known function survives"
    );
}

#[test]
fn unreachable_aarch64_tail_features_are_excluded() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "adrp", 0x9000_0008),
        aarch64_insn(0x1004, "add", 0x9104_8D08),
        aarch64_insn(0x1008, "nop", 0xD503_201F),
        aarch64_insn(0x100C, "ret", 0xD65F_03C0),
        aarch64_insn(0x1010, "adrp", 0x9000_0008),
        aarch64_insn(0x1014, "add", 0x9111_5908),
        aarch64_insn(0x1018, "bl", 0x9400_03FA),
        aarch64_insn(0x101C, "ret", 0xD65F_03C0),
    ];
    let index: ImageIndex = ImageIndex {
        strings: BTreeMap::from([
            (0x1123, "reachable".to_owned()),
            (0x1456, "unreachable".to_owned()),
        ]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::from([0x2000]);
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

    assert_eq!(
        parts.references,
        vec![DataReference::string_literal("reachable".to_owned())]
    );
    assert!(parts.structure.is_some());
    assert!(parts.calls.is_empty());
}

#[test]
fn aarch64_cfg_refusal_uses_only_the_terminated_prefix() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "adrp", 0x9000_0008),
        aarch64_insn(0x1004, "add", 0x9104_8D08),
        aarch64_insn(0x1008, "nop", 0xD503_201F),
        aarch64_insn(0x100C, "br", 0xD61F_0000),
        aarch64_insn(0x1010, "bl", 0x9400_03FC),
    ];
    let index: ImageIndex = ImageIndex {
        strings: BTreeMap::from([(0x1123, "preserved".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::from([0x2000]);
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

    assert_eq!(
        parts.references,
        vec![DataReference::string_literal("preserved".to_owned())]
    );
    assert!(parts.structure.is_none());
    assert!(parts.calls.is_empty());
}

#[test]
fn incomplete_aarch64_cfg_refusal_suppresses_full_span_calls() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "br", 0xD61F_0000),
        aarch64_insn(0x1004, "bl", 0x9400_03FF),
    ];
    let index: ImageIndex = ImageIndex::default();
    let entries: BTreeSet<u64> = BTreeSet::from([0x2000]);
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, false);

    assert!(parts.references.is_empty());
    assert!(parts.structure.is_none());
    assert!(parts.calls.is_empty());
}

#[test]
fn incomplete_aarch64_features_do_not_cross_instruction_gaps() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "nop", 0xD503_201F),
        aarch64_insn(0x2000, "bl", 0x9400_0400),
        aarch64_insn(0x2004, "ret", 0xD65F_03C0),
    ];
    let index: ImageIndex = ImageIndex::default();
    let entries: BTreeSet<u64> = BTreeSet::from([0x3000]);
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, false);

    assert!(parts.references.is_empty());
    assert!(parts.structure.is_none());
    assert!(parts.calls.is_empty());
}

#[test]
fn unreachable_aarch64_interior_features_are_excluded() {
    let mut branch: DisasmInstruction = aarch64_insn(0x1000, "b", 0x1400_0004);
    branch.operands = vec!["$+0x10".to_owned()];
    let body: Vec<DisasmInstruction> = vec![
        branch,
        aarch64_insn(0x1004, "adrp", 0x9000_0008),
        aarch64_insn(0x1008, "add", 0x9111_5908),
        aarch64_insn(0x100C, "bl", 0x9400_03FD),
        aarch64_insn(0x1010, "ret", 0xD65F_03C0),
    ];
    let index: ImageIndex = ImageIndex {
        strings: BTreeMap::from([(0x1456, "unreachable".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::from([0x2000]);
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

    assert!(parts.references.is_empty());
    assert!(parts.structure.is_some());
    assert!(parts.calls.is_empty());
}

#[test]
fn reachable_aarch64_reference_chains_cross_basic_block_leaders() {
    let mut branch: DisasmInstruction = aarch64_insn(0x1000, "cbz", 0x3400_0040);
    branch.operands = vec!["w0".to_owned(), "$+0x8".to_owned()];
    let body: Vec<DisasmInstruction> = vec![
        branch,
        aarch64_insn(0x1004, "adrp", 0x9000_0008),
        aarch64_insn(0x1008, "add", 0x9104_8D08),
        aarch64_insn(0x100C, "ret", 0xD65F_03C0),
    ];
    let index: ImageIndex = ImageIndex {
        strings: BTreeMap::from([(0x1123, "across leader".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::new();
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

    assert_eq!(
        parts.references,
        vec![DataReference::string_literal("across leader".to_owned())]
    );
    assert!(parts.structure.is_some());
}

#[test]
fn aarch64_reference_chains_do_not_cross_authenticated_exception_returns() {
    let mut branch: DisasmInstruction = aarch64_insn(0x1000, "cbz", 0x3400_0060);
    branch.operands = vec!["w0".to_owned(), "$+0xc".to_owned()];
    let body: Vec<DisasmInstruction> = vec![
        branch,
        aarch64_insn(0x1004, "adrp", 0x9000_0008),
        aarch64_insn(0x1008, "eretaa", 0xD69F_0BFF),
        aarch64_insn(0x100C, "add", 0x9104_8D08),
        aarch64_insn(0x1010, "ret", 0xD65F_03C0),
    ];
    let index: ImageIndex = ImageIndex {
        strings: BTreeMap::from([(0x1123, "must not cross".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::new();
    let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

    assert!(parts.references.is_empty());
    assert!(parts.structure.is_some());
}

#[test]
fn aarch64_exception_returns_exclude_trailing_calls() {
    for (mnemonic, word) in [
        ("eretaa", 0xD69F_0BFF),
        ("eretab", 0xD69F_0FFF),
        ("drps", 0xD6BF_03E0),
    ] {
        let body: Vec<DisasmInstruction> = vec![
            aarch64_insn(0x1000, mnemonic, word),
            aarch64_insn(0x1004, "bl", 0x9400_03FF),
        ];
        let index: ImageIndex = ImageIndex::default();
        let entries: BTreeSet<u64> = BTreeSet::from([0x2000]);
        let parts: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

        assert!(parts.structure.is_some(), "{mnemonic}");
        assert!(parts.calls.is_empty(), "{mnemonic}");
    }
}

#[test]
fn discovered_aarch64_parts_suppress_only_reference_anchors() {
    let body: Vec<DisasmInstruction> = vec![
        aarch64_insn(0x1000, "adrp", 0x9000_0008),
        aarch64_insn(0x1004, "add", 0x9104_8D08),
        aarch64_insn(0x1008, "nop", 0xD503_201F),
        aarch64_insn(0x100C, "bl", 0x9400_03FD),
        aarch64_insn(0x1010, "ret", 0xD65F_03C0),
    ];
    let index: ImageIndex = ImageIndex {
        strings: BTreeMap::from([(0x1123, "retained for symbols".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::from([0x2000]);
    let discovered: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, false);
    let symbol_backed: Aarch64FeatureParts = aarch64_feature_parts(&body, &index, &entries, true);

    assert!(discovered.references.is_empty());
    assert!(discovered.structure.is_some());
    assert_eq!(discovered.calls, BTreeSet::from([FunctionId::from(0x2000)]));
    assert_eq!(
        symbol_backed.references,
        vec![DataReference::string_literal(
            "retained for symbols".to_owned()
        )]
    );
}

fn x86_insn(address: u64, mnemonic: &str, flow: InsnFlow, bytes: &[u8]) -> DisasmInstruction {
    let mut carried: DisasmInstruction = DisasmInstruction {
        offset: address,
        bytes: bytes.to_vec(),
        mnemonic: mnemonic.to_owned(),
        flow,
        ..DisasmInstruction::default()
    };
    if let Some(decoded) = decode_x86(64, &carried)
        && matches!(
            decoded.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    {
        carried.branch_target = Some(decoded.near_branch_target());
    }
    carried
}

fn only_graph(text: &[u8]) -> ControlFlowGraph {
    let features: Vec<FunctionFeatures> = features_of(text);
    assert_eq!(features.len(), 1, "one discovered function: {features:?}");
    features[0]
        .structure()
        .expect("a fully resolved body carries a structure")
        .clone()
}

#[test]
fn a_tail_jump_to_a_discovered_function_ends_the_body_and_names_a_call_edge() {
    let text: [u8; 12] = [
        0xE8, 0x03, 0x00, 0x00, 0x00, 0xEB, 0x01, 0xCC, 0x31, 0xC0, 0xC3, 0xC3,
    ];
    let features: Vec<FunctionFeatures> = features_of(&text);
    let entry: u64 = pe64_text_base() + 0x1000;
    assert_eq!(features.len(), 2, "a caller and a callee: {features:?}");

    let graph: &ControlFlowGraph = features[0]
        .structure()
        .expect("a body ending in a tail jump carries a structure");
    assert_eq!(graph.block_count(), 1, "call then tail jump is one block");
    assert_eq!(
        graph.instruction_mix().total(),
        2,
        "the alignment fill behind the tail jump is not part of the body"
    );
    assert_eq!(
        features[0].call_targets(),
        &BTreeSet::from([FunctionId::from(entry + 8)]),
        "the tail jump reaches the same function the call reaches"
    );
}

#[test]
fn a_tail_jump_to_an_address_that_is_not_a_function_yields_no_structure() {
    let text: [u8; 8] = [0x31, 0xC0, 0xE9, 0x00, 0x10, 0x00, 0x00, 0xC3];
    let features: Vec<FunctionFeatures> = features_of(&text);
    assert_eq!(features.len(), 1, "one discovered function: {features:?}");
    assert!(
        features[0].structure().is_none(),
        "a jump whose target is neither inside the body nor a known function stays unresolved"
    );
    assert!(features[0].call_targets().is_empty());
}

#[test]
fn a_tail_jump_through_an_import_slot_is_named_and_returns_to_the_caller() {
    let insn: DisasmInstruction = x86_insn(
        0x1000,
        "jmp",
        InsnFlow::IndirectBranch,
        &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00],
    );
    let decoded: Instruction = decode_x86(64, &insn).expect("a jump through memory decodes");
    let named: ImageIndex = ImageIndex {
        import_slots: BTreeMap::from([(0x1006, "GetProcAddress".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::new();
    let positions: BTreeMap<u64, usize> = BTreeMap::from([(0x1000, 0)]);

    assert_eq!(
        x86_transfer(&decoded, tail_context(&named, &entries, &positions)),
        Transfer::Terminal { returns: true }
    );
    assert_eq!(
        x86_import_name(&insn, &decoded, &named).as_deref(),
        Some("GetProcAddress")
    );

    let bare: ImageIndex = ImageIndex::default();
    assert_eq!(
        x86_transfer(&decoded, tail_context(&bare, &entries, &positions)),
        Transfer::Unresolved,
        "a slot the import table does not name proves nothing"
    );
    assert!(x86_import_name(&insn, &decoded, &bare).is_none());
}

#[test]
fn a_direct_tail_jump_to_an_import_thunk_is_named_and_returns_to_the_caller() {
    let insn: DisasmInstruction = x86_insn(
        0x1000,
        "jmp",
        InsnFlow::UnconditionalBranch,
        &[0xE9, 0xFB, 0x0F, 0x00, 0x00],
    );
    let decoded: Instruction = decode_x86(64, &insn).expect("a relative jump decodes");
    assert_eq!(insn.branch_target, Some(0x2000));
    let named: ImageIndex = ImageIndex {
        import_stubs: BTreeMap::from([(0x2000, "memcpy".to_owned())]),
        ..ImageIndex::default()
    };
    let entries: BTreeSet<u64> = BTreeSet::new();
    let positions: BTreeMap<u64, usize> = BTreeMap::from([(0x1000, 0)]);

    assert_eq!(
        x86_transfer(&decoded, tail_context(&named, &entries, &positions)),
        Transfer::Terminal { returns: true }
    );
    assert_eq!(
        x86_import_name(&insn, &decoded, &named).as_deref(),
        Some("memcpy")
    );
}

#[test]
fn an_unreachable_x86_immediate_is_not_a_reference() {
    let mut text: Vec<u8> = vec![0x48, 0xB8];
    text.extend_from_slice(&0x9e37_79b9_7f4a_7c15_u64.to_le_bytes());
    text.push(0xC3);
    text.extend_from_slice(&[0x48, 0xB8]);
    text.extend_from_slice(&0xc4ce_b9fe_1a85_ec53_u64.to_le_bytes());
    text.push(0xC3);
    assert_eq!(
        all_references(&features_of(&text)),
        vec![DataReference::UnusualConstant(0x9e37_79b9_7f4a_7c15)],
        "an immediate behind the return is never executed and never anchors"
    );
}

#[test]
fn an_always_taken_condition_drops_the_arm_it_never_reaches() {
    let text: [u8; 8] = [0x31, 0xC0, 0x74, 0x03, 0x48, 0xFF, 0xC0, 0xC3];
    let graph: ControlFlowGraph = only_graph(&text);
    assert_eq!(
        graph.block_count(),
        2,
        "the zeroing block and the arm the condition always reaches"
    );
    assert_eq!(graph.instruction_mix().total(), 3);
    assert_eq!(
        graph
            .instruction_mix()
            .count(InstructionCategory::Arithmetic),
        0,
        "the increment behind an always taken branch is not part of the body"
    );
}

#[test]
fn a_never_taken_condition_leaves_one_straight_run() {
    let text: [u8; 8] = [0x31, 0xC0, 0x75, 0x03, 0x48, 0xFF, 0xC0, 0xC3];
    let graph: ControlFlowGraph = only_graph(&text);
    assert_eq!(graph.block_count(), 1, "nothing branches: {graph:?}");
    assert_eq!(graph.instruction_mix().total(), 4);
    assert_eq!(
        graph
            .instruction_mix()
            .count(InstructionCategory::Arithmetic),
        1,
        "the increment the condition always reaches stays in the body"
    );
}

#[test]
fn a_compare_against_a_loaded_immediate_folds() {
    let text: [u8; 16] = [
        0xB8, 0x39, 0x05, 0x00, 0x00, 0x3D, 0x39, 0x05, 0x00, 0x00, 0x75, 0x03, 0x48, 0xFF, 0xC0,
        0xC3,
    ];
    let graph: ControlFlowGraph = only_graph(&text);
    assert_eq!(graph.block_count(), 1, "the compare can only agree");
    assert_eq!(graph.instruction_mix().total(), 5);
}

#[test]
fn a_condition_the_body_cannot_prove_keeps_both_arms() {
    let text: [u8; 6] = [0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3];
    let graph: ControlFlowGraph = only_graph(&text);
    assert_eq!(
        graph.block_count(),
        3,
        "a register the caller set proves nothing: {graph:?}"
    );
    assert_eq!(graph.blocks()[0].successors().len(), 2);
}

#[test]
fn a_call_between_the_constant_and_the_compare_stops_the_fold() {
    let text: [u8; 10] = [0x31, 0xC0, 0xFF, 0xD0, 0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3];
    let graph: ControlFlowGraph = only_graph(&text);
    assert_eq!(
        graph.block_count(),
        3,
        "a call clears every register the fold could have relied on: {graph:?}"
    );
}

#[test]
fn a_constant_reached_only_through_a_branch_target_is_not_carried_into_the_condition() {
    let text: [u8; 10] = [0x31, 0xC0, 0xEB, 0x00, 0x85, 0xC0, 0x74, 0x01, 0xC3, 0xC3];
    let graph: ControlFlowGraph = only_graph(&text);
    assert!(
        graph.block_count() >= 3,
        "a leader between the zeroing and the test breaks the run: {graph:?}"
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
