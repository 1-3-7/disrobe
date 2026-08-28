#![allow(clippy::expect_used)]

use std::path::Path;

use disrobe_binfmt::containers::{
    EnigmaVariant, detect_enigma_virtual_box, enigma_member_bytes, parse_enigma_virtual_box,
};
use disrobe_binfmt::{
    ContainerKind, Error, ExtractionQuota, detect_and_extract_with_hint, detect_container,
    extract_to_with_quota,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/enigma/x86_evb_10_70_20240522.exe");
const ORIGINAL_MEMBER: &[u8] = include_bytes!("fixtures/enigma/README_packed.txt");
const EVB_MAGIC: &[u8] = b"EVB\0";

fn find_unique(haystack: &[u8], needle: &[u8]) -> usize {
    let mut matches: Vec<usize> = haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window): (usize, &[u8])| (window == needle).then_some(offset))
        .collect();
    assert_eq!(matches.len(), 1, "fixture needle must occur once");
    matches.pop().expect("one fixture match")
}

fn utf16le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn pe_section_raw_offset(bytes: &[u8], expected_name: [u8; 8]) -> usize {
    let pe_offset: usize = usize::try_from(u32::from_le_bytes(
        bytes[0x3c..0x40].try_into().expect("PE header offset"),
    ))
    .expect("PE header offset fits usize");
    let section_count: usize = usize::from(u16::from_le_bytes(
        bytes[pe_offset + 6..pe_offset + 8]
            .try_into()
            .expect("PE section count"),
    ));
    let optional_size: usize = usize::from(u16::from_le_bytes(
        bytes[pe_offset + 20..pe_offset + 22]
            .try_into()
            .expect("PE optional-header size"),
    ));
    let section_table: usize = pe_offset + 24 + optional_size;
    (0..section_count)
        .find_map(|index: usize| {
            let header: usize = section_table + index * 40;
            (bytes[header..header + 8] == expected_name).then(|| {
                usize::try_from(u32::from_le_bytes(
                    bytes[header + 20..header + 24]
                        .try_into()
                        .expect("section raw offset"),
                ))
                .expect("section raw offset fits usize")
            })
        })
        .expect("named PE section")
}

fn relocated_overlay_fixture() -> (Vec<u8>, usize, usize) {
    let magic_offset: usize = memchr::memmem::find(FIXTURE, EVB_MAGIC).expect("fixture EVB magic");
    let payload_offset: usize = find_unique(FIXTURE, ORIGINAL_MEMBER);
    let bundle_end: usize = payload_offset + ORIGINAL_MEMBER.len();
    let relocated: &[u8] = &FIXTURE[magic_offset..bundle_end];
    let mut overlay: Vec<u8> = FIXTURE.to_vec();
    overlay[magic_offset] = b'X';
    let overlay_offset: usize = overlay.len();
    overlay.extend_from_slice(relocated);
    (overlay, overlay_offset, payload_offset - magic_offset)
}

fn fixture_with_alias_names(first_name: &str, second_name: &str) -> Vec<u8> {
    let magic_offset: usize = memchr::memmem::find(FIXTURE, EVB_MAGIC).expect("fixture EVB magic");
    let payload_offset: usize = find_unique(FIXTURE, ORIGINAL_MEMBER);
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let node_offset: usize = name_offset - 16;
    let node_end: usize = name_offset + encoded_name.len() + 2 + 1 + 2 + 4 + 4 + 24 + 15 + 4;
    let node_prefix: &[u8] = &FIXTURE[node_offset..name_offset];
    let node_suffix: &[u8] = &FIXTURE[name_offset + encoded_name.len()..node_end];
    let encoded_root: Vec<u8> = utf16le("%DEFAULT FOLDER%");
    let root_relative: usize = find_unique(&FIXTURE[magic_offset..payload_offset], &encoded_root);
    let root_node_offset: usize = magic_offset + root_relative - 16;
    let main_size_offset: usize = magic_offset + 64;
    let main_size: u32 = u32::from_le_bytes(
        FIXTURE[main_size_offset..main_size_offset + 4]
            .try_into()
            .expect("fixture main size"),
    );
    let build_node = |name: &str| -> Vec<u8> {
        let encoded: Vec<u8> = utf16le(name);
        let mut node: Vec<u8> =
            Vec::with_capacity(node_prefix.len() + encoded.len() + node_suffix.len());
        node.extend_from_slice(node_prefix);
        node.extend_from_slice(&encoded);
        node.extend_from_slice(node_suffix);
        node
    };
    let first_node: Vec<u8> = build_node(first_name);
    let second_node: Vec<u8> = build_node(second_name);
    let replacement_size: usize = first_node
        .len()
        .checked_add(second_node.len())
        .expect("test node sizes remain bounded");
    let size_delta: usize = replacement_size
        .checked_sub(node_end - node_offset)
        .expect("two test nodes exceed the replaced node");
    let mut aliased: Vec<u8> = FIXTURE[..node_offset].to_vec();
    aliased.extend_from_slice(&first_node);
    aliased.extend_from_slice(&second_node);
    aliased.extend_from_slice(&FIXTURE[node_end..payload_offset]);
    aliased[main_size_offset..main_size_offset + 4].copy_from_slice(
        &main_size
            .checked_add(u32::try_from(size_delta).expect("node size delta fits u32"))
            .expect("main size remains bounded")
            .to_le_bytes(),
    );
    aliased[root_node_offset + 12..root_node_offset + 16].copy_from_slice(&2_u32.to_le_bytes());
    aliased.extend_from_slice(ORIGINAL_MEMBER);
    aliased.extend_from_slice(ORIGINAL_MEMBER);
    aliased.extend_from_slice(&FIXTURE[payload_offset + ORIGINAL_MEMBER.len()..]);
    aliased
}

fn fixture_with_non_ascii_case_aliases() -> Vec<u8> {
    fixture_with_alias_names("ÄEADME.txt", "äEADME.txt")
}

fn fixture_with_normalization_aliases() -> Vec<u8> {
    fixture_with_alias_names("éEADME.txt", "e\u{301}EADME.txt")
}

fn fixture_with_exact_duplicate_names() -> Vec<u8> {
    let magic_offset: usize = memchr::memmem::find(FIXTURE, EVB_MAGIC).expect("fixture EVB magic");
    let payload_offset: usize = find_unique(FIXTURE, ORIGINAL_MEMBER);
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let node_offset: usize = name_offset - 16;
    let node_end: usize = name_offset + encoded_name.len() + 2 + 1 + 2 + 4 + 4 + 24 + 15 + 4;
    let node: &[u8] = &FIXTURE[node_offset..node_end];
    let encoded_root: Vec<u8> = utf16le("%DEFAULT FOLDER%");
    let root_relative: usize = find_unique(&FIXTURE[magic_offset..payload_offset], &encoded_root);
    let root_node_offset: usize = magic_offset + root_relative - 16;
    let main_size_offset: usize = magic_offset + 64;
    let main_size: u32 = u32::from_le_bytes(
        FIXTURE[main_size_offset..main_size_offset + 4]
            .try_into()
            .expect("fixture main size"),
    );
    let mut duplicate: Vec<u8> = FIXTURE[..node_end].to_vec();
    duplicate[main_size_offset..main_size_offset + 4].copy_from_slice(
        &main_size
            .checked_add(u32::try_from(node.len()).expect("node size fits u32"))
            .expect("main size remains bounded")
            .to_le_bytes(),
    );
    duplicate[root_node_offset + 12..root_node_offset + 16].copy_from_slice(&2_u32.to_le_bytes());
    duplicate.extend_from_slice(node);
    duplicate.extend_from_slice(&FIXTURE[node_end..payload_offset]);
    duplicate.extend_from_slice(ORIGINAL_MEMBER);
    duplicate.extend_from_slice(ORIGINAL_MEMBER);
    duplicate.extend_from_slice(&FIXTURE[payload_offset + ORIGINAL_MEMBER.len()..]);
    duplicate
}

fn stored_bundle_with_member_len(member_len: u32) -> Vec<u8> {
    let magic_offset: usize = memchr::memmem::find(FIXTURE, EVB_MAGIC).expect("fixture EVB magic");
    let payload_offset: usize = find_unique(FIXTURE, ORIGINAL_MEMBER);
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let original_size_offset: usize = name_offset + encoded_name.len() + 2 + 1 + 2;
    let stored_size_offset: usize = original_size_offset + 4 + 4 + 24 + 15;
    let mut bundle: Vec<u8> =
        FIXTURE[magic_offset..payload_offset + ORIGINAL_MEMBER.len()].to_vec();
    let relative_original_size: usize = original_size_offset - magic_offset;
    let relative_stored_size: usize = stored_size_offset - magic_offset;
    bundle[relative_original_size..relative_original_size + 4]
        .copy_from_slice(&member_len.to_le_bytes());
    bundle[relative_stored_size..relative_stored_size + 4]
        .copy_from_slice(&member_len.to_le_bytes());
    let member_len: usize = usize::try_from(member_len).expect("member length fits usize");
    bundle.truncate(payload_offset - magic_offset + member_len);
    bundle
}

#[test]
fn real_evb_10_70_member_is_recovered_byte_identically_through_the_public_caller() {
    assert_eq!(
        detect_container(FIXTURE),
        Some(ContainerKind::EnigmaVirtualBox)
    );

    let parsed = parse_enigma_virtual_box(FIXTURE, ExtractionQuota::default_safe())
        .expect("parse EVB 10.70 fixture");
    assert_eq!(parsed.variant, EnigmaVariant::X86BuiltInFileLayout);
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].name, "README.txt");
    assert_eq!(
        enigma_member_bytes(FIXTURE, &parsed.entries[0]).expect("member bytes"),
        ORIGINAL_MEMBER
    );

    let scratch = disrobe_core::scratch::ScratchDir::create("binfmt-enigma-real")
        .expect("create scratch directory");
    let output = scratch.path().join("out");
    let result = detect_and_extract_with_hint(FIXTURE, Some(Path::new("sample.exe")), &output)
        .expect("extract EVB fixture");
    assert_eq!(result.kind, ContainerKind::EnigmaVirtualBox);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].name, "README.txt");
    assert_eq!(
        std::fs::read(output.join("README.txt")).expect("read extracted member"),
        ORIGINAL_MEMBER
    );
}

#[test]
fn marker_only_and_copied_section_name_decoys_are_not_detected() {
    assert!(!detect_enigma_virtual_box(b"MZ marker only EVB\0"));
    assert_eq!(detect_container(b"MZ marker only EVB\0"), None);

    let mut copied_section_decoy: Vec<u8> = FIXTURE.to_vec();
    let magic_offsets: Vec<usize> =
        memchr::memmem::find_iter(&copied_section_decoy, EVB_MAGIC).collect();
    for offset in magic_offsets {
        copied_section_decoy[offset] = b'X';
    }
    assert!(
        copied_section_decoy
            .windows(8)
            .any(|window: &[u8]| window == b".enigma1")
    );
    assert!(
        copied_section_decoy
            .windows(8)
            .any(|window: &[u8]| window == b".enigma2")
    );
    assert!(!detect_enigma_virtual_box(&copied_section_decoy));
    assert_eq!(detect_container(&copied_section_decoy), None);
}

#[test]
fn the_graded_directory_is_found_when_relocated_to_the_pe_overlay() {
    let (overlay, _, _) = relocated_overlay_fixture();

    let parsed = parse_enigma_virtual_box(&overlay, ExtractionQuota::default_safe())
        .expect("parse relocated EVB directory");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].name, "README.txt");
    assert_eq!(
        enigma_member_bytes(&overlay, &parsed.entries[0]).expect("relocated member bytes"),
        ORIGINAL_MEMBER
    );
}

#[test]
fn the_graded_directory_is_found_when_derived_into_the_existing_resource_section() {
    let magic_offset: usize = memchr::memmem::find(FIXTURE, EVB_MAGIC).expect("fixture EVB magic");
    let payload_offset: usize = find_unique(FIXTURE, ORIGINAL_MEMBER);
    let bundle_end: usize = payload_offset + ORIGINAL_MEMBER.len();
    let relocated: &[u8] = &FIXTURE[magic_offset..bundle_end];
    let resource_raw_offset: usize = pe_section_raw_offset(FIXTURE, *b".rsrc\0\0\0");
    let mut resource_placed: Vec<u8> = FIXTURE.to_vec();
    resource_placed[magic_offset] = b'X';
    resource_placed[resource_raw_offset..resource_raw_offset + relocated.len()]
        .copy_from_slice(relocated);

    let parsed = parse_enigma_virtual_box(&resource_placed, ExtractionQuota::default_safe())
        .expect("parse EVB directory derived into .rsrc bytes");
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].name, "README.txt");
    assert_eq!(
        enigma_member_bytes(&resource_placed, &parsed.entries[0])
            .expect("resource-placed member bytes"),
        ORIGINAL_MEMBER
    );
}

#[test]
fn unsupported_compressed_layout_names_the_missing_codec() {
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let original_size_offset: usize = name_offset + encoded_name.len() + 2 + 1 + 2;
    let mut compressed: Vec<u8> = FIXTURE.to_vec();
    compressed[original_size_offset..original_size_offset + 4]
        .copy_from_slice(&18_u32.to_le_bytes());

    assert_eq!(
        detect_container(&compressed),
        Some(ContainerKind::EnigmaVirtualBox),
        "structural detection must not depend on extraction capability"
    );
    let scratch = disrobe_core::scratch::ScratchDir::create("binfmt-enigma-compressed")
        .expect("create scratch directory");
    let caller_error: Error = detect_and_extract_with_hint(
        &compressed,
        Some(Path::new("compressed.exe")),
        &scratch.path().join("out"),
    )
    .expect_err("public extraction caller must name the missing codec");
    assert!(
        matches!(caller_error, Error::UnsupportedContainer(reason) if reason.contains("compressed Enigma Virtual Box")),
        "got {caller_error:?}"
    );

    let error: Error = parse_enigma_virtual_box(&compressed, ExtractionQuota::default_safe())
        .expect_err("compressed member must be unsupported");
    assert!(
        matches!(error, Error::UnsupportedContainer(reason) if reason.contains("compressed Enigma Virtual Box")),
        "got {error:?}"
    );
}

#[test]
fn first_structurally_valid_compressed_directory_cannot_fall_through_to_later_magic() {
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let original_size_offset: usize = name_offset + encoded_name.len() + 2 + 1 + 2;
    let mut input: Vec<u8> = FIXTURE.to_vec();
    input[original_size_offset..original_size_offset + 4].copy_from_slice(&18_u32.to_le_bytes());
    input.extend_from_slice(&stored_bundle_with_member_len(17));

    let result = parse_enigma_virtual_box(&input, ExtractionQuota::default_safe());
    assert!(
        matches!(result, Err(Error::UnsupportedContainer(reason)) if reason.contains("compressed Enigma Virtual Box")),
        "got {result:?}"
    );
}

#[test]
fn first_structurally_valid_quota_failure_cannot_fall_through_to_later_magic() {
    let mut input: Vec<u8> = FIXTURE.to_vec();
    input.extend_from_slice(&stored_bundle_with_member_len(16));
    let quota: ExtractionQuota = ExtractionQuota {
        max_per_entry_uncompressed: 16,
        ..ExtractionQuota::default_safe()
    };

    let result = parse_enigma_virtual_box(&input, quota);
    assert!(
        matches!(result, Err(Error::QuotaExceeded { .. })),
        "got {result:?}"
    );
}

#[test]
fn hostile_member_path_is_rejected_before_extraction() {
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let hostile_name: Vec<u8> = utf16le("../bad.txt");
    assert_eq!(encoded_name.len(), hostile_name.len());
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let mut hostile: Vec<u8> = FIXTURE.to_vec();
    hostile[name_offset..name_offset + encoded_name.len()].copy_from_slice(&hostile_name);

    assert!(matches!(
        parse_enigma_virtual_box(&hostile, ExtractionQuota::default_safe()),
        Err(Error::UnsafeEntryPath(path)) if path == "../bad.txt"
    ));
}

#[test]
fn absolute_member_path_is_rejected_before_extraction() {
    let encoded_name: Vec<u8> = utf16le("README.txt");
    let hostile_name: Vec<u8> = utf16le("C:/bad.txt");
    assert_eq!(encoded_name.len(), hostile_name.len());
    let name_offset: usize = find_unique(FIXTURE, &encoded_name);
    let mut hostile: Vec<u8> = FIXTURE.to_vec();
    hostile[name_offset..name_offset + encoded_name.len()].copy_from_slice(&hostile_name);

    assert!(matches!(
        parse_enigma_virtual_box(&hostile, ExtractionQuota::default_safe()),
        Err(Error::UnsafeEntryPath(path)) if path == "C:/bad.txt"
    ));
}

#[test]
fn exact_duplicate_member_names_are_rejected_before_extraction() {
    let duplicate: Vec<u8> = fixture_with_exact_duplicate_names();
    let result = parse_enigma_virtual_box(&duplicate, ExtractionQuota::default_safe());
    assert!(
        matches!(&result, Err(Error::UnsafeEntryPath(path)) if path == "README.txt"),
        "got {result:?}"
    );
}

#[test]
fn non_ascii_case_aliases_are_rejected_before_extraction() {
    let aliased: Vec<u8> = fixture_with_non_ascii_case_aliases();
    let result = parse_enigma_virtual_box(&aliased, ExtractionQuota::default_safe());
    assert!(
        matches!(&result, Err(Error::UnsafeEntryPath(path)) if path == "äEADME.txt"),
        "got {result:?}"
    );
}

#[test]
fn unicode_normalization_aliases_are_rejected_before_extraction() {
    let aliased: Vec<u8> = fixture_with_normalization_aliases();
    let result = parse_enigma_virtual_box(&aliased, ExtractionQuota::default_safe());
    assert!(
        matches!(&result, Err(Error::UnsafeEntryPath(path)) if path == "e\u{301}EADME.txt"),
        "got {result:?}"
    );
}

#[test]
fn quota_rejects_the_real_member_before_a_write() {
    let quota: ExtractionQuota = ExtractionQuota {
        max_per_entry_uncompressed: 16,
        ..ExtractionQuota::default_safe()
    };
    let scratch = disrobe_core::scratch::ScratchDir::create("binfmt-enigma-quota")
        .expect("create scratch directory");
    let output = scratch.path().join("out");
    let error: Error =
        extract_to_with_quota(ContainerKind::EnigmaVirtualBox, FIXTURE, &output, quota)
            .expect_err("17-byte member must exceed the 16-byte cap");
    assert!(matches!(error, Error::QuotaExceeded { .. }));
    assert!(
        !output.join("README.txt").exists(),
        "quota refusal must occur before the member write"
    );
}

#[test]
fn truncated_directory_and_member_ranges_refuse_without_panicking() {
    let (relocated, overlay_offset, directory_len) = relocated_overlay_fixture();
    let cuts: [usize; 6] = [
        overlay_offset,
        overlay_offset + 4,
        overlay_offset + 64,
        overlay_offset + directory_len - 1,
        overlay_offset + directory_len,
        relocated.len() - 1,
    ];
    for cut in cuts {
        assert!(
            parse_enigma_virtual_box(&relocated[..cut], ExtractionQuota::default_safe()).is_err(),
            "truncation at {cut:#x} must refuse"
        );
    }
}

#[test]
fn oversized_directory_count_refuses_without_allocation() {
    let magic_offset: usize = memchr::memmem::find(FIXTURE, EVB_MAGIC).expect("fixture EVB magic");
    let main_count_offset: usize = magic_offset + 76;
    let mut oversized: Vec<u8> = FIXTURE.to_vec();
    oversized[main_count_offset..main_count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(parse_enigma_virtual_box(&oversized, ExtractionQuota::default_safe()).is_err());
}

#[test]
fn pe32_plus_variant_is_not_claimed() {
    let pe_offset: usize = usize::try_from(u32::from_le_bytes(
        FIXTURE[0x3c..0x40].try_into().expect("PE header offset"),
    ))
    .expect("PE header offset fits usize");
    let optional_magic_offset: usize = pe_offset + 24;
    let mut pe32_plus: Vec<u8> = FIXTURE.to_vec();
    pe32_plus[optional_magic_offset..optional_magic_offset + 2]
        .copy_from_slice(&0x020b_u16.to_le_bytes());

    assert!(!detect_enigma_virtual_box(&pe32_plus));
    assert_eq!(detect_container(&pe32_plus), None);
    assert!(parse_enigma_virtual_box(&pe32_plus, ExtractionQuota::default_safe()).is_err());
}

#[cfg(feature = "chain")]
#[test]
fn real_evb_10_70_member_reaches_the_automatic_container_pass() {
    use disrobe_core::chain::{ChildArtifact, DetectContext, Detector as _, Pass as _};
    use disrobe_core::{Artifact, Rung};

    let context: DetectContext<'_> = DetectContext {
        bytes: FIXTURE,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let verdict: disrobe_core::chain::DetectVerdict =
        disrobe_binfmt::chain_detector::ContainerDetector
            .detect(&context)
            .expect("Enigma fixture container verdict");
    assert_eq!(verdict.format_tag, "enigma-virtual-box");

    let artifact: Artifact = Artifact::new(Rung::Raw, FIXTURE.to_vec(), [0_u8; 32]);
    let children: Vec<ChildArtifact> = disrobe_binfmt::chain_detector::CONTAINER_PASS
        .extract_children(&artifact)
        .expect("Enigma container children");
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].handle.relative_path, "README.txt");
    assert_eq!(children[0].bytes, ORIGINAL_MEMBER);

    let rendered: Artifact = disrobe_binfmt::chain_detector::CONTAINER_PASS
        .run(&artifact)
        .expect("Enigma container manifest");
    let manifest: String =
        String::from_utf8(rendered.envelope).expect("Enigma container manifest must be UTF-8");
    assert!(manifest.contains("format=enigma-virtual-box"));
    assert!(manifest.contains("README.txt\tbytes=17"));
}
