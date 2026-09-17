#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::code_signature::{
    self, CodeDirectory, CodeSignature, HashKind, PageHashVerdict, SlotKind,
};
use disrobe_pass_swift_objc::macho::{self, CpuKind, ParsedSlice};

use macho_corpus::{
    CorpusFixture, EDGE_CASES_FAT, SWIFT_EDGE_CASES_OBFUSCATED, SWIFT_HELLO_ORIGINAL, first_slice,
    read_tracked, slice_preferring,
};

fn signature_of(fixture: CorpusFixture) -> (Vec<u8>, ParsedSlice, Option<CodeSignature>) {
    let bytes: Vec<u8> = read_tracked(fixture);
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(fixture, &bytes);
    let signature: Option<CodeSignature> = code_signature::parse(&slice, &parsed);
    (slice, parsed, signature)
}

#[test]
fn swift_hello_reports_the_adhoc_linker_signature_apple_wrote() {
    let (_, _, signature): (Vec<u8>, ParsedSlice, Option<CodeSignature>) =
        signature_of(SWIFT_HELLO_ORIGINAL);
    let signature: CodeSignature = signature.expect(
        "SwiftHello.original carries an LC_CODE_SIGNATURE whose superblob parses; returning None \
         here would report a signed binary as unsigned",
    );
    assert_eq!(signature.slot_count, 1, "slots: {:?}", signature.slots);
    assert_eq!(signature.slots[0].kind, SlotKind::CodeDirectory);

    let directory: CodeDirectory = signature
        .code_directory
        .expect("the sole slot is a code directory");
    assert_eq!(directory.identifier.as_deref(), Some("SwiftHello"));
    assert_eq!(directory.hash_kind, HashKind::Sha256);
    assert_eq!(directory.hash_size, 32);
    assert_eq!(directory.page_size, 4096);
    assert_eq!(directory.code_slot_count, 15);
    assert_eq!(directory.code_limit, 61_216);
    assert_eq!(directory.flags, 0x0002_0002);
    assert!(directory.is_adhoc, "this binary is ad hoc signed");
    assert!(
        directory.is_linker_signed,
        "the linker wrote this signature"
    );
    assert!(
        !directory.is_hardened_runtime,
        "no hardened runtime flag is set"
    );
    assert_eq!(
        directory.team_id, None,
        "an ad hoc signature carries no team"
    );
    assert_eq!(
        directory.cd_hash.as_deref(),
        Some("e6e926a1ff52ebdb2f5b4069bc741594e2bda52bb54a7fd75d32023351466a02"),
        "the cdhash is the identity an analyst quotes, so it is pinned to the value an \
         independent sha256 of the directory blob produces"
    );
    assert_eq!(
        directory.cd_hash_truncated.as_deref(),
        Some("e6e926a1ff52ebdb2f5b4069bc741594e2bda52b")
    );
    assert!(
        !signature.has_cms_signature,
        "an ad hoc signature carries no CMS blob"
    );
    assert_eq!(signature.entitlements_xml, None);
}

#[test]
fn swift_hello_signature_covers_every_byte_outside_itself() {
    let (_, parsed, signature): (Vec<u8>, ParsedSlice, Option<CodeSignature>) =
        signature_of(SWIFT_HELLO_ORIGINAL);
    let signature: CodeSignature = signature.expect("SwiftHello.original is signed");
    assert_eq!(parsed.code_signature_off, Some(61_216));
    assert!(
        signature.coverage.covers_all_bytes_before_signature,
        "the signed range must end exactly at the signature blob: {}",
        signature.coverage.note
    );
    assert_eq!(signature.coverage.unsigned_gap_bytes, 0);
    assert_eq!(signature.coverage.code_limit, 61_216);
    assert_eq!(signature.coverage.signature_offset, 61_216);
}

#[test]
fn swift_hello_page_hashes_match_the_file_content() {
    let (_, _, signature): (Vec<u8>, ParsedSlice, Option<CodeSignature>) =
        signature_of(SWIFT_HELLO_ORIGINAL);
    let signature: CodeSignature = signature.expect("SwiftHello.original is signed");
    assert_eq!(
        signature.page_hashes.verdict,
        PageHashVerdict::AllPagesMatch,
        "every signed page must hash to the digest the directory records: {}",
        signature.page_hashes.note
    );
    assert_eq!(signature.page_hashes.pages_declared, 15);
    assert_eq!(signature.page_hashes.pages_checked, 15);
    assert_eq!(signature.page_hashes.pages_matched, 15);
    assert_eq!(signature.page_hashes.first_mismatch_page, None);
}

#[test]
fn a_patched_code_byte_fails_the_page_hash_check() {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let (slice, _): (Vec<u8>, ParsedSlice) = first_slice(SWIFT_HELLO_ORIGINAL, &bytes);
    let mut patched: Vec<u8> = slice;
    let target: usize = 0x2000;
    let original: u8 = patched[target];
    patched[target] = original.wrapping_add(1);
    let parsed: ParsedSlice = macho::parse_slice(&patched).expect("the patched slice still parses");
    let signature: CodeSignature = code_signature::parse(&patched, &parsed)
        .expect("the signature blob is untouched by the patch");
    assert_eq!(
        signature.page_hashes.verdict,
        PageHashVerdict::Mismatch,
        "flipping one byte of signed code must fail the page hash check, otherwise the check \
         asserts nothing: {}",
        signature.page_hashes.note
    );
    assert_eq!(
        signature.page_hashes.first_mismatch_page,
        Some(2),
        "the mismatch must be reported at the page holding the patched byte"
    );
    assert_eq!(
        signature.page_hashes.pages_matched, 14,
        "exactly one page of fifteen changed"
    );
}

#[test]
fn swift_edge_cases_reports_its_own_identifier_and_slot_count() {
    let (_, _, signature): (Vec<u8>, ParsedSlice, Option<CodeSignature>) =
        signature_of(SWIFT_EDGE_CASES_OBFUSCATED);
    let signature: CodeSignature = signature.expect("SwiftEdgeCases.obfuscated is signed");
    let directory: CodeDirectory = signature
        .code_directory
        .expect("a code directory is present");
    assert_eq!(
        directory.identifier.as_deref(),
        Some("SwiftEdgeCases.obfuscated"),
        "the identifier survives the name obfuscation applied to the Swift symbols"
    );
    assert_eq!(directory.code_slot_count, 18);
    assert_eq!(directory.code_limit, 70_800);
    assert!(directory.is_adhoc);
    assert_eq!(
        signature.page_hashes.verdict,
        PageHashVerdict::AllPagesMatch,
        "{}",
        signature.page_hashes.note
    );
}

#[test]
fn an_unsigned_slice_reports_no_signature_rather_than_an_empty_one() {
    let bytes: Vec<u8> = read_tracked(EDGE_CASES_FAT);
    let (slice, parsed): (Vec<u8>, ParsedSlice) =
        slice_preferring(EDGE_CASES_FAT, &bytes, CpuKind::X86_64);
    assert_eq!(
        parsed.code_signature_off, None,
        "the x86_64 slice of EdgeCases.fat carries no LC_CODE_SIGNATURE, which is what makes it \
         the negative case here"
    );
    assert!(
        code_signature::parse(&slice, &parsed).is_none(),
        "an unsigned image must report no signature, never a signature with empty fields"
    );
}

#[test]
fn each_slice_of_a_fat_binary_is_judged_on_its_own_signature() {
    let bytes: Vec<u8> = read_tracked(EDGE_CASES_FAT);
    let (unsigned, unsigned_parsed): (Vec<u8>, ParsedSlice) =
        slice_preferring(EDGE_CASES_FAT, &bytes, CpuKind::X86_64);
    let (signed, signed_parsed): (Vec<u8>, ParsedSlice) =
        slice_preferring(EDGE_CASES_FAT, &bytes, CpuKind::Arm64);
    assert_ne!(
        unsigned, signed,
        "the two slices must be different images for this case to mean anything"
    );
    assert!(
        code_signature::parse(&unsigned, &unsigned_parsed).is_none(),
        "the x86_64 slice is unsigned"
    );
    let signature: CodeSignature = code_signature::parse(&signed, &signed_parsed).expect(
        "the arm64 slice of the same fat binary is signed, so a fat report that judged the whole \
         file by one slice would be wrong",
    );
    let directory: CodeDirectory = signature
        .code_directory
        .expect("a code directory is present");
    assert_eq!(directory.identifier.as_deref(), Some("EdgeCases.arm64"));
    assert_eq!(directory.code_slot_count, 69);
    assert_eq!(directory.code_limit, 281_792);
    assert!(directory.is_adhoc);
    assert_eq!(
        directory.cd_hash_truncated.as_deref(),
        Some("3aedba799efb77252b397fbdc0edd4dc359adb28")
    );
    assert!(signature.coverage.covers_all_bytes_before_signature);
    assert_eq!(
        signature.page_hashes.verdict,
        PageHashVerdict::AllPagesMatch,
        "{}",
        signature.page_hashes.note
    );
    assert_eq!(signature.page_hashes.pages_checked, 69);
}
