#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::code_signature::{
    CodeDirectory, CodeSignature, HashKind, PageHashVerdict, SlotKind,
};
use disrobe_pass_swift_objc::macho::{self, CpuKind, FatArchEntry, MachoKind, ParsedSlice};

#[derive(Debug, Clone, Copy)]
struct TrackedFixture {
    relative: &'static str,
    size_bytes: usize,
    blake3: &'static str,
}

const SWIFT_HELLO: TrackedFixture = TrackedFixture {
    relative: "mobile/macho-mac/SwiftHello.original",
    size_bytes: 61_816,
    blake3: "49f667381558ef2fc3688c323ff13e502e46e3c464f1df03788114553fb5015c",
};

const SWIFT_EDGE_CASES: TrackedFixture = TrackedFixture {
    relative: "mobile/macho-mac/swiftshield-edgecases/SwiftEdgeCases.obfuscated",
    size_bytes: 71_512,
    blake3: "51c37abb5b887b73ef5483c5f8ae15fc86a844093dbc8808eec4612411062d27",
};

const EDGE_CASES_FAT: TrackedFixture = TrackedFixture {
    relative: "mac/megafile/EdgeCases.fat",
    size_bytes: 546_272,
    blake3: "2e2c3755358b7f82073b09f071ea8ffa37715bf2857796f4c69c99669fb981aa",
};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("the crate sits two directories below the workspace root");
    workspace_root.join("corpus")
}

fn read_tracked(fixture: TrackedFixture) -> Vec<u8> {
    let mut path: PathBuf = corpus_root();
    for part in fixture.relative.split('/') {
        path.push(part);
    }
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "corpus/{} is tracked in this repository and the figures below are measured against it, \
             so a run that cannot read it must fail rather than measure nothing: {error} at {}. \
             Restore it with `git checkout -- corpus/{}`",
            fixture.relative,
            path.display(),
            fixture.relative
        )
    });
    assert_eq!(
        bytes.len(),
        fixture.size_bytes,
        "corpus/{} is {} bytes here but every value asserted below was measured against {} bytes; \
         grading a different file would measure a different binary",
        fixture.relative,
        bytes.len(),
        fixture.size_bytes
    );
    let digest: String = blake3::hash(&bytes).to_hex().to_string();
    assert_eq!(
        digest, fixture.blake3,
        "corpus/{} is not the file these figures were measured against; restore the committed \
         bytes, or re-measure every value and re-pin this digest in the same change",
        fixture.relative
    );
    bytes
}

fn thin_slice(fixture: TrackedFixture, bytes: &[u8], preferred: Option<CpuKind>) -> Vec<u8> {
    let kind: MachoKind = macho::detect_magic(bytes).unwrap_or_else(|| {
        panic!(
            "corpus/{} carries no Mach-O magic; a fixture that is present but is not the container \
             this case grades is never a skip",
            fixture.relative
        )
    });
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> = macho::walk_fat(bytes).unwrap_or_else(|error| {
                panic!(
                    "corpus/{} is a fat Mach-O whose arch table does not walk: {error}",
                    fixture.relative
                )
            });
            let entry: &FatArchEntry = preferred
                .and_then(|cpu: CpuKind| entries.iter().find(|e: &&FatArchEntry| e.cpu == cpu))
                .or_else(|| entries.first())
                .unwrap_or_else(|| panic!("corpus/{} carries zero arch entries", fixture.relative));
            macho::slice_bytes(bytes, entry)
                .unwrap_or_else(|| {
                    panic!(
                        "corpus/{} declares a slice outside the file bounds",
                        fixture.relative
                    )
                })
                .to_vec()
        }
        _ => bytes.to_vec(),
    }
}

fn signature_of(fixture: TrackedFixture) -> (Vec<u8>, ParsedSlice, Option<CodeSignature>) {
    let bytes: Vec<u8> = read_tracked(fixture);
    let slice: Vec<u8> = thin_slice(fixture, &bytes, None);
    let parsed: ParsedSlice = macho::parse_slice(&slice).unwrap_or_else(|error| {
        panic!(
            "corpus/{} yields a Mach-O slice that does not parse: {error}",
            fixture.relative
        )
    });
    let signature: Option<CodeSignature> =
        disrobe_pass_swift_objc::code_signature::parse(&slice, &parsed);
    (slice, parsed, signature)
}

#[test]
fn swift_hello_reports_the_adhoc_linker_signature_apple_wrote() {
    let (_, _, signature): (Vec<u8>, ParsedSlice, Option<CodeSignature>) =
        signature_of(SWIFT_HELLO);
    let signature: CodeSignature = signature.expect(
        "corpus/mobile/macho-mac/SwiftHello.original carries an LC_CODE_SIGNATURE whose superblob \
         parses; returning None here would report a signed binary as unsigned",
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
        signature_of(SWIFT_HELLO);
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
        signature_of(SWIFT_HELLO);
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
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO);
    let mut patched: Vec<u8> = thin_slice(SWIFT_HELLO, &bytes, None);
    let target: usize = 0x2000;
    let original: u8 = patched[target];
    patched[target] = original.wrapping_add(1);
    let parsed: ParsedSlice = macho::parse_slice(&patched).expect("the patched slice still parses");
    let signature: CodeSignature =
        disrobe_pass_swift_objc::code_signature::parse(&patched, &parsed)
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
        signature_of(SWIFT_EDGE_CASES);
    let signature: CodeSignature = signature.expect(
        "corpus/mobile/macho-mac/swiftshield-edgecases/SwiftEdgeCases.obfuscated is signed",
    );
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
    let slice: Vec<u8> = thin_slice(EDGE_CASES_FAT, &bytes, Some(CpuKind::X86_64));
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("the x86_64 slice parses");
    assert_eq!(
        parsed.code_signature_off, None,
        "the x86_64 slice of corpus/mac/megafile/EdgeCases.fat carries no LC_CODE_SIGNATURE, \
         which is what makes it the negative case here"
    );
    assert!(
        disrobe_pass_swift_objc::code_signature::parse(&slice, &parsed).is_none(),
        "an unsigned image must report no signature, never a signature with empty fields"
    );
}

#[test]
fn each_slice_of_a_fat_binary_is_judged_on_its_own_signature() {
    let bytes: Vec<u8> = read_tracked(EDGE_CASES_FAT);
    let unsigned: Vec<u8> = thin_slice(EDGE_CASES_FAT, &bytes, Some(CpuKind::X86_64));
    let signed: Vec<u8> = thin_slice(EDGE_CASES_FAT, &bytes, Some(CpuKind::Arm64));
    assert_ne!(
        unsigned, signed,
        "the two slices must be different images for this case to mean anything"
    );

    let unsigned_parsed: ParsedSlice =
        macho::parse_slice(&unsigned).expect("the x86_64 slice parses");
    let signed_parsed: ParsedSlice = macho::parse_slice(&signed).expect("the arm64 slice parses");
    assert!(
        disrobe_pass_swift_objc::code_signature::parse(&unsigned, &unsigned_parsed).is_none(),
        "the x86_64 slice is unsigned"
    );
    let signature: CodeSignature =
        disrobe_pass_swift_objc::code_signature::parse(&signed, &signed_parsed).expect(
            "the arm64 slice of the same fat binary is signed, so a fat report that judged the \
             whole file by one slice would be wrong",
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
