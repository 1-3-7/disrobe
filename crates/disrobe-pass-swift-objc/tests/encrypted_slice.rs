#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::fairplay::{self, EncryptedTextNotice, FairPlayStatus};
use disrobe_pass_swift_objc::macho::{
    self, EncryptedRegion, LC_ENCRYPTION_INFO_64, ParsedSlice, Section, SliceView,
};
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};

use macho_corpus::{
    FEATHER_IPA, ONION_BROWSER_IPA, PPSSPP_IPA, SWIFT_HELLO_ORIGINAL, first_slice,
    read_host_sourced, read_tracked,
};

const ENCRYPTION_CMD_SIZE: usize = 24;
const TEXT_FILESIZE: u32 = 16_384;
const HEADER_SIZE: usize = 32;

fn with_encryption_command(slice: &[u8], crypt_id: u32) -> Vec<u8> {
    let mut out: Vec<u8> = slice.to_vec();
    let ncmds: u32 = u32::from_le_bytes(
        out[16..20]
            .try_into()
            .expect("a 64-bit Mach-O header carries ncmds at offset 16"),
    );
    let sizeofcmds: u32 = u32::from_le_bytes(
        out[20..24]
            .try_into()
            .expect("a 64-bit Mach-O header carries sizeofcmds at offset 20"),
    );
    let at: usize = HEADER_SIZE + sizeofcmds as usize;
    let padding: &[u8] = out
        .get(at..at + ENCRYPTION_CMD_SIZE)
        .expect("the fixture must have room after its load commands");
    assert!(
        padding.iter().all(|byte: &u8| *byte == 0),
        "this fixture is built by writing an LC_ENCRYPTION_INFO_64 command into the zero padding \
         that follows the load commands, so every file offset in the fixture stays exactly where \
         the real binary put it; the padding is not free here, so the fixture would move real \
         content and grade a file that is not the pinned one"
    );
    let mut command: Vec<u8> = Vec::with_capacity(ENCRYPTION_CMD_SIZE);
    command.extend_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes());
    let cmd_size: u32 = u32::try_from(ENCRYPTION_CMD_SIZE).expect("the command size fits in u32");
    command.extend_from_slice(&cmd_size.to_le_bytes());
    command.extend_from_slice(&0u32.to_le_bytes());
    command.extend_from_slice(&TEXT_FILESIZE.to_le_bytes());
    command.extend_from_slice(&crypt_id.to_le_bytes());
    command.extend_from_slice(&0u32.to_le_bytes());
    out[at..at + ENCRYPTION_CMD_SIZE].copy_from_slice(&command);
    out[16..20].copy_from_slice(&(ncmds + 1).to_le_bytes());
    out[20..24].copy_from_slice(&(sizeofcmds + cmd_size).to_le_bytes());
    out
}

fn tracked_slice_with_cryptid(crypt_id: u32) -> (Vec<u8>, ParsedSlice) {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(SWIFT_HELLO_ORIGINAL, &bytes);
    assert!(
        parsed.encryption.is_none(),
        "{} carries no encryption command of its own, so the one this case adds is the only one \
         in play",
        SWIFT_HELLO_ORIGINAL.relative()
    );
    let mutated: Vec<u8> = with_encryption_command(&slice, crypt_id);
    let reparsed: ParsedSlice = macho::parse_slice(&mutated)
        .unwrap_or_else(|error| panic!("the fixture must still parse as Mach-O: {error}"));
    (mutated, reparsed)
}

#[test]
fn a_zero_cryptid_slice_parses_and_recovers_its_classes() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice_with_cryptid(0);
    let status: FairPlayStatus = fairplay::detect(&parsed);
    assert!(status.has_encryption_info_lc);
    assert!(
        !status.is_encrypted,
        "cryptid 0 means the text is present in the file, not encrypted at rest"
    );
    assert_eq!(macho::encrypted_region(&parsed), None);
    assert_eq!(fairplay::encrypted_text_notice(&parsed), None);

    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);
    assert_eq!(dump.encrypted_text, None);
    let names: Vec<&str> = dump
        .interfaces
        .iter()
        .map(|interface| interface.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "_TtC10SwiftHello19LoginViewController",
            "_TtC10SwiftHello21AuthenticationService"
        ],
        "with cryptid 0 the same fixture yields both of its real class names"
    );

    let swift_dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    assert!(
        !swift_dump.reflected_types.is_empty(),
        "with cryptid 0 the Swift reflection sections in __TEXT are readable"
    );
}

#[test]
fn a_nonzero_cryptid_slice_reports_encryption_and_yields_no_recovered_text() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice_with_cryptid(1);
    let status: FairPlayStatus = fairplay::detect(&parsed);
    assert!(status.is_encrypted);
    assert_eq!(status.crypt_id, 1);
    assert!(
        status.residual_note.is_some(),
        "an encrypted slice must state why its text is not recoverable from these bytes"
    );

    let region: EncryptedRegion =
        macho::encrypted_region(&parsed).expect("cryptid 1 marks a region encrypted at rest");
    assert_eq!(region.file_off, 0);
    assert_eq!(region.size, u64::from(TEXT_FILESIZE));
    assert_eq!(region.crypt_id, 1);

    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);
    let notice: &EncryptedTextNotice = dump
        .encrypted_text
        .as_ref()
        .expect("the dump must carry the encryption notice rather than leave a reader to infer it");
    assert_eq!(notice.crypt_id, 1);
    assert_eq!(notice.file_off, 0);
    assert_eq!(notice.file_end, u64::from(TEXT_FILESIZE));
    for withheld in [
        "__TEXT/__objc_methname",
        "__TEXT/__objc_classname",
        "__TEXT/__objc_methtype",
        "__TEXT/__swift5_reflstr",
        "__TEXT/__text",
    ] {
        assert!(
            notice
                .withheld_sections
                .iter()
                .any(|section: &String| section == withheld),
            "{withheld} lies inside the encrypted range and must be named as withheld, got {:?}",
            notice.withheld_sections
        );
    }

    assert!(
        dump.interfaces.is_empty(),
        "the class names of this fixture live in __TEXT/__objc_classname, which is encrypted at \
         rest, so presenting a recovered @interface would be presenting whatever those bytes \
         happen to decode to"
    );
    assert!(dump.unique_selectors.is_empty());
    assert!(dump.unique_class_names.is_empty());
    assert!(dump.unique_method_types.is_empty());
    assert!(
        dump.class_count > 0,
        "__objc_classlist lives outside the encrypted range, so the count of classes the image \
         declares is still a read and must still be reported"
    );

    let swift_dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    assert!(
        swift_dump.reflected_types.is_empty(),
        "the Swift reflection sections are inside the encrypted range, so no reflected type may \
         be presented"
    );
    assert!(
        swift_dump
            .reflection_strings
            .as_ref()
            .is_none_or(|strings| strings.strings.is_empty()),
        "no reflection string may be read out of the encrypted range"
    );
    let symbol_table: Vec<String> = macho::symbol_names(&slice, &parsed);
    assert!(
        !swift_dump.mangled_symbols.is_empty(),
        "cryptid covers __TEXT, not __LINKEDIT, so the symbol table is still present in the file \
         and its names are still a read"
    );
    assert!(
        swift_dump
            .mangled_symbols
            .iter()
            .all(|symbol: &String| symbol_table.contains(symbol)),
        "every name this slice still reports must come from the symbol table that lies outside \
         the encrypted range, never from a section inside it"
    );
}

#[test]
fn section_reads_inside_the_encrypted_range_are_refused_and_reads_outside_are_not() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice_with_cryptid(1);
    let inside: &Section = macho::find_section(&parsed, "__TEXT", "__objc_methname")
        .expect("the fixture carries __TEXT/__objc_methname");
    assert!(macho::section_is_encrypted_at_rest(&parsed, inside));
    assert_eq!(macho::readable_section_bytes(&slice, &parsed, inside), None);
    assert!(
        macho::section_bytes(&slice, inside).is_some(),
        "the bytes are addressable; what the pass refuses is presenting them as recovered text"
    );

    let outside: &Section = macho::find_section(&parsed, "__DATA_CONST", "__objc_classlist")
        .expect("the fixture carries __DATA_CONST/__objc_classlist");
    assert!(!macho::section_is_encrypted_at_rest(&parsed, outside));
    assert!(macho::readable_section_bytes(&slice, &parsed, outside).is_some());

    let view: SliceView<'_> =
        SliceView::new(&slice, &parsed).expect("the fixture has an image base");
    assert_eq!(view.encrypted(), macho::encrypted_region(&parsed));
    assert!(
        !view.readable(0, 4),
        "a read at the start of the range is refused"
    );
    assert!(
        !view.readable(usize::try_from(TEXT_FILESIZE).expect("fits") - 1, 8),
        "a read that straddles the end of the range is refused"
    );
    assert!(
        view.readable(usize::try_from(TEXT_FILESIZE).expect("fits"), 8),
        "a read that starts at the first byte past the range is allowed"
    );
    assert_eq!(
        view.read_u32_at(0),
        None,
        "every record reader goes through this view, so refusing here is what makes the refusal \
         hold for readers that have not been written yet"
    );
}

#[test]
fn real_sideload_ipas_are_not_reported_as_encrypted() {
    for fixture in [FEATHER_IPA, PPSSPP_IPA, ONION_BROWSER_IPA] {
        let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
            continue;
        };
        let report: disrobe_pass_swift_objc::pass::SwiftObjcReport =
            disrobe_pass_swift_objc::pass::analyze(&bytes)
                .unwrap_or_else(|error| panic!("{} does not analyze: {error}", fixture.relative()));
        for slice in &report.slices {
            assert!(
                slice.fairplay.has_encryption_info_lc,
                "{} carries an LC_ENCRYPTION_INFO_64 command",
                fixture.relative()
            );
            assert!(
                !slice.fairplay.is_encrypted,
                "{} is a sideload build whose cryptid is 0, so its text is present in the file",
                fixture.relative()
            );
            assert_eq!(
                slice.objc.encrypted_text,
                None,
                "{} must not carry an encryption notice when nothing is encrypted",
                fixture.relative()
            );
        }
    }
}
