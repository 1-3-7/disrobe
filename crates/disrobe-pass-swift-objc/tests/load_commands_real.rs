#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::{
    self, DylibKind, DylibReference, DysymtabInfo, EntryPoint, ImportThunk, ParsedSlice,
    PlatformVersion, Section, Segment,
};

use macho_corpus::{SWIFT_HELLO_ORIGINAL, first_slice, read_tracked};

fn swift_hello() -> (Vec<u8>, ParsedSlice) {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    first_slice(SWIFT_HELLO_ORIGINAL, &bytes)
}

#[test]
fn dylib_dependencies_are_recovered_with_their_link_kind() {
    let (_, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    let names: Vec<&str> = parsed
        .dylibs
        .iter()
        .map(|d: &DylibReference| d.name.as_str())
        .collect();
    assert_eq!(
        parsed.dylibs.len(),
        11,
        "SwiftHello.original links eleven dylibs: {names:?}"
    );
    assert!(
        names.contains(&"/usr/lib/libSystem.B.dylib"),
        "the C runtime must appear: {names:?}"
    );
    assert!(
        names.contains(&"/usr/lib/swift/libswiftCore.dylib"),
        "the Swift runtime must appear, since it is what makes this a Swift image: {names:?}"
    );

    let weak: Vec<&str> = parsed
        .dylibs
        .iter()
        .filter(|d: &&DylibReference| d.kind == DylibKind::LoadWeak)
        .map(|d: &DylibReference| d.name.as_str())
        .collect();
    assert_eq!(
        weak.len(),
        7,
        "seven of the eleven are weak links and the kind must survive: {weak:?}"
    );
    assert!(
        weak.contains(&"/usr/lib/swift/libswiftFoundation.dylib"),
        "{weak:?}"
    );

    let libsystem: &DylibReference = parsed
        .dylibs
        .iter()
        .find(|d: &&DylibReference| d.name == "/usr/lib/libSystem.B.dylib")
        .expect("libSystem is linked");
    assert_eq!(libsystem.kind, DylibKind::Load);
    assert_eq!(libsystem.current_version, "1356.0.0");
    assert_eq!(libsystem.compatibility_version, "1.0.0");
}

#[test]
fn rpaths_uuid_and_entry_point_are_recovered() {
    let (_, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    assert_eq!(
        parsed.uuid.as_deref(),
        Some("f34fbfd6-6a49-30bb-be3f-3176c4c57566"),
        "the uuid is how a crash report is tied back to this exact build"
    );
    assert_eq!(
        parsed.rpaths,
        vec![
            "/usr/lib/swift".to_owned(),
            "@loader_path".to_owned(),
            "/Library/Developer/CommandLineTools/usr/lib/swift-5.5/macosx".to_owned(),
            "/Library/Developer/CommandLineTools/usr/lib/swift-6.2/macosx".to_owned(),
        ],
        "every rpath is recovered in load-command order"
    );
    let entry: EntryPoint = parsed.entry_point.expect("an executable declares LC_MAIN");
    assert_eq!(entry.entry_offset, 0x1C38);
    assert_eq!(entry.stack_size, 0);
    assert_eq!(parsed.source_version, Some(0));
    assert_eq!(parsed.id_dylib, None, "an executable is not a dylib");
}

#[test]
fn build_version_names_the_platform_and_both_sdk_bounds() {
    let (_, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    let platform: PlatformVersion = parsed
        .platform_version
        .expect("LC_BUILD_VERSION is present");
    assert_eq!(platform.platform, 1);
    assert_eq!(platform.platform_label(), "macos");
    assert_eq!(platform.min_os.to_string(), "11.0.0");
    assert_eq!(platform.sdk.to_string(), "26.5.0");
}

#[test]
fn linkedit_blobs_are_located() {
    let (_, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    let starts: macho::LinkeditData = parsed
        .function_starts
        .expect("LC_FUNCTION_STARTS is present");
    assert_eq!(starts.offset, 50_168);
    assert_eq!(starts.size, 64);
    let dic: macho::LinkeditData = parsed.data_in_code.expect("LC_DATA_IN_CODE is present");
    assert_eq!(dic.offset, 50_232);
    assert_eq!(
        dic.size, 0,
        "a present but empty blob must report zero rather than being dropped"
    );
}

#[test]
fn dysymtab_ranges_are_recovered() {
    let (_, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    let dysymtab: DysymtabInfo = parsed.dysymtab.expect("LC_DYSYMTAB is present");
    assert_eq!(dysymtab.local_sym_index, 0);
    assert_eq!(dysymtab.local_sym_count, 186);
    assert_eq!(dysymtab.extdef_sym_index, 186);
    assert_eq!(dysymtab.extdef_sym_count, 3);
    assert_eq!(dysymtab.undef_sym_index, 189);
    assert_eq!(dysymtab.undef_sym_count, 38);
    assert_eq!(dysymtab.indirect_sym_off, 53_864);
    assert_eq!(dysymtab.indirect_sym_count, 49);
}

#[test]
fn stub_sections_carry_their_reserved_fields() {
    let (_, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    let stubs: &Section = parsed
        .segments
        .iter()
        .flat_map(|s: &Segment| s.sections.iter())
        .find(|s: &&Section| s.name == "__stubs")
        .expect("a Swift executable carries a __stubs section");
    assert_eq!(stubs.seg, "__TEXT");
    assert_eq!(stubs.addr, 0x1_0000_20AC);
    assert_eq!(stubs.size, 276);
    assert_eq!(
        stubs.reserved1, 0,
        "reserved1 indexes this section's first slot in the indirect symbol table"
    );
    assert_eq!(
        stubs.reserved2, 12,
        "reserved2 is the stub stride, without which the slots cannot be walked"
    );
    assert_eq!(
        stubs.flags & macho::SECTION_TYPE_MASK,
        macho::S_SYMBOL_STUBS
    );
}

#[test]
fn import_thunks_resolve_stub_addresses_to_imported_symbol_names() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    let thunks: Vec<ImportThunk> = macho::import_thunks(&slice, &parsed);
    assert!(
        !thunks.is_empty(),
        "an image with a populated indirect symbol table must yield named thunks, since an \
         empty result here is what leaves a lifted call target unnamed"
    );

    let stubs: Vec<&ImportThunk> = thunks
        .iter()
        .filter(|t: &&ImportThunk| t.section == "__stubs")
        .collect();
    assert_eq!(
        stubs.len(),
        23,
        "the 276 byte __stubs section holds 23 slots at a 12 byte stride"
    );

    let first: &ImportThunk = stubs.first().expect("at least one stub");
    assert_eq!(first.address, 0x1_0000_20AC);
    assert_eq!(
        first.name.as_deref(),
        Some("_$sSS6appendyySSF"),
        "the first stub resolves through the indirect symbol table to the mangled Swift symbol"
    );

    let named: Vec<&str> = stubs
        .iter()
        .filter_map(|t: &&ImportThunk| t.name.as_deref())
        .collect();
    assert!(
        named.contains(&"_$ss5print_9separator10terminatoryypd_S2StF"),
        "the Swift print entry point resolves: {named:?}"
    );
    assert!(
        named.contains(&"__Znwm"),
        "operator new resolves: {named:?}"
    );
    assert_eq!(
        named.len(),
        stubs.len(),
        "every stub slot in this image resolves to a name, so a partial map would be caught"
    );

    let addresses_ascend: bool = stubs
        .windows(2)
        .all(|w: &[&ImportThunk]| w[0].address < w[1].address);
    assert!(addresses_ascend, "stub addresses advance by the stride");
}

#[test]
fn import_thunks_are_empty_without_an_indirect_symbol_table() {
    let (slice, mut parsed): (Vec<u8>, ParsedSlice) = swift_hello();
    parsed.dysymtab = None;
    assert!(
        macho::import_thunks(&slice, &parsed).is_empty(),
        "with no LC_DYSYMTAB there is nothing to resolve against, and inventing a name would be \
         worse than reporting none"
    );
}
