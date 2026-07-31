#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use std::collections::BTreeSet;
use std::io::{Cursor, Read};

use disrobe_pass_swift_objc::ipa::{self, IpaInventory};
use disrobe_pass_swift_objc::macho::{
    self, ExportKind, ExportedSymbol, FunctionSymbol, ParsedSlice,
};

use macho_corpus::{
    CorpusFixture, EDGE_CASES_FAT, ONION_BROWSER_IPA, PPSSPP_IPA, SWIFT_EDGE_CASES_ORIGINAL,
    SWIFT_HELLO_ORIGINAL, first_slice, read_host_sourced, read_tracked, select_slice,
};

const MACH_HEADER_SYMBOL: &str = "__mh_execute_header";

struct Recovered {
    starts: Vec<u64>,
    exports: Vec<ExportedSymbol>,
    symbol_function_addresses: BTreeSet<u64>,
    symbol_names: BTreeSet<String>,
    image_base: u64,
}

fn recover(slice: &[u8], parsed: &ParsedSlice) -> Recovered {
    Recovered {
        starts: macho::function_starts(slice, parsed),
        exports: macho::exported_symbols(slice, parsed),
        symbol_function_addresses: macho::function_symbols(slice, parsed)
            .iter()
            .map(|symbol: &FunctionSymbol| symbol.address)
            .collect(),
        symbol_names: macho::symbol_names(slice, parsed).into_iter().collect(),
        image_base: macho::image_base(parsed).unwrap_or(0),
    }
}

fn assert_starts_are_addresses_in_the_image(label: &str, parsed: &ParsedSlice, r: &Recovered) {
    assert!(
        r.starts.windows(2).all(|pair: &[u64]| pair[0] < pair[1]),
        "{label}: LC_FUNCTION_STARTS is a list of deltas, so the addresses it decodes to are \
         strictly increasing. A run that emits an out-of-order address has added a delta it \
         misread rather than one the file carries"
    );
    let unmapped: Vec<&u64> = r
        .starts
        .iter()
        .filter(|address: &&u64| macho::vmaddr_to_offset(parsed, **address).is_none())
        .collect();
    assert!(
        unmapped.is_empty(),
        "{label}: {} of {} decoded function starts fall outside every mapped segment, so they are \
         not addresses in this image: {:?}",
        unmapped.len(),
        r.starts.len(),
        unmapped.iter().take(4).collect::<Vec<&&u64>>()
    );
    assert!(
        r.starts.iter().all(|address: &u64| *address > r.image_base),
        "{label}: every function start lies past the mach header at the image base"
    );
}

fn addressable_in_image(parsed: &ParsedSlice, address: u64) -> bool {
    parsed.segments.iter().any(|segment: &macho::Segment| {
        segment.name != "__PAGEZERO"
            && address >= segment.vmaddr
            && address < segment.vmaddr.saturating_add(segment.vmsize)
    })
}

fn assert_exports_are_real_symbols(label: &str, parsed: &ParsedSlice, r: &Recovered) {
    let missing: Vec<&str> = r
        .exports
        .iter()
        .filter(|export: &&ExportedSymbol| !r.symbol_names.contains(&export.name))
        .map(|export: &ExportedSymbol| export.name.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "{label}: {} of {} names decoded out of the export trie do not appear in this image's \
         symbol table. The trie and the symbol table are two independent encodings of the same \
         exports, so a name in one and not the other is a name the walk assembled from the wrong \
         edges rather than one the file carries: {:?}",
        missing.len(),
        r.exports.len(),
        missing.iter().take(6).collect::<Vec<&&str>>()
    );
    let outside: Vec<&str> = r
        .exports
        .iter()
        .filter(|export: &&ExportedSymbol| {
            export.kind != ExportKind::Absolute
                && export.kind != ExportKind::Reexport
                && export
                    .address
                    .is_none_or(|address: u64| !addressable_in_image(parsed, address))
        })
        .map(|export: &ExportedSymbol| export.name.as_str())
        .collect();
    assert!(
        outside.is_empty(),
        "{label}: an export names an address the loader will resolve inside this image, so it \
         must land in one of the image's virtual address ranges. A zero fill section such as \
         __bss occupies addresses without occupying file bytes, so this is a virtual range check \
         rather than a file offset one, and an exported data symbol is not evidence of a bad walk. \
         Got {:?}",
        outside.iter().take(6).collect::<Vec<&&str>>()
    );
    assert!(
        r.exports
            .iter()
            .all(|export: &ExportedSymbol| !export.name.is_empty()),
        "{label}: an empty export name is an edge walk that produced nothing rather than a name"
    );
}

#[test]
fn tracked_fixtures_decode_the_function_starts_their_symbol_tables_agree_with() {
    for (fixture, expected_starts, expected_symbol_addresses) in [
        (SWIFT_HELLO_ORIGINAL, 46usize, 47usize),
        (SWIFT_EDGE_CASES_ORIGINAL, 124, 125),
        (EDGE_CASES_FAT, 718, 703),
    ] {
        let bytes: Vec<u8> = read_tracked(fixture);
        let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(fixture, &bytes);
        let r: Recovered = recover(&slice, &parsed);
        let label: String = fixture.relative();

        assert!(
            parsed.function_starts.is_some(),
            "{label} carries an LC_FUNCTION_STARTS command"
        );
        assert_eq!(
            r.starts.len(),
            expected_starts,
            "{label} declares {expected_starts} function starts"
        );
        assert_starts_are_addresses_in_the_image(&label, &parsed, &r);
        assert_eq!(
            r.symbol_function_addresses.len(),
            expected_symbol_addresses,
            "{label} carries {expected_symbol_addresses} distinct text symbol addresses"
        );

        let start_set: BTreeSet<u64> = r.starts.iter().copied().collect();
        let absent: Vec<u64> = r
            .symbol_function_addresses
            .difference(&start_set)
            .copied()
            .collect();
        assert_eq!(
            absent,
            vec![r.image_base],
            "{label}: the symbol table and LC_FUNCTION_STARTS are two independent records of \
             where the functions are, so every text symbol address must appear among the function \
             starts. The one address that legitimately does not is {MACH_HEADER_SYMBOL} at the \
             image base, which names the mach header rather than a function"
        );
        assert!(
            r.symbol_names.contains(MACH_HEADER_SYMBOL),
            "{label} carries the {MACH_HEADER_SYMBOL} symbol this case excludes by name"
        );
    }
}

#[test]
fn tracked_fixtures_decode_every_symbol_their_export_trie_carries() {
    for (fixture, expected) in [
        (
            SWIFT_HELLO_ORIGINAL,
            vec!["_SwiftHello_main", "__mh_execute_header", "_main"],
        ),
        (
            SWIFT_EDGE_CASES_ORIGINAL,
            vec!["__mh_execute_header", "_main"],
        ),
        (EDGE_CASES_FAT, vec!["__mh_execute_header", "_main"]),
    ] {
        let bytes: Vec<u8> = read_tracked(fixture);
        let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(fixture, &bytes);
        let r: Recovered = recover(&slice, &parsed);
        let label: String = fixture.relative();

        assert!(
            parsed.exports_trie.is_some() || parsed.dyld_info_exports.is_some(),
            "{label} carries its export trie in one of the two load commands that can hold it"
        );
        assert_eq!(
            r.exports
                .iter()
                .map(|export: &ExportedSymbol| export.name.as_str())
                .collect::<Vec<&str>>(),
            expected,
            "{label} exports exactly these symbols"
        );
        assert!(
            r.exports
                .iter()
                .all(|export: &ExportedSymbol| export.kind == ExportKind::Regular),
            "{label} exports only regular symbols"
        );
        assert_exports_are_real_symbols(&label, &parsed, &r);
    }
}

#[test]
fn a_command_that_is_absent_recovers_nothing_rather_than_guessing() {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let (slice, mut parsed): (Vec<u8>, ParsedSlice) = first_slice(SWIFT_HELLO_ORIGINAL, &bytes);
    parsed.function_starts = None;
    parsed.exports_trie = None;
    parsed.dyld_info_exports = None;
    assert!(
        macho::function_starts(&slice, &parsed).is_empty(),
        "with no LC_FUNCTION_STARTS there is nothing to decode, and the same bytes must not be \
         read as a delta list on the strength of being there"
    );
    assert!(macho::exported_symbols(&slice, &parsed).is_empty());
}

#[test]
fn the_pass_report_carries_what_the_linkedit_decoders_recover() {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let report: disrobe_pass_swift_objc::pass::SwiftObjcReport =
        disrobe_pass_swift_objc::pass::analyze(&bytes).expect("the fixture analyzes");
    let slice: &disrobe_pass_swift_objc::pass::SliceReport = report
        .slices
        .first()
        .expect("a thin fixture yields one slice report");

    assert_eq!(
        slice.function_starts.len(),
        46,
        "a decoder the report does not carry is a decoder nobody reading this pass can see"
    );
    assert_eq!(
        slice.metadata_summary.function_starts_recovered,
        slice.function_starts.len()
    );
    assert_eq!(
        slice
            .exports
            .iter()
            .map(|export: &ExportedSymbol| export.name.as_str())
            .collect::<Vec<&str>>(),
        vec!["_SwiftHello_main", "__mh_execute_header", "_main"]
    );
    assert_eq!(
        slice.metadata_summary.exported_symbols_recovered,
        slice.exports.len()
    );
    assert_eq!(slice.metadata_summary.function_symbols_recovered, 48);
    assert!(
        slice.metadata_summary.function_starts_recovered
            < slice.metadata_summary.function_symbols_recovered,
        "this fixture keeps its symbol table, so the two counts are close; the case that matters \
         is the stripped one, where the symbol count collapses and the function start count does \
         not"
    );
}

fn ipa_images(fixture: CorpusFixture, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let inventory: IpaInventory = ipa::inventory(bytes).expect("the archive is an ipa");
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(Cursor::new(bytes)).expect("the archive opens");
    let candidates: Vec<String> = inventory
        .entries
        .iter()
        .filter(|entry: &&ipa::IpaEntry| {
            entry.is_executable_candidate && entry.size > 4096 && entry.size < 96 * 1024 * 1024
        })
        .map(|entry: &ipa::IpaEntry| entry.name.clone())
        .collect();
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for path in candidates {
        let Ok(mut entry) = archive.by_name(&path) else {
            continue;
        };
        let mut buf: Vec<u8> = Vec::new();
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }
        drop(entry);
        if macho::detect_magic(&buf).is_some() {
            out.push((format!("{}:{path}", fixture.name), buf));
        }
    }
    out
}

#[test]
fn every_export_in_every_pinned_ipa_image_is_a_symbol_that_image_declares() {
    let mut images: usize = 0;
    let mut exports: usize = 0;
    for fixture in [ONION_BROWSER_IPA, PPSSPP_IPA] {
        let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
            continue;
        };
        for (label, image) in ipa_images(fixture, &bytes) {
            let (slice, parsed): (Vec<u8>, ParsedSlice) = select_slice(fixture, &image, None);
            let r: Recovered = recover(&slice, &parsed);
            if r.exports.is_empty() && r.starts.is_empty() {
                continue;
            }
            images += 1;
            exports += r.exports.len();
            assert_exports_are_real_symbols(&label, &parsed, &r);
            assert_starts_are_addresses_in_the_image(&label, &parsed, &r);
        }
    }
    if images > 0 {
        assert_eq!(
            images, 14,
            "the two pinned archives carry 14 Mach-O images that declare exports or function \
             starts"
        );
        assert_eq!(
            exports, 24_644,
            "those 14 images export 24644 symbols between them, and every one of them was \
             cross-checked against the symbol table of the image that exports it"
        );
    }
}

#[test]
fn a_dylib_agrees_exactly_with_its_symbol_table_on_where_the_functions_are() {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(PPSSPP_IPA) else {
        return;
    };
    let image: Vec<u8> = ipa_images(PPSSPP_IPA, &bytes)
        .into_iter()
        .find(|(label, _)| label.ends_with("Frameworks/libMoltenVK.dylib"))
        .map(|(_, image)| image)
        .expect("the archive carries libMoltenVK.dylib");
    let (slice, parsed): (Vec<u8>, ParsedSlice) = select_slice(PPSSPP_IPA, &image, None);
    let r: Recovered = recover(&slice, &parsed);

    let start_set: BTreeSet<u64> = r.starts.iter().copied().collect();
    assert_eq!(
        r.starts.len(),
        9_747,
        "libMoltenVK declares 9747 function starts"
    );
    assert_eq!(
        start_set, r.symbol_function_addresses,
        "this image keeps its full symbol table, so its delta encoded function starts and its \
         nlist symbol addresses describe the same set of functions by two unrelated routes. \
         Exact agreement across 9747 addresses is what says the delta walk tracked the file \
         rather than drifting somewhere plausible"
    );
}

#[test]
fn a_stripped_binary_recovers_the_functions_its_symbol_table_no_longer_names() {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(ONION_BROWSER_IPA) else {
        return;
    };
    let image: Vec<u8> = ipa_images(ONION_BROWSER_IPA, &bytes)
        .into_iter()
        .find(|(label, _)| label.ends_with(":Payload/OnionBrowser.app/OnionBrowser"))
        .map(|(_, image)| image)
        .expect("the archive carries the main binary");
    let (slice, parsed): (Vec<u8>, ParsedSlice) = select_slice(ONION_BROWSER_IPA, &image, None);
    let r: Recovered = recover(&slice, &parsed);

    assert_eq!(
        r.symbol_function_addresses.len(),
        2,
        "this binary ships stripped, so its symbol table names almost no functions"
    );
    assert_eq!(
        r.starts.len(),
        33_302,
        "LC_FUNCTION_STARTS survives stripping, so the function boundaries are still in the file \
         and this is the count that recovers from them"
    );
    assert_starts_are_addresses_in_the_image("OnionBrowser", &parsed, &r);
    assert_eq!(r.exports.len(), 43);
    assert_exports_are_real_symbols("OnionBrowser", &parsed, &r);
}
