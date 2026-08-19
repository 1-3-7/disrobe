#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "support/dyld_cache_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dyld_cache_fixture;

use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_swift_objc::dyld_cache::subcache::{CacheFamily, SubCacheEntryKind};
use disrobe_pass_swift_objc::dyld_cache::{
    self, AuthPointerRecord, CacheHeaderLayout, DyldSharedCache, ReconstructBatch,
    ReconstructOptions, ReconstructedDylib, SegmentLayout, UnresolvedImage,
};
use disrobe_pass_swift_objc::error::Error;
use disrobe_pass_swift_objc::macho::{self, ExportedSymbol, ParsedSlice, Segment};

use dyld_cache_fixture::{
    AuthSpec, BuiltCache, CACHE_PAGE, CacheSpec, HeaderShape, SlideExpectation, SlidePlan,
};
use macho_corpus::{SWIFT_HELLO_ORIGINAL, read_tracked};

const INSTALL_NAME: &str = "/usr/lib/libSwiftHello.dylib";
const PINNED_NAMED_SYMBOLS: usize = 204;
const PINNED_NLIST_ENTRIES: u32 = 227;
const PINNED_INDIRECT_SYMBOLS: u32 = 49;

fn original() -> Vec<u8> {
    read_tracked(SWIFT_HELLO_ORIGINAL)
}

fn parse_original(bytes: &[u8]) -> ParsedSlice {
    macho::parse_slice(bytes).expect("the committed dylib parses")
}

fn built(spec: &CacheSpec) -> (Vec<u8>, BuiltCache) {
    let image: Vec<u8> = original();
    let cache: BuiltCache = dyld_cache_fixture::build(&image, spec);
    (image, cache)
}

fn assert_same_bytes(label: &str, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{label}: recovered {} bytes but the original holds {}",
        actual.len(),
        expected.len()
    );
    let Some(at): Option<usize> = actual
        .iter()
        .zip(expected.iter())
        .position(|(left, right): (&u8, &u8)| left != right)
    else {
        return;
    };
    let from: usize = at.saturating_sub(8);
    let to: usize = (at + 24).min(actual.len());
    panic!(
        "{label}: first difference at byte {at} ({at:#x}); recovered {:02x?} where the original holds {:02x?}",
        &actual[from..to],
        &expected[from..to]
    );
}

fn recover(cache: &[u8], options: ReconstructOptions) -> ReconstructedDylib {
    let parsed: DyldSharedCache = dyld_cache::parse(cache).expect("the built cache parses");
    dyld_cache::reconstruct_image_with(cache, &parsed, 0, options)
        .expect("the bundled image reconstructs")
}

#[test]
fn a_cache_built_around_the_committed_dylib_reports_its_mappings_and_image() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let parsed: DyldSharedCache = dyld_cache::parse(&cache.primary).expect("cache parses");
    assert_eq!(parsed.layout, CacheHeaderLayout::RelocatedImages);
    assert_eq!(parsed.arch, "arm64e");
    assert_eq!(parsed.images.len(), 1);
    assert_eq!(parsed.images[0].install_name, INSTALL_NAME);
    assert_eq!(parsed.images[0].address, cache.image_address);
    assert_eq!(
        parsed.mappings.len(),
        4,
        "__TEXT, __DATA_CONST, __DATA and __LINKEDIT each get a mapping"
    );
    assert!(
        parsed.truncated_mappings.is_empty(),
        "every fixture mapping must lie inside the file it describes"
    );
}

#[test]
fn compact_reconstruction_restores_every_segment_byte_of_the_committed_dylib() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::COMPACT);
    let parsed: ParsedSlice = parse_original(&image);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    assert_eq!(reparsed.segments.len(), parsed.segments.len());
    for original_segment in &parsed.segments {
        if original_segment.filesize == 0 {
            continue;
        }
        let recovered_segment: &Segment = reparsed
            .segments
            .iter()
            .find(|segment: &&Segment| segment.name == original_segment.name)
            .unwrap_or_else(|| panic!("segment '{}' is missing", original_segment.name));
        let payload: u64 = payload_start(original_segment);
        let from: usize = (original_segment.fileoff + payload) as usize;
        let to: usize = (original_segment.fileoff + original_segment.filesize) as usize;
        let at: usize = (recovered_segment.fileoff + payload) as usize;
        let end: usize = (recovered_segment.fileoff + recovered_segment.filesize) as usize;
        assert_same_bytes(
            &format!("segment '{}'", original_segment.name),
            &recovered.bytes[at..end],
            &image[from..to],
        );
        assert_eq!(
            recovered_segment.fileoff, original_segment.fileoff,
            "compact placement reproduces the original file offset of '{}'",
            original_segment.name
        );
    }
    for (original_segment, recovered_segment) in
        parsed.segments.iter().zip(reparsed.segments.iter())
    {
        for (left, right) in original_segment
            .sections
            .iter()
            .zip(recovered_segment.sections.iter())
        {
            assert_eq!(
                right.offset, left.offset,
                "section '{}' must be pointed back at its own content",
                left.name
            );
            assert_eq!(right.addr, left.addr);
        }
    }
}

fn payload_start(segment: &Segment) -> u64 {
    if segment.name != "__TEXT" {
        return 0;
    }
    segment
        .sections
        .iter()
        .filter(|section: &&macho::Section| section.offset != 0)
        .map(|section: &macho::Section| u64::from(section.offset) - segment.fileoff)
        .min()
        .unwrap_or(0)
}

#[test]
fn load_ready_reconstruction_recovers_the_symbol_table_the_committed_dylib_declares() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let parsed: ParsedSlice = parse_original(&image);
    let expected: Vec<String> = macho::symbol_names(&image, &parsed);
    assert_eq!(
        expected.len(),
        PINNED_NAMED_SYMBOLS,
        "the committed dylib declares a fixed symbol count; a different count means a different file"
    );

    let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let actual: Vec<String> = macho::symbol_names(&recovered.bytes, &reparsed);
    assert_eq!(
        actual, expected,
        "the synthesized symbol table must name exactly what the original binary names, in order"
    );
    let summary = recovered
        .linkedit
        .expect("a load-ready image carries a synthesized linkedit");
    assert_eq!(summary.symbols, PINNED_NLIST_ENTRIES);
    assert_eq!(summary.indirect_symbols, PINNED_INDIRECT_SYMBOLS);
    assert!(summary.string_table_bytes > 0);
}

#[test]
fn load_ready_reconstruction_recovers_the_exports_and_function_starts_of_the_committed_dylib() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let parsed: ParsedSlice = parse_original(&image);
    let expected_exports: Vec<ExportedSymbol> = macho::exported_symbols(&image, &parsed);
    let expected_starts: Vec<u64> = macho::function_starts(&image, &parsed);
    assert!(
        !expected_exports.is_empty(),
        "the committed dylib exports symbols through its dyld info trie"
    );
    assert!(!expected_starts.is_empty());

    let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let actual_exports: Vec<ExportedSymbol> = macho::exported_symbols(&recovered.bytes, &reparsed);
    let actual_starts: Vec<u64> = macho::function_starts(&recovered.bytes, &reparsed);
    let expected_names: Vec<String> = expected_exports
        .iter()
        .map(|symbol: &ExportedSymbol| symbol.name.clone())
        .collect();
    let actual_names: Vec<String> = actual_exports
        .iter()
        .map(|symbol: &ExportedSymbol| symbol.name.clone())
        .collect();
    assert_eq!(actual_names, expected_names);
    assert_eq!(actual_starts, expected_starts);
}

#[test]
fn load_ready_output_is_page_aligned_and_reports_the_page_it_used() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    assert!(recovered.page_aligned);
    assert_eq!(recovered.page_size, CACHE_PAGE);
    assert_eq!(recovered.bytes.len() as u64 % CACHE_PAGE, 0);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    for segment in &reparsed.segments {
        assert_eq!(
            segment.fileoff % CACHE_PAGE,
            0,
            "segment '{}' starts at {} which is not a {CACHE_PAGE:#x} boundary",
            segment.name,
            segment.fileoff
        );
    }
}

#[test]
fn reconstruction_is_byte_reproducible_across_two_runs() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let first: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    let second: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    assert_eq!(first.bytes, second.bytes);
    assert_eq!(
        blake3::hash(&first.bytes).to_hex().to_string(),
        blake3::hash(&second.bytes).to_hex().to_string()
    );
}

#[test]
fn every_header_shape_the_builder_writes_parses_to_its_named_layout() {
    let cases: [(HeaderShape, CacheHeaderLayout); 5] = [
        (HeaderShape::Legacy, CacheHeaderLayout::Legacy),
        (HeaderShape::LocalSymbols, CacheHeaderLayout::LocalSymbols),
        (HeaderShape::SlideMappings, CacheHeaderLayout::SlideMappings),
        (HeaderShape::SubCachesNoSuffix, CacheHeaderLayout::SubCaches),
        (HeaderShape::SubCaches, CacheHeaderLayout::RelocatedImages),
    ];
    for (shape, expected) in cases {
        let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME).with_shape(shape);
        let (image, cache): (Vec<u8>, BuiltCache) = built(&spec);
        let parsed: DyldSharedCache = dyld_cache::parse(&cache.primary).expect("each shape parses");
        assert_eq!(parsed.layout, expected, "shape {shape:?}");
        let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
        let reparsed: ParsedSlice =
            macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
        assert_eq!(
            macho::symbol_names(&recovered.bytes, &reparsed).len(),
            macho::symbol_names(&image, &parse_original(&image)).len(),
            "shape {shape:?} must recover the same symbol table"
        );
    }
}

const V2_DELTA_MASK: u64 = 0x00FF_FF00_0000_0000;
const V4_DELTA_MASK: u64 = 0xC000_0000;
const V4_VALUE_ADD: u64 = 0x1A00_0000;

fn slide_plan(version: u32, parsed: &ParsedSlice) -> SlidePlan {
    let text: &Segment = dyld_cache_fixture::segment_of(parsed, "__TEXT");
    let data: &Segment = dyld_cache_fixture::segment_of(parsed, "__DATA");
    match version {
        1 => SlidePlan {
            version,
            value_add: 0,
            delta_mask: 0,
            targets: vec![
                (0x1234_5678, None),
                (0x0000_4000, None),
                (0xFFFF_0004, None),
            ],
        },
        4 => SlidePlan {
            version,
            value_add: V4_VALUE_ADD,
            delta_mask: V4_DELTA_MASK,
            targets: vec![
                (0x0000_1234, None),
                (0x3FFF_8001, None),
                (0x0001_0000, None),
            ],
        },
        2 => SlidePlan {
            version,
            value_add: text.vmaddr,
            delta_mask: V2_DELTA_MASK,
            targets: vec![
                (text.vmaddr + 0xF68, None),
                (data.vmaddr + 0x218, None),
                (text.vmaddr + 0x22E0, None),
            ],
        },
        _ => SlidePlan {
            version,
            value_add: text.vmaddr,
            delta_mask: 0,
            targets: vec![
                (text.vmaddr + 0xF68, None),
                (
                    data.vmaddr + 0x218,
                    Some(AuthSpec {
                        key: 2,
                        diversity: 0xABCD,
                        address_diversity: true,
                    }),
                ),
                (
                    text.vmaddr + 0x22E0,
                    Some(AuthSpec {
                        key: 0,
                        diversity: 0x1234,
                        address_diversity: false,
                    }),
                ),
            ],
        },
    }
}

fn assert_slide_round_trip(version: u32) -> ReconstructedDylib {
    let image: Vec<u8> = original();
    let parsed: ParsedSlice = parse_original(&image);
    let plan: SlidePlan = slide_plan(version, &parsed);
    let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME).with_slide(plan);
    let cache: BuiltCache = dyld_cache_fixture::build(&image, &spec);
    let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let data: &Segment = dyld_cache_fixture::segment_of(&reparsed, "__DATA_CONST");
    assert_eq!(
        cache.slide_expectations.len(),
        3,
        "v{version}: the fixture encodes three chained pointers"
    );

    for (index, expectation) in cache.slide_expectations.iter().enumerate() {
        let expectation: &SlideExpectation = expectation;
        let offset: usize = (data.fileoff + (expectation.vm_address - data.vmaddr)) as usize;
        let width: usize = usize::from(expectation.width);
        let slot: &[u8] = &recovered.bytes[offset..offset + width];
        let actual: u64 = if width == 4 {
            u64::from(u32::from_le_bytes(
                slot.try_into().expect("a four-byte slide slot"),
            ))
        } else {
            u64::from_le_bytes(slot.try_into().expect("an eight-byte slide slot"))
        };
        assert_eq!(
            actual, expectation.unslid,
            "v{version} pointer {index} at {:#x} un-slid to {actual:#x} rather than the {:#x} the published rule gives for the raw word {:#x}",
            expectation.vm_address, expectation.unslid, expectation.raw
        );
        if width == 8 {
            let inside: bool = reparsed.segments.iter().any(|segment: &Segment| {
                expectation.unslid >= segment.vmaddr
                    && expectation.unslid < segment.vmaddr + segment.vmsize
            });
            assert!(
                inside,
                "v{version} pointer {index} un-slid to {:#x}, which lands in no segment of the image",
                expectation.unslid
            );
        }
    }

    let last: &SlideExpectation = cache
        .slide_expectations
        .last()
        .expect("the fixture encoded a chain");
    let tail_at: usize =
        (data.fileoff + (last.vm_address + u64::from(last.width) - data.vmaddr)) as usize;
    let tail_width: usize = usize::from(last.width);
    let tail: &[u8] = &recovered.bytes[tail_at..tail_at + tail_width];
    let expected_tail: &[u8] = &dyld_cache_fixture::SLIDE_TAIL_SENTINEL.to_le_bytes()[..tail_width];
    assert_eq!(
        tail, expected_tail,
        "v{version}: un-applying a {tail_width}-byte chain must not write past its last slot"
    );

    assert_eq!(
        recovered.slide.len(),
        1,
        "v{version}: exactly one slide region covers the fixture data segment"
    );
    assert_eq!(recovered.slide[0].version.number(), version);
    let expected_pointers: usize = if version == 1 { 4 } else { 3 };
    assert_eq!(
        recovered.slide[0].pointers, expected_pointers,
        "v{version}: the fixture marks {expected_pointers} slots in the region"
    );
    recovered
}

fn assert_no_authenticated_pointers(version: u32, recovered: &ReconstructedDylib) {
    assert_eq!(
        recovered.slide[0].authenticated_pointers, 0,
        "v{version} carries no pointer-authentication bits"
    );
    assert!(recovered.authenticated_pointers.is_empty());
    assert_eq!(recovered.authenticated_pointer_total, 0);
    assert!(!recovered.authenticated_records_truncated);
}

fn assert_the_two_authenticated_pointers_are_recorded(
    version: u32,
    recovered: &ReconstructedDylib,
) {
    let authenticated: &[AuthPointerRecord] = &recovered.authenticated_pointers;
    assert_eq!(
        authenticated.len(),
        2,
        "v{version}: both authenticated pointers must be recorded, not dropped"
    );
    assert_eq!(recovered.authenticated_pointer_total, 2);
    assert!(!recovered.authenticated_records_truncated);
    assert_eq!(authenticated[0].auth.key, 2);
    assert_eq!(authenticated[0].auth.key_label(), "DA");
    assert_eq!(authenticated[0].auth.diversity, 0xABCD);
    assert!(authenticated[0].auth.address_diversity);
    assert_eq!(authenticated[1].auth.key, 0);
    assert_eq!(authenticated[1].auth.key_label(), "IA");
    assert!(!authenticated[1].auth.address_diversity);
    assert_eq!(recovered.slide[0].authenticated_pointers, 2);
}

#[test]
fn slide_info_version_1_walks_the_page_bitmap_and_leaves_its_four_byte_words_alone() {
    let recovered: ReconstructedDylib = assert_slide_round_trip(1);
    assert_no_authenticated_pointers(1, &recovered);
    assert_eq!(
        recovered.slide[0].page_size, 4096,
        "version 1 slide info fixes the page at 4096 bytes rather than reading one from the blob"
    );
    assert_eq!(
        recovered.slide[0].pages_walked, 4,
        "a {CACHE_PAGE:#x}-byte region spans four 4096-byte version 1 pages"
    );
    assert_eq!(
        dyld_cache_fixture::V1_LAST_MARKED_SLOT_OFFSET,
        4092,
        "the last bit of a 128-byte bitmap addresses the final four-byte word of a 4096-byte page"
    );

    let image: Vec<u8> = original();
    let parsed: ParsedSlice = parse_original(&image);
    let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME).with_slide(slide_plan(1, &parsed));
    let cache: BuiltCache = dyld_cache_fixture::build(&image, &spec);
    let carrier: &dyld_cache_fixture::PlacedSegment = cache.segment("__DATA_CONST");
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let data: &Segment = dyld_cache_fixture::segment_of(&reparsed, "__DATA_CONST");
    let from: usize = carrier.cache_offset as usize;
    let len: usize = carrier.filesize as usize;
    let at: usize = data.fileoff as usize;
    assert_same_bytes(
        "version 1 leaves every marked word at the value the cache holds",
        &recovered.bytes[at..at + len],
        &cache.primary[from..from + len],
    );
}

#[test]
fn slide_info_version_2_un_application_restores_the_addresses_the_fixture_encoded() {
    let recovered: ReconstructedDylib = assert_slide_round_trip(2);
    assert_no_authenticated_pointers(2, &recovered);
}

#[test]
fn slide_info_version_3_un_application_restores_the_addresses_the_fixture_encoded() {
    let recovered: ReconstructedDylib = assert_slide_round_trip(3);
    assert_the_two_authenticated_pointers_are_recorded(3, &recovered);
}

#[test]
fn slide_info_version_4_un_application_restores_the_four_byte_words_the_fixture_encoded() {
    let recovered: ReconstructedDylib = assert_slide_round_trip(4);
    assert_no_authenticated_pointers(4, &recovered);
}

#[test]
fn slide_info_version_5_un_application_restores_the_addresses_the_fixture_encoded() {
    let recovered: ReconstructedDylib = assert_slide_round_trip(5);
    assert_the_two_authenticated_pointers_are_recorded(5, &recovered);
}

#[test]
fn the_fixture_encodes_the_raw_words_the_published_slide_formats_define() {
    let image: Vec<u8> = original();
    let parsed: ParsedSlice = parse_original(&image);
    let text: &Segment = dyld_cache_fixture::segment_of(&parsed, "__TEXT");
    let data: &Segment = dyld_cache_fixture::segment_of(&parsed, "__DATA");

    let v2: SlidePlan = slide_plan(2, &parsed);
    let step: u64 = 8 << (V2_DELTA_MASK.trailing_zeros() - 2);
    assert_eq!(step, 0x0000_0200_0000_0000);
    assert_eq!(
        dyld_cache_fixture::encode_pointer(&v2, text.vmaddr + 0xF68, None, 8),
        0x0000_0200_0000_0F68,
        "a version 2 word holds target minus value_add with the byte delta scaled by ctz(delta_mask) - 2"
    );
    assert_eq!(
        dyld_cache_fixture::encode_pointer(&v2, data.vmaddr + 0x218, None, 0),
        data.vmaddr + 0x218 - text.vmaddr,
        "the last version 2 word in a chain carries a zero delta"
    );

    let v4: SlidePlan = slide_plan(4, &parsed);
    assert_eq!(
        dyld_cache_fixture::encode_pointer(&v4, 0x3FFF_8001, None, 4),
        0x7FFF_8001,
        "a version 4 word packs its two delta bits above the 30-bit value"
    );
    assert_eq!(
        dyld_cache_fixture::encode_pointer(&v4, 0x0001_0000, None, 0),
        0x0001_0000
    );
}

#[test]
fn an_unsampled_slide_info_version_is_refused_by_number() {
    let image: Vec<u8> = original();
    let parsed: ParsedSlice = parse_original(&image);
    let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME).with_slide(slide_plan(3, &parsed));
    let mut cache: BuiltCache = dyld_cache_fixture::build(&image, &spec);
    let at: usize = cache
        .slide_blob_offset
        .expect("the fixture wrote a slide-info blob") as usize;
    cache.primary[at..at + 4].copy_from_slice(&7u32.to_le_bytes());
    let parsed_cache: DyldSharedCache =
        dyld_cache::parse(&cache.primary).expect("the header still parses");
    let refusal: Error = dyld_cache::reconstruct_image_with(
        &cache.primary,
        &parsed_cache,
        0,
        ReconstructOptions::LOAD_READY,
    )
    .expect_err("version 7 has no sample and must be refused");
    assert!(
        matches!(refusal, Error::UnsupportedDyldSlideInfo(7)),
        "got {refusal}"
    );
}

fn write_family(dir: &Path, cache: &BuiltCache) -> PathBuf {
    let primary: PathBuf = dir.join("dyld_shared_cache_arm64e");
    std::fs::write(&primary, &cache.primary).expect("write the primary cache");
    if let Some(sibling) = cache.sibling.as_ref() {
        std::fs::write(dir.join("dyld_shared_cache_arm64e.1"), sibling)
            .expect("write the sibling cache");
    }
    if let Some(symbols) = cache.symbols.as_ref() {
        std::fs::write(dir.join("dyld_shared_cache_arm64e.symbols"), symbols)
            .expect("write the symbols cache");
    }
    primary
}

const LOCAL_SYMBOL_NAMES: [&str; 2] = ["_local_alpha", "_local_beta"];

#[test]
fn local_symbols_held_in_the_sibling_symbols_file_join_the_synthesized_symbol_table() {
    let (image, cache): (Vec<u8>, BuiltCache) =
        built(&CacheSpec::modern(INSTALL_NAME).with_local_symbols(&LOCAL_SYMBOL_NAMES));
    let dir: ScratchDir = ScratchDir::create("dr-dyld-locals").expect("scratch directory");
    let primary: PathBuf = write_family(dir.path(), &cache);

    let (family, parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens");
    assert!(
        family.symbols.is_some(),
        "the computed .symbols sibling loads"
    );
    assert!(family.partial_reason().is_none());

    let batch: ReconstructBatch =
        dyld_cache::reconstruct_family(&family, &parsed, ReconstructOptions::LOAD_READY)
            .expect("the family reconstructs");
    assert_eq!(batch.dylibs.len(), 1);
    let recovered: &ReconstructedDylib = &batch.dylibs[0];
    let summary = recovered
        .linkedit
        .expect("a load-ready image carries a synthesized linkedit");
    assert_eq!(summary.local_symbols, LOCAL_SYMBOL_NAMES.len() as u32);
    assert_eq!(
        summary.symbols,
        PINNED_NLIST_ENTRIES + LOCAL_SYMBOL_NAMES.len() as u32
    );
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let names: Vec<String> = macho::symbol_names(&recovered.bytes, &reparsed);
    let mut expected: Vec<String> = macho::symbol_names(&image, &parse_original(&image));
    expected.extend(
        LOCAL_SYMBOL_NAMES
            .iter()
            .map(|name: &&str| (*name).to_owned()),
    );
    assert_eq!(
        names, expected,
        "the central local-symbol run must be appended to the image's own symbol table"
    );
}

#[test]
fn local_symbols_held_in_the_primary_cache_itself_join_the_synthesized_symbol_table() {
    let (image, cache): (Vec<u8>, BuiltCache) =
        built(&CacheSpec::modern(INSTALL_NAME).with_local_symbols_in_primary(&LOCAL_SYMBOL_NAMES));
    let parsed: DyldSharedCache =
        dyld_cache::parse(&cache.primary).expect("the older-layout cache parses");
    assert_eq!(parsed.layout, CacheHeaderLayout::SlideMappings);
    let location = parsed
        .local_symbols
        .as_ref()
        .expect("the older layout carries its local symbols in the primary file");
    assert!(!location.in_symbols_file);

    let recovered: ReconstructedDylib = dyld_cache::reconstruct_image_with(
        &cache.primary,
        &parsed,
        0,
        ReconstructOptions::LOAD_READY,
    )
    .expect("the image reconstructs");
    let summary = recovered
        .linkedit
        .expect("a load-ready image carries a synthesized linkedit");
    assert_eq!(summary.local_symbols, LOCAL_SYMBOL_NAMES.len() as u32);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let mut expected: Vec<String> = macho::symbol_names(&image, &parse_original(&image));
    expected.extend(
        LOCAL_SYMBOL_NAMES
            .iter()
            .map(|name: &&str| (*name).to_owned()),
    );
    assert_eq!(
        macho::symbol_names(&recovered.bytes, &reparsed),
        expected,
        "a 32-bit local-symbols entry keyed by file offset must resolve to the same image"
    );
}

#[test]
fn a_missing_symbols_file_degrades_to_a_named_partial_result() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(
        &CacheSpec::modern(INSTALL_NAME)
            .with_local_symbols(&LOCAL_SYMBOL_NAMES)
            .without_symbols_file(),
    );
    let dir: ScratchDir = ScratchDir::create("dr-dyld-nolocals").expect("scratch directory");
    let primary: PathBuf = write_family(dir.path(), &cache);

    let (family, parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens without a symbols file");
    assert!(family.symbols.is_none());
    let reason: String = family
        .partial_reason()
        .expect("an absent symbols file must be named");
    assert!(
        reason.contains("dyld_shared_cache_arm64e.symbols"),
        "got: {reason}"
    );

    let batch: ReconstructBatch =
        dyld_cache::reconstruct_family(&family, &parsed, ReconstructOptions::LOAD_READY)
            .expect("the image still reconstructs without its local symbols");
    let recovered: &ReconstructedDylib = &batch.dylibs[0];
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    assert_eq!(
        macho::symbol_names(&recovered.bytes, &reparsed),
        macho::symbol_names(&image, &parse_original(&image)),
        "without the symbols file the image keeps exactly its own symbol table"
    );
}

#[test]
fn a_split_cache_resolves_the_image_whose_linkedit_lives_in_the_sibling_file() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME).split());
    let dir: ScratchDir = ScratchDir::create("dr-dyld-split").expect("scratch directory");
    let primary: PathBuf = write_family(dir.path(), &cache);

    let (family, parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens");
    assert!(family.is_complete());
    assert_eq!(family.sub_caches.len(), 1);
    assert!(family.partial_reason().is_none());

    let batch: ReconstructBatch =
        dyld_cache::reconstruct_family(&family, &parsed, ReconstructOptions::LOAD_READY)
            .expect("the family reconstructs");
    assert!(batch.unresolved.is_empty(), "got {:?}", batch.unresolved);
    assert_eq!(batch.dylibs.len(), 1);
    let recovered: &ReconstructedDylib = &batch.dylibs[0];
    assert!(
        recovered.source_files.len() >= 2,
        "the recovered image must draw bytes from the primary and the sibling, got {:?}",
        recovered.source_files
    );
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    assert_eq!(
        macho::symbol_names(&recovered.bytes, &reparsed),
        macho::symbol_names(&image, &parse_original(&image)),
        "a symbol table read out of the sibling file must match the original"
    );
}

fn uuid_of_repeated_byte(byte: u8) -> String {
    let pair: String = format!("{byte:02X}");
    let group = |count: usize| -> String { pair.repeat(count) };
    format!(
        "{}-{}-{}-{}-{}",
        group(4),
        group(2),
        group(2),
        group(2),
        group(6)
    )
}

fn assert_narrow_sub_cache_entries_are_read_at_their_own_stride() {
    let widths: [(HeaderShape, usize); 2] = [
        (HeaderShape::SubCachesNoSuffix, 24),
        (HeaderShape::SubCaches, 56),
    ];
    for (shape, entry_size) in widths {
        let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME)
            .split()
            .with_shape(shape)
            .with_extra_sub_cache_entries(2);
        let (_image, cache): (Vec<u8>, BuiltCache) = built(&spec);
        let parsed: DyldSharedCache =
            dyld_cache::parse(&cache.primary).expect("a multi-entry sub-cache array parses");
        assert_eq!(parsed.sub_caches.len(), 3, "shape {shape:?}");
        for (index, entry) in parsed.sub_caches.iter().enumerate() {
            assert_eq!(
                entry.vm_offset,
                index as u64 * dyld_cache_fixture::EXTRA_SUB_CACHE_VM_STEP,
                "shape {shape:?} entry {index} must be read {entry_size} bytes after the one before it"
            );
            let byte: u8 = 0xCD_u8.wrapping_add(index as u8);
            assert_eq!(
                entry.uuid,
                uuid_of_repeated_byte(byte),
                "shape {shape:?} entry {index} uuid"
            );
        }
    }
}

#[test]
fn a_sub_cache_array_without_a_file_suffix_field_still_finds_its_sibling_by_computed_name() {
    let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME)
        .split()
        .with_shape(HeaderShape::SubCachesNoSuffix);
    let (image, cache): (Vec<u8>, BuiltCache) = built(&spec);
    let parsed_primary: DyldSharedCache =
        dyld_cache::parse(&cache.primary).expect("the narrow sub-cache header parses");
    assert_eq!(parsed_primary.layout, CacheHeaderLayout::SubCaches);
    assert_eq!(
        parsed_primary
            .sub_cache_entry_kind
            .map(SubCacheEntryKind::label),
        Some("uuid+offset"),
        "a header that stops before the cache sub-type carries the narrow sub-cache entry"
    );
    assert_eq!(parsed_primary.sub_caches.len(), 1);
    assert!(
        parsed_primary.sub_caches[0].declared_suffix.is_none(),
        "the narrow entry has no suffix field to declare"
    );
    assert_narrow_sub_cache_entries_are_read_at_their_own_stride();

    let dir: ScratchDir = ScratchDir::create("dr-dyld-narrow").expect("scratch directory");
    let primary: PathBuf = write_family(dir.path(), &cache);
    let (family, parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens");
    assert!(family.is_complete());
    assert_eq!(family.sub_caches.len(), 1);

    let batch: ReconstructBatch =
        dyld_cache::reconstruct_family(&family, &parsed, ReconstructOptions::LOAD_READY)
            .expect("the family reconstructs");
    assert!(batch.unresolved.is_empty(), "got {:?}", batch.unresolved);
    let recovered: &ReconstructedDylib = &batch.dylibs[0];
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    assert_eq!(
        macho::symbol_names(&recovered.bytes, &reparsed),
        macho::symbol_names(&image, &parse_original(&image))
    );
}

#[test]
fn the_architecture_and_format_flags_the_header_declares_reach_the_report() {
    for arch in ["arm64", "arm64e", "x86_64"] {
        let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME).with_arch(arch);
        let (image, cache): (Vec<u8>, BuiltCache) = built(&spec);
        let parsed: DyldSharedCache =
            dyld_cache::parse(&cache.primary).expect("each architecture parses");
        assert_eq!(parsed.arch, arch);
        assert_eq!(parsed.magic, format!("dyld_v1  {arch}"));
        let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
        let reparsed: ParsedSlice =
            macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
        assert_eq!(
            macho::symbol_names(&recovered.bytes, &reparsed),
            macho::symbol_names(&image, &parse_original(&image)),
            "arch {arch} must recover the same symbol table"
        );
    }

    let device: DyldSharedCache =
        dyld_cache::parse(&built(&CacheSpec::modern(INSTALL_NAME)).1.primary)
            .expect("the device cache parses");
    assert!(!device.simulator);
    assert!(!device.built_from_chained_fixups);
    assert_eq!(device.format_version, 0);

    let flags: u32 = 0x0A07;
    let simulator: DyldSharedCache = dyld_cache::parse(
        &built(&CacheSpec::modern(INSTALL_NAME).with_format_flags(flags))
            .1
            .primary,
    )
    .expect("the simulator cache parses");
    assert!(
        simulator.simulator,
        "bit 9 of the format word marks a simulator cache"
    );
    assert!(
        simulator.built_from_chained_fixups,
        "bit 11 of the format word marks a cache built from chained fixups"
    );
    assert_eq!(
        simulator.format_version, 7,
        "the low byte of the format word is the closure format version"
    );
}

#[test]
fn an_image_whose_header_address_lies_outside_every_mapping_is_refused_by_name() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let mut mutated: Vec<u8> = cache.primary;
    let parsed: DyldSharedCache = dyld_cache::parse(&mutated).expect("the cache parses");
    let at: usize = parsed.images_offset as usize;
    mutated[at..at + 8].copy_from_slice(&0xDEAD_0000_u64.to_le_bytes());
    let reparsed: DyldSharedCache =
        dyld_cache::parse(&mutated).expect("the header still parses with a stray image address");
    let refusal: Error =
        dyld_cache::reconstruct_image_with(&mutated, &reparsed, 0, ReconstructOptions::LOAD_READY)
            .expect_err("an image outside every mapping cannot be rebuilt");
    let Error::DyldImageUnsupported { image, reason } = refusal else {
        panic!("expected a named image refusal, got {refusal}");
    };
    assert_eq!(image, INSTALL_NAME);
    assert!(
        reason.contains("0xdead0000") && reason.contains("mapping"),
        "the refusal must name the address it could not map, got: {reason}"
    );
}

#[test]
fn two_mappings_that_claim_the_same_address_range_are_reported_as_overlapping() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let clean: DyldSharedCache = dyld_cache::parse(&cache.primary).expect("the cache parses");
    assert!(
        clean.overlapping_mappings.is_empty(),
        "the built cache maps each address once"
    );
    assert!(clean.truncated_mappings.is_empty());
    assert!(clean.mappings.len() >= 2);

    let mut mutated: Vec<u8> = cache.primary;
    let first: usize = clean.mapping_offset as usize;
    let second: usize = first + 32;
    let address: [u8; 8] = clean.mappings[0].address.to_le_bytes();
    mutated[second..second + 8].copy_from_slice(&address);
    let overlapped: DyldSharedCache =
        dyld_cache::parse(&mutated).expect("an overlapping cache still parses");
    assert_eq!(
        overlapped.overlapping_mappings,
        vec![(0u32, 1u32)],
        "the report must name the pair of mappings that claim one address range"
    );
}

#[test]
fn a_header_too_small_for_the_mapping_table_is_refused_by_the_size_it_declares() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let mut mutated: Vec<u8> = cache.primary;
    mutated[0x10..0x14].copy_from_slice(&0x10u32.to_le_bytes());
    let refusal: Error = dyld_cache::parse(&mutated)
        .expect_err("a header that ends before its own image fields cannot be read");
    let Error::UnsupportedDyldLayout { layout, reason } = refusal else {
        panic!("expected a named layout refusal");
    };
    assert_eq!(layout, "header-size-0x10");
    assert!(reason.contains("0x10"), "got: {reason}");
}

#[test]
fn a_mapping_whose_file_range_runs_past_the_end_of_the_file_is_reported_as_truncated() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let clean: DyldSharedCache = dyld_cache::parse(&cache.primary).expect("the cache parses");
    assert!(clean.truncated_mappings.is_empty());
    let size_at: usize = clean.mapping_offset as usize + 8;
    let length: u64 = cache.primary.len() as u64;
    assert!(clean.mappings[0].file_offset > 0);

    let mut oversized: Vec<u8> = cache.primary.clone();
    oversized[size_at..size_at + 8].copy_from_slice(&length.to_le_bytes());
    let parsed: DyldSharedCache =
        dyld_cache::parse(&oversized).expect("a truncated mapping is reported, not fatal");
    assert_eq!(
        parsed.truncated_mappings,
        vec![0u32],
        "a mapping whose file offset plus size passes the end of the file must be named"
    );

    let mut overflowing: Vec<u8> = cache.primary;
    overflowing[size_at..size_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let wrapped: DyldSharedCache =
        dyld_cache::parse(&overflowing).expect("a mapping size that overflows is reported too");
    assert_eq!(wrapped.truncated_mappings, vec![0u32]);
}

#[test]
fn a_cache_that_declares_no_images_recovers_nothing_rather_than_failing() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let mut mutated: Vec<u8> = cache.primary;
    mutated[0x1C4..0x1C8].copy_from_slice(&0u32.to_le_bytes());
    let parsed: DyldSharedCache =
        dyld_cache::parse(&mutated).expect("a cache with no images still parses");
    assert!(parsed.images.is_empty());
    let dylibs: Vec<ReconstructedDylib> =
        dyld_cache::reconstruct_all_with(&mutated, &parsed, ReconstructOptions::LOAD_READY)
            .expect("an empty image list is not an error");
    assert!(dylibs.is_empty());

    for shape in [
        HeaderShape::Legacy,
        HeaderShape::LocalSymbols,
        HeaderShape::SlideMappings,
        HeaderShape::SubCachesNoSuffix,
    ] {
        let (_image, cache): (Vec<u8>, BuiltCache) =
            built(&CacheSpec::modern(INSTALL_NAME).with_shape(shape));
        let mut mutated: Vec<u8> = cache.primary.clone();
        mutated[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        let parsed: DyldSharedCache = dyld_cache::parse(&mutated).unwrap_or_else(|error: Error| {
            panic!(
                "a {shape:?} cache that bundles no images is a data sub-cache, not an unsupported layout: {error}"
            )
        });
        assert!(parsed.images.is_empty());
        assert!(
            !parsed.mappings.is_empty(),
            "a data sub-cache still carries the mappings its siblings resolve through"
        );
    }

    let (_image, cache): (Vec<u8>, BuiltCache) =
        built(&CacheSpec::modern(INSTALL_NAME).with_shape(HeaderShape::SlideMappings));
    let mut declared: Vec<u8> = cache.primary;
    declared[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());
    let refusal: Error = dyld_cache::parse(&declared)
        .expect_err("an image count with no image table names the layout it cannot read");
    let Error::UnsupportedDyldLayout { layout, reason } = refusal else {
        panic!("expected a named layout refusal");
    };
    assert_eq!(layout, "slide-mappings");
    assert!(reason.contains("declares 1 images"), "got: {reason}");
}

#[test]
fn a_missing_sibling_degrades_to_a_named_partial_result() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(
        &CacheSpec::modern(INSTALL_NAME)
            .split()
            .without_sibling_file(),
    );
    let dir: ScratchDir = ScratchDir::create("dr-dyld-missing").expect("scratch directory");
    let primary: PathBuf = write_family(dir.path(), &cache);

    let (family, parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("an incomplete family still opens");
    assert!(!family.is_complete());
    let reason: String = family
        .partial_reason()
        .expect("an incomplete family names what is missing");
    assert!(
        reason.contains("dyld_shared_cache_arm64e.1"),
        "the partial result must name the computed sibling it looked for, got: {reason}"
    );

    let batch: ReconstructBatch =
        dyld_cache::reconstruct_family(&family, &parsed, ReconstructOptions::LOAD_READY)
            .expect("an incomplete family reconstructs what it can");
    assert!(batch.dylibs.is_empty());
    assert_eq!(batch.unresolved.len(), 1);
    let unresolved: &UnresolvedImage = &batch.unresolved[0];
    assert_eq!(unresolved.install_name, INSTALL_NAME);
    assert!(
        unresolved.reason.contains("__LINKEDIT"),
        "the refusal must name the segment it could not reach, got: {}",
        unresolved.reason
    );
    assert!(batch.partial_reason.is_some());
}

#[test]
fn a_declared_sub_cache_suffix_that_escapes_the_cache_directory_is_rejected() {
    for hostile in ["../evil", "..\\evil", "/etc/passwd", "sub/dir"] {
        let (_image, cache): (Vec<u8>, BuiltCache) =
            built(&CacheSpec::modern(INSTALL_NAME).with_declared_suffix(hostile));
        let refusal: Error = dyld_cache::parse(&cache.primary)
            .expect_err("a traversal suffix must be refused before any file is opened");
        match refusal {
            Error::DyldSubCachePathRejected { suffix, .. } => assert_eq!(suffix, hostile),
            other => panic!("{hostile} produced {other}"),
        }
    }
}

#[test]
fn the_sibling_a_split_cache_loads_is_named_by_computation_not_by_cache_content() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME).split());
    let dir: ScratchDir = ScratchDir::create("dr-dyld-computed").expect("scratch directory");
    let primary: PathBuf = dir.path().join("renamed_cache");
    std::fs::write(&primary, &cache.primary).expect("write the primary cache");
    let sibling: &Vec<u8> = cache
        .sibling
        .as_ref()
        .expect("the split cache has a sibling");
    std::fs::write(dir.path().join("dyld_shared_cache_arm64e.1"), sibling)
        .expect("write a sibling named after the ORIGINAL primary");

    let (family, _parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens");
    assert!(
        family.sub_caches.is_empty(),
        "a sibling named after a different primary must not be adopted"
    );
    assert_eq!(family.missing.len(), 1);
    assert_eq!(
        family.missing[0].candidate_names,
        vec!["renamed_cache.1".to_owned(), "renamed_cache.01".to_owned()],
        "the loader must look only for names computed from the primary it was given"
    );

    std::fs::write(dir.path().join("renamed_cache.01"), sibling)
        .expect("write the zero-padded computed sibling");
    let (family, _parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens");
    assert_eq!(family.sub_caches.len(), 1);
    assert!(family.is_complete());
}

#[test]
fn mutating_any_header_field_never_panics_and_never_reports_an_empty_success() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let mut mutated: Vec<u8> = cache.primary.clone();
    for at in (0x10..0x200).step_by(4) {
        for pattern in [0xFFu8, 0x00, 0x7F] {
            mutated[at..at + 4].copy_from_slice(&[pattern; 4]);
            if let Ok(parsed) = dyld_cache::parse(&mutated) {
                let outcome: Result<Vec<ReconstructedDylib>, Error> =
                    dyld_cache::reconstruct_all_with(
                        &mutated,
                        &parsed,
                        ReconstructOptions::LOAD_READY,
                    );
                if let Ok(dylibs) = outcome {
                    for dylib in &dylibs {
                        assert!(
                            !dylib.bytes.is_empty(),
                            "a reported reconstruction at byte {at} carried no bytes"
                        );
                    }
                }
            }
            mutated[at..at + 4].copy_from_slice(&cache.primary[at..at + 4]);
        }
    }
}

#[test]
fn a_truncated_cache_is_refused_rather_than_reconstructed_from_nothing() {
    let (_image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    for keep in [0usize, 1, 0x10, 0x100, 0x4000, 0x8000] {
        let short: &[u8] = &cache.primary[..keep.min(cache.primary.len())];
        if let Ok(parsed) = dyld_cache::parse(short) {
            let outcome: Result<Vec<ReconstructedDylib>, Error> =
                dyld_cache::reconstruct_all_with(short, &parsed, ReconstructOptions::LOAD_READY);
            if let Ok(dylibs) = outcome {
                for dylib in &dylibs {
                    assert!(!dylib.bytes.is_empty());
                }
            }
        }
    }
}

#[test]
fn compact_and_load_ready_layouts_agree_on_the_segment_content_they_recover() {
    let (image, cache): (Vec<u8>, BuiltCache) = built(&CacheSpec::modern(INSTALL_NAME));
    let compact: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::COMPACT);
    let load_ready: ReconstructedDylib = recover(
        &cache.primary,
        ReconstructOptions {
            layout: SegmentLayout::PageAligned,
            page_size: CACHE_PAGE,
            synthesize_linkedit: true,
            unapply_slide: false,
        },
    );
    let original_parsed: ParsedSlice = parse_original(&image);
    let compact_parsed: ParsedSlice =
        macho::parse_slice(&compact.bytes).expect("compact output parses");
    let ready_parsed: ParsedSlice =
        macho::parse_slice(&load_ready.bytes).expect("load-ready output parses");
    for segment in &original_parsed.segments {
        if segment.filesize == 0 || segment.name == "__LINKEDIT" {
            continue;
        }
        let compact_segment: &Segment =
            dyld_cache_fixture::segment_of(&compact_parsed, &segment.name);
        let ready_segment: &Segment = dyld_cache_fixture::segment_of(&ready_parsed, &segment.name);
        let compact_at: usize = compact_segment.fileoff as usize;
        let ready_at: usize = ready_segment.fileoff as usize;
        let len: usize = segment.filesize as usize;
        assert_eq!(
            &compact.bytes[compact_at + 0x1000..compact_at + len],
            &load_ready.bytes[ready_at + 0x1000..ready_at + len],
            "segment '{}' content past the load commands must not depend on the layout",
            segment.name
        );
    }
}
