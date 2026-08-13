#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "support/dyld_cache_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dyld_cache_fixture;

use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_swift_objc::dyld_cache::subcache::CacheFamily;
use disrobe_pass_swift_objc::dyld_cache::{
    self, AuthPointerRecord, CacheHeaderLayout, DyldSharedCache, ReconstructBatch,
    ReconstructOptions, ReconstructedDylib, SegmentLayout, UnresolvedImage,
};
use disrobe_pass_swift_objc::error::Error;
use disrobe_pass_swift_objc::macho::{self, ExportedSymbol, ParsedSlice, Segment};

use dyld_cache_fixture::{AuthSpec, BuiltCache, CACHE_PAGE, CacheSpec, HeaderShape, SlidePlan};
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
    let cases: [(HeaderShape, CacheHeaderLayout); 3] = [
        (HeaderShape::Legacy, CacheHeaderLayout::Legacy),
        (HeaderShape::SlideMappings, CacheHeaderLayout::SlideMappings),
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

fn slide_plan(version: u32, parsed: &ParsedSlice) -> SlidePlan {
    let text: &Segment = dyld_cache_fixture::segment_of(parsed, "__TEXT");
    let data: &Segment = dyld_cache_fixture::segment_of(parsed, "__DATA");
    SlidePlan {
        version,
        value_add: text.vmaddr,
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
    }
}

fn assert_slide_round_trip(version: u32) {
    let image: Vec<u8> = original();
    let parsed: ParsedSlice = parse_original(&image);
    let plan: SlidePlan = slide_plan(version, &parsed);
    let spec: CacheSpec = CacheSpec::modern(INSTALL_NAME).with_slide(plan);
    let cache: BuiltCache = dyld_cache_fixture::build(&image, &spec);
    let recovered: ReconstructedDylib = recover(&cache.primary, ReconstructOptions::LOAD_READY);
    let reparsed: ParsedSlice =
        macho::parse_slice(&recovered.bytes).expect("the recovered image parses");
    let data: &Segment = dyld_cache_fixture::segment_of(&reparsed, "__DATA_CONST");

    for (index, (vm_address, expected)) in cache.slide_expectations.iter().enumerate() {
        let offset: usize = (data.fileoff + (vm_address - data.vmaddr)) as usize;
        let mut raw: [u8; 8] = [0u8; 8];
        raw.copy_from_slice(&recovered.bytes[offset..offset + 8]);
        let actual: u64 = u64::from_le_bytes(raw);
        assert_eq!(
            actual, *expected,
            "v{version} pointer {index} at {vm_address:#x} un-slid to {actual:#x} rather than the address the fixture encoded"
        );
        let inside: bool = reparsed.segments.iter().any(|segment: &Segment| {
            *expected >= segment.vmaddr && *expected < segment.vmaddr + segment.vmsize
        });
        assert!(
            inside,
            "v{version} pointer {index} un-slid to {expected:#x}, which lands in no segment of the image"
        );
    }

    let authenticated: Vec<&AuthPointerRecord> = recovered.authenticated_pointers.iter().collect();
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
    assert_eq!(
        recovered.slide.len(),
        1,
        "v{version}: exactly one slide region covers the fixture data segment"
    );
    assert_eq!(recovered.slide[0].version.number(), version);
    assert_eq!(recovered.slide[0].pointers, 3);
    assert_eq!(recovered.slide[0].authenticated_pointers, 2);
}

#[test]
fn slide_info_version_3_un_application_restores_the_addresses_the_fixture_encoded() {
    assert_slide_round_trip(3);
}

#[test]
fn slide_info_version_5_un_application_restores_the_addresses_the_fixture_encoded() {
    assert_slide_round_trip(5);
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
