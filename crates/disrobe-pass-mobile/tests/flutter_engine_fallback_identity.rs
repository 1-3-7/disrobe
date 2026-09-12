#![cfg(feature = "native-image")]
#![allow(clippy::expect_used, clippy::panic)]

use object::Object as _;
use object::ObjectSection as _;

use disrobe_pass_mobile::{
    FlutterEngineSymbolCache, FlutterEngineSymbolMap, FlutterEngineSymbolMapIdentityKind,
    flutter_engine_identity_for_elf, parse_flutter_engine_symbol_map,
    validate_cached_flutter_engine_symbols_for_elf, validate_flutter_engine_symbol_map_for_elf,
};

fn fixture_bytes() -> Vec<u8> {
    let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("disrobe_sample")
        .join("libapp_arm64.so");
    std::fs::read(fixture).expect("read Flutter fixture")
}

fn without_build_id(mut bytes: Vec<u8>) -> Vec<u8> {
    let program_headers: usize = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("ELF program header offset"),
    ))
    .expect("program header offset fits usize");
    let entry_size: usize = usize::from(u16::from_le_bytes(
        bytes[54..56].try_into().expect("ELF program header size"),
    ));
    let count: usize = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().expect("ELF program header count"),
    ));
    for index in 0..count {
        let offset: usize = program_headers + index * entry_size;
        if u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("segment type")) == 4 {
            bytes[offset..offset + 4].copy_from_slice(&0_u32.to_le_bytes());
            return bytes;
        }
    }
    panic!("fixture contains a GNU build-ID note segment");
}

fn text_offset(bytes: &[u8]) -> usize {
    let file: object::read::File<'_> = object::read::File::parse(bytes).expect("parse ELF");
    let offsets: Vec<u64> = file
        .sections()
        .filter_map(|section| {
            (section.name().ok() == Some(".text") && section.kind() == object::SectionKind::Text)
                .then(|| section.file_range())
                .flatten()
                .and_then(|(offset, size)| (size != 0).then_some(offset))
        })
        .collect();
    let [offset] = offsets.as_slice() else {
        panic!("fixture has exactly one non-empty executable .text section");
    };
    usize::try_from(*offset).expect("text offset fits usize")
}

fn map_for(
    bytes: &[u8],
    identity: &disrobe_pass_mobile::FlutterEngineIdentity,
) -> FlutterEngineSymbolMap {
    let native: disrobe_binfmt::NativeFile =
        disrobe_binfmt::parse_native(bytes).expect("parse ELF");
    let address: u64 = native
        .segments
        .iter()
        .find(|segment| segment.size != 0)
        .expect("mapped segment")
        .address;
    let map: serde_json::Value = serde_json::json!({
        "format": "disrobe.flutter.engine-symbol-map",
        "version": 1,
        "identity": identity,
        "symbols": [{ "address": address, "name": "FallbackEngineName" }]
    });
    parse_flutter_engine_symbol_map(&serde_json::to_vec(&map).expect("serialize map"))
        .expect("parse fallback map")
}

#[test]
fn identifies_a_build_id_less_elf_by_its_executable_text() {
    let bytes: Vec<u8> = without_build_id(fixture_bytes());
    let identity = flutter_engine_identity_for_elf(&bytes).expect("fallback identity");

    assert_eq!(
        identity.kind,
        FlutterEngineSymbolMapIdentityKind::ElfExecutableTextBlake3
    );
    assert_eq!(identity.value.len(), 64);
}

#[test]
fn validates_exact_fallback_maps_and_cache_entries_but_refuses_a_text_mutation() {
    let bytes: Vec<u8> = without_build_id(fixture_bytes());
    let identity = flutter_engine_identity_for_elf(&bytes).expect("fallback identity");
    let map: FlutterEngineSymbolMap = map_for(&bytes, &identity);
    let validated = validate_flutter_engine_symbol_map_for_elf(&bytes, map)
        .expect("exact fallback map validates");
    let cache_directory: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("flutter-engine-fallback-cache")
            .expect("create cache directory");
    let cache: FlutterEngineSymbolCache = FlutterEngineSymbolCache::new(cache_directory.path());
    cache
        .store_validated(&validated)
        .expect("store fallback cache");
    let cached = cache
        .load(&identity)
        .expect("load fallback cache")
        .expect("exact fallback cache entry");
    validate_cached_flutter_engine_symbols_for_elf(&bytes, identity.clone(), cached.clone())
        .expect("exact fallback cache validates");

    let mut mutated: Vec<u8> = bytes;
    let offset: usize = text_offset(&mutated);
    mutated[offset] ^= 1;
    let mutated_identity =
        flutter_engine_identity_for_elf(&mutated).expect("mutated fallback identity");
    assert_ne!(mutated_identity, identity);
    assert!(validate_cached_flutter_engine_symbols_for_elf(&mutated, identity, cached).is_err());
}

#[test]
fn refuses_a_malformed_build_id_note_instead_of_using_the_fallback() {
    let mut bytes: Vec<u8> = fixture_bytes();
    let program_headers: usize = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("ELF program header offset"),
    ))
    .expect("program header offset fits usize");
    let entry_size: usize = usize::from(u16::from_le_bytes(
        bytes[54..56].try_into().expect("ELF program header size"),
    ));
    let count: usize = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().expect("ELF program header count"),
    ));
    for index in 0..count {
        let header: usize = program_headers + index * entry_size;
        if u32::from_le_bytes(bytes[header..header + 4].try_into().expect("segment type")) == 4 {
            let note_offset: usize = usize::try_from(u64::from_le_bytes(
                bytes[header + 8..header + 16]
                    .try_into()
                    .expect("note offset"),
            ))
            .expect("note offset fits usize");
            bytes[note_offset + 4..note_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(flutter_engine_identity_for_elf(&bytes).is_err());
            return;
        }
    }
    panic!("fixture contains a GNU build-ID note segment");
}
