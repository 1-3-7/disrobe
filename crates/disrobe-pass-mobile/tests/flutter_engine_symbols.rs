#![allow(clippy::expect_used, clippy::format_push_string)]

#[cfg(feature = "native-image")]
use disrobe_pass_mobile::validate_flutter_engine_symbol_map_for_elf;
use disrobe_pass_mobile::{
    Error, FlutterEngineSymbolMap, FlutterEngineSymbolMapIdentityKind,
    parse_flutter_engine_symbol_map, parse_flutter_engine_symbol_map_reader,
};

const VALID_MAP: &[u8] = br#"{
  "format": "disrobe.flutter.engine-symbol-map",
  "version": 1,
  "identity": { "kind": "elf-build-id", "value": "0123456789abcdef0123456789abcdef" },
  "symbols": [
    { "address": 8192, "name": "FlutterEngineStart" },
    { "address": 4096, "name": "Dart_Invoke" }
  ]
}"#;

#[test]
fn parses_a_versioned_engine_map_in_deterministic_address_order() {
    let map: FlutterEngineSymbolMap =
        parse_flutter_engine_symbol_map(VALID_MAP).expect("map parses");

    assert_eq!(
        map.identity().kind,
        FlutterEngineSymbolMapIdentityKind::ElfBuildId
    );
    assert_eq!(map.identity().value, "0123456789abcdef0123456789abcdef");
    assert_eq!(map.symbols().len(), 2);
    assert_eq!(map.symbols()[0].address, 4096);
    assert_eq!(map.symbols()[0].name, "Dart_Invoke");
    assert_eq!(map.symbols()[1].address, 8192);
}

#[test]
fn rejects_an_unknown_engine_map_version() {
    let bytes: &[u8] = br#"{
      "format": "disrobe.flutter.engine-symbol-map",
      "version": 2,
      "identity": { "kind": "elf-build-id", "value": "0123456789abcdef0123456789abcdef" },
      "symbols": []
    }"#;

    let error: Error = parse_flutter_engine_symbol_map(bytes).expect_err("version must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapUnsupportedVersion { version: 2 }
    ));
}

#[test]
fn rejects_an_identity_that_does_not_match_its_declared_kind() {
    let bytes: &[u8] = br#"{
      "format": "disrobe.flutter.engine-symbol-map",
      "version": 1,
      "identity": { "kind": "elf-build-id", "value": "not-a-build-id" },
      "symbols": []
    }"#;

    let error: Error = parse_flutter_engine_symbol_map(bytes).expect_err("identity must fail");

    assert!(matches!(error, Error::FlutterEngineSymbolMapMalformed(_)));
}

#[test]
fn accepts_sha1_length_elf_build_ids() {
    let bytes: &[u8] = br#"{
      "format": "disrobe.flutter.engine-symbol-map",
      "version": 1,
      "identity": { "kind": "elf-build-id", "value": "0123456789abcdef0123456789abcdef01234567" },
      "symbols": []
    }"#;

    let map: FlutterEngineSymbolMap =
        parse_flutter_engine_symbol_map(bytes).expect("SHA-1 build ID parses");

    assert_eq!(map.identity().value.len(), 40);
}

#[test]
fn rejects_truncated_engine_map_json() {
    let error: Error =
        parse_flutter_engine_symbol_map(b"{\"format\":").expect_err("truncated JSON must fail");

    assert!(matches!(error, Error::FlutterEngineSymbolMapMalformed(_)));
}

#[test]
fn rejects_duplicate_engine_symbol_addresses() {
    let bytes: &[u8] = br#"{
      "format": "disrobe.flutter.engine-symbol-map",
      "version": 1,
      "identity": { "kind": "elf-build-id", "value": "0123456789abcdef0123456789abcdef" },
      "symbols": [
        { "address": 4096, "name": "first" },
        { "address": 4096, "name": "second" }
      ]
    }"#;

    let error: Error = parse_flutter_engine_symbol_map(bytes).expect_err("duplicate must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapDuplicateAddress { address: 4096 }
    ));
}

#[test]
fn rejects_map_bytes_over_the_hard_cap_before_deserializing() {
    let bytes: Vec<u8> = vec![b' '; disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES + 1];

    let error: Error =
        parse_flutter_engine_symbol_map(&bytes).expect_err("oversized map must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapTooLarge { actual, limit }
            if actual == disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES + 1
                && limit == disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES
    ));
}

#[test]
fn streaming_reader_stops_one_byte_past_the_hard_cap() {
    let bytes: Vec<u8> = vec![b' '; disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES + 64];
    let error: Error = parse_flutter_engine_symbol_map_reader(std::io::Cursor::new(bytes))
        .expect_err("oversized reader must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapTooLarge { actual, limit }
            if actual == disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES + 1
                && limit == disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_BYTES
    ));
}

#[test]
#[cfg(feature = "native-image")]
fn validated_map_rejects_an_address_between_elf_segments() {
    let fixture: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join("disrobe_sample")
        .join("libapp_arm64.so");
    let input: Vec<u8> = std::fs::read(&fixture).expect("read Flutter fixture");
    let native: disrobe_binfmt::NativeFile =
        disrobe_binfmt::parse_native(&input).expect("parse Flutter fixture");
    let mut segments: Vec<(u64, u64)> = native
        .segments
        .iter()
        .filter_map(|segment| {
            segment
                .address
                .checked_add(segment.size)
                .map(|end| (segment.address, end))
        })
        .collect();
    segments.sort_unstable();
    let gap: u64 = segments
        .windows(2)
        .find_map(|pair| (pair[0].1 < pair[1].0).then_some(pair[0].1))
        .expect("fixture carries a segment gap");
    let map_json: String = format!(
        "{{\"format\":\"disrobe.flutter.engine-symbol-map\",\"version\":1,\"identity\":{{\"kind\":\"elf-build-id\",\"value\":\"b71885094a73117bf90d3cfa05824129\"}},\"symbols\":[{{\"address\":{gap},\"name\":\"gap\"}}]}}"
    );
    let map: FlutterEngineSymbolMap =
        parse_flutter_engine_symbol_map(map_json.as_bytes()).expect("parse gap map");

    let error: Error =
        validate_flutter_engine_symbol_map_for_elf(&input, map).expect_err("segment gap must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapAddressOutsideSegments { address } if address == gap
    ));
}

#[test]
fn rejects_map_entries_over_the_hard_cap() {
    let mut symbols: String = String::new();
    for address in 0..=disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES {
        if !symbols.is_empty() {
            symbols.push(',');
        }
        symbols.push_str(&format!(
            "{{\"address\":{address},\"name\":\"f{address}\"}}"
        ));
    }
    let bytes: Vec<u8> = format!(
        "{{\"format\":\"disrobe.flutter.engine-symbol-map\",\"version\":1,\"identity\":{{\"kind\":\"elf-build-id\",\"value\":\"0123456789abcdef0123456789abcdef\"}},\"symbols\":[{symbols}]}}"
    )
    .into_bytes();

    let error: Error = parse_flutter_engine_symbol_map(&bytes).expect_err("entry cap must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapTooManyEntries { count, limit }
            if count == disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES + 1
                && limit == disrobe_pass_mobile::FLUTTER_ENGINE_SYMBOL_MAP_MAX_ENTRIES
    ));
}

#[test]
fn validates_every_address_against_a_half_open_image_range() {
    let map: FlutterEngineSymbolMap =
        parse_flutter_engine_symbol_map(VALID_MAP).expect("map parses");

    map.validate_image_range(4096, 4097)
        .expect("both addresses fit");

    let error: Error = map
        .validate_image_range(4096, 4096)
        .expect_err("upper bound is exclusive");
    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapAddressOutsideImage {
            address: 8192,
            start: 4096,
            end: 8192
        }
    ));
}

#[test]
fn rejects_an_overflowing_image_range() {
    let map: FlutterEngineSymbolMap =
        parse_flutter_engine_symbol_map(VALID_MAP).expect("map parses");

    let error: Error = map
        .validate_image_range(u64::MAX, 1)
        .expect_err("overflowing image range must fail");

    assert!(matches!(
        error,
        Error::FlutterEngineSymbolMapImageRangeOverflow {
            start: u64::MAX,
            size: 1
        }
    ));
}
