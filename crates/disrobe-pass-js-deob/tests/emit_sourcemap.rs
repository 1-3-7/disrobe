#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use disrobe_pass_js_deob::{
    BundlerKind, SourceMapEmit, SourceMapInfo, SynthesizedSourceMap, UnbundleGraphResult,
    decode_inline_data_url, find_source_map, unbundle_with_sourcemaps,
};

const WEBPACK5_FULL: &str = include_str!("../corpus/bundlers/webpack5/full-graph/bundle.js");
const INLINE_BUNDLE: &str = include_str!("../corpus/bundlers/sourcemap/inline/bundle.js");

const WEBPACK5_EXPECTED_MODULE_IDS: &[&str] = &[
    "./src/index.js",
    "./src/util.js",
    "./node_modules/lib/index.js",
];

fn decode_vlq(segment: &str) -> Vec<i64> {
    let mut values: Vec<i64> = Vec::new();
    let mut shift: u32 = 0;
    let mut acc: i64 = 0;
    for ch in segment.chars() {
        let digit: i64 = base64_value(ch);
        let continuation: bool = (digit & 0b10_0000) != 0;
        acc += (digit & 0b1_1111) << shift;
        if continuation {
            shift += 5;
        } else {
            let negative: bool = (acc & 1) != 0;
            let magnitude: i64 = acc >> 1;
            values.push(if negative { -magnitude } else { magnitude });
            acc = 0;
            shift = 0;
        }
    }
    values
}

fn base64_value(ch: char) -> i64 {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    TABLE.iter().position(|&b: &u8| b == ch as u8).map_or_else(
        || panic!("invalid base64 vlq char {ch:?}"),
        |p: usize| p as i64,
    )
}

#[test]
fn inline_data_url_is_independent_ground_truth() {
    let info: SourceMapInfo =
        find_source_map(INLINE_BUNDLE).expect("inline bundle must advertise a source map");
    assert!(info.inline, "the source map must be an inline data url");

    let decoded: disrobe_pass_js_deob::DecodedInlineMap =
        decode_inline_data_url(&info.url).expect("decode inline data url");
    let map: serde_json::Value =
        serde_json::from_str(&decoded.raw_json).expect("inline map must be valid json");

    assert_eq!(map["version"], 3);
    let sources: &Vec<serde_json::Value> = map["sources"].as_array().expect("sources array");
    assert_eq!(sources, &vec![serde_json::Value::from("a.js")]);

    let content: &str = map["sourcesContent"][0]
        .as_str()
        .expect("sourcesContent[0]");
    assert!(
        INLINE_BUNDLE.contains(content),
        "the source-map's own sourcesContent {content:?} must trace back into the bundle body"
    );
}

#[test]
fn webpack5_debundle_recovers_sourcemap_module_boundaries() {
    let (graph, emit): (UnbundleGraphResult, SourceMapEmit) =
        unbundle_with_sourcemaps(BundlerKind::Webpack5, WEBPACK5_FULL).expect("unbundle");

    let recovered_ids: Vec<&str> = graph
        .modules
        .iter()
        .map(|m: &disrobe_pass_js_deob::ExtractedModule| m.id.as_str())
        .collect();
    for id in WEBPACK5_EXPECTED_MODULE_IDS {
        assert!(
            recovered_ids.contains(id),
            "debundle must recover bundle-intrinsic module id {id:?}; got {recovered_ids:?}"
        );
    }

    let all_sourcemap_sources: Vec<String> = emit
        .per_chunk
        .values()
        .flat_map(|m: &SynthesizedSourceMap| m.sources.iter().cloned())
        .collect();
    for id in WEBPACK5_EXPECTED_MODULE_IDS {
        assert!(
            all_sourcemap_sources.iter().any(|s: &String| s == id),
            "every recovered module {id:?} must appear as a source-map source; got {all_sourcemap_sources:?}"
        );
    }

    let main_map: &SynthesizedSourceMap = emit.per_chunk.get("main").expect("main chunk map");
    assert_eq!(
        main_map.sources,
        vec!["./src/index.js".to_owned(), "./src/util.js".to_owned()],
        "main chunk source boundaries must match the bundle's __webpack_modules__ key order"
    );
}

#[test]
fn webpack5_mappings_decode_to_recovered_source_indices() {
    let (_graph, emit): (UnbundleGraphResult, SourceMapEmit) =
        unbundle_with_sourcemaps(BundlerKind::Webpack5, WEBPACK5_FULL).expect("unbundle");
    let main_map: &SynthesizedSourceMap = emit.per_chunk.get("main").expect("main chunk map");

    let lines: Vec<&str> = main_map.mappings.split(';').collect();
    assert_eq!(
        lines.len(),
        main_map.sources.len(),
        "one generated mapping line per recovered module: {:?}",
        main_map.mappings
    );

    let mut resolved_source: i64 = 0;
    for (line_idx, line) in lines.iter().enumerate() {
        let fields: Vec<i64> = decode_vlq(line);
        assert_eq!(
            fields.len(),
            4,
            "v3 segment must carry [genCol, srcIdx, srcLine, srcCol]; line {line_idx} = {line:?}"
        );
        resolved_source += fields[1];
        assert_eq!(
            resolved_source,
            i64::try_from(line_idx).unwrap(),
            "decoded source index must walk 0..n across recovered modules"
        );
    }
    assert_eq!(
        resolved_source,
        i64::try_from(main_map.sources.len() - 1).unwrap(),
        "final resolved source index must reach the last recovered module"
    );
}

#[test]
fn falsification_wrong_module_id_is_not_a_sourcemap_source() {
    let (_graph, emit): (UnbundleGraphResult, SourceMapEmit) =
        unbundle_with_sourcemaps(BundlerKind::Webpack5, WEBPACK5_FULL).expect("unbundle");
    let all_sources: Vec<String> = emit
        .per_chunk
        .values()
        .flat_map(|m: &SynthesizedSourceMap| m.sources.iter().cloned())
        .collect();
    assert!(
        !all_sources
            .iter()
            .any(|s: &String| s == "./src/does-not-exist.js"),
        "falsification: a module id the bundle never declared must not surface as a source-map source"
    );
}

#[test]
fn falsification_inline_content_mismatch_is_detectable() {
    let info: SourceMapInfo = find_source_map(INLINE_BUNDLE).expect("inline source map");
    let decoded: disrobe_pass_js_deob::DecodedInlineMap =
        decode_inline_data_url(&info.url).expect("decode");
    let map: serde_json::Value = serde_json::from_str(&decoded.raw_json).expect("json");
    let content: &str = map["sourcesContent"][0].as_str().expect("content");
    assert_ne!(
        content, "var z = 99;",
        "falsification control: the inline map's real content is not the fabricated string"
    );
}
