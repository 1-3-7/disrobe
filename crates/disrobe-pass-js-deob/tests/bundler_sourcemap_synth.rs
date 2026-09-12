#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    BundlerKind, DecodedInlineMap, SourceMapEmit, SynthesizedSourceMap, decode_inline_data_url,
    unbundle_with_sourcemaps, write_sourcemaps,
};

const INLINE_BUNDLE: &str = include_str!("../corpus/bundlers/sourcemap/inline/bundle.js");
const WEBPACK5_FULL: &str = include_str!("../corpus/bundlers/webpack5/full-graph/bundle.js");

fn unique_dir(label: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-bundler-sourcemap-{label}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

#[test]
fn inline_data_url_decodes_to_valid_v3_source_map() {
    let url: String = INLINE_BUNDLE
        .lines()
        .find(|l: &&str| l.contains("sourceMappingURL=data:"))
        .map(|l: &str| {
            l.split("sourceMappingURL=")
                .nth(1)
                .map(str::to_owned)
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let decoded: DecodedInlineMap = decode_inline_data_url(&url).expect("decode");
    assert!(decoded.raw_json.contains("\"version\":3"));
    assert!(decoded.raw_json.contains("a.js"));
}

#[test]
fn webpack5_full_synthesizes_v3_map_for_chunk() {
    let (_graph_result, emit): (disrobe_pass_js_deob::UnbundleGraphResult, SourceMapEmit) =
        unbundle_with_sourcemaps(BundlerKind::Webpack5, WEBPACK5_FULL).expect("unbundle");
    let main_map: &SynthesizedSourceMap = emit.per_chunk.get("main").expect("main map");
    assert_eq!(main_map.version, 3);
    assert!(!main_map.sources.is_empty(), "{:?}", main_map.sources);
    assert!(
        main_map
            .sources
            .iter()
            .any(|s: &String| s == "./src/index.js"),
        "{:?}",
        main_map.sources
    );
    assert!(!main_map.mappings.is_empty());
    let scratch: disrobe_core::scratch::ScratchDir = unique_dir("write");
    let dir: PathBuf = scratch.path().to_path_buf();
    let written: BTreeMap<String, PathBuf> = write_sourcemaps(&dir, &emit).expect("write");
    assert!(written.contains_key("main"));
    let raw: String =
        std::fs::read_to_string(written.get("main").expect("main path")).expect("read");
    assert!(raw.contains("\"version\": 3"));
}
