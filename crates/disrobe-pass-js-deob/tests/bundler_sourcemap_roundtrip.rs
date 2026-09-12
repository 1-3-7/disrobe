#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    DecodedMappings, RecoveredSourceMap, decode_mappings, decode_vlq, parse_source_map,
};

fn corpus_map(rel: &str) -> Option<String> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p: PathBuf = manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel);
    fs::read_to_string(p).ok()
}

fn embedded_sources(raw_json: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(raw_json).expect("json");
    v.get("sources")
        .and_then(|s: &serde_json::Value| s.as_array())
        .map(|a: &Vec<serde_json::Value>| {
            a.iter()
                .map(|x: &serde_json::Value| x.as_str().unwrap_or_default().to_owned())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

fn embedded_names(raw_json: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(raw_json).expect("json");
    v.get("names")
        .and_then(|s: &serde_json::Value| s.as_array())
        .map(|a: &Vec<serde_json::Value>| {
            a.iter()
                .map(|x: &serde_json::Value| x.as_str().unwrap_or_default().to_owned())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

#[test]
fn vlq_decoder_matches_known_spec_vectors() {
    assert_eq!(decode_vlq("AAAA"), Some(vec![0, 0, 0, 0]));
    assert_eq!(decode_vlq("UACA"), Some(vec![10, 0, 1, 0]));
    assert_eq!(decode_vlq("D"), Some(vec![-1]));
    assert_eq!(decode_vlq("2H"), Some(vec![123]));
}

#[test]
fn webpack5_real_map_recovers_every_module_boundary() {
    let Some(raw): Option<String> = corpus_map("webpack5/bundle.js.map") else {
        return;
    };
    let parsed: RecoveredSourceMap = parse_source_map(&raw).expect("parse webpack5 map");
    let truth: Vec<String> = embedded_sources(&raw);
    assert!(!truth.is_empty(), "ground-truth sources must exist");
    assert_eq!(
        parsed.sources, truth,
        "recovered sources must equal the map's own sources list"
    );
    for src in &truth {
        if src.ends_with("/src/index.js")
            || src.ends_with("/src/math.js")
            || src.ends_with("/src/util.js")
        {
            assert!(
                parsed.source_token_counts.contains_key(src),
                "every real module boundary must produce >=1 mapping token: {src}"
            );
        }
    }
    let mapped_sources: usize = parsed.source_token_counts.len();
    assert!(
        mapped_sources >= 3,
        "webpack5 bundle maps at least the three app modules; got {mapped_sources}"
    );
}

#[test]
fn vite_real_map_recovers_sources_and_referenced_names() {
    let Some(raw): Option<String> = corpus_map("vite/assets/index-DQvCGGXF.js.map") else {
        return;
    };
    let parsed: RecoveredSourceMap = parse_source_map(&raw).expect("parse vite map");
    let truth_sources: Vec<String> = embedded_sources(&raw);
    let truth_names: Vec<String> = embedded_names(&raw);
    assert_eq!(parsed.sources, truth_sources);
    for name in &parsed.referenced_names {
        assert!(
            truth_names.contains(name),
            "every recovered name must come from the map's own names table: {name}"
        );
    }
    assert!(
        parsed
            .sources
            .iter()
            .any(|s: &String| s.ends_with("index.js")),
        "index module must be recovered: {:?}",
        parsed.sources
    );
}

#[test]
fn esbuild_real_map_segment_count_is_consistent() {
    let Some(raw): Option<String> = corpus_map("esbuild/bundle.js.map") else {
        return;
    };
    let parsed: RecoveredSourceMap = parse_source_map(&raw).expect("parse esbuild map");
    let total_tokens: usize = parsed.source_token_counts.values().sum();
    assert!(
        total_tokens > 0 && total_tokens <= parsed.mappings.segment_count,
        "source-bearing tokens {total_tokens} must be within total segment count {}",
        parsed.mappings.segment_count
    );
    assert_eq!(parsed.sources.len(), embedded_sources(&raw).len());
}

#[test]
fn every_corpus_map_decodes_without_loss() {
    let maps: &[&str] = &[
        "webpack5/bundle.js.map",
        "webpack5/899.bundle.js.map",
        "vite/assets/index-DQvCGGXF.js.map",
        "vite/assets/lazy-mZ_fD4Dv.js.map",
        "esbuild/bundle.js.map",
        "rollup/bundle.js.map",
        "bun/bundle.js.map",
        "systemjs/bundle.js.map",
        "parcel/bundle.js.map",
    ];
    let mut checked: usize = 0;
    for rel in maps {
        let Some(raw): Option<String> = corpus_map(rel) else {
            continue;
        };
        let v: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let mappings: &str = v
            .get("mappings")
            .and_then(|m: &serde_json::Value| m.as_str())
            .unwrap_or_default();
        let decoded: DecodedMappings =
            decode_mappings(mappings).unwrap_or_else(|| panic!("decode failed for {rel}"));
        assert!(
            decoded.segment_count > 0,
            "{rel} must decode at least one mapping segment"
        );
        checked += 1;
    }
    assert!(checked > 0, "expected at least one corpus map present");
}
