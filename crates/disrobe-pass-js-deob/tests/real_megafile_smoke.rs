#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::format_javascript;

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> Option<String> {
    let p: PathBuf = corpus_path(rel);
    if !p.exists() {
        return None;
    }
    fs::read_to_string(&p).ok()
}

#[test]
fn megafile_is_parseable_by_oxc() {
    let Some(src): Option<String> = load("megafile/edge_cases.js") else {
        return;
    };
    let formatted: String = format_javascript(&src);
    assert!(
        !formatted.is_empty(),
        "format_javascript must emit non-empty output"
    );
}

#[test]
fn megafile_contains_expected_es2024_features() {
    let Some(src): Option<String> = load("megafile/edge_cases.js") else {
        return;
    };
    let markers: &[&str] = &[
        "async function",
        "async function*",
        "function*",
        "for await",
        "Promise.allSettled",
        "Promise.any",
        "?.",
        "??",
        "??=",
        "||=",
        "&&=",
        "Symbol.iterator",
        "WeakRef",
        "FinalizationRegistry",
        "Proxy",
        "Reflect",
        "BigInt64Array",
        "Object.hasOwn",
        "structuredClone",
        "AbortController",
        "AggregateError",
        "(?<year>",
        "(?<=",
        "(?=",
    ];
    for marker in markers {
        assert!(
            src.contains(marker),
            "megafile must exercise {marker} (otherwise it is not the canonical edge-case canvas)",
        );
    }
}
