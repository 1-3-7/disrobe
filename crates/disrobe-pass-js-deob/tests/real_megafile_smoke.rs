#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> String {
    let p: PathBuf = corpus_path(rel);
    fs::read_to_string(&p).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "tracked corpus fixture {} is required: {error}",
            p.display()
        )
    })
}

fn reparses(source: &str) -> bool {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType =
        oxc_span::SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

#[test]
fn megafile_is_parseable_by_oxc() {
    let src: String = load("megafile/edge_cases.js");
    assert!(reparses(&src), "the edge-case canvas itself must parse");
}

#[test]
fn megafile_contains_expected_es2024_features() {
    let src: String = load("megafile/edge_cases.js");
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
