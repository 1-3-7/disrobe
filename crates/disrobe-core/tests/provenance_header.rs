#![allow(clippy::expect_used)]

use std::time::Duration;

use disrobe_core::provenance::{
    CommentStyle, Language, PROVENANCE_JSON_KEY, Protocol, ProvenanceHeader, header_for,
    pretty_duration,
};

fn expect_header(protocol: Protocol, lang: Language, ver: &str, dur: Duration, want: &str) {
    let h: ProvenanceHeader = header_for(protocol, dur, lang, ver);
    let rendered: String = h.render();
    assert_eq!(
        rendered, want,
        "render mismatch for {protocol:?}/{lang:?}/{ver:?}"
    );
}

#[test]
fn python_disassembled_matches_spec_example() {
    expect_header(
        Protocol::Disassembled,
        Language::Python,
        "3.13",
        Duration::from_millis(1200),
        "# Disassembled in 1.2s with Disrobe (https://github.com/1-3-7/disrobe)\n# Python 3.13\n",
    );
}

#[test]
fn javascript_deobfuscated_matches_spec_example() {
    expect_header(
        Protocol::Deobfuscated,
        Language::JavaScript,
        "ES2024",
        Duration::from_millis(340),
        "// Deobfuscated in 340ms with Disrobe (https://github.com/1-3-7/disrobe)\n// JavaScript ES2024\n",
    );
}

#[test]
fn wat_decompiled_matches_spec_example() {
    expect_header(
        Protocol::Decompiled,
        Language::Wat,
        "1.0",
        Duration::from_millis(5100),
        ";; Decompiled in 5.1s with Disrobe (https://github.com/1-3-7/disrobe)\n;; WebAssembly 1.0\n",
    );
}

#[test]
fn lua_decompiled_uses_double_dash() {
    let h: ProvenanceHeader = header_for(
        Protocol::Decompiled,
        Duration::from_secs(2),
        Language::Lua,
        "5.4",
    );
    let s: String = h.render();
    assert!(s.starts_with("-- Decompiled in 2.0s"));
    assert!(s.ends_with("-- Lua 5.4\n"));
}

#[test]
fn html_extracted_pairs_marker() {
    let h: ProvenanceHeader = header_for(
        Protocol::Extracted,
        Duration::from_millis(50),
        Language::Html,
        "5",
    );
    let s: String = h.render();
    assert!(s.contains("<!-- Extracted in 50ms with Disrobe"));
    assert!(s.contains(" -->\n"));
}

#[test]
fn duration_bucket_ms_unit() {
    assert_eq!(pretty_duration(Duration::from_millis(1)), "1ms");
    assert_eq!(pretty_duration(Duration::from_millis(999)), "999ms");
}

#[test]
fn duration_bucket_seconds_unit() {
    assert_eq!(pretty_duration(Duration::from_millis(1_500)), "1.5s");
}

#[test]
fn duration_bucket_minutes_unit() {
    assert_eq!(pretty_duration(Duration::from_secs(60 * 5)), "5.0m");
}

#[test]
fn duration_bucket_hours_unit() {
    assert_eq!(pretty_duration(Duration::from_secs(60 * 60 * 2)), "2.0h");
}

#[test]
fn duration_bucket_days_unit() {
    assert_eq!(
        pretty_duration(Duration::from_secs(60 * 60 * 24 * 3 + 60 * 60 * 12)),
        "3.5d"
    );
}

#[test]
fn duration_zero_renders_zero_ms() {
    assert_eq!(pretty_duration(Duration::ZERO), "0ms");
}

#[test]
fn duration_overflow_caps_at_five_days_plus() {
    assert_eq!(
        pretty_duration(Duration::from_secs(60 * 60 * 24 * 30)),
        "5d+"
    );
}

#[test]
fn prepend_to_preserves_body_after_header() {
    let h: ProvenanceHeader = header_for(
        Protocol::Unpacked,
        Duration::from_millis(0),
        Language::Python,
        "3.12",
    );
    let out: String = h.prepend_to("import sys\n");
    assert!(out.starts_with("# Unpacked in 0ms"));
    assert!(out.ends_with("import sys\n"));
}

#[test]
fn prepend_to_bytes_keeps_payload_intact() {
    let h: ProvenanceHeader = header_for(
        Protocol::Lifted,
        Duration::from_millis(123),
        Language::Rust,
        "edition 2024",
    );
    let body: &[u8] = b"fn main() {}\n";
    let out: Vec<u8> = h.prepend_to_bytes(body);
    let header: String = h.render();
    assert!(out.starts_with(header.as_bytes()));
    assert_eq!(&out[header.len()..], body);
}

#[test]
fn json_inject_adds_provenance_key() {
    let h: ProvenanceHeader = header_for(
        Protocol::Decoded,
        Duration::from_millis(7),
        Language::Python,
        "3.12",
    );
    let original: serde_json::Value = serde_json::json!({"k": "v"});
    let injected: serde_json::Value = h.inject_into_json(original);
    let obj: &serde_json::Map<String, serde_json::Value> = injected.as_object().expect("object");
    assert!(obj.contains_key("k"));
    assert!(obj.contains_key(PROVENANCE_JSON_KEY));
}

#[test]
fn comment_style_prefixes_are_stable_strings() {
    assert_eq!(CommentStyle::Hash.prefix(), "#");
    assert_eq!(CommentStyle::DoubleSlash.prefix(), "//");
    assert_eq!(CommentStyle::DoubleDash.prefix(), "--");
    assert_eq!(CommentStyle::SemiSemi.prefix(), ";;");
    assert_eq!(CommentStyle::Pound.prefix(), "%");
    assert_eq!(CommentStyle::HtmlComment.prefix(), "<!--");
}
