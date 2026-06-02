#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::str::FromStr;

use disrobe_llm_metadata::Category;

#[test]
fn all_18_categories_present_and_unique() {
    let count: usize = Category::ALL.len();
    assert_eq!(count, 18);
    let mut sorted: Vec<&'static str> =
        Category::ALL.iter().map(|c: &Category| c.label()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 18, "duplicate category label detected");
}

#[test]
fn label_matches_schema_snake_case() {
    let expected: [(Category, &str); 18] = [
        (Category::Ast, "ast"),
        (Category::Disasm, "disasm"),
        (Category::Cfg, "cfg"),
        (Category::Dfg, "dfg"),
        (Category::Symbols, "symbols"),
        (Category::Strings, "strings"),
        (Category::Types, "types"),
        (Category::Imports, "imports"),
        (Category::Constants, "constants"),
        (Category::Signatures, "signatures"),
        (Category::Provenance, "provenance"),
        (Category::RoundtripVerdict, "roundtrip_verdict"),
        (Category::SourceMap, "source_map"),
        (Category::Manifest, "manifest"),
        (Category::DecryptionKeys, "decryption_keys"),
        (Category::Confidence, "confidence"),
        (Category::OpcodeCoverage, "opcode_coverage"),
        (Category::PiiMap, "pii_map"),
    ];
    for (c, label) in expected {
        assert_eq!(c.label(), label, "label mismatch for {c:?}");
    }
}

#[test]
fn display_and_fromstr_roundtrip() {
    for c in Category::ALL {
        let displayed: String = c.to_string();
        let parsed: Category = Category::from_str(&displayed).expect("parse must roundtrip label");
        assert_eq!(parsed, c, "roundtrip failed for {c:?}");
    }
}

#[test]
fn parse_is_case_insensitive_and_trims() {
    assert_eq!(Category::parse("AST").unwrap(), Category::Ast);
    assert_eq!(
        Category::parse("  source_map  ").unwrap(),
        Category::SourceMap
    );
    assert_eq!(
        Category::parse("Decryption_Keys").unwrap(),
        Category::DecryptionKeys
    );
    assert_eq!(
        Category::parse("OPCODE_COVERAGE").unwrap(),
        Category::OpcodeCoverage
    );
}

#[test]
fn parse_unknown_returns_error() {
    let err: disrobe_llm_metadata::LlmMetadataError =
        Category::parse("not_a_category").unwrap_err();
    assert!(matches!(
        err,
        disrobe_llm_metadata::LlmMetadataError::UnknownCategory(_)
    ));
}

#[test]
fn serde_emits_snake_case() {
    let json: String = serde_json::to_string(&Category::RoundtripVerdict).unwrap();
    assert_eq!(json, "\"roundtrip_verdict\"");
    let parsed: Category = serde_json::from_str("\"pii_map\"").unwrap();
    assert_eq!(parsed, Category::PiiMap);
}
