#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use disrobe_llm_metadata::{Category, Pack};

#[test]
fn pack1_matches_spec() {
    let got: BTreeSet<Category> = Pack::Pack1.expand();
    let want: BTreeSet<Category> = [
        Category::Ast,
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
}

#[test]
fn pack2_matches_spec() {
    let got: BTreeSet<Category> = Pack::Pack2.expand();
    let want: BTreeSet<Category> = [
        Category::Ast,
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Cfg,
        Category::Types,
        Category::Imports,
        Category::Provenance,
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
}

#[test]
fn pack3_matches_spec() {
    let got: BTreeSet<Category> = Pack::Pack3.expand();
    let want: BTreeSet<Category> = [
        Category::Ast,
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Cfg,
        Category::Types,
        Category::Imports,
        Category::Provenance,
        Category::Dfg,
        Category::Signatures,
        Category::Constants,
        Category::RoundtripVerdict,
        Category::SourceMap,
        Category::Manifest,
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
}

#[test]
fn pack4_includes_all_18_including_decryption_keys() {
    let got: BTreeSet<Category> = Pack::Pack4.expand();
    assert_eq!(got.len(), 18);
    for c in Category::ALL {
        assert!(got.contains(&c), "pack-4 missing {c:?}");
    }
}

#[test]
fn pack_labels_are_kebab_case() {
    assert_eq!(Pack::Pack1.label(), "pack-1");
    assert_eq!(Pack::Pack4.label(), "pack-4");
}

#[test]
fn serde_emits_kebab_case() {
    let s: String = serde_json::to_string(&Pack::Pack3).unwrap();
    assert_eq!(s, "\"pack-3\"");
    let parsed: Pack = serde_json::from_str("\"pack-2\"").unwrap();
    assert_eq!(parsed, Pack::Pack2);
}
