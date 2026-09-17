#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_llm_metadata::{Category, MetadataCapability};

const PY_DISASM_CAP: MetadataCapability = MetadataCapability::new(
    "disrobe-pass-py-disasm",
    "0.1.0",
    &[
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Constants,
        Category::OpcodeCoverage,
        Category::Provenance,
    ],
);

const _: () = {
    assert!(PY_DISASM_CAP.supports(Category::Disasm));
    assert!(!PY_DISASM_CAP.supports(Category::Ast));
    assert!(PY_DISASM_CAP.supports(Category::Provenance));
};

#[test]
fn supports_returns_true_for_listed() {
    for c in [
        Category::Disasm,
        Category::Symbols,
        Category::Strings,
        Category::Constants,
        Category::OpcodeCoverage,
        Category::Provenance,
    ] {
        assert!(PY_DISASM_CAP.supports(c), "should support {c:?}");
    }
}

#[test]
fn supports_returns_false_for_missing() {
    for c in [
        Category::Ast,
        Category::Cfg,
        Category::Dfg,
        Category::Types,
        Category::Imports,
        Category::Signatures,
        Category::RoundtripVerdict,
        Category::SourceMap,
        Category::Manifest,
        Category::DecryptionKeys,
        Category::Confidence,
        Category::PiiMap,
    ] {
        assert!(!PY_DISASM_CAP.supports(c), "should NOT support {c:?}");
    }
}

#[test]
fn empty_capability_supports_nothing() {
    const EMPTY: MetadataCapability = MetadataCapability::new("empty-pass", "0.0.1", &[]);
    for c in Category::ALL {
        assert!(!EMPTY.supports(c));
    }
}
