#![allow(clippy::expect_used)]
use disrobe_core::format::test_helpers::{is_available, run_subprocess};
use disrobe_core::format::{FormatError, FormatterLanguage, format_or_passthrough};

const GUARANTEED_MISSING: &str = "disrobe-this-formatter-does-not-exist-anywhere-xyz";

#[test]
fn missing_tool_yields_tool_missing_error() {
    assert!(
        !is_available(GUARANTEED_MISSING),
        "the guaranteed-missing sentinel must not exist on PATH"
    );
    let err: FormatError = run_subprocess(GUARANTEED_MISSING, &["--help"], "", 5)
        .expect_err("must fail because tool is missing");
    assert!(matches!(err, FormatError::ToolMissing(_)));
}

#[test]
fn identity_fallthrough_never_panics() {
    let src: &str = "{\"unformatted\":true}\n";
    let out: String = format_or_passthrough(src, FormatterLanguage::Identity);
    assert_eq!(out, src);
}

#[test]
fn dispatch_factory_returns_box_dyn_for_every_lang() {
    let f = disrobe_core::format::formatter_for(FormatterLanguage::Wat);
    assert_eq!(f.language(), FormatterLanguage::Wat);
    assert!(f.is_available(), "wat passthrough must always be available");
}
