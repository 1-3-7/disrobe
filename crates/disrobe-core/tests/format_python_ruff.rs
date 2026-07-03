#![allow(clippy::expect_used)]
use disrobe_core::format::{
    FormatterLanguage, PythonRuffFormatter, SourceFormatter, format_or_passthrough,
};

#[test]
fn python_ruff_formats_or_passes_through() {
    let src: &str = "def f():pass\n";
    let formatter: PythonRuffFormatter = PythonRuffFormatter;
    if formatter.is_available() {
        let out: String = formatter
            .format(src)
            .expect("ruff is available; format must succeed");
        assert!(out.ends_with('\n'), "ruff output should end with newline");
        assert!(
            out.contains("def f"),
            "ruff output should preserve function"
        );
    } else {
        let out: String = format_or_passthrough(src, FormatterLanguage::Python);
        assert_eq!(out, src, "identity fall-through must preserve input");
    }
}
