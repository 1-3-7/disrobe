use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_javascript(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::JavaScript)
}

#[must_use]
pub fn format_typescript(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::TypeScript)
}
