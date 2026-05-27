use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_wat(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Wat)
}

#[must_use]
pub fn format_rust(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Rust)
}

#[must_use]
pub fn format_c(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::C)
}

#[must_use]
pub fn format_typescript(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::TypeScript)
}
