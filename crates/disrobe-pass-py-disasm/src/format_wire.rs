use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_python(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Python)
}

#[must_use]
pub fn format_identity(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Identity)
}
