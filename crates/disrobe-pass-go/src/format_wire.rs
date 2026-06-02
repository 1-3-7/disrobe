use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_go(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Go)
}
