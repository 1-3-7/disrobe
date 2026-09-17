use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_lua(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Lua)
}
