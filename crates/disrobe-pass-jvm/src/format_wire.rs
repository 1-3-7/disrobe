use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_java(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Java)
}

#[must_use]
pub fn format_kotlin(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Kotlin)
}

#[must_use]
pub fn format_scala(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Scala)
}
