use disrobe_core::format::{FormatterLanguage, format_or_passthrough};

#[must_use]
pub fn format_c(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::C)
}

#[must_use]
pub fn format_cpp(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Cpp)
}

#[must_use]
pub fn format_rust(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Rust)
}

#[must_use]
pub fn format_objc(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::ObjectiveC)
}

#[must_use]
pub fn format_swift(src: &str) -> String {
    format_or_passthrough(src, FormatterLanguage::Swift)
}
