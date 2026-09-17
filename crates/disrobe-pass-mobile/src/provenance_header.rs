use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn hermes_disasm_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Disassembled, duration, Language::Hermes, version)
}

#[must_use]
pub fn hermes_lifted_to_js_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::JavaScript, version)
}

#[must_use]
pub fn dart_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Dart, version)
}

#[must_use]
pub fn rn_bundle_extracted_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::JavaScript, version)
}

#[must_use]
pub fn render_hermes_disasm_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    hermes_disasm_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_hermes_lifted_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    hermes_lifted_to_js_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_dart_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    dart_decompiled_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_rn_bundle_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    rn_bundle_extracted_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermes_disasm_header_uses_double_slash() {
        let s: String =
            render_hermes_disasm_with_header(".hbc\n", Duration::from_millis(50), "0.12");
        assert!(s.starts_with("// Disassembled in 50ms"));
        assert!(s.contains("\n// Hermes 0.12\n"));
    }

    #[test]
    fn hermes_lifted_uses_js_label() {
        let s: String = render_hermes_lifted_with_header(
            "function f(){}\n",
            Duration::from_millis(200),
            "ES2024",
        );
        assert!(s.starts_with("// Lifted in 200ms"));
        assert!(s.contains("\n// JavaScript ES2024\n"));
    }
}
