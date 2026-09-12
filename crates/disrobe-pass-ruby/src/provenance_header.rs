use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn yarv_disasm_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Disassembled, duration, Language::Ruby, version)
}

#[must_use]
pub fn ruby_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Ruby, version)
}

#[must_use]
pub fn mruby_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Ruby, version)
}

#[must_use]
pub fn render_yarv_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    yarv_disasm_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_ruby_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    ruby_decompiled_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yarv_disasm_header_uses_hash() {
        let s: String = render_yarv_with_header("trace\n", Duration::from_millis(15), "3.3");
        assert!(s.starts_with("# Disassembled in 15ms"));
        assert!(s.contains("\n# Ruby 3.3\n"));
    }

    #[test]
    fn ruby_decompiled_header_uses_hash() {
        let s: String = render_ruby_with_header("def x; end\n", Duration::from_millis(80), "3.3");
        assert!(s.starts_with("# Decompiled in 80ms"));
        assert!(s.contains("\n# Ruby 3.3\n"));
    }
}
