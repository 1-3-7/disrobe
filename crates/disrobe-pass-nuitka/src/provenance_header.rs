use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn c_disasm_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Disassembled, duration, Language::C, version)
}

#[must_use]
pub fn python_extracted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::Python, version)
}

#[must_use]
pub fn render_c_disasm_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    c_disasm_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuitka_c_disasm_header_uses_double_slash() {
        let s: String =
            render_c_disasm_with_header("manifest\n", Duration::from_millis(900), "Nuitka 2.4");
        assert!(s.starts_with("// Disassembled in 900ms"));
        assert!(s.contains("\n// C Nuitka 2.4\n"));
    }
}
