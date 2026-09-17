use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn python_disasm_header(
    duration: Duration,
    python_version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Disassembled,
        duration,
        Language::Python,
        python_version,
    )
}

#[must_use]
pub fn python_unpacked_header(
    duration: Duration,
    python_version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Unpacked,
        duration,
        Language::Python,
        python_version,
    )
}

#[must_use]
pub fn render_disasm_with_header(
    body: &str,
    duration: Duration,
    python_version: impl Into<String>,
) -> String {
    python_disasm_header(duration, python_version).prepend_to(body)
}

#[must_use]
pub fn render_unpacked_with_header(
    body: &str,
    duration: Duration,
    python_version: impl Into<String>,
) -> String {
    python_unpacked_header(duration, python_version).prepend_to(body)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn disasm_header_emits_python_hash_two_line_header() {
        let out: String =
            render_disasm_with_header("dis goes here\n", Duration::from_millis(1200), "3.13");
        assert!(out.starts_with("# Disassembled in 1.2s with Disrobe"));
        assert!(out.contains("\n# Python 3.13\n"));
        assert!(out.ends_with("dis goes here\n"));
    }

    #[test]
    fn unpacked_header_uses_unpacked_protocol_label() {
        let h: ProvenanceHeader = python_unpacked_header(Duration::from_millis(50), "3.12");
        let r: String = h.render();
        assert!(r.starts_with("# Unpacked in 50ms"));
    }
}
