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
pub fn render_disasm_with_header(
    body: &str,
    duration: Duration,
    python_version: impl Into<String>,
) -> String {
    python_disasm_header(duration, python_version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_disasm_header_starts_correctly() {
        let s: String =
            render_disasm_with_header("LOAD_CONST\n", Duration::from_millis(11), "3.13");
        assert!(s.starts_with("# Disassembled in 11ms"));
        assert!(s.contains("\n# Python 3.13\n"));
    }
}
