use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn python_decoded_header(
    duration: Duration,
    python_version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Decoded,
        duration,
        Language::Python,
        python_version,
    )
}

#[must_use]
pub fn render_decoded_with_header(
    body: &str,
    duration: Duration,
    python_version: impl Into<String>,
) -> String {
    python_decoded_header(duration, python_version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_python_header_prepends_two_lines() {
        let s: String = render_decoded_with_header("x = 1\n", Duration::from_millis(220), "3.12");
        assert!(s.starts_with("# Decoded in 220ms"));
        assert!(s.contains("\n# Python 3.12\n"));
        assert!(s.ends_with("x = 1\n"));
    }
}
