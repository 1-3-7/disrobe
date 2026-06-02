use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn python_extracted_header(
    duration: Duration,
    python_version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Extracted,
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
pub fn render_extracted_with_header(
    body: &str,
    duration: Duration,
    python_version: impl Into<String>,
) -> String {
    python_extracted_header(duration, python_version).prepend_to(body)
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
    fn extracted_header_starts_with_python_hash() {
        let s: String = render_extracted_with_header("body", Duration::from_millis(40), "3.13");
        assert!(s.starts_with("# Extracted in 40ms"));
        assert!(s.contains("\n# Python 3.13\n"));
    }
}
