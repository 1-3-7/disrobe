use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn python_deobfuscated_header(
    duration: Duration,
    python_version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Deobfuscated,
        duration,
        Language::Python,
        python_version,
    )
}

#[must_use]
pub fn render_deobfuscated_with_header(
    body: &str,
    duration: Duration,
    python_version: impl Into<String>,
) -> String {
    python_deobfuscated_header(duration, python_version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deobfuscated_python_header_prepends_correctly() {
        let s: String =
            render_deobfuscated_with_header("clean()\n", Duration::from_millis(75), "3.13");
        assert!(s.starts_with("# Deobfuscated in 75ms"));
        assert!(s.contains("\n# Python 3.13\n"));
    }
}
