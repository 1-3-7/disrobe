use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn php_deobfuscated_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Deobfuscated, duration, Language::Php, version)
}

#[must_use]
pub fn php_extracted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::Php, version)
}

#[must_use]
pub fn render_php_deobfuscated_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    php_deobfuscated_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_php_extracted_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    php_extracted_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn php_header_uses_hash() {
        let s: String = render_php_deobfuscated_with_header(
            "<?php echo 1; ?>\n",
            Duration::from_millis(8),
            "8.3",
        );
        assert!(s.starts_with("# Deobfuscated in 8ms"));
        assert!(s.contains("\n# PHP 8.3\n"));
    }
}
