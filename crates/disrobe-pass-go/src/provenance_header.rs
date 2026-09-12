use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn go_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Go, version)
}

#[must_use]
pub fn go_extracted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::Go, version)
}

#[must_use]
pub fn render_go_decompiled_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    go_decompiled_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_decompiled_header_uses_double_slash() {
        let s: String =
            render_go_decompiled_with_header("package main\n", Duration::from_millis(330), "1.22");
        assert!(s.starts_with("// Decompiled in 330ms"));
        assert!(s.contains("\n// Go 1.22\n"));
    }
}
