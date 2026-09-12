use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn as3_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(
        Protocol::Decompiled,
        duration,
        Language::ActionScript3,
        version,
    )
}

#[must_use]
pub fn render_as3_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    as3_decompiled_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as3_header_uses_double_slash() {
        let s: String = render_as3_with_header("package x{}\n", Duration::from_millis(70), "3.0");
        assert!(s.starts_with("// Decompiled in 70ms"));
        assert!(s.contains("\n// ActionScript 3.0\n"));
    }
}
