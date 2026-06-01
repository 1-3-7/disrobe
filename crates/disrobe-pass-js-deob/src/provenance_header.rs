use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn js_deobfuscated_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(
        Protocol::Deobfuscated,
        duration,
        Language::JavaScript,
        version,
    )
}

#[must_use]
pub fn ts_deobfuscated_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(
        Protocol::Deobfuscated,
        duration,
        Language::TypeScript,
        version,
    )
}

#[must_use]
pub fn js_decoded_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decoded, duration, Language::JavaScript, version)
}

#[must_use]
pub fn js_extracted_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Extracted, duration, Language::JavaScript, version)
}

#[must_use]
pub fn v8_bytecode_disasm_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(
        Protocol::Disassembled,
        duration,
        Language::V8Bytecode,
        version,
    )
}

#[must_use]
pub fn v8_bytecode_lifted_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Lifted, duration, Language::JavaScript, version)
}

#[must_use]
pub fn render_js_deobfuscated_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    js_deobfuscated_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_ts_deobfuscated_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    ts_deobfuscated_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_v8_disasm_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    v8_bytecode_disasm_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_deobfuscated_header_matches_spec_example() {
        let s: String = render_js_deobfuscated_with_header(
            "var x = 1;\n",
            Duration::from_millis(340),
            "ES2024",
        );
        assert!(s.starts_with("// Deobfuscated in 340ms"));
        assert!(s.contains("\n// JavaScript ES2024\n"));
    }

    #[test]
    fn ts_deobfuscated_header_uses_double_slash() {
        let s: String = render_ts_deobfuscated_with_header(
            "type X = unknown;\n",
            Duration::from_millis(60),
            "5.5",
        );
        assert!(s.starts_with("// Deobfuscated in 60ms"));
        assert!(s.contains("\n// TypeScript 5.5\n"));
    }
}
