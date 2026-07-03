use std::time::Duration;

use disrobe_core::provenance::{Language, Protocol, ProvenanceHeader, header_for};

#[must_use]
pub fn smali_disasm_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Disassembled, duration, Language::Smali, version)
}

#[must_use]
pub fn java_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Java, version)
}

#[must_use]
pub fn kotlin_decompiled_header(
    duration: Duration,
    version: impl Into<String>,
) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Kotlin, version)
}

#[must_use]
pub fn scala_decompiled_header(duration: Duration, version: impl Into<String>) -> ProvenanceHeader {
    header_for(Protocol::Decompiled, duration, Language::Scala, version)
}

#[must_use]
pub fn render_smali_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    smali_disasm_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_java_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    java_decompiled_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_kotlin_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    kotlin_decompiled_header(duration, version).prepend_to(body)
}

#[must_use]
pub fn render_scala_with_header(
    body: &str,
    duration: Duration,
    version: impl Into<String>,
) -> String {
    scala_decompiled_header(duration, version).prepend_to(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smali_disasm_header_uses_double_slash() {
        let s: String = render_smali_with_header(".class\n", Duration::from_millis(70), "JVM 21");
        assert!(s.starts_with("// Disassembled in 70ms"));
        assert!(s.contains("\n// Smali JVM 21\n"));
    }

    #[test]
    fn java_decompiled_header_uses_double_slash() {
        let s: String = render_java_with_header("class C{}\n", Duration::from_millis(900), "21");
        assert!(s.starts_with("// Decompiled in 900ms"));
        assert!(s.contains("\n// Java 21\n"));
    }
}
